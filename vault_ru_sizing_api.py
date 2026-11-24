#!/usr/bin/env python3
"""
vault_ru_sizing_api.py — Vault RU sizing, live API only. No audit logs.

Counts the three RU categories readable straight from Vault:
  * Static Secrets            unique KV secrets (v1 and v2, recursive)
  * Dynamic / Auto-Rotated    roles across aws/azure/gcp/ldap/database/etc.
  * KMSE                      managed keys

PKI, SSH and Transit/Transform need audit logs — use vault_ru_sizing.py. Use
this one when you'd rather not ask for logs at all, since they expose mount
structure and request paths.

Unlike `vault list <mount>/roles`, which sees only the token's own namespace
and undercounts silently, this walks every namespace it can reach.

DISCLAIMER — NOT AN OFFICIAL IBM OR HASHICORP TOOL. USE AT YOUR OWN RISK.
    Unofficial, unsupported, no warranty. Never run against production —
    correctness rests on synthetic fixtures only. Output is NOT a quote and NOT
    a licensing determination; confirm every figure with your account team or
    deal desk before it reaches a customer or a contract.

SCOPE — SELF-MANAGED VAULT ENTERPRISE ONLY. HCP is licensed on cluster +
    client count and is not a valid target; an HCP run is detected,
    banner-stamped and written to *.INVALID-HCP.* files.

READ-ONLY. Issues only LIST and GET.

USAGE
    export VAULT_ADDR=https://vault.example.com:8200 VAULT_TOKEN=hvs....
    python3 vault_ru_sizing_api.py --namespace admin
    python3 vault_ru_sizing_api.py --namespace admin --mounts-only  # skip KV walk

    # monthly high-water mark: sample on a schedule, then report the peak
    python3 vault_ru_sizing_api.py --metrics --quiet --sample-to history.ndjson
    python3 vault_ru_sizing_api.py --report-only --highwater history.ndjson

TOKEN POLICY
    path "sys/namespaces"     { capabilities = ["list"] }
    path "sys/mounts"         { capabilities = ["read"] }
    path "sys/host-info"      { capabilities = ["read"] }   # platform detection
    path "sys/managed-keys/*" { capabilities = ["list"] }
    path "+/metadata/*"       { capabilities = ["list"] }   # kv-v2
    path "+/*"                { capabilities = ["list"] }   # kv-v1, roles
"""

import argparse, csv, json, os, ssl, sys, threading
from datetime import datetime, timezone
import urllib.request, urllib.error, urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

ROLE_ENDPOINTS = {
    "aws":       ["roles"],
    "azure":     ["roles"],
    "gcp":       ["roles", "static-accounts"],
    "database":  ["roles", "static-roles"],
    "ldap":      ["role", "static-role"],
    "consul":    ["roles"],
    "nomad":     ["role"],
    "terraform": ["role"],
    "kubernetes":["roles"],
    "rabbitmq":  ["roles"],
    "mongodbatlas": ["roles"],
    "alicloud":  ["role"],
}
NON_ROLE_TYPES = {"kv", "cubbyhole", "system", "identity", "ns_system", "ns_identity",
                  "pki", "ssh", "transit", "transform", "keymgmt", "totp"}
MANAGED_KEY_TYPES = ["pkcs11", "awskms", "azurekeyvault", "gcpckms"]

# Scope: RUs are the SELF-MANAGED Vault Enterprise model. HCP is licensed on
# cluster + client count, so an HCP run is banner-stamped and written to
# *.INVALID-HCP.* files - usable as a test cluster, never as sizing data.
HCP_HOST_SUFFIXES = (".hashicorp.cloud",)

HCP_BANNER = [
    "!! TARGET IS HCP VAULT - NOT A VALID RU SIZING TARGET",
    "   Resource Units apply to self-managed Vault Enterprise. HCP Vault is",
    "   licensed on the cluster + client-count model, so the numbers below",
    "   are a structural exercise only. Do NOT use them for sizing, quoting,",
    "   or anything customer-facing.",
]


def detect_platform(v):
    """
    Returns (platform, evidence): 'hcp' | 'self-managed' | 'unknown'.

    Only a positive read of sys/host-info proves self-managed; a failure proves
    nothing (the token may lack the capability), so anything unproven is
    'unknown' and treated as self-managed - the supported target.
    """
    host = (urllib.parse.urlsplit(v.addr).hostname or "").lower()
    for suffix in HCP_HOST_SUFFIXES:
        if host.endswith(suffix):
            return "hcp", "VAULT_ADDR host %s" % host
    try:
        _, code = v.req("sys/host-info", with_code=True)
    except Exception:
        code = None
    if code == 200:
        return "self-managed", "sys/host-info readable"
    return "unknown", "no distinguishing signal (sys/host-info -> %s)" % (code or "unreadable")


_lock = threading.Lock()


class Vault:
    def __init__(self, addr, token, verify=True, timeout=30):
        self.addr, self.token, self.timeout = addr.rstrip("/"), token, timeout
        self.ctx = None
        if not verify:
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    # Speculative probing, so these are normal rather than failures: 400
    # unavailable (e.g. managed keys on HCP), 403 no permission, 404 no path,
    # 405 LIST unsupported, 501 not in this edition.
    TOLERATED = (400, 403, 404, 405, 501)

    def req(self, path, namespace=None, list_op=False, strict=False, with_code=False):
        """
        With with_code=True, returns (data, http_status) instead of data alone.
        Callers need the status to tell "the endpoint answered and there is
        nothing here" from "the endpoint refused us" — both of which otherwise
        arrive as None and get counted as zero.
        """
        url = "%s/v1/%s" % (self.addr, path.lstrip("/"))
        if list_op:
            url += ("&" if "?" in url else "?") + "list=true"
        r = urllib.request.Request(url, method="GET")
        r.add_header("X-Vault-Token", self.token)
        if namespace:
            r.add_header("X-Vault-Namespace", namespace)
        try:
            with urllib.request.urlopen(r, timeout=self.timeout, context=self.ctx) as resp:
                code = getattr(resp, "status", None) or resp.getcode()
                body = resp.read().decode("utf-8")
                data = json.loads(body) if body.strip() else None
                return (data, code) if with_code else data
        except urllib.error.HTTPError as e:
            if not strict and e.code in self.TOLERATED:
                return (None, e.code) if with_code else None
            raise
        except urllib.error.URLError as e:
            raise SystemExit("Cannot reach %s: %s" % (self.addr, e.reason))


def fetch_metrics(v, namespace):
    """
    Pull the Prometheus-format telemetry scrape. Vault emits usage gauges here —
    vault.secret.kv.count (per mount) and vault.identity.entity.count (per
    namespace) — which answer the two slowest questions instantly, without
    walking anything.

    Requires telemetry to be enabled with prometheus_retention_time set, and
    read on sys/metrics. Returns raw text, or None if unavailable.

    Note: the gauges are emitted on an interval (usage_gauge_period, 10m by
    default), so a freshly started node may report nothing yet.
    """
    url = "%s/v1/sys/metrics?format=prometheus" % v.addr
    r = urllib.request.Request(url, method="GET")
    r.add_header("X-Vault-Token", v.token)
    if namespace:
        r.add_header("X-Vault-Namespace", namespace)
    try:
        with urllib.request.urlopen(r, timeout=v.timeout, context=v.ctx) as resp:
            return resp.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        why = {
            400: "HTTP 400 - telemetry not enabled, or Prometheus format not "
                 "configured (needs telemetry { prometheus_retention_time })",
            403: "HTTP 403 - token lacks read on sys/metrics",
            404: "HTTP 404 - endpoint not exposed (common on managed/HCP Vault; "
                 "use the HCP metrics streaming integration instead)",
        }.get(e.code, "HTTP %s" % e.code)
        return None, why
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)


def parse_prom(text, metric):
    """Sum a Prometheus metric and return (total, [(labels, value), ...])."""
    total, rows = 0.0, []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not line.startswith(metric):
            continue
        rest = line[len(metric):]
        if rest and rest[0] not in "{ ":
            continue                      # different metric sharing a prefix
        labels = ""
        if rest.startswith("{"):
            end = rest.rfind("}")
            if end == -1:
                continue
            labels, rest = rest[1:end], rest[end + 1:]
        try:
            val = float(rest.strip().split()[0])
        except (ValueError, IndexError):
            continue
        total += val
        rows.append((labels, val))
    return total, rows


def all_namespaces(v, root, max_depth):
    found, frontier, depth = [root], [root], 0
    while frontier and depth < max_depth:
        nxt = []
        for ns in frontier:
            resp = v.req("sys/namespaces", namespace=ns, list_op=True)
            for k in ((resp or {}).get("data", {}) or {}).get("keys", []) or []:
                child = (ns + "/" if ns else "") + k.rstrip("/")
                found.append(child); nxt.append(child)
        frontier, depth = nxt, depth + 1
    return found


def count_kv(v, ns, mount, is_v2, cap):
    base = mount.rstrip("/") + ("/metadata" if is_v2 else "")
    total, stack = 0, [""]
    while stack:
        if total >= cap:
            return total, True
        sub = stack.pop()
        resp = v.req(base + "/" + sub if sub else base, namespace=ns, list_op=True)
        for k in ((resp or {}).get("data", {}) or {}).get("keys", []) or []:
            if k.endswith("/"):
                stack.append((sub + k) if sub else k)
            else:
                total += 1
    return total, False


def count_roles(v, ns, mount, endpoints):
    n, detail = 0, []
    for ep in endpoints:
        resp = v.req(mount.rstrip("/") + "/" + ep, namespace=ns, list_op=True)
        c = len(((resp or {}).get("data", {}) or {}).get("keys", []) or [])
        if c:
            n += c; detail.append("%s=%d" % (ep, c))
    return n, ",".join(detail)


def count_managed_keys(v, ns):
    """
    Returns (total, detail, status). KMSE is a billed category, so a bare 0 must
    not cover both "nothing configured" and "you may not look":

        counted / empty / unsupported (400/405/501)
        forbidden - token lacks permission; the count is UNKNOWN, not zero
    """
    total, detail, codes = 0, [], []
    for kt in MANAGED_KEY_TYPES:
        try:
            resp, code = v.req("sys/managed-keys/" + kt, namespace=ns,
                               list_op=True, with_code=True)
        except Exception:
            codes.append(None)
            continue
        codes.append(code)
        c = len(((resp or {}).get("data", {}) or {}).get("keys", []) or [])
        if c:
            total += c; detail.append("%s=%d" % (kt, c))
    if total:
        return total, ",".join(detail), "counted"
    seen = [c for c in codes if c is not None]
    if 403 in seen:
        return 0, "", "forbidden"
    if seen and all(c in (400, 405, 501) for c in seen):
        return 0, "", "unsupported"
    return 0, "", "empty"


# ---------------------------------------------------------------------------
# Monthly high-water mark
# ---------------------------------------------------------------------------
# Static Secrets and KMSE bill on a monthly peak, which no single run can
# observe: a run appends one sample to an NDJSON file, a later report pass
# reduces them to a per-month peak.
#
# The licensing collateral says only "monthly high-water mark". It does NOT
# define sampling frequency, month boundary, or whether the peak is of the
# estate TOTAL at one instant or the SUM of each mount's own peak (always >=
# the total). Both are reported rather than one guessed at - confirm with deal
# desk before quoting.
#
# Any sampled peak is a LOWER BOUND, so reports print the largest unobserved
# window rather than implying the figure is exact.
SAMPLE_SCHEMA = 1


def month_key(ts):
    return ts[:7]


def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def month_bounds(mkey):
    start = datetime.strptime(mkey + "-01", "%Y-%m-%d").replace(tzinfo=timezone.utc)
    end = (start.replace(year=start.year + 1, month=1) if start.month == 12
           else start.replace(month=start.month + 1))
    return start, end


def write_sample(path, rec, detail):
    """Append one sample. NDJSON append-only: a truncated final line costs one
    sample, not the history."""
    if detail == "totals":
        rec = dict(rec)
        rec.pop("static_by_mount", None)
        rec.pop("kmse_by_ns", None)
    new = not os.path.exists(path)
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return new


def load_samples(path):
    """Returns (samples, skipped_lines). Bad lines are skipped, not fatal."""
    out, bad = [], 0
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if "ts" in rec and "estate" in rec:
                    out.append(rec)
                else:
                    bad += 1
            except ValueError:
                bad += 1
    out.sort(key=lambda r: r["ts"])
    return out, bad


def _peak(samples, field, usable):
    """Max of `field` over usable samples; returns (value, ts, n_used, n_excl)."""
    ok = [s for s in samples if usable(s)]
    if not ok:
        return None, None, 0, len(samples)
    best = max(ok, key=lambda s: s.get(field) or 0)
    return best.get(field) or 0, best["ts"], len(ok), len(samples) - len(ok)


def _sum_of_peaks(samples, field, usable):
    per = defaultdict(int)
    for s in samples:
        if not usable(s):
            continue
        for k, val in (s.get(field) or {}).items():
            if val > per[k]:
                per[k] = val
    return (sum(per.values()) if per else None), len(per)


def _coverage(samples, mkey):
    """Largest unobserved window in the month, including the run-up from month
    start and the tail to now/month end. An unseen peak hides there."""
    start, end = month_bounds(mkey)
    now = datetime.now(timezone.utc)
    horizon = min(end, now)
    times = [parse_iso(s["ts"]) for s in samples]
    marks = [start] + times + [horizon]
    gaps = [(marks[i + 1] - marks[i]).total_seconds() / 3600.0
            for i in range(len(marks) - 1)]
    blind = max(gaps) if gaps else (horizon - start).total_seconds() / 3600.0
    if blind >= 168:
        grade = "POOR"
    elif blind >= 24:
        grade = "THIN"
    else:
        grade = "OK"
    return {"n": len(samples), "first": times[0] if times else None,
            "last": times[-1] if times else None, "blind_hours": blind,
            "grade": grade, "complete": now >= end}


def summarize_month(samples, mkey):
    """Reduce one estate-month of samples to peaks plus a coverage verdict."""
    ms = [s for s in samples if month_key(s["ts"]) == mkey]
    if not ms:
        return None
    static_ok = lambda s: s.get("static_basis") not in (None, "skipped")
    kmse_ok = lambda s: s.get("kmse_status") == "counted"
    sp, sts, sn, sx = _peak(ms, "static_total", static_ok)
    kp, kts, kn, kx = _peak(ms, "kmse_total", kmse_ok)
    ssum, smounts = _sum_of_peaks(ms, "static_by_mount", static_ok)
    ksum, kns = _sum_of_peaks(ms, "kmse_by_ns", kmse_ok)
    bases = sorted({s.get("static_basis") for s in ms if static_ok(s)})
    return {"month": mkey, "coverage": _coverage(ms, mkey),
            "static_peak": sp, "static_peak_ts": sts, "static_n": sn,
            "static_excluded": sx, "static_sum_of_peaks": ssum,
            "static_mounts": smounts, "static_bases": bases,
            "kmse_peak": kp, "kmse_peak_ts": kts, "kmse_n": kn,
            "kmse_excluded": kx, "kmse_sum_of_peaks": ksum, "kmse_ns": kns}


def render_highwater(path, only_month=None):
    """Returns (lines, {estate: {month: summary}}) for the sample file."""
    o = []
    try:
        samples, bad = load_samples(path)
    except IOError as e:
        return ["High-water mark: cannot read %s (%s)" % (path, e)], {}

    hcp = [s for s in samples if s.get("platform") == "hcp"]
    samples = [s for s in samples if s.get("platform") != "hcp"]

    o.append("=" * 72)
    o.append("MONTHLY HIGH-WATER MARK  (Static Secrets, KMSE)")
    o.append("=" * 72)
    o.append("Sample file: %s" % path)
    o.append("Samples:     %d usable" % len(samples))
    if bad:
        o.append("             %d unparseable line(s) skipped" % bad)
    if hcp:
        o.append("             %d HCP sample(s) EXCLUDED - not a valid RU target" % len(hcp))
    if not samples:
        o.append("")
        o.append("No usable samples yet. Take one with --sample-to before reporting.")
        o.append("=" * 72)
        return o, {}

    estates = defaultdict(list)
    for s in samples:
        estates[s["estate"]].append(s)
    if len(estates) > 1:
        o.append("")
        o.append("!! %d DISTINCT ESTATES in this file. They are NOT summed - a peak"
                 % len(estates))
        o.append("   across different clusters or root namespaces is meaningless.")
        o.append("   Reported separately below; use one sample file per estate.")

    result = {}
    for estate in sorted(estates):
        es = estates[estate]
        months = sorted({month_key(s["ts"]) for s in es})
        if only_month:
            months = [m for m in months if m == only_month]
        result[estate] = {}
        o.append("")
        o.append("-" * 72)
        o.append("Estate: %s" % estate)
        o.append("-" * 72)
        if not months:
            o.append("  No samples for %s." % only_month)
            continue
        for mkey in months:
            r = summarize_month(es, mkey)
            result[estate][mkey] = r
            cov = r["coverage"]
            o.append("")
            o.append("  %s   %d sample(s)   coverage %s" % (mkey, cov["n"], cov["grade"]))
            if cov["first"]:
                o.append("    observed %s -> %s"
                         % (cov["first"].strftime("%m-%d %H:%M"),
                            cov["last"].strftime("%m-%d %H:%M")))
            o.append("    largest unobserved window: %.1f h%s"
                     % (cov["blind_hours"], "" if cov["complete"] else "  (month in progress)"))
            o.append("")
            o.append("    %-24s %12s   %s" % ("", "PEAK OF TOTAL", "SUM OF PER-UNIT PEAKS"))
            for label, peak, pts, sop, units, unitword, nx in (
                    ("Static Secrets", r["static_peak"], r["static_peak_ts"],
                     r["static_sum_of_peaks"], r["static_mounts"], "mount", r["static_excluded"]),
                    ("KMSE", r["kmse_peak"], r["kmse_peak_ts"],
                     r["kmse_sum_of_peaks"], r["kmse_ns"], "namespace", r["kmse_excluded"])):
                pv = "{:,}".format(peak) if peak is not None else "no data"
                sv = ("{:,} ({} {}{})".format(sop, units, unitword,
                      "" if units == 1 else "s") if sop is not None else "n/a")
                o.append("    %-24s %12s   %s" % (label, pv, sv))
                if peak is not None and pts:
                    o.append("      peaked %s" % pts)
                if nx:
                    o.append("      %d sample(s) excluded as unusable for this category" % nx)
            if len(r["static_bases"]) > 1:
                o.append("")
                o.append("    !! Mixed measurement bases in one month: %s."
                         % ", ".join(r["static_bases"]))
                o.append("       Telemetry lags the gauge interval and the recursive walk")
                o.append("       does not; the peak may be an artifact of the method.")
            if cov["grade"] != "OK":
                o.append("")
                o.append("    !! Coverage %s. A %.0f h window went unobserved, so this"
                         % (cov["grade"], cov["blind_hours"]))
                o.append("       peak is a FLOOR, not the month's high-water mark.")
            if not cov["complete"]:
                o.append("    !! Month incomplete - not a billable figure yet.")

    o.append("")
    o.append("Reading of the model:")
    o.append("  PEAK OF TOTAL is the headline - the highest single observation of")
    o.append("  the estate. SUM OF PER-UNIT PEAKS adds each mount's own maximum and")
    o.append("  is always >= that, since mounts peak at different moments. The")
    o.append("  licensing doc says only 'monthly high-water mark' and does not say")
    o.append("  which applies. CONFIRM WITH DEAL DESK before quoting.")
    o.append("")
    o.append("  Any sampled peak is a LOWER BOUND. Sample at least daily; hourly if")
    o.append("  the estate churns. Suggested cron (hourly, telemetry fast path):")
    o.append("    0 * * * * VAULT_ADDR=... VAULT_TOKEN=... \\")
    o.append("      python3 vault_ru_sizing_api.py --metrics --quiet \\")
    o.append("      --sample-to %s" % path)
    o.append("=" * 72)
    return o, result


def main():
    ap = argparse.ArgumentParser(description="Vault RU sizing, live API only. Read-only.")
    ap.add_argument("--namespace", default=os.environ.get("VAULT_NAMESPACE", ""))
    ap.add_argument("--mounts-only", action="store_true", help="Skip the slow KV walk")
    ap.add_argument("--metrics", action="store_true",
                    help="Read KV/entity counts from sys/metrics telemetry instead of "
                         "walking every KV mount. Far faster on large estates; needs "
                         "telemetry enabled and read on sys/metrics.")
    ap.add_argument("--max-depth", type=int, default=10)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--cap", type=int, default=200000,
                    help="Per-mount secret ceiling; guards against runaway walks")
    ap.add_argument("--out-dir", default="./ru-report")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--sample-to", metavar="FILE",
                    help="Append this run as one sample to an NDJSON history, for "
                         "monthly high-water-mark reporting. Run on a schedule.")
    ap.add_argument("--sample-detail", choices=("full", "totals"), default="full",
                    help="'totals' drops per-mount detail from the sample, shrinking "
                         "the history at the cost of the sum-of-peaks figure.")
    ap.add_argument("--highwater", metavar="FILE",
                    help="Report monthly peaks from a sample history.")
    ap.add_argument("--highwater-month", metavar="YYYY-MM",
                    help="Limit --highwater to one month.")
    ap.add_argument("--report-only", action="store_true",
                    help="With --highwater, analyse samples without contacting Vault.")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress the report on stdout. For scheduled sampling.")
    ap.add_argument("--platform", choices=("auto", "self-managed", "hcp"), default="auto",
                    help="Target platform. RUs are a self-managed Vault Enterprise "
                         "model; an HCP target is stamped as invalid for sizing. "
                         "'auto' detects; override only if detection is wrong.")
    args = ap.parse_args()

    if args.report_only:
        if not args.highwater:
            sys.exit("--report-only requires --highwater FILE.")
        lines, _ = render_highwater(args.highwater, args.highwater_month)
        text = "\n".join(lines)
        os.makedirs(args.out_dir, exist_ok=True)
        with open(os.path.join(args.out_dir, "ru_highwater.txt"), "w") as fh:
            fh.write(text + "\n")
        print(text)
        return

    addr, token = os.environ.get("VAULT_ADDR"), os.environ.get("VAULT_TOKEN")
    if not addr or not token:
        sys.exit("VAULT_ADDR and VAULT_TOKEN must be set.")

    v = Vault(addr, token, verify=not args.insecure)
    root = args.namespace.strip("/")

    if args.platform == "auto":
        platform, evidence = detect_platform(v)
    else:
        platform, evidence = args.platform, "--platform override"
    is_hcp = platform == "hcp"
    if is_hcp:
        for ln in HCP_BANNER:
            print(ln, file=sys.stderr)
        print("", file=sys.stderr)

    metrics_kv = metrics_entities = None
    metrics_kv_rows = []
    if args.metrics:
        print("Reading sys/metrics telemetry ...", file=sys.stderr)
        txt, why = fetch_metrics(v, root)
        if txt is None:
            print("  sys/metrics unavailable — %s" % why, file=sys.stderr)
            print("  Falling back to the recursive KV walk.", file=sys.stderr)
        else:
            kv_total, metrics_kv_rows = parse_prom(txt, "vault_secret_kv_count")
            ent_total, _ = parse_prom(txt, "vault_identity_entity_count")
            if metrics_kv_rows:
                metrics_kv = int(round(kv_total))
                print("  vault_secret_kv_count: %d across %d mounts"
                      % (metrics_kv, len(metrics_kv_rows)), file=sys.stderr)
            else:
                print("  vault_secret_kv_count not present — the gauge may not have"
                      "\n  been emitted yet (usage_gauge_period, 10m default)."
                      "\n  Falling back to the recursive KV walk.", file=sys.stderr)
            if ent_total:
                metrics_entities = int(round(ent_total))

    print("Enumerating namespaces from %r ..." % (root or "root"), file=sys.stderr)
    namespaces = all_namespaces(v, root, args.max_depth)
    print("Found %d namespaces. Scanning mounts ..." % len(namespaces), file=sys.stderr)

    rows, truncated, custom, scan_errors, kmse_unknown = [], [], [], [], []
    done = [0]

    def scan(ns):
        try:
            _scan(ns)
        except Exception as exc:
            # A single unreadable namespace must not abort a walk of hundreds.
            with _lock:
                scan_errors.append((ns or "root", "%s: %s" % (type(exc).__name__, exc)))

    def _scan(ns):
        resp = v.req("sys/mounts", namespace=ns)
        data = (resp or {}).get("data") or resp or {}
        for path, info in data.items():
            if not isinstance(info, dict) or "type" not in info:
                continue
            mtype, opts = info.get("type"), (info.get("options") or {})
            if mtype == "kv":
                v2 = str(opts.get("version", "1")) == "2"
                label = "kv-v2" if v2 else "kv-v1"
                if args.mounts_only or metrics_kv is not None:
                    rows.append([ns or "root", path, label, "static", "", ""])
                else:
                    n, tr = count_kv(v, ns, path, v2, args.cap)
                    if tr:
                        truncated.append((ns or "root") + path)
                    rows.append([ns or "root", path, label, "static", n, ""])
            elif mtype in ROLE_ENDPOINTS:
                n, d = count_roles(v, ns, path, ROLE_ENDPOINTS[mtype])
                rows.append([ns or "root", path, mtype, "dynamic", n, d])
            elif mtype not in NON_ROLE_TYPES:
                n, d = count_roles(v, ns, path, ["roles", "role"])
                if n:
                    custom.append((mtype, n))
                rows.append([ns or "root", path, mtype,
                             "dynamic-custom" if n else "other", n if n else "", d])
            else:
                rows.append([ns or "root", path, mtype, "other", "", ""])
        mk, mkd, mk_status = count_managed_keys(v, ns)
        if mk:
            rows.append([ns or "root", "sys/managed-keys", "kmse", "kmse", mk, mkd])
        elif mk_status == "forbidden":
            # Not zero - unreadable. Reported as a floor, not a fact.
            with _lock:
                kmse_unknown.append(ns or "root")
            rows.append([ns or "root", "sys/managed-keys", "kmse", "kmse-unknown",
                         "", "403 - token lacks list on sys/managed-keys/*"])
        with _lock:
            done[0] += 1
            if done[0] % 25 == 0 or done[0] == len(namespaces):
                print("  %d/%d namespaces" % (done[0], len(namespaces)), file=sys.stderr)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(scan, namespaces))

    static_by_mount = {"%s:%s" % (r[0], r[1]): r[4] for r in rows
                       if r[3] == "static" and isinstance(r[4], int)}
    kmse_by_ns = defaultdict(int)
    for r in rows:
        if r[3] == "kmse" and isinstance(r[4], int):
            kmse_by_ns[r[0]] += r[4]
    static = sum(r[4] for r in rows if r[3] == "static" and isinstance(r[4], int))
    dynamic = sum(r[4] for r in rows if r[3] in ("dynamic", "dynamic-custom")
                  and isinstance(r[4], int))
    managed = sum(r[4] for r in rows if r[3] == "kmse" and isinstance(r[4], int))
    by_type = defaultdict(int)
    for r in rows:
        by_type[r[2]] += 1

    # ---- high-water sampling ----
    # "skipped" marks a sample that cannot contribute to the Static peak
    # (--mounts-only counted no secrets); kmse_status likewise gates KMSE, so a
    # degraded run never lowers a month's peak.
    if metrics_kv is not None:
        sample_basis = "telemetry"
    elif args.mounts_only:
        sample_basis = "skipped"
    else:
        sample_basis = "walk"
    if args.sample_to:
        rec = {
            "v": SAMPLE_SCHEMA, "ts": utcnow_iso(),
            "estate": "%s|%s" % (addr, root or "root"),
            "addr": addr, "root_ns": root or "root", "platform": platform,
            "namespaces": len(namespaces),
            "static_total": None if sample_basis == "skipped" else static,
            "static_basis": sample_basis,
            "static_by_mount": static_by_mount,
            "kmse_total": managed,
            "kmse_status": "incomplete" if kmse_unknown else "counted",
            "kmse_unknown_ns": len(kmse_unknown),
            "kmse_by_ns": dict(kmse_by_ns),
            "scan_errors": len(scan_errors), "truncated": len(truncated),
        }
        first = write_sample(args.sample_to, rec, args.sample_detail)
        print("Sample appended to %s%s"
              % (args.sample_to, " (created)" if first else ""), file=sys.stderr)
        if is_hcp:
            print("  Marked platform=hcp; the report pass will exclude it.",
                  file=sys.stderr)

    hw_lines = []
    hw_path = args.highwater or args.sample_to
    if hw_path and os.path.exists(hw_path):
        hw_lines, _ = render_highwater(hw_path, args.highwater_month)

    o = []
    o.append("=" * 72)
    o.append("VAULT RESOURCE UNIT SIZING  (live API only)")
    o.append("=" * 72)
    if is_hcp:
        o.extend(HCP_BANNER)
        o.append("")
    o.append("Vault:      %s" % addr)
    o.append("Platform:   %s  (%s)" % (platform, evidence))
    o.append("Root ns:    %s" % (root or "root"))
    o.append("Namespaces: %d" % len(namespaces))
    o.append("Mounts:     %d" % len(rows))
    o.append("")
    o.append("%-34s %14s   %s" % ("RESOURCE UNIT", "RU", "BASIS"))
    o.append("-" * 72)
    if metrics_kv is not None:
        static = metrics_kv
        static_basis = "vault_secret_kv_count telemetry"
        static_disp = "{:,}".format(static)
    elif args.mounts_only:
        static_basis, static_disp = "skipped (--mounts-only)", "SKIPPED"
    else:
        static_basis, static_disp = "unique secrets, recursive walk", "{:,}".format(static)
    o.append("%-34s %14s   %s" % ("Static Secrets (KV)", static_disp, static_basis))
    o.append("%-34s %14s   %s" % ("Dynamic / Auto-Rotated Secrets",
             "{:,}".format(dynamic), "roles configured"))
    if kmse_unknown:
        kmse_disp, kmse_basis = ">= {:,}".format(managed), \
            "INCOMPLETE - %d ns unreadable" % len(kmse_unknown)
    else:
        kmse_disp, kmse_basis = "{:,}".format(managed), "keys, point-in-time"
    o.append("%-34s %14s   %s" % ("KMSE (managed keys)", kmse_disp, kmse_basis))
    o.append("-" * 72)
    subtotal = dynamic + managed + (0 if (args.mounts_only and metrics_kv is None) else static)
    o.append("%-34s %14s" % ("SUBTOTAL", "{:,}".format(subtotal)))
    o.append("")
    if metrics_entities is not None:
        o.append("Cross-check (client model, not RU):")
        o.append("  vault_identity_entity_count .. {:,} stored entities".format(metrics_entities))
        o.append("  Stored entities are NOT billed clients — only entities whose tokens")
        o.append("  are used in the period count. Compare against `vault operator usage`.")
        o.append("")
    if metrics_kv_rows:
        o.append("Top KV mounts by secret count (telemetry):")
        for lbl, val in sorted(metrics_kv_rows, key=lambda r: -r[1])[:15]:
            o.append("  %-52s %8d" % (lbl[:52], int(val)))
        o.append("")
    o.append("NOT MEASURED HERE — require audit logs (use vault_ru_sizing.py):")
    o.append("  PKI                 duration-based, 730 cert-hours = 1 RU")
    o.append("  SSH                 duration-based, 730 cred-hours = 1 RU")
    o.append("  Transit / Transform per element, 150,000 elements = 1 RU")
    o.append("")
    o.append("Mounts by type:")
    for t, c in sorted(by_type.items(), key=lambda kv: -kv[1]):
        o.append("  %-30s %5d" % (t, c))
    o.append("")
    if custom:
        agg = defaultdict(int)
        for mtype, n in custom:
            agg[mtype] += n
        o.append("Custom / third-party engines exposing roles — whether these attract")
        o.append("RUs is a DEAL DESK question. Confirm before quoting:")
        for mtype, n in sorted(agg.items(), key=lambda kv: -kv[1]):
            o.append("  %-30s %5d roles" % (mtype, n))
        o.append("")
    if truncated:
        o.append("!! %d KV mount(s) hit --cap; those counts are floors:" % len(truncated))
        for t in truncated[:10]:
            o.append("   %s" % t)
        o.append("")
    if scan_errors:
        o.append("!! %d namespace(s) could not be fully scanned — counts are FLOORS:"
                 % len(scan_errors))
        for ns, err in scan_errors[:10]:
            o.append("   %-34s %s" % (ns[:34], err[:70]))
        if len(scan_errors) > 10:
            o.append("   ... and %d more" % (len(scan_errors) - 10))
        o.append("")
    if hw_lines:
        o.append("")
        o.extend(hw_lines)
        o.append("")
    if kmse_unknown:
        o.append("!! KMSE is a FLOOR, not a count. %d namespace(s) returned 403 on"
                 % len(kmse_unknown))
        o.append("   sys/managed-keys/* - keys may exist there and are not included.")
        o.append("   Grant `list` on sys/managed-keys/* and re-run before quoting:")
        for ns in kmse_unknown[:10]:
            o.append("     %s" % ns)
        if len(kmse_unknown) > 10:
            o.append("     ... and %d more" % (len(kmse_unknown) - 10))
        o.append("")
    o.append("Caveats:")
    if hw_lines:
        o.append("  * Static Secrets and KMSE above are POINT-IN-TIME. The billable")
        o.append("    figure is the monthly peak - see the high-water section above.")
    else:
        o.append("  * Static Secrets and KMSE are priced on a MONTHLY HIGH-WATER MARK.")
        o.append("    This is a point-in-time count and understates a month that peaked")
        o.append("    higher. Build a history with --sample-to on a schedule, then")
        o.append("    report the peak with --highwater.")
    o.append("  * Namespaces your token cannot read are skipped silently.")
    o.append("=" * 72)

    # An HCP run is not a sizing artifact - name it so.
    tag = ".INVALID-HCP" if is_hcp else ""
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "ru_inventory_api%s.csv" % tag), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["namespace", "mount", "type", "ru_category", "count", "detail"])
        w.writerows(sorted(rows, key=lambda r: (r[0], r[1])))
    text = "\n".join(o)
    with open(os.path.join(args.out_dir, "ru_summary_api%s.txt" % tag), "w") as fh:
        fh.write(text + "\n")
    if not args.quiet:
        print(text)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
