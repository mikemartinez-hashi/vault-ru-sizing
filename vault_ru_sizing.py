#!/usr/bin/env python3
"""
vault_ru_sizing.py — all-in-one Resource Unit sizing for a Vault estate.

All six RU categories:
  | Static Secrets     | unique KV secrets, monthly high-water mark  | live API  |
  | Dynamic/Auto-Rot.  | roles configured                            | live API  |
  | PKI                | duration-adjusted; 730 cert-hours = 1 RU    | audit log |
  | SSH                | duration-adjusted; 730 cred-hours = 1 RU    | audit log |
  | Transit/Transform  | per element; 150,000 elements = 1 RU        | audit log |
  | KMSE               | managed keys, monthly high-water mark       | live API  |

WHY NOT THE DOCUMENTED ONE-LINERS
  * They are namespace-scoped, so an estate with many namespaces undercounts
    silently. This walks them all.
  * `jq -s` slurps gigabyte logs into memory. This streams, and handles .gz.
  * The documented Transit query counts API *calls*; the model prices
    *elements*, and one batch call can carry thousands.
  * An empty result set errors ("null and number cannot be divided") instead of
    returning 0.

DISCLAIMER — NOT AN OFFICIAL IBM OR HASHICORP TOOL. USE AT YOUR OWN RISK.
    Unofficial, unsupported, no warranty. Never run against production —
    correctness rests on synthetic fixtures only. Output is NOT a quote and NOT
    a licensing determination; confirm every figure with your account team or
    deal desk before it reaches a customer or a contract.

SCOPE — SELF-MANAGED VAULT ENTERPRISE ONLY. HCP is licensed on cluster +
    client count and is not a valid target; an HCP run is detected,
    banner-stamped and written to *.INVALID-HCP.* files.

READ-ONLY against Vault. Issues only LIST and GET.

USAGE
    export VAULT_ADDR=https://vault.example.com:8200 VAULT_TOKEN=hvs....
    python3 vault_ru_sizing.py --namespace admin --audit-log 'audit*.log*'
    python3 vault_ru_sizing.py --namespace admin                  # API only
    python3 vault_ru_sizing.py --audit-log audit.log --no-api     # logs only

    # fold in a monthly peak sampled by vault_ru_sizing_api.py --sample-to
    python3 vault_ru_sizing.py --namespace admin --highwater history.ndjson

TOKEN POLICY
    path "sys/namespaces"          { capabilities = ["list"] }
    path "sys/mounts"              { capabilities = ["read"] }
    path "sys/host-info"           { capabilities = ["read"] }   # platform detection
    path "sys/managed-keys/*"      { capabilities = ["list"] }
    path "+/metadata/*"            { capabilities = ["list"] }   # kv-v2
    path "+/*"                     { capabilities = ["list"] }   # kv-v1, roles
"""

import argparse, csv, glob, gzip, json, math, os, ssl, sys, threading
import urllib.request, urllib.error, urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

HOURS_PER_RU = 730.0
TRANSIT_ELEMENTS_PER_RU = 150000.0

# mount type -> LIST endpoints that enumerate roles
ROLE_ENDPOINTS = {
    "aws":       ["roles"],
    "azure":     ["roles"],
    "gcp":       ["roles", "static-accounts"],
    "gcpkms":    ["keys"],
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
# types that never carry "roles" in the RU sense — don't probe them
NON_ROLE_TYPES = {"kv", "cubbyhole", "system", "identity", "ns_system", "ns_identity",
                  "pki", "ssh", "transit", "transform", "keymgmt", "totp", "cubbyhole"}

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


# ----------------------------------------------------------------------------
# Vault client
# ----------------------------------------------------------------------------
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


# ----------------------------------------------------------------------------
# Audit log
# ----------------------------------------------------------------------------
def parse_time(s):
    if not isinstance(s, str):
        return None
    try:
        s = s.replace("Z", "+00:00")
        if "." in s:                       # trim sub-second to 6 digits
            head, rest = s.split(".", 1)
            frac, tz = rest[:-6], rest[-6:]
            s = "%s.%s%s" % (head, frac[:6], tz)
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def hours_valid(entry):
    """
    Duration of an issued credential, in hours. PKI and SSH share this metric
    (730 hours = 1 RU), but they expose it differently, so try in order:
      1. response.data.expiration      (PKI: unix epoch seconds)
      2. response.data.expiration_time (RFC3339)
      3. response.lease_duration       (seconds — SSH and other leased creds)
      4. response.data.lease_duration
    Returns (hours, source) or (None, reason).
    """
    resp = entry.get("response") or {}
    data = resp.get("data") or {}

    exp = data.get("expiration")
    if isinstance(exp, (int, float)):
        t = parse_time(entry.get("time"))
        if t:
            return (exp - t.timestamp()) / 3600.0, "expiration"
        return None, "unparseable-time"
    if isinstance(exp, str):
        return None, "hmac-or-string-expiration"

    et = data.get("expiration_time")
    if isinstance(et, str):
        t0, t1 = parse_time(entry.get("time")), parse_time(et)
        if t0 and t1:
            return (t1 - t0).total_seconds() / 3600.0, "expiration_time"

    for src, container in (("lease_duration", resp), ("data.lease_duration", data)):
        ld = container.get("lease_duration")
        if isinstance(ld, (int, float)) and ld > 0:
            return ld / 3600.0, src

    return None, "no-duration-field"


# Hosted platforms (HCP, and most log shippers) wrap each Vault audit entry in an
# envelope rather than emitting the raw entry. The real record is then a JSON
# string inside a field like "log" or "message". Unwrap it so those exports work
# without preprocessing — otherwise every count silently comes back zero.
ENVELOPE_KEYS = ("log", "message", "msg", "event", "data", "record", "body")


def unwrap(e):
    if not isinstance(e, dict):
        return None
    if "type" in e and "request" in e:
        return e                                   # already a raw audit entry
    for k in ENVELOPE_KEYS:
        v = e.get(k)
        if isinstance(v, dict) and "type" in v and "request" in v:
            return v
        if isinstance(v, str) and v.lstrip().startswith("{"):
            try:
                inner = json.loads(v)
            except ValueError:
                continue
            if isinstance(inner, dict) and "type" in inner:
                return inner
    return e if "type" in e else None


# Engines whose audit activity attracts RUs, keyed by conventional mount name.
# Only used when an entry carries no mount_type AND the live mount inventory
# has no answer, so it is a last resort, not the primary path.
ENGINE_BY_NAME = {"pki": "pki", "ssh": "ssh", "transit": "transit",
                  "transform": "transform"}


def infer_mount_type(path, mount_map):
    """
    Resolve an audit entry's engine when `request.mount_type` is absent.

    Vault has not always emitted mount_type, and some log pipelines drop it.
    Without a fallback every PKI/SSH/Transit count silently returns zero on
    such a log - which is exactly what it looks like when there is genuinely no
    activity, so the failure is invisible. Returns (type, how).

    Preference order, most trustworthy first:
      "mount_map"  longest-prefix match against the live sys/mounts inventory.
                   Exact, and handles mounts named anything (a transit engine
                   mounted at crypto/).
      "name"       first path segment matches a conventional engine name. Right
                   for the common case, wrong for unconventional mount names -
                   which is why the report says how many entries needed it.
    """
    if mount_map:
        best = None
        for mp, mtype in mount_map.items():
            if path.startswith(mp) and (best is None or len(mp) > len(best[0])):
                best = (mp, mtype)
        if best:
            return best[1], "mount_map"
    seg = path.split("/", 1)[0]
    if seg in ENGINE_BY_NAME:
        return ENGINE_BY_NAME[seg], "name"
    return None, None


def scan_audit(paths, mount_map=None):
    st = {
        "lines": 0, "parsed": 0,
        "mt_present": 0, "mt_inferred": defaultdict(int), "mt_missing": 0,
        "path_prefixes": defaultdict(int),
        "pki_hours": 0.0, "pki_events": 0, "pki_undetermined": 0,
        "ssh_hours": 0.0, "ssh_events": 0, "ssh_undetermined": 0,
        "ssh_by_role": defaultdict(int),
        "transit_elements": 0, "transit_calls": 0,
        "transform_elements": 0, "transform_calls": 0,
        "reasons": defaultdict(int),
        "first_time": None, "last_time": None,
    }
    pki_ops = ("/issue/", "/sign/", "/sign-verbatim/", "/generate/", "/acme/")
    tp_ops = ("/encrypt/", "/decrypt/", "/rewrap/", "/datakey/", "/hmac/",
              "/sign/", "/verify/", "/cmac/",
              "/encode/", "/decode/")

    for p in paths:
        opener = gzip.open if p.endswith(".gz") else open
        mode = "rt" if p.endswith(".gz") else "r"
        with opener(p, mode, errors="replace") as fh:
            for line in fh:
                st["lines"] += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                e = unwrap(e)
                if e is None:
                    continue
                st["parsed"] += 1
                if e.get("type") != "response":
                    continue

                t = parse_time(e.get("time"))
                if t:
                    if st["first_time"] is None or t < st["first_time"]:
                        st["first_time"] = t
                    if st["last_time"] is None or t > st["last_time"]:
                        st["last_time"] = t

                req = e.get("request") or {}
                path = req.get("path") or ""
                mt = req.get("mount_type")
                if mt:
                    st["mt_present"] += 1
                else:
                    mt, how = infer_mount_type(path, mount_map)
                    if mt:
                        st["mt_inferred"][how] += 1
                    else:
                        st["mt_missing"] += 1
                # Kept for the "nothing matched" diagnostic. Bounded: only the
                # first two segments, so key count stays proportional to mounts.
                if len(st["path_prefixes"]) < 5000:
                    st["path_prefixes"]["/".join(path.split("/")[:2])] += 1

                if mt == "pki" and any(o in path for o in pki_ops):
                    h, why = hours_valid(e)
                    st["pki_events"] += 1
                    if h is None:
                        st["pki_undetermined"] += 1; st["reasons"][why] += 1
                    else:
                        st["pki_hours"] += max(h, 0.0)

                elif mt == "ssh" and ("/sign/" in path or "/creds/" in path or "/issue/" in path):
                    h, why = hours_valid(e)
                    st["ssh_events"] += 1
                    role = path.rsplit("/", 1)[-1] or "?"
                    st["ssh_by_role"][role] += 1
                    if h is None:
                        st["ssh_undetermined"] += 1; st["reasons"][why] += 1
                    else:
                        st["ssh_hours"] += max(h, 0.0)

                elif mt in ("transit", "transform") and any(o in path for o in tp_ops):
                    # The model prices ELEMENTS, not calls. One batch call can
                    # carry thousands, so count batch_input where present.
                    d = req.get("data") or {}
                    bi = d.get("batch_input")
                    n = len(bi) if isinstance(bi, list) and bi else 1
                    if mt == "transit":
                        st["transit_calls"] += 1; st["transit_elements"] += n
                    else:
                        st["transform_calls"] += 1; st["transform_elements"] += n
    return st


# ----------------------------------------------------------------------------
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
# Samples are WRITTEN by vault_ru_sizing_api.py --sample-to (the light job you
# put on a schedule). This script only READS a history.
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
    ap = argparse.ArgumentParser(
        description="All-in-one Vault Resource Unit sizing. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--namespace", default=os.environ.get("VAULT_NAMESPACE", ""))
    ap.add_argument("--audit-log", action="append", default=[],
                    help="Audit log path or glob; repeatable. Supports .gz")
    ap.add_argument("--no-api", action="store_true", help="Skip live Vault queries")
    ap.add_argument("--mounts-only", action="store_true", help="Skip the slow KV walk")
    ap.add_argument("--max-depth", type=int, default=10)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--cap", type=int, default=200000)
    ap.add_argument("--out-dir", default="./ru-report")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--highwater", metavar="FILE",
                    help="Fold monthly Static/KMSE peaks in from a sample history "
                         "built by vault_ru_sizing_api.py --sample-to.")
    ap.add_argument("--highwater-month", metavar="YYYY-MM",
                    help="Limit --highwater to one month.")
    ap.add_argument("--platform", choices=("auto", "self-managed", "hcp"), default="auto",
                    help="Target platform. RUs are a self-managed Vault Enterprise "
                         "model; an HCP target is stamped as invalid for sizing. "
                         "'auto' detects; override only if detection is wrong.")
    args = ap.parse_args()

    rows, truncated, custom_role_mounts, scan_errors = [], [], [], []
    kmse_unknown = []
    static = dynamic = managed = 0
    namespaces = []
    # --no-api never touches a cluster, so there is no platform to detect and
    # nothing to stamp; the audit log alone carries no platform identity.
    platform, evidence, is_hcp = "not queried (--no-api)", "", False

    if not args.no_api:
        addr, token = os.environ.get("VAULT_ADDR"), os.environ.get("VAULT_TOKEN")
        if not addr or not token:
            sys.exit("VAULT_ADDR and VAULT_TOKEN must be set (or pass --no-api).")
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

        print("Enumerating namespaces from %r ..." % (root or "root"), file=sys.stderr)
        namespaces = all_namespaces(v, root, args.max_depth)
        print("Found %d namespaces. Scanning mounts ..." % len(namespaces), file=sys.stderr)
        done = [0]

        def scan(ns):
            resp = v.req("sys/mounts", namespace=ns)
            data = (resp or {}).get("data") or resp or {}
            for path, info in data.items():
                if not isinstance(info, dict) or "type" not in info:
                    continue
                mtype = info.get("type")
                opts = info.get("options") or {}
                if mtype == "kv":
                    v2 = str(opts.get("version", "1")) == "2"
                    label = "kv-v2" if v2 else "kv-v1"
                    if args.mounts_only:
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
                    # Unknown or custom plugin — probe for role endpoints so
                    # third-party engines are surfaced rather than missed.
                    n, d = count_roles(v, ns, path, ["roles", "role"])
                    cat = "dynamic-custom" if n else "other"
                    if n:
                        custom_role_mounts.append((ns or "root", path, mtype, n))
                    rows.append([ns or "root", path, mtype, cat, n if n else "", d])
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

        static = sum(r[4] for r in rows if r[3] == "static" and isinstance(r[4], int))
        dynamic = sum(r[4] for r in rows if r[3] in ("dynamic", "dynamic-custom")
                      and isinstance(r[4], int))
        managed = sum(r[4] for r in rows if r[3] == "kmse" and isinstance(r[4], int))

    # ---- audit log ----
    paths = []
    for pat in args.audit_log:
        paths.extend(sorted(glob.glob(os.path.expanduser(pat))))
    st = None
    if paths:
        print("Scanning %d audit file(s) ..." % len(paths), file=sys.stderr)
        # The live inventory maps real mount paths to types, so audit entries
        # classify correctly even when mount_type is absent and the mount is
        # named unconventionally.
        mount_map = {r[1]: r[2] for r in rows
                     if r[2] in ("pki", "ssh", "transit", "transform")}
        st = scan_audit(paths, mount_map or None)

    pki_ru = math.ceil(st["pki_hours"] / HOURS_PER_RU) if st else None
    ssh_ru = math.ceil(st["ssh_hours"] / HOURS_PER_RU) if st else None
    transit_ru = math.ceil((st["transit_elements"] + st["transform_elements"])
                           / TRANSIT_ELEMENTS_PER_RU) if st else None

    hw_lines = []
    if args.highwater:
        hw_lines, _ = render_highwater(args.highwater, args.highwater_month)

    # ---- report ----
    o = []
    o.append("=" * 72)
    o.append("VAULT RESOURCE UNIT SIZING")
    o.append("=" * 72)
    if is_hcp:
        o.extend(HCP_BANNER)
        o.append("")
    if not args.no_api:
        o.append("Platform .................... %s%s"
                 % (platform, ("  (%s)" % evidence) if evidence else ""))
        o.append("Namespaces scanned .......... %d" % len(namespaces))
        o.append("Mounts found ................ %d" % len(rows))
    if st:
        span = "unknown"
        if st["first_time"] and st["last_time"]:
            days = (st["last_time"] - st["first_time"]).total_seconds() / 86400.0
            span = "%s -> %s  (%.1f days)" % (st["first_time"].date(),
                                              st["last_time"].date(), days)
        o.append("Audit log lines ............. {:,}".format(st["lines"]))
        o.append("Audit entries parsed ........ {:,}".format(st["parsed"]))
        o.append("Audit log span .............. %s" % span)
    o.append("")
    o.append("%-34s %14s   %s" % ("RESOURCE UNIT", "RU", "BASIS"))
    o.append("-" * 72)

    def line(name, val, basis):
        o.append("%-34s %14s   %s" % (name, val, basis))

    line("Static Secrets (KV)",
         "SKIPPED" if args.mounts_only else ("{:,}".format(static) if not args.no_api else "n/a"),
         "unique secrets, point-in-time")
    line("Dynamic / Auto-Rotated Secrets",
         "{:,}".format(dynamic) if not args.no_api else "n/a",
         "roles configured")
    def dur_basis(hours, undet, events, unit):
        b = "%.0f %s / 730" % (hours, unit)
        if undet:
            b += "  !! %d of %d events UNDETERMINED" % (undet, events)
        return b

    line("PKI", "{:,}".format(pki_ru) if pki_ru is not None else "n/a",
         dur_basis(st["pki_hours"], st["pki_undetermined"], st["pki_events"],
                   "cert-hours") if st else "needs --audit-log")
    line("SSH", "{:,}".format(ssh_ru) if ssh_ru is not None else "n/a",
         dur_basis(st["ssh_hours"], st["ssh_undetermined"], st["ssh_events"],
                   "cred-hours") if st else "needs --audit-log")
    line("Transit / Transform",
         "{:,}".format(transit_ru) if transit_ru is not None else "n/a",
         "{:,} elements / 150k".format(st["transit_elements"] + st["transform_elements"])
         if st else "needs --audit-log")
    if args.no_api:
        kmse_disp, kmse_basis = "n/a", "keys, point-in-time"
    elif kmse_unknown:
        kmse_disp = ">= {:,}".format(managed)
        kmse_basis = "INCOMPLETE - %d ns unreadable" % len(kmse_unknown)
    else:
        kmse_disp, kmse_basis = "{:,}".format(managed), "keys, point-in-time"
    line("KMSE (managed keys)", kmse_disp, kmse_basis)
    o.append("-" * 72)

    known = [x for x in (static if not (args.no_api or args.mounts_only) else None,
                         dynamic if not args.no_api else None,
                         pki_ru, ssh_ru, transit_ru,
                         managed if not args.no_api else None) if isinstance(x, int)]
    line("TOTAL (measured categories only)", "{:,}".format(sum(known)), "")
    o.append("")

    if st:
        o.append("Audit detail:")
        o.append("  PKI issuance events ....... {:,}  (undetermined duration: {:,})"
                 .format(st["pki_events"], st["pki_undetermined"]))
        o.append("  SSH issuance events ....... {:,}  (undetermined duration: {:,})"
                 .format(st["ssh_events"], st["ssh_undetermined"]))
        o.append("  Transit calls / elements .. {:,} / {:,}"
                 .format(st["transit_calls"], st["transit_elements"]))
        o.append("  Transform calls/elements .. {:,} / {:,}"
                 .format(st["transform_calls"], st["transform_elements"]))
        if st["reasons"]:
            o.append("  Why durations were missing:")
            for r, c in sorted(st["reasons"].items(), key=lambda kv: -kv[1]):
                o.append("    %-28s %d" % (r, c))
        if st["ssh_by_role"]:
            o.append("  SSH issuances by role (multiply by that role's TTL for RU):")
            for r, c in sorted(st["ssh_by_role"].items(), key=lambda kv: -kv[1])[:15]:
                o.append("    %-28s %d" % (r, c))
        o.append("")
        if st["mt_inferred"]:
            how = ", ".join("%s=%s" % (k, "{:,}".format(v))
                            for k, v in sorted(st["mt_inferred"].items()))
            o.append("  Engine inferred (no mount_type in entry): %s" % how)
            if st["mt_inferred"].get("name"):
                o.append("    'name' matches the first path segment against conventional")
                o.append("    engine names. An engine mounted somewhere non-obvious (a")
                o.append("    transit engine at crypto/) is MISSED. Re-run with live API")
                o.append("    access to classify from the real mount inventory instead.")
            o.append("")

        matched = (st["pki_events"] + st["ssh_events"]
                   + st["transit_calls"] + st["transform_calls"])
        if st["parsed"] and not matched:
            # A zero here reads identically to "no activity", so say which it is.
            o.append("  !! {:,} entries parsed, NONE classified as PKI/SSH/Transit."
                     .format(st["parsed"]))
            if not st["mt_present"] and not st["mt_inferred"]:
                o.append("     No entry carried request.mount_type and no engine could")
                o.append("     be inferred from the path. Most likely the log is from a")
                o.append("     pipeline that strips fields, or mounts are named")
                o.append("     unconventionally. Re-run with live API access so mounts")
                o.append("     can be resolved from sys/mounts.")
            else:
                o.append("     Entries were classified, but none used a billable")
                o.append("     operation (issue/sign/encrypt/decrypt/...).")
            top = sorted(st["path_prefixes"].items(), key=lambda kv: -kv[1])[:10]
            if top:
                o.append("     Most common request paths seen:")
                for pfx, n in top:
                    o.append("       %-44s {:,}".format(n) % pfx[:44])
            o.append("")
        elif st["pki_events"] == 0:
            o.append("  NOTE: zero PKI events. If PKI mounts exist, this log window")
            o.append("        does not cover them — RU is a MONTHLY measure, so the")
            o.append("        log must span a representative month.")
            o.append("")

    if custom_role_mounts:
        o.append("Custom/third-party engines with roles (%d mounts) — RU treatment"
                 % len(custom_role_mounts))
        o.append("is a DEAL DESK question, confirm before quoting:")
        seen = defaultdict(int)
        for ns, path, mtype, n in custom_role_mounts:
            seen[mtype] += n
        for mtype, n in sorted(seen.items(), key=lambda kv: -kv[1]):
            o.append("  %-34s %d roles" % (mtype, n))
        o.append("")

    if truncated:
        o.append("!! %d KV mount(s) hit --cap; those counts are floors." % len(truncated))
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
        o.append("  * Static Secrets and KMSE in the table above are POINT-IN-TIME.")
        o.append("    The billable figure is the monthly peak - see the high-water")
        o.append("    section above.")
    else:
        o.append("  * Static Secrets and KMSE are priced on a MONTHLY HIGH-WATER MARK.")
        o.append("    This is a point-in-time count and will understate a month that")
        o.append("    peaked higher. Build a history with")
        o.append("      vault_ru_sizing_api.py --sample-to FILE   (on a schedule)")
        o.append("    then pass --highwater FILE here.")
    o.append("  * PKI/SSH/Transit reflect only the supplied audit window. Scale to a")
    o.append("    full month if the log is shorter.")
    o.append("  * Audit logs HMAC string values by default; a hashed expiration")
    o.append("    cannot be used. See 'undetermined duration' above.")
    o.append("=" * 72)

    # An HCP run is not a sizing artifact - name it so.
    tag = ".INVALID-HCP" if is_hcp else ""
    os.makedirs(args.out_dir, exist_ok=True)
    if rows:
        with open(os.path.join(args.out_dir, "ru_inventory%s.csv" % tag), "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["namespace", "mount", "type", "ru_category", "count", "detail"])
            w.writerows(sorted(rows, key=lambda r: (r[0], r[1])))
    text = "\n".join(o)
    with open(os.path.join(args.out_dir, "ru_summary%s.txt" % tag), "w") as fh:
        fh.write(text + "\n")
    print(text)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
