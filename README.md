# Vault Resource Unit (RU) Sizing Tools

> ### ⚠️ Not an official IBM or HashiCorp tool — use at your own risk
>
> Personal, unofficial project. Not produced, endorsed, supported, or reviewed by
> IBM or HashiCorp, and not covered by any support agreement. No warranty.
>
> **Never run against a production Vault cluster** — correctness rests entirely on
> synthetic fixtures. Output is **not a quote and not a licensing determination**;
> RU rules and pricing are set by HashiCorp/IBM and may change. Confirm every
> figure with your account team or deal desk before it reaches a customer or a
> contract.
>
> Read-only against Vault (LIST and GET only), but reviewing the code and scoping
> the token you hand it are on you.

Sizes a Vault estate against the **Resource Unit** licensing model. Built because
the documented sizing one-liners are namespace-scoped and undercount badly.

---

## Scope: self-managed Vault Enterprise only

RUs are the self-managed Vault Enterprise model. HCP Vault Dedicated is licensed
on cluster + client count and is **not a valid target**.

HCP is fine as a *test* cluster. A run against it is detected, banner-stamped in
the report, written to `*.INVALID-HCP.*` filenames, and excluded from every
high-water peak — so it can't be mistaken for, or contaminate, real sizing data.

Detection: `.hashicorp.cloud` host → hcp; readable `sys/host-info` →
self-managed; otherwise `unknown`, treated as self-managed. Override with
`--platform {auto,self-managed,hcp}`.

One script per job, not per platform — the platform delta is a handful of probes
against ~900 lines of shared walking and parsing.

---

## The model

Transcribed from internal HashiCorp licensing collateral (not public).
**Unofficial — verify against current guidance.**

| Resource Unit | Counted how | Source |
|---|---|---|
| Static Secrets | unique secrets, **monthly high-water mark** | API + sample history |
| Dynamic / Auto-Rotated | roles configured | API |
| PKI | duration-adjusted; **730 cert-hours = 1 RU** | audit log |
| SSH | duration-adjusted; **730 cred-hours = 1 RU** | audit log |
| Transit / Transform | **per element**; 150,000 = 1 RU | audit log |
| KMSE | managed keys, monthly high-water mark | API + sample history |

Legacy model for comparison: Vault Installs (clusters) + Client Count.

---

## Usage

Both scripts are read-only. Outputs land in `--out-dir`.

**`vault_ru_sizing_api.py`** — live API only: Static Secrets, Dynamic roles, KMSE.
Use when you'd rather not ask for audit logs, which expose mount structure and
request paths even with values HMAC'd.

```bash
export VAULT_ADDR=... VAULT_TOKEN=...
python3 vault_ru_sizing_api.py --namespace admin                # full walk
python3 vault_ru_sizing_api.py --namespace admin --metrics      # telemetry fast path
python3 vault_ru_sizing_api.py --namespace admin --mounts-only  # inventory only
```

**`vault_ru_sizing.py`** — superset, adds PKI / SSH / Transit from audit logs.

```bash
python3 vault_ru_sizing.py --namespace admin --audit-log 'audit*.log*'
python3 vault_ru_sizing.py --no-api --audit-log audit.log   # log-only
```

### Token policy
```hcl
path "sys/namespaces"     { capabilities = ["list"] }
path "sys/mounts"         { capabilities = ["read"] }
path "sys/managed-keys/*" { capabilities = ["list"] }
path "sys/metrics"        { capabilities = ["read"] }   # only for --metrics
path "sys/host-info"      { capabilities = ["read"] }   # platform detection
path "+/metadata/*"       { capabilities = ["list"] }   # kv-v2
path "+/*"                { capabilities = ["list"] }   # kv-v1, roles
```

---

## Monthly high-water mark

Static Secrets and KMSE bill on a monthly peak, which no single run can observe.
Sample on a schedule, report later.

```bash
# sample (cheap; --metrics skips the recursive KV walk)
0 * * * * VAULT_ADDR=... VAULT_TOKEN=... \
  python3 vault_ru_sizing_api.py --metrics --quiet --sample-to /var/lib/ru/history.ndjson

# report the peak — no cluster access needed
python3 vault_ru_sizing_api.py --report-only --highwater history.ndjson [--highwater-month 2026-07]

# or fold into the full six-category report
python3 vault_ru_sizing.py --namespace admin --audit-log 'audit*.log*' --highwater history.ndjson
```

Append-only NDJSON, one sample per line. `--sample-detail totals` shrinks it
(~30 KB/sample at 500 mounts) at the cost of the sum-of-peaks figure.

**Two readings, both reported.** The collateral says only "monthly high-water
mark" — it doesn't define sampling frequency, month boundary, or whether the peak
is of the estate **total** at one instant or the **sum of each mount's own peak**
(always ≥ the total, since mounts peak at different times). They diverge in
practice. **Confirm with deal desk which applies before quoting.**

**Audit classification.** Entries are classified by `request.mount_type` when
present. When it's absent the engine is resolved from the live `sys/mounts`
inventory, or failing that from the first path segment — so **run with API access
when you can**, since name matching misses engines mounted at non-obvious paths.
The report says how many entries needed each method, and if nothing classifies at
all it prints the most common request paths seen rather than a silent zero.

**A sampled peak is a lower bound.** The report prints the largest unobserved
window and grades coverage OK / THIN (≥24 h) / POOR (≥168 h); an in-progress
month is marked not-yet-billable.

Excluded from peaks, each of which would otherwise corrupt one silently: HCP
samples; `--mounts-only` samples (counted no secrets ≠ dropped to zero);
KMSE-403 samples. Separate clusters or root namespaces are grouped, never summed.
A month mixing telemetry and walk measurements is flagged.

---

## Why not the documented one-liners

Each is a real defect these scripts fix:

1. **Namespace scoping** — `vault list <mount>/roles` and `sys/mounts` see only the
   token's namespace; the rest is invisible and the result looks plausible.
2. **Transit counts calls, not elements** — one `batch_input` can carry thousands.
3. **Empty audit results error** — `jq ... | add | ./730` throws *"null and number
   cannot be divided"* instead of returning 0.
4. **`jq -s` slurps gigabyte logs into memory** — these stream, and handle `.gz`.
5. **Hosted-platform envelope wrapping** — the real record is a JSON string inside
   a `log`/`message` field; unhandled, every count silently returns zero.
6. **Custom engines missed** — unknown mount types are probed and reported
   separately, since whether they attract RUs is a deal-desk question.
7. **An unreadable KMSE probe read as zero** — a 403 became a clean `KMSE: 0`,
   undercounting a billed category. Now reports `>= N  INCOMPLETE` and names the
   affected namespaces.
8. **Classification depended entirely on `request.mount_type`** — logs that don't
   carry it (older Vault, or a pipeline that strips fields) returned zero across
   PKI, SSH and Transit, indistinguishable from no activity. Now falls back to
   the live `sys/mounts` inventory (exact, handles a transit engine mounted at
   `crypto/`), then to conventional mount names, and reports which was used.

---

## Verification status

**Fixture-tested:** PKI duration math; SSH `lease_duration` fallback; Transit
batch element counting; HMAC'd expiration → "undetermined" not dropped; `.gz`,
raw NDJSON and wrapped-envelope parity; Prometheus parser incl. prefix collisions;
HTTP 400 tolerance and per-namespace error isolation; platform detection incl.
suffix-spoofing rejection; HCP stamping; KMSE 403 → `INCOMPLETE`; high-water math
on a known history (peak-of-total 150 vs sum-of-peaks 190, blind-window
arithmetic, all exclusions, multi-estate separation, corrupt-line tolerance);
live sampling round-trip; mount_type inference both ways (a transit engine at
`crypto/` is found via the mount inventory and correctly missed-with-warning
without it). Exercised end to end against a 617 MB / 1,005,345-entry synthetic
log: 3.6 s, 1M transit elements counted.

**Never run against a real Vault cluster.** No production validation of the
namespace walk, KV recursion at scale, or real audit log formats.

---

## Known gaps

- **PKI attribution is issuance-based** — hours-valid of certs *issued* in the
  window, all attributed to that month. A cert issued on the 30th with a 90-day
  TTL dumps 2,160 hours into it. Needs 3 months, or role TTLs read directly.
- **SSH duration often isn't recorded** — falls back to per-role issuance counts;
  multiply by that role's TTL manually.
- **Transform detection is thin** — shares Transit's path matching; `/encode/`
  and `/decode/` handled but lightly tested.
- **No RU-vs-client cross-check** — emitting `vault operator usage` client counts
  alongside RUs would make the model comparison direct.
- **No pricing.** Unit counts only; whether RU beats clients is deal-desk info.
- **High-water needs lead time** — a month of scheduled sampling before the first
  figure means anything. Start the cron at engagement kickoff, not before a quote.
- **Platform detection has no positive self-managed signal on a thin token** —
  `sys/host-info` may not be readable, so legitimate runs often say `unknown`.
  Harmless; `--platform self-managed` silences it.
- **The two scripts duplicate the Vault client, namespace walk, KMSE probe and the
  ~240-line high-water reader.** Deliberate, to keep each a single self-contained
  file, but it's the weakest part of the layout. A third consumer is the trigger
  to extract a shared module.

---

## Gotchas

- `sys/managed-keys/*` returns **400** on HCP (unsupported), not 404. Tolerated:
  400/403/404/405/501. On self-managed a **403** means a missing capability — now
  reported as unknown, not zero.
- `sys/metrics` is generally unavailable on HCP, so `--metrics` falls back to the
  walk on a test cluster.
- HCP audit logs are `.gz`, retained 30 days, chunked by time window rather than
  month. The glob handles multiple files; **always check the printed date span**
  before trusting a monthly figure.
- `vault.secret.kv.count` needs Vault 1.16+ and telemetry; the gauge emits on
  `usage_gauge_period` (10m default), so a fresh node reports nothing.
- **Stored entities are not billed clients** — `vault_identity_entity_count` is a
  cross-check only; only entities whose tokens are *used* in the period bill.
