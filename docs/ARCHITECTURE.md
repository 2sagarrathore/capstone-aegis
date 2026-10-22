# Architecture

## The pipeline

Every entry point — CLI, CI, scheduled rescan — runs the same function,
`aegis.pipeline.run_scan`:

```
  scan ──► apply exceptions ──► diff vs history ──► evaluate policy
                                                         │
                   ┌──────────────┬──────────────┬───────┴───────┐
                   ▼              ▼              ▼               ▼
               persist        reports         metrics       notifications
              (SQLite)    (JSON/HTML/MD)   (Prometheus)    (Slack/Teams)
```

Order matters:

1. **Exceptions are applied before the gate**, so a waived CVE cannot fail a
   build — but it is still recorded and still shown in the report. Suppression
   is a policy decision, not a data deletion.
2. **The diff runs before persistence**, so the fresh result is compared against
   the *previous* stored scan rather than against itself.
3. **Only the scan can abort the run.** Reports, metrics and notifications all
   degrade to a logged error: a read-only reports directory or a dead webhook
   must never mask a clean result or invent a failure.

## Modules

| Module | Responsibility |
|---|---|
| `models.py` | `Severity`, `Vulnerability`, `ScanResult`, `PolicyDecision` |
| `scanner.py` | runs Trivy, classifies failures, normalizes JSON |
| `exceptions_store.py` | the time-boxed allowlist |
| `policy.py` | the build gate |
| `storage.py` | SQLite history, diffing, aggregates |
| `reporting/` | JSON, HTML (Jinja) and Markdown renderers |
| `notify/` | Slack Block Kit, Teams MessageCard |
| `metrics.py` | Prometheus registries, textfile/pushgateway export |
| `charts.py` | server-rendered SVG for the dashboard |
| `dashboard.py` | Flask app: pages, JSON API, `/metrics`, `/healthz` |
| `pipeline.py` | wires the above together |
| `cli.py` | argument parsing, output formatting, exit codes |

### The engine boundary

`scanner.py` is the only module that knows what Trivy's JSON looks like.
Everything downstream works against `ScanResult`. Adding Grype or Clair means
writing one class satisfying the `Scanner` interface and registering it in
`ENGINES` — no other module changes.

### Error taxonomy

`scanner.py` classifies failures, because the right response differs:

| Class | Examples | Response |
|---|---|---|
| `TransientScannerError` | i/o timeout, 503, rate limit, DB download failure | retry with linear backoff |
| `ImageNotFound` | manifest unknown, unauthorized | fail immediately — retrying cannot help |
| `ScannerNotInstalled` | binary missing from PATH | exit 3 with an actionable message |
| `ScannerError` | unparseable output, non-zero exit | fail after the retry budget |

Retrying a missing image wastes a minute of CI time per build and teaches
people to ignore the scanner.

## Data model

Two tables. `scans` holds one row per scan with denormalized severity counts —
the dashboard's landing page and every Prometheus scrape read only this table,
which keeps them fast as history grows. `findings` holds the individual CVEs.

```
scans(scan_id PK, image, image_digest, scanned_at, scanner, scanner_version,
      duration_seconds, os_family, os_version, image_size_bytes,
      total, critical, high, medium, low, unknown, fixable, suppressed,
      verdict, reasons, source)

findings(scan_id FK, vuln_id, package, installed_version, fixed_version,
         severity, target, pkg_type, cvss_score, primary_url, title,
         published_date, suppressed)
         PRIMARY KEY (scan_id, vuln_id, package, installed_version)
```

`scan_id` is `sha256(image|scanned_at|digest)[:16]`, so re-recording the same
scan is idempotent.

Findings are identified by a **fingerprint** of `vuln_id:package:installed_version`.
That is what makes the diff meaningful: upgrading a package resolves the old
finding and, if the CVE persists, introduces a new one against the new version.

### Why SQLite

The brief suggests Prometheus for trend data. Prometheus is the right place for
*metrics*, but a CVE is a record, not a number — you want to ask "which CVEs
appeared in this image last Tuesday", which is a query, not a time series.
SQLite gives that with zero operational cost: no service to run, one file both
the CLI and the dashboard open, and it works inside a CI container.

Prometheus still gets the numbers (`/metrics`), so Grafana and alerting work as
the brief intends. The two are complementary, not alternatives.

The schema is deliberately plain SQL with no SQLite-specific types, so moving to
Postgres is a connection change plus `AUTOINCREMENT` syntax. Do that when you
have concurrent writers — SQLite serializes writes, which is fine for one CI
runner and a read-only dashboard, and not fine for twenty parallel jobs sharing
one network volume. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md#database-is-locked).

## Timestamps

`scanned_at` has **millisecond** resolution. With second resolution, two scans
of the same image inside one second — a matrix build, a rescan loop — cannot
find each other as predecessors, and the diff silently reports every finding as
new.

## The dashboard

Flask, server-rendered, with charts emitted as inline SVG from `charts.py`.
There is no JavaScript charting library: the dashboard has to work inside an
air-gapped network where a CDN is not reachable, and a security tool pulling
scripts from a third party is a poor look.

The JavaScript that does ship is ~40 lines of vanilla DOM code for tooltips and
table filters, and every page is fully usable without it.

### Colour

Severity is an **ordinal** scale — swapping Critical and Low changes the
meaning — so the charts use a single red hue stepped light→dark rather than four
unrelated colours. The reader sees the order in the colour. Both the light and
the dark ramp were checked against the surface they actually render on (light
end 2.14:1 and 2.91:1 respectively, adjacent lightness gaps ≥ 0.06).

Colour never carries meaning alone: every severity appears as text in the
legend, in the table and in each segment's tooltip and `<title>`.

## Security notes

* The HTML report renders with `autoescape=True` **unconditionally**. Jinja's
  `select_autoescape()` does not recognise a `*.html.j2` filename as HTML, and
  CVE titles come from a vulnerability database rather than from us. There is a
  test for this.
* Webhook URLs are never stored in the config — only the *name* of the
  environment variable that holds one.
* The container image runs as uid 10001, ships no build toolchain, and removes
  `curl` in the layer that used it.
* The dashboard is read-only and takes no user input that reaches the database.

## Testing

114 tests, no network and no Trivy binary required:

* parser tests run against **real** Trivy output captured in `tests/fixtures/`;
* retry, timeout and not-found handling are tested by scripting `subprocess.run`;
* webhook transport is tested by stubbing `requests.post`;
* the pipeline and CLI are tested end-to-end against a fake scanner engine.

Three real bugs were found this way and are covered by regression tests: the
previous-scan lookup keyed on an unwritten `scan_id`, the shared metrics file
that multi-image runs overwrote, and the unescaped HTML report.
