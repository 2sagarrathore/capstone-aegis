# Usage

## Commands

```
aegis [-c CONFIG] [-v|-vv] [-q] <command> [options]
```

| Command | What it does |
|---|---|
| `scan IMAGE [IMAGE…]` | scan, gate, report, record, notify |
| `images` | latest result for every tracked image |
| `history` | past scans, filterable |
| `rescan` | re-scan images whose last result is stale |
| `exceptions list\|add\|remove\|prune` | manage the approved-vulnerability allowlist |
| `serve` | run the web dashboard |
| `purge` | delete scans older than the retention window |
| `doctor` | verify the local setup |

### `aegis scan`

```bash
aegis scan python:3.12-slim
aegis scan app:1 app:2 registry.io/team/api:sha-abc123      # several at once
aegis scan app:1 --fail-on CRITICAL --max-critical 0
aegis scan app:1 --format json --output-dir out/ --no-notify
aegis scan app:1 --warn-only                                 # report, never fail
aegis scan app:1 --json | jq '.[0].summary'                  # machine-readable
```

| Flag | Effect |
|---|---|
| `--fail-on {UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL}` | severity floor that fails the build |
| `--max-critical/-high/-medium/-low N` | per-severity budget (overrides the floor) |
| `--max-total N` | total-findings budget |
| `--warn-only` | report breaches, always exit 0 |
| `--fixable-only` | only count findings with an upstream fix |
| `--ignore-unfixed` | ask the scanner not to report unfixed CVEs at all |
| `--severity HIGH,CRITICAL` | restrict which severities are collected |
| `--offline` | never update the CVE database |
| `--format json,html,markdown` | which reports to write |
| `-o/--output-dir DIR` | where to write them |
| `--source LABEL` | label recorded in history (`github-actions`, `jenkins`, …) |
| `--no-report / --no-store / --no-notify / --no-metrics` | switch off one stage |
| `--exit-zero` | always exit 0 (observation mode) |
| `--json` | emit the full result as JSON instead of the summary |

A scan of several images continues past individual failures — one unreachable
image does not abandon a nightly sweep. The exit code reflects the worst
outcome across all of them.

**`--fixable-only` vs `--ignore-unfixed`.** `--fixable-only` still *reports*
unfixable CVEs, it just does not let them fail the build — you keep the
visibility. `--ignore-unfixed` tells the scanner not to look for them at all,
so they vanish from the reports too. Prefer the first.

### `aegis images` / `aegis history`

```bash
aegis images                       # one row per image, worst first
aegis history --image 'team/*' --days 7 --limit 50
aegis history --json | jq '.[] | select(.verdict=="FAIL") | .image'
```

### `aegis rescan`

```bash
aegis rescan                       # everything older than the configured window
aegis rescan --stale-hours 6
aegis rescan --image api           # only images whose name contains "api"
```

Images listed under `rescan.images` in the config are always eligible, even if
they have never been scanned.

### `aegis exceptions`

```bash
aegis exceptions add CVE-2024-45491 \
    --package libexpat1 \
    --image 'internal/*' \
    --reason "not reachable: this service parses no XML" \
    --approved-by security@acme.com \
    --ticket SEC-1421 \
    --days 60

aegis exceptions list              # days remaining; red once expired
aegis exceptions remove CVE-2024-45491
aegis exceptions prune --dry-run
aegis exceptions prune
```

`--expires YYYY-MM-DD` sets an exact date; `--days N` counts from today. With
neither, `exceptions.default_expiry_days` applies. There is no way to create a
permanent exception — that is deliberate.

`package` and `image` are shell globs. `--package '*'` (the default) applies to
every package; `CVE id` can also be `*` to waive a whole package.

### `aegis serve`

```bash
aegis serve --host 0.0.0.0 --port 8080
```

| Route | Purpose |
|---|---|
| `/` | overview: tiles, 30-day trend, most-affected packages, image table |
| `/image/<ref>` | per-image history and full finding list, with filters |
| `/scans` | scan history with image/date/verdict filters |
| `/exceptions` | the allowlist and how close each entry is to expiring |
| `/metrics` | Prometheus scrape endpoint |
| `/healthz` | liveness probe |
| `/api/summary`, `/api/images`, `/api/scans`, `/api/findings/<scan_id>`, `/api/trend`, `/api/top-packages` | JSON API |

The dashboard is **read-only** — it cannot trigger a scan — so it can be shown
to a wider audience than the credentials that produce the data.

The built-in server is Flask's development server. For anything beyond a team
tool, put it behind gunicorn: `gunicorn 'aegis.dashboard:build()' -b 0.0.0.0:8080`.

## Configuration reference

Precedence: **CLI flag > environment variable > `aegis.yml` > default**.

### `scanner`

| Key | Default | Meaning |
|---|---|---|
| `engine` | `trivy` | scanner backend |
| `timeout_seconds` | `600` | per-scan timeout |
| `retries` | `2` | retries for *transient* failures only |
| `retry_backoff_seconds` | `5` | linear backoff base |
| `ignore_unfixed` | `false` | skip CVEs with no upstream fix |
| `severities` | all four | which severities to collect |
| `cache_dir` | `""` | CVE database cache (set this in CI) |
| `offline` | `false` | never contact the network |
| `skip_db_update` | `false` | use the cached database as-is |
| `db_repository` | `""` | mirror the CVE database internally |
| `platform` | `""` | e.g. `linux/arm64` for multi-arch images |

### `policy`

| Key | Default | Meaning |
|---|---|---|
| `fail_on` | `HIGH` | severity floor |
| `max_allowed` | `{}` | per-severity budgets; override the floor |
| `fail_on_fixable_only` | `false` | only count findings with a fix |
| `max_total` | `null` | total-findings budget |
| `warn_only` | `false` | report without failing |

### `exceptions`, `reporting`, `notifications`, `storage`, `metrics`, `rescan`

| Key | Default | Meaning |
|---|---|---|
| `exceptions.file` | `exceptions.yml` | allowlist location |
| `exceptions.default_expiry_days` | `90` | window used when `add` gets no date |
| `exceptions.warn_on_expiring_within_days` | `14` | "expiring soon" threshold |
| `reporting.output_dir` | `reports` | where reports are written |
| `reporting.formats` | `[json, html, markdown]` | which to write |
| `reporting.max_rows_in_html` | `500` | table cap in the HTML report |
| `notifications.<channel>.enabled` | `false` | switch the channel on |
| `notifications.<channel>.webhook_url_env` | `SLACK_WEBHOOK_URL` | **name** of the env var holding the URL |
| `notifications.<channel>.min_severity` | `HIGH` | new findings at/above this notify |
| `notifications.<channel>.notify_on_pass` | `false` | also message on a clean scan |
| `storage.database` | `aegis.db` | SQLite file |
| `storage.retention_days` | `365` | window used by `aegis purge` |
| `metrics.textfile_path` | `reports/aegis_metrics.prom` | stem for per-image `.prom` files |
| `metrics.pushgateway_url` | `""` | push instead of writing files |
| `rescan.stale_after_hours` | `24` | staleness window |
| `rescan.images` | `[]` | always-eligible images |

### Environment overrides

| Variable | Overrides |
|---|---|
| `AEGIS_CONFIG` | config file location |
| `AEGIS_FAIL_ON` | `policy.fail_on` |
| `AEGIS_MAX_CRITICAL`, `AEGIS_MAX_HIGH`, `AEGIS_MAX_MEDIUM`, `AEGIS_MAX_LOW` | `policy.max_allowed.<SEVERITY>` |
| `AEGIS_WARN_ONLY` | `policy.warn_only` |
| `AEGIS_FIXABLE_ONLY` | `policy.fail_on_fixable_only` |
| `AEGIS_IGNORE_UNFIXED`, `AEGIS_OFFLINE`, `AEGIS_SKIP_DB_UPDATE` | scanner behaviour |
| `AEGIS_CACHE_DIR`, `AEGIS_TIMEOUT_SECONDS`, `AEGIS_RETRIES` | scanner tuning |
| `AEGIS_OUTPUT_DIR`, `AEGIS_FORMATS` | reporting |
| `AEGIS_DB`, `AEGIS_EXCEPTIONS_FILE` | file locations |
| `AEGIS_SLACK_ENABLED`, `AEGIS_TEAMS_ENABLED`, `AEGIS_DASHBOARD_URL` | notifications |

Booleans accept `1/true/yes/on`. A malformed integer is ignored rather than
crashing the run.

## Reports

Each scan writes `<slug>_<timestamp>.<ext>` plus a stable `latest_<slug>.<ext>`
pointer, so a CI link never goes stale.

* **JSON** — the integration format: full findings, summary counts, the policy
  decision and its reasons, and the diff against the previous scan.
* **HTML** — self-contained (no CDN, no external assets): opens from a
  `file://` URL, works offline, has client-side severity/fix/text filters.
* **Markdown** — pastes straight into a PR comment or a job summary.

## Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `aegis_vulnerabilities` | `image`, `severity` | active (non-suppressed) findings |
| `aegis_fixable_vulnerabilities` | `image` | findings with an upstream fix |
| `aegis_suppressed_vulnerabilities` | `image` | hidden by an exception |
| `aegis_policy_pass` | `image` | 1 = passed, 0 = failed |
| `aegis_scan_duration_seconds` | `image` | wall-clock scan time |
| `aegis_scan_timestamp_seconds` | `image` | when it last ran |
| `aegis_image_size_bytes` | `image` | image size |
| `aegis_new_vulnerabilities` | `image`, `severity` | introduced since the previous scan |
| `aegis_resolved_vulnerabilities` | `image` | resolved since the previous scan |
| `aegis_images_tracked`, `aegis_scans_total` | — | store totals |
| `aegis_exceptions_active`, `aegis_exceptions_expiring_soon` | — | allowlist health |

Three delivery paths: the dashboard's `/metrics` endpoint (preferred — always
current), per-image `.prom` files for the node_exporter textfile collector, and
a Pushgateway for ephemeral CI jobs.

Alert rules ship in `deploy/prometheus/alerts.yml`, including `AegisScanStale`
— an image nobody has re-scanned is not the same as an image with no new CVEs.
