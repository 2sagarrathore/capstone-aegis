# Troubleshooting

Start with `aegis doctor` — it checks the binary, the database, the exceptions
file, the reports directory and the webhook environment in one pass, and exits
non-zero if anything is wrong.

---

## `trivy not found on PATH`

```
error: 'trivy' not found on PATH. Install it with `brew install trivy`…
```

Exit code 3. Install Trivy ([SETUP.md](SETUP.md#2-install-trivy)). In CI,
install it with the pinned installer rather than relying on the runner image.

## The scan reports zero vulnerabilities and you do not believe it

Three common causes:

1. **The base OS is end-of-life.** Trivy marks these `EOSL` and stops reporting
   package CVEs, because the distribution no longer publishes security data.
   `alpine:3.14` scans clean for exactly this reason — it is not clean, it is
   unmaintained. Check with `trivy image --format json <image> | jq .Metadata.OS`.
   An `"EOSL": true` here is a *worse* finding than a list of CVEs.
2. **`ignore_unfixed` or `--severity` is filtering them out.** Check the policy
   line Aegis prints at the top of every run.
3. **A distroless or scratch image with no package manager.** There is no
   package database to read; use `--scanners vuln,secret` or an SBOM-based scan.

## `cannot resolve image 'x': MANIFEST_UNKNOWN`

Exit code 2. The reference does not exist, or you are not authenticated. This is
deliberately **not** retried — retrying a missing image wastes CI minutes.

```bash
docker pull <image>                 # does it resolve at all?
docker login <registry>             # private registry?
aegis scan <image> -vv              # see the exact trivy invocation
```

## Scans are slow or time out

The first scan on a machine downloads the whole CVE database. Later scans reuse
the cache — if every scan is slow, the cache is not persisting.

```bash
export AEGIS_CACHE_DIR=~/.cache/trivy      # and cache this path in CI
aegis scan <image> --offline               # use the cached DB, never update
```

Raise `AEGIS_TIMEOUT_SECONDS` for very large images. See
[COST_OPTIMIZATION.md](COST_OPTIMIZATION.md) for the caching recipes per CI
platform.

## Repeated `transient scan failure … retrying`

Registry rate limiting (Docker Hub limits anonymous pulls) or a flaky CVE
database download. Authenticate to the registry, or mirror the database
internally:

```yaml
scanner:
  db_repository: registry.internal/trivy-db
```

If the network is genuinely unavailable, `--offline` + `--skip-db-update` will
scan against the cached database. The findings are only as fresh as that cache.

## The build fails and you think it should not

The gate prints its reasoning. Check, in order:

```bash
aegis scan <image> -v                      # prints the active policy
aegis exceptions list                      # did a waiver expire?
```

* An exception that lapsed yesterday stops suppressing findings today. That is
  the design — but it does mean a build can break with no code change.
  `aegis_exceptions_expiring_soon` and the `AegisExceptionsExpiring` alert exist
  to give you warning.
* `max_allowed` **overrides** `fail_on` for the severities it names. With
  `fail_on: HIGH` and `max_allowed: {HIGH: 10}`, eleven highs fail and ten pass.
* A new CVE published overnight can fail a build on an unchanged image. Check
  the `change:` line — `+N introduced` with an unchanged digest means the
  database moved, not your code.

To unblock urgently without disabling the gate everywhere:

```bash
aegis scan <image> --warn-only             # this run reports but passes
```

…and then file the exception properly, with a reason and an expiry.

## `exceptions … needs an 'expires' date`

Exit code 3. Permanent waivers are rejected by design. Add `expires:
YYYY-MM-DD`, or use `aegis exceptions add --days N`.

## `database is locked`

SQLite serializes writes. Several CI jobs writing to one database on a shared
volume will collide.

* Give each runner its own database and ship the **reports** to a central place; or
* point only the nightly rescan at the shared database; or
* move to Postgres if you genuinely need concurrent writers
  ([ARCHITECTURE.md](ARCHITECTURE.md#why-sqlite)).

Aegis uses WAL mode and a 30-second busy timeout, which handles brief overlap
but not sustained parallel writes.

## The dashboard is empty

```bash
aegis images                               # is there anything in the store?
aegis doctor                               # which database is in use?
```

Usually the dashboard and the scan are using **different** databases. Relative
paths in `aegis.yml` resolve against the config file's directory; `$AEGIS_DB`
overrides it. In Docker, both the scanner and the dashboard must mount the same
`/data` volume.

## The trend chart shows a single bar

That is correct on a new installation — there is one day of history. It fills in
as scans accumulate. For a demo, `scripts/seed_demo_history.py` backfills
plausible history from your real findings; its rows are labelled
`source='demo-seed'` and the script prints how to remove them. Do not run it
against a database you report real numbers from.

## Slack or Teams says nothing

```bash
aegis scan <image> -v | grep notify
```

| Message | Cause |
|---|---|
| `skipped: nothing above the notification threshold` | working as configured — the gate passed and nothing new appeared at/above `min_severity` |
| `error: Slack is enabled but $SLACK_WEBHOOK_URL is not set` | export the variable (the config holds the variable's *name*, not the URL) |
| `error: HTTP 404` | the webhook was revoked — regenerate it |
| `error: … after 3 attempts` | network or a sustained 5xx; the build outcome is unaffected |

Notification failures never change the exit code. That is deliberate: a dead
webhook must not fail a build that passed the gate.

## Prometheus has no Aegis metrics

* Scraping the dashboard: check `curl localhost:8080/metrics` and the target
  status in Prometheus.
* Using textfile collection: Aegis writes **one file per image**
  (`aegis_metrics_<slug>.prom`), so point node_exporter's
  `--collector.textfile.directory` at the directory, not a file.
* Using a Pushgateway: metrics are grouped by `image`; `honor_labels: true` is
  required on the scrape config.

## The HTML report will not open / looks unstyled

The report is deliberately self-contained — no CDN, no external assets — so it
opens from `file://` and works offline. If it looks wrong, the file was likely
truncated in transit; check the size and regenerate with
`aegis scan <image> --format html`.

Reports cap at `reporting.max_rows_in_html` (500) rows; the header says
"N of M shown" when truncated. The JSON report always has everything.

## Getting more detail

```bash
aegis -v  <command>      # info: what is running, what was suppressed and why
aegis -vv <command>      # debug: the exact trivy command line
```
