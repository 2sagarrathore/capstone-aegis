# Aegis — Container Image Vulnerability Scanner with Reporting

Aegis scans container images for known CVEs, **blocks the build** when the findings
breach a policy you define, writes human- and machine-readable reports, notifies
Slack or Teams, and keeps the history so you can see whether your backlog is
getting better or worse.

It is a thin, opinionated layer over [Trivy](https://github.com/aquasecurity/trivy):
Trivy finds the CVEs; Aegis decides what to do about them.

```
  image ──► scan ──► apply exceptions ──► diff vs history ──► policy gate
                                                                 │
              ┌──────────────┬──────────────┬───────────────┬────┘
              ▼              ▼              ▼               ▼
        JSON/HTML/MD    SQLite history   Prometheus    Slack / Teams
          reports        + dashboard      metrics       notification
                                                              │
                                                        exit 0 / 1 → CI
```

---

## Quick start

```bash
git clone <this-repo> && cd capstone-aegis
make install                       # creates .venv and installs Aegis
brew install trivy                 # or: see docs/SETUP.md
.venv/bin/aegis doctor             # verify the setup
.venv/bin/aegis scan python:3.12-slim
.venv/bin/aegis serve              # dashboard on http://127.0.0.1:8080
```

Or run the whole stack — dashboard, Prometheus and Grafana — in containers:

```bash
docker compose up -d --build
docker compose run --rm scanner scan nginx:1.27
```

## What it does

| Capability | Where |
|---|---|
| CVE scanning of any image reference (registry or local daemon) | `aegis/scanner.py` |
| Build gate: severity floor **plus** per-severity budgets | `aegis/policy.py` |
| Time-boxed CVE exceptions, with expiry enforcement | `aegis/exceptions_store.py` |
| JSON, self-contained HTML and Markdown reports | `aegis/reporting/` |
| Slack Block Kit and Teams MessageCard notifications | `aegis/notify/` |
| SQLite history with new/resolved diffing per scan | `aegis/storage.py` |
| Web dashboard with trends, filters and a JSON API | `aegis/dashboard.py` |
| Prometheus metrics (scrape endpoint, textfile, pushgateway) | `aegis/metrics.py` |
| GitHub Actions, Jenkins and GitLab CI integrations | `ci/`, `.github/workflows/` |

## The gate

Two rules decide whether a build passes. `fail_on` is the severity floor;
`max_allowed` sets per-severity budgets that override the floor for the
severities they name:

```yaml
policy:
  fail_on: HIGH            # anything HIGH or above fails...
  max_allowed:
    CRITICAL: 0            # ...no criticals at all
    HIGH: 10               # ...but up to ten highs are tolerated
  fail_on_fixable_only: false   # true = ignore CVEs with no upstream fix
  warn_only: false              # true = report, never fail (rollout mode)
```

Exit codes are the CI contract:

| Code | Meaning |
|---:|---|
| 0 | scan completed, gate passed |
| 1 | scan completed, gate failed |
| 2 | scan could not be completed (unreachable image, scanner error) |
| 3 | usage or configuration error |

`--warn-only` and `--exit-zero` let you roll the gate into an existing pipeline
without breaking every build on day one.

## Exceptions, not suppressions

A CVE with no upstream fix should not block every build forever — but an
allowlist that never expires is just a vulnerability you decided to forget
about. Every Aegis exception **must** carry an expiry date, and lapses on its own:

```bash
aegis exceptions add CVE-2024-45491 \
  --package libexpat1 --image 'internal/*' \
  --reason "not reachable: no XML parsing in this service" \
  --approved-by security@acme.com --days 60
aegis exceptions list        # shows days remaining, red when expired
aegis exceptions prune       # drop the lapsed ones
```

Suppressed findings are still scanned, still recorded, and still shown in the
reports and the dashboard — they just do not fail the build.

## Documentation

| Document | Covers |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | Installation, Docker, CI setup, Slack/Teams webhooks |
| [docs/USAGE.md](docs/USAGE.md) | Every command, every config key, every env override |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the pieces fit, data model, design decisions |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Failure modes and what to do about them |
| [docs/COST_OPTIMIZATION.md](docs/COST_OPTIMIZATION.md) | What this costs to run and how to cut it |
| [docs/CAPSTONE.md](docs/CAPSTONE.md) | Sprint-by-sprint mapping to the project brief |

## Development

```bash
make install     # venv + dev dependencies
make test        # 114 tests, no network or Trivy needed
make demo        # scan a demo image set and backfill trend history
make stack       # dashboard + Prometheus + Grafana in Docker
```

The test suite stubs the scanner subprocess and the webhook transport, so it
runs offline in a few seconds. Parser tests run against real Trivy output
captured in `tests/fixtures/`.

## License

MIT.
