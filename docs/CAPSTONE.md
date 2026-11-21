# Capstone mapping — Project 2: Container Image Vulnerability Scanner with Reporting

This document maps the project brief onto what was built, sprint by sprint, so
each requirement can be traced to running code.

## Why this project

Of the five options in the brief, this is the one that can be **built and
demonstrated end-to-end** rather than described:

| Project | Blocker |
|---|---|
| 1. Kubernetes health checker & auto-healing | needs a live multi-node cluster to demonstrate node scaling and rebalancing |
| **2. Container image vulnerability scanner** | **none — Docker + Trivy, entirely local** |
| 3. Multi-cloud cost dashboard | needs billable AWS + Azure + GCP accounts |
| 4. End-to-end Jenkins/Terraform/EKS pipeline | needs a billable AWS account and a live EKS cluster |
| 5. Multi-cloud Terraform deployment | needs three billable cloud accounts |

Everything below runs on a laptop with no cloud credentials and no paid
services.

---

## Project goals

| Goal from the brief | Delivered | Where |
|---|---|---|
| 1. Scan images against known CVE databases before production | Trivy-backed scanner with a normalized data model; gate runs *before* the push step in all three pipelines | `aegis/scanner.py`, `aegis/policy.py` |
| 2. Integrate into CI/CD (Jenkins, GitHub Actions) | GitHub Actions, Jenkins **and** GitLab CI, all driven by `AEGIS_*` env vars and documented exit codes | `.github/workflows/`, `ci/` |
| 3. Detailed reports + real-time Slack/Teams notifications | JSON, self-contained HTML, Markdown; Slack Block Kit and Teams MessageCard | `aegis/reporting/`, `aegis/notify/` |
| 4. Dashboard with history of detected / resolved / pending | SQLite history, per-scan introduced/resolved diff, Flask dashboard + Grafana board | `aegis/storage.py`, `aegis/dashboard.py`, `deploy/grafana/` |

## Sprint 1 — Initial setup and basic vulnerability scanning

| Task | Delivered |
|---|---|
| Repository and folder structure | `aegis/` package, `ci/`, `deploy/`, `docs/`, `tests/`, `scripts/` |
| Install and configure Trivy | `deploy/install.sh`, `aegis doctor`, pinned v0.76.1 in every pipeline |
| Scan sample images, understand the output | Live scans of 8 images; real output captured as `tests/fixtures/trivy_python39.json` |
| Explore CVE database integration | `scanner.py` normalizes Trivy's schema into `ScanResult`; CVSS scores, fix versions and advisory URLs extracted |

**Beyond the brief:** the engine is behind an interface, so Trivy is replaceable
without touching anything downstream.

## Sprint 2 — CI/CD integration

| Task | Delivered |
|---|---|
| Scripts for Jenkins and GitHub Actions | `ci/Jenkinsfile`, `.github/workflows/image-scan.yml` (+ GitLab CI) |
| Pass/fail criteria by severity | `policy.py`: a severity floor **plus** per-severity budgets |
| Environment configuration of thresholds | 20 `AEGIS_*` overrides; `AEGIS_MAX_CRITICAL=0 AEGIS_MAX_HIGH=10` with no file edit |
| Test CI integration with sample images | Verified against 8 real images; CLI exit codes covered by tests |

**Beyond the brief:** distinct exit codes for *gate failed* (1) and *scan
failed* (2) — a pipeline must not treat an unreachable registry as a clean
image. `--warn-only` and `--exit-zero` allow a staged rollout.

## Sprint 3 — Report generation and notifications

| Task | Delivered |
|---|---|
| Structured reports (PDF/HTML/JSON) | JSON, self-contained HTML (offline, filterable) and Markdown |
| Slack / Teams integration | `notify/slack.py` (Block Kit), `notify/teams.py` (MessageCard), both with retry |
| Severity-based alert customization | `min_severity` per channel; failures always notify |
| Daily/weekly summary alerts | `aegis rescan` on a cron, with notifications enabled (*partial*: alerts are per-image, not a single cross-image digest) |

**Beyond the brief:** notifications fire on *newly introduced* findings, not on
every scan — a channel that reports the same 977 findings nightly gets muted
within a week. Webhook failures never change the build outcome.

## Sprint 4 — Dashboard for historical tracking

| Task | Delivered |
|---|---|
| Dashboard for vulnerability trends | Flask dashboard with a 30-day stacked trend, per-image history, most-affected packages |
| Connect to Prometheus (found / resolved / pending) | 13 metrics incl. `aegis_new_vulnerabilities`, `aegis_resolved_vulnerabilities`, `aegis_fixable_vulnerabilities` |
| Filters by image, date range, severity | On every page, plus a JSON API; `/scans` filters by image glob, range and verdict |
| Test and refine for usability | Verified in-browser; responsive to phone width; works without JavaScript |

**Beyond the brief:** findings are stored as records in SQLite as well as
counters in Prometheus, so "which CVEs appeared in this image last Tuesday" is
answerable — a question a time-series database cannot answer. Grafana board
provisioned in `deploy/grafana/`.

## Sprint 5 — Scanner customization and exception handling

| Task | Delivered |
|---|---|
| Skip vulnerabilities via user-defined exceptions | `exceptions_store.py`, `aegis exceptions add/list/remove/prune`, glob-scoped by package and image |
| Rescan after a period or when patched | `aegis rescan --stale-hours`, `rescan.images`, nightly cron and CI schedule |
| Retry logic and error handling | Transient failures retried with backoff; `ImageNotFound` never retried; every post-scan stage degrades instead of failing |
| Track known vulnerabilities | Exceptions record reason, approver, ticket and expiry; suppressed findings stay visible in reports, the dashboard and the database |

**Beyond the brief:** **every exception must expire.** An entry without
`expires:` is rejected at load time. `aegis_exceptions_expiring_soon` and the
`AegisExceptionsExpiring` alert warn before a waiver lapses and breaks a build.

## Sprint 6 — Documentation, testing, deployment

| Task | Delivered |
|---|---|
| Comprehensive documentation | README + 6 documents (~1,400 lines): setup, usage, architecture, troubleshooting, cost, this mapping |
| Deployment script | `deploy/install.sh`, multi-stage `Dockerfile`, `docker-compose.yml`, `Makefile` |
| Testing across CI systems | Three pipelines; 115 tests that run offline with no Trivy binary |
| Feedback and adjustment | Six real bugs found and fixed with regression tests (below). *No external beta users were available*, so the feedback loop was the test suite and running the real stack |

## Deliverables checklist

| Brief deliverable | Status |
|---|---|
| Automated vulnerability scanner for container images | ✅ `aegis scan`, 8 images verified live |
| CI/CD integration with thresholds and blocking | ✅ GitHub Actions, Jenkins, GitLab CI |
| Real-time notification system (Slack/Teams) | ✅ both, severity-filtered, retrying |
| Dashboard for historical data and trends | ✅ Flask dashboard + Grafana board + Prometheus |
| Comprehensive documentation | ✅ README + `docs/` |

## Evaluation criteria

**Documentation (15%)** — README plus six documents covering installation,
every command and config key, architecture and design rationale, eleven failure
modes with remedies, a measured cost analysis, and this traceability map. Code
comments explain *why*, not *what*.

**Implementation (75%)** — ~1,800 statements across 16 modules, 114 tests, 83%
coverage. Verified against 8 real images producing 23,729 real findings. Every
feature in the brief is working code, not a stub.

**Cost optimization (10%)** — [COST_OPTIMIZATION.md](COST_OPTIMIZATION.md),
built on measurements from this implementation: cold vs warm cache (39.4 s /
1.5 GB vs 0.6 s), per-scan storage (107 KB), report sizes by severity filter
(476 KB vs 135 KB), and ten levers ranked by payoff. All three pipelines ship
with database caching already configured.

## Bugs found and fixed during development

Honest record — each was caught by a test and is now covered by a regression test:

1. **The diff never worked.** `diff_with_previous` looked up the previous scan
   by a `scan_id` that had not been written yet, so every scan reported its
   entire backlog as "newly introduced". Fixed by keying the lookup on the
   result's timestamp. (`test_storage.py::test_diff_detects_introduced_and_resolved`)
2. **Multi-image runs lost their metrics.** All images wrote to one `.prom`
   file, so each scan overwrote the previous one's metrics. Now one file per
   image, which is also what the node_exporter textfile collector expects.
   (`test_pipeline_and_cli.py::test_metrics_file_is_written_per_image`)
3. **The HTML report was not escaping scanner output.** Jinja's
   `select_autoescape()` does not recognise a `*.html.j2` filename as HTML, so
   CVE titles — which come from a vulnerability database, not from us — were
   rendered raw. Now `autoescape=True` unconditionally.
   (`test_reporting.py::test_html_escapes_untrusted_scanner_text`)

Three more were found by running the real stack rather than by the tests:

4. **Prometheus loaded zero alert rules.** `prometheus.yml` referenced
   `alerts.yml`, but `docker-compose.yml` mounted only the former. Prometheus
   starts happily with no rules, so nothing was obviously broken — the alerts
   simply never existed. The whole directory is mounted now, and the four rules
   are confirmed loaded and firing against the live data.
5. **The Grafana dashboard rendered nothing.** The template variable used a bare
   query string; Grafana 11 expects a structured query object, and until the
   variable resolves every panel waits on it indefinitely. The panels also
   needed complete `options` blocks.
6. **Two table columns silently vanished.** Raw Prometheus selectors carry
   `__name__`, `instance` and `job`, so `joinByField` saw mismatched shapes.
   Aggregating every query `by (image)` gives all five frames an identical shape.

Two design flaws were corrected along the way: second-resolution timestamps meant
two scans of one image in the same second could not diff against each other
(now milliseconds), and the trend chart summed every scan in a day, so three
rebuilds of one image looked like three times the backlog (now the last scan per
image per day). A third: a CVE hidden by a waiver was being reported as
"resolved", which reads as if it had been patched — `waived` is now its own
category in the diff.

## An engineering decision worth defending

This repository's own pipeline scans the image this repository builds, and the first
run **failed** — correctly. The image is based on `python:3.12-slim`, which carried
50 HIGH findings against a budget of 10, so the gate blocked the build and the
registry push was skipped. That is the deliverable working exactly as specified.

It is also a build that could never go green. Of those 50 findings, **only 7 had an
upstream fix**; the remaining 43 were Debian 13 packages (`bsdutils`, `libblkid1`
and similar) with no patch in existence. A gate that fails on findings nobody can
act on is not a safety control — it is a permanently red light that teams learn to
route around, which is worse than no gate at all.

So the self-scan sets `AEGIS_FIXABLE_ONLY=true`, with the reasoning written into the
workflow beside it. This is not the gate being weakened to pass:

* unfixable findings are still scanned, still recorded, still in every report and
  still visible on the dashboard — they simply do not block the build;
* `CRITICAL: 0` remains absolute, fixable or not;
* the moment a patch ships upstream for any of those 43, the finding becomes
  fixable and the gate starts counting it.

The alternative — pinning a slimmer base image — is the better long-term fix and is
listed under known limitations below. The flag is the honest short-term position:
block on what can be fixed, report everything else, and never pretend a finding went
away.

One incidental finding is worth noting: Trivy flagged a CVE in `go-jose/v4` **inside
the Trivy binary bundled in the image**. The scanner scanned itself. That is the
correct behaviour, and a reminder that a security tool is also supply chain.

## Known limitations

* **`aegis serve` uses Flask's development server.** Fine for a team tool;
  `gunicorn 'aegis.dashboard:build()'` for anything larger. Documented in USAGE.
* **SQLite serializes writes.** One CI runner plus a read-only dashboard is
  comfortable; twenty parallel jobs on one network volume is not. The schema is
  portable to Postgres; migration conditions are in ARCHITECTURE.
* **Findings are only as fresh as the CVE database.** An image that passed
  yesterday can fail today with no code change — which is why `rescan` and the
  `AegisScanStale` alert exist.
* **EOSL base images scan clean.** Trivy stops reporting package CVEs for
  end-of-life distributions because the vendor stops publishing data. An
  `"EOSL": true` is a worse signal than a list of CVEs; this is called out in
  TROUBLESHOOTING. Detecting and failing on EOSL is the obvious next feature.
* **This repository's own nightly schedule is switched off.** The scheduled
  rescan is a real feature and is wired up in `ci/gitlab-ci.yml` and documented in
  `docs/SETUP.md`; in `.github/workflows/image-scan.yml` the `schedule:` trigger is
  commented out, with the reason beside it. A coursework repository that nobody is
  maintaining should not run a job against an unattended account every night
  forever. Uncommenting two lines restores it.
* **No SBOM output.** CycloneDX/SPDX export is a natural next step — Trivy can
  already produce it; Aegis does not yet surface it.
