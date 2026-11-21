# Capstone Submission — Project 2: Container Image Vulnerability Scanner with Reporting

**Student:** Akash
**Repository:** https://github.com/2sagarrathore/capstone-aegis
**Project name:** Aegis

---

## Problem statement

Containerised applications ship whatever CVEs their base images carry. Most DevOps
teams either check manually or do not check at all, because the tooling does not
integrate cleanly into CI/CD. Aegis is an automated scanner that checks container
images against the CVE database **before they reach a registry**, blocks the build
when findings breach a defined policy, reports in machine- and human-readable form,
notifies the team, and keeps the history so the backlog can be tracked over time.

## What was built

A production-shaped tool, not a prototype: a thin, opinionated layer over Trivy.
Trivy finds the CVEs; Aegis decides what to do about them.

```
image ─► scan ─► apply exceptions ─► diff vs history ─► policy gate
                                                            │
         ┌──────────────┬──────────────┬───────────────┬────┘
         ▼              ▼              ▼               ▼
   JSON/HTML/MD    SQLite history  Prometheus    Slack / Teams
     reports        + dashboard      metrics      notification
                                                         │
                                                   exit 0 / 1 → CI
```

## Deliverables (as specified in the brief)

| Deliverable | Status | Where |
|---|---|---|
| Automated vulnerability scanner for container images | Complete | `aegis/scanner.py`, `aegis/policy.py` |
| CI/CD integration with thresholds and blocking | Complete | `.github/workflows/`, `ci/Jenkinsfile`, `ci/gitlab-ci.yml` |
| Real-time notification system (Slack / Teams) | Complete | `aegis/notify/` |
| Dashboard for historical data and trends | Complete | `aegis/dashboard.py`, `deploy/grafana/` |
| Comprehensive documentation | Complete | `README.md` + `docs/` |

## Sprint coverage

All six sprints delivered as working code. Full task-by-task traceability in
[`docs/CAPSTONE.md`](docs/CAPSTONE.md).

1. **Setup & basic scanning** — Trivy integration, normalised data model, CLI, config
2. **CI/CD integration** — GitHub Actions, Jenkins and GitLab CI; severity thresholds; documented exit codes
3. **Reporting & notifications** — JSON, self-contained HTML and Markdown; Slack Block Kit and Teams MessageCard
4. **Dashboard & history** — SQLite store, introduced/resolved diffing, Flask dashboard, 13 Prometheus metrics, Grafana board
5. **Customisation & exceptions** — time-boxed CVE allowlist, rescan, retry and error handling
6. **Documentation, testing, deployment** — 6 documents, 114 tests, Dockerfile, compose stack, installer

## Evidence it works

* Verified against **8 real images** producing **23,729 real findings**
* **114 tests passing**, 83% coverage, runs offline with no Trivy binary required
* **~4,960 lines** of Python across 16 modules; **1,282 lines** of documentation
* Full stack verified live: dashboard, Prometheus (4 alert rules firing), Grafana
* **Proven in public CI:** the GitHub Actions run installs Aegis and Trivy on a clean
  runner, builds the image, scans it, **fails the build on policy breach, and skips
  the registry push** — a vulnerable image is never published

## Evaluation criteria

**Documentation (15%)** — README plus six documents: installation, every command and
config key, architecture and design rationale, eleven failure modes with remedies, a
measured cost analysis, and sprint traceability.

**Implementation (75%)** — every feature in the brief is working code. Six real bugs
were found during development and fixed with regression tests; they are documented
honestly in `docs/CAPSTONE.md` rather than hidden.

**Cost optimisation (10%)** — [`docs/COST_OPTIMIZATION.md`](docs/COST_OPTIMIZATION.md),
built on measurements from this implementation: cold cache 39.4 s and 1.5 GB downloaded
vs warm cache 0.6 s; 107 KB of history per scan; report sizes by severity filter
(476 KB vs 135 KB). Ten levers ranked by payoff. All three CI pipelines ship with CVE
database caching already configured.

## How to run it

```bash
git clone https://github.com/2sagarrathore/capstone-aegis
cd capstone-aegis
make install
brew install trivy          # or see docs/SETUP.md
.venv/bin/aegis doctor      # verify the setup
.venv/bin/aegis scan python:3.12-slim
.venv/bin/aegis serve       # dashboard at http://127.0.0.1:8080
```

Full stack (dashboard + Prometheus + Grafana):

```bash
docker compose up -d --build
```

## Documentation index

| Document | Covers |
|---|---|
| `README.md` | Overview, quick start, the gate, exceptions |
| `docs/SETUP.md` | Installation, Docker, CI setup, webhooks |
| `docs/USAGE.md` | Every command, config key and environment override |
| `docs/ARCHITECTURE.md` | How the pieces fit, data model, design decisions |
| `docs/TROUBLESHOOTING.md` | Failure modes and remedies |
| `docs/COST_OPTIMIZATION.md` | Measured cost analysis |
| `docs/CAPSTONE.md` | Sprint-by-sprint traceability, bugs found, known limitations |
