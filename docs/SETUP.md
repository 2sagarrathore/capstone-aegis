# Setup

## 1. Requirements

| Component | Minimum | Notes |
|---|---|---|
| Python | 3.10 | 3.12 recommended |
| Trivy | 0.50 | the scanner engine; 0.76.1 is what this was built against |
| Docker | any recent | only needed to scan images from the local daemon |
| Disk | ~1 GB | the Trivy CVE database is several hundred MB |

Aegis never needs root, and never needs a cloud account.

## 2. Install Trivy

```bash
# macOS
brew install trivy

# Debian / Ubuntu
sudo apt-get install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy

# Anywhere (pinned version — what CI should use)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin v0.76.1
```

Pin the version in CI. An unpinned `latest` means a scanner upgrade can change
your findings — and therefore your build outcome — on a day you changed nothing.

## 3. Install Aegis

```bash
make install            # creates .venv and installs in editable mode
# or
python3 -m venv .venv && .venv/bin/pip install -e .
```

This puts an `aegis` executable in `.venv/bin/`.

## 4. Verify

```bash
.venv/bin/aegis doctor
```

```
aegis doctor
 ✓ config file — /path/to/aegis.yml
 ✓ trivy binary — version 0.76.1
 ✓ history database — /path/to/aegis.db (0 scans)
 ✓ exceptions file — 0 entries
 ✓ reports directory writable — /path/to/reports
 ✓ policy — fail_on>=HIGH budgets[CRITICAL<=0, HIGH<=10]
```

`doctor` exits non-zero if anything is wrong, so it is safe to run as a CI
pre-flight step.

## 5. First scan

```bash
.venv/bin/aegis scan python:3.12-slim
```

The first run downloads the CVE database (a few hundred MB, one to two minutes).
Later runs reuse the cache — see [COST_OPTIMIZATION.md](COST_OPTIMIZATION.md)
for how to keep that cache warm in CI.

## 6. Configuration

Aegis looks for `aegis.yml` in the current directory and then walks up the tree.
Override the location with `-c/--config` or `$AEGIS_CONFIG`. Start from the
annotated `aegis.yml` in the repository root; every key is documented in
[USAGE.md](USAGE.md#configuration-reference).

Relative paths inside the config resolve against the **config file's own
directory**, not the working directory — so a pipeline can `cd` anywhere and
still write to the same database.

## 7. Docker

```bash
docker build -t aegis-scanner:1.0.0 .

# scan an image from a registry
docker run --rm -v aegis-data:/data -v aegis-cache:/cache \
  aegis-scanner:1.0.0 scan nginx:1.27

# scan an image from the host's Docker daemon
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v aegis-data:/data -v aegis-cache:/cache \
  aegis-scanner:1.0.0 scan my-local-image:dev
```

Always mount `/cache` to a persistent volume. Without it, every container start
re-downloads the CVE database.

The image runs as uid 10001 and contains no build toolchain and no `curl`.

## 8. The full stack

```bash
docker compose up -d --build
```

| Service | URL | Purpose |
|---|---|---|
| dashboard | http://localhost:8080 | trends, per-image detail, `/metrics`, JSON API |
| prometheus | http://localhost:9090 | scrapes the dashboard, evaluates the alert rules |
| grafana | http://localhost:3000 | pre-provisioned "Aegis" dashboard (admin/admin) |

Scan into the shared database with:

```bash
docker compose run --rm scanner scan nginx:1.27 redis:7
```

Change the Grafana password before exposing it anywhere:
`GRAFANA_PASSWORD=... docker compose up -d`.

## 9. Notifications

Aegis never stores a webhook URL in its config — only the **name of the
environment variable** that holds it.

```yaml
notifications:
  slack:
    enabled: true
    webhook_url_env: SLACK_WEBHOOK_URL
    min_severity: HIGH
    notify_on_pass: false
    dashboard_url: https://aegis.internal
```

```bash
export SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'
aegis scan myimage:1.0
```

A message goes out when the gate fails, or when a *new* finding at or above
`min_severity` appears since the previous scan of that image. A webhook outage
is logged and never fails a build that the gate already passed.

Teams works the same way with `TEAMS_WEBHOOK_URL`.

## 10. CI integration

| Platform | File | Notes |
|---|---|---|
| GitHub Actions | `.github/workflows/image-scan.yml` | gate runs before the push step; report posted to the PR and the job summary |
| Jenkins | `ci/Jenkinsfile` | distinguishes gate failure (exit 1) from scan failure (exit 2); publishes the HTML report |
| GitLab CI | `ci/gitlab-ci.yml` | feeds the merge-request container-scanning widget |

All three cache the CVE database and set the policy through `AEGIS_*`
environment variables rather than editing the config file.

## 11. Scheduled rescans

An image that passed last week is not necessarily clean today — the image has
not changed, but the CVE database has. Run a nightly rescan:

```bash
# cron: 03:00 daily
0 3 * * * cd /opt/aegis && .venv/bin/aegis rescan --stale-hours 20
```

`rescan` only re-scans images whose last result is older than the window, so it
is cheap to run often.
