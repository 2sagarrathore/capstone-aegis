# Cost optimization

Container scanning is cheap to run badly and cheap to run well — the difference
is mostly whether you download the CVE database on every build. This document
lists what Aegis actually costs, the measurements behind those numbers, and the
levers that reduce them.

All figures below were measured on this implementation (Trivy 0.76.1, macOS
arm64, 8 images / 86 scans / 23,729 findings).

---

## 1. Why self-hosted at all

| Option | Indicative cost at ~50 images, ~500 scans/month |
|---|---|
| Commercial scanning SaaS (per-image or per-seat) | typically **$15–50 per image per month**, i.e. $750–2,500/mo |
| Registry-native scanning (ECR/ACR/GCR enhanced) | **$0.09–0.10 per image scan** + per-image/month charges |
| **Aegis + Trivy, self-hosted** | **$0 licence**; compute only — see §2 |

Trivy and its vulnerability database are free and Apache-2.0. The entire cost of
this system is CI minutes, bandwidth and a few megabytes of disk.

The trade is support and curated intelligence: a commercial feed may carry
vendor-specific advisories and exploit-maturity data that the public feeds do
not. That is a real reason to buy — "we need scanning at all" is not.

## 2. What a scan actually costs

Measured end-to-end (`aegis scan`, process start to exit), warm CVE-database
cache, images already present locally:

| Image | Size | Findings | Warm scan |
|---|---:|---:|---:|
| `alpine:3.14` | 6 MB | 0 | 1.1 s |
| `python:3.9-slim` | 152 MB | 462 | 1.9 s |
| `postgres:13-alpine` | 271 MB | 171 | 3.2 s |
| `nginx:1.21` | 146 MB | 977 | 3.9 s |
| `node:16-alpine` | 120 MB | 81 | 4.6 s |

Now the same image with an **empty cache directory** — the state of every fresh
CI runner:

| `python:3.11-slim` | Duration | Downloaded |
|---|---:|---:|
| Cold cache | **39.4 s** | 1.5 GB |
| Warm cache | **0.6 s** | 0 |

> A warm scan is **~1–5 seconds**. A cold one is **~39 seconds and 1.5 GB of
> download** — on a 38 MB/s link. On a slower or contended runner the download
> dominates even harder, and the 1.5 GB is the part that does not get faster.
>
> Caching the CVE database is the single highest-value change in this document.

At GitHub-hosted Linux rates ($0.008/min), 500 builds/month, taking 40 s cold
vs 4 s warm:

| Setup | Minutes/month | Cost/month | Egress |
|---|---:|---:|---:|
| No cache | 333 | **$2.67** | **750 GB** |
| Cached DB | 33 | **$0.27** | ~0 |

The dollar figure is small. The **750 GB/month of egress** is not: it is what
gets you rate-limited, and on a self-hosted runner behind a metered link or a
cloud NAT gateway it is the line item that actually hurts (NAT data processing
alone runs ~$0.045/GB — roughly **$34/month** to download the same database
1,500 times).

## 3. The levers, in order of payoff

### 3.1 Cache the vulnerability database (biggest win by far)

```yaml
# GitHub Actions
- uses: actions/cache@v4
  with:
    path: ~/.cache/trivy
    key: trivy-db-${{ github.run_id }}
    restore-keys: trivy-db-
env:
  AEGIS_CACHE_DIR: ~/.cache/trivy
```

```yaml
# GitLab CI
cache:
  key: "trivy-db-$CI_COMMIT_REF_SLUG"
  paths: [.cache/trivy]
```

```groovy
// Jenkins — one cache shared by every job on the agent
AEGIS_CACHE_DIR = "${env.JENKINS_HOME}/caches/trivy"
```

All three shipped pipelines do this already. The `restore-keys` prefix means a
new run starts from yesterday's cache and downloads only the delta.

### 3.2 Watch what the cache costs you in storage

| Cache component | Size | Needed? |
|---|---:|---|
| `db/trivy.db` | 1.5 GB | **yes** — this is the CVE database |
| `java-db/` | 1.5 GB | only if you scan JARs/WARs |
| `fanal/` | 4 MB | image layer metadata; trivially small |

If you do not scan Java artifacts, **do not cache `java-db/`** — it is half the
cache for nothing. Cache `~/.cache/trivy/db` and `~/.cache/trivy/fanal`
specifically rather than the parent directory. On a CI platform that bills
cache storage, that is a 50% cut in cache size for no loss.

### 3.3 Mirror the database internally

At more than a handful of pipelines, every runner pulling 1.5 GB from a public
endpoint is both slow and rate-limit-prone:

```yaml
scanner:
  db_repository: registry.internal/trivy-db
```

One internal pull per runner, no public egress, no rate limits. Combine with
`skip_db_update: true` on short-lived jobs and refresh the mirror once a day.

### 3.4 Do not scan the same digest twice

An image digest is immutable: scanning it again on the same CVE database tells
you nothing new. Aegis records the digest with every scan, so a pipeline can
skip the work:

```bash
DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE")
if aegis history --json --limit 200 | jq -e --arg d "$DIGEST" \
     '.[] | select(.image_digest == $d)' >/dev/null; then
  echo "digest already scanned today — skipping"; exit 0
fi
```

In a monorepo where ten pipelines build the same base image, this removes nine
scans per cycle.

### 3.5 Scan once, gate many times

The expensive step is the scan; the gate is microseconds. Scan in one job,
publish the JSON report as an artifact, and let downstream jobs apply their own
policy to it — a staging gate can tolerate what the production gate will not,
from one scan.

### 3.6 Narrow the severity set in fast feedback loops

```bash
aegis scan "$IMAGE" --severity HIGH,CRITICAL   # PR builds
aegis scan "$IMAGE"                            # nightly: everything
```

Measured on `nginx:1.21`: all four severities produce a **476 KB** JSON report
(977 findings); `HIGH,CRITICAL` only produces **135 KB** (274 findings) — a 72%
reduction. The scan itself is barely faster, so this is an artifact-storage and
review-attention saving rather than a CPU one: 274 findings is a list a person
might actually read, 977 is a list they will scroll past.

### 3.7 Run the nightly sweep against staleness, not against everything

`aegis rescan --stale-hours 20` only re-scans images whose last result is older
than the window. A nightly cron over 50 images where 30 were already scanned by
their own pipelines does 20 scans, not 50 — a 60% reduction for one flag.

### 3.8 Keep the history from growing without bound

Measured: **9.0 MB for 86 scans / 23,729 findings** ≈ 107 KB per scan.

At 500 scans/month that is ~52 MB/month, ~630 MB/year. Harmless on a disk,
annoying in a backup. The retention window handles it:

```yaml
storage:
  retention_days: 365
```
```bash
aegis purge            # delete scans older than the window
```

Reports are the larger artifact: 268 KB HTML + 476 KB JSON + 6 KB Markdown per
scan of a busy image (~750 KB). The shipped pipelines set
`retention-days: 30` on the artifact upload; the history database keeps the
*numbers* for a year regardless, at a fraction of the size.

### 3.9 Right-size the stack you actually run

The `docker-compose.yml` stack is dashboard + Prometheus + Grafana. For a small
team, the dashboard alone is enough — it already renders the trends, serves the
JSON API and exposes `/metrics`. Dropping Prometheus and Grafana removes two
containers (~400 MB of images and ~250 MB RSS) and a 90-day TSDB volume.

Add them back when you want alerting that survives the dashboard restarting, or
when Aegis metrics need to sit on the same board as the rest of your estate.

### 3.10 The scanner image itself

The multi-stage `Dockerfile` keeps the build toolchain out of the runtime layer
and removes `curl` in the same layer that used it. Smaller image, faster pull on
every CI job, smaller attack surface — the three usually travel together.

## 4. The cost this system removes

The direct costs above are small. The costs it is actually aimed at:

* **A vulnerable image reaching production.** The gate runs *before* the push
  step in all three pipelines, so a failing image is never published. Nothing
  else in this document saves money on the scale that one prevented incident does.
* **Manual review.** Prioritisation is in the tool — `fixable` counts separate
  "can be fixed today" from "nothing to do yet", and the diff surfaces what is
  *new* rather than re-presenting a backlog of hundreds.
* **Repeat investigation of known-accepted CVEs.** The exception list records
  the reason, the approver and the ticket once, rather than re-litigating it in
  every build. The mandatory expiry keeps that from becoming permanent amnesia.
* **Patching the wrong thing.** "Most affected packages" on the dashboard shows
  that one `curl` upgrade clears dozens of findings across images, which is a
  better use of an afternoon than chasing individual CVEs.

## 5. Summary

| Lever | Saving | Effort |
|---|---|---|
| Cache the CVE database | **~10× CI time** (39 s → 4 s) and 1.5 GB egress per runner | one cache block |
| Exclude `java-db` from the cache | 50% cache storage | one path change |
| Mirror the database internally | public egress + rate limits | one config key |
| Skip already-scanned digests | up to 90% of scans in a monorepo | ~5 lines of pipeline |
| Scan once, gate many | N−1 scans per pipeline fan-out | artifact wiring |
| `rescan --stale-hours` | ~60% of a nightly sweep | one flag |
| `purge` + artifact retention | bounded storage | one cron |
| Drop Prometheus/Grafana if unused | 2 containers, ~250 MB RSS | compose edit |
