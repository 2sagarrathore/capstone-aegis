"""Prometheus metrics.

Two delivery paths, because CI jobs and long-lived services need different things:

* **Textfile / Pushgateway** -- a CI job is gone seconds after it finishes, so it
  writes a ``.prom`` file for the node_exporter textfile collector (or pushes to
  a Pushgateway when one is configured).
* **Scrape endpoint** -- the dashboard exposes ``/metrics`` built from the
  SQLite history, so Prometheus always sees the current state of every tracked
  image even when no build is running.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from prometheus_client import CollectorRegistry, Gauge, generate_latest, write_to_textfile

from .config import AegisConfig
from .models import ALL_SEVERITIES, PolicyDecision, ScanResult

log = logging.getLogger("aegis.metrics")


def _registry() -> tuple[CollectorRegistry, dict[str, Gauge]]:
    registry = CollectorRegistry()
    gauges = {
        "vulns": Gauge(
            "aegis_vulnerabilities",
            "Active (non-suppressed) vulnerabilities in the most recent scan",
            ["image", "severity"],
            registry=registry,
        ),
        "fixable": Gauge(
            "aegis_fixable_vulnerabilities",
            "Vulnerabilities with a fixed version available upstream",
            ["image"],
            registry=registry,
        ),
        "suppressed": Gauge(
            "aegis_suppressed_vulnerabilities",
            "Vulnerabilities hidden by an approved exception",
            ["image"],
            registry=registry,
        ),
        "pass": Gauge(
            "aegis_policy_pass",
            "1 if the image passed the gate policy, 0 if it failed",
            ["image"],
            registry=registry,
        ),
        "duration": Gauge(
            "aegis_scan_duration_seconds",
            "Wall-clock duration of the scan",
            ["image"],
            registry=registry,
        ),
        "timestamp": Gauge(
            "aegis_scan_timestamp_seconds",
            "Unix timestamp of the most recent scan",
            ["image"],
            registry=registry,
        ),
        "size": Gauge(
            "aegis_image_size_bytes",
            "Size of the scanned image",
            ["image"],
            registry=registry,
        ),
        "introduced": Gauge(
            "aegis_new_vulnerabilities",
            "Vulnerabilities introduced since the previous scan of this image",
            ["image", "severity"],
            registry=registry,
        ),
        "resolved": Gauge(
            "aegis_resolved_vulnerabilities",
            "Vulnerabilities resolved since the previous scan of this image",
            ["image"],
            registry=registry,
        ),
        "images": Gauge(
            "aegis_images_tracked",
            "Number of distinct images in the history store",
            registry=registry,
        ),
        "scans": Gauge(
            "aegis_scans_total",
            "Number of scans recorded in the history store",
            registry=registry,
        ),
        "exceptions": Gauge(
            "aegis_exceptions_active",
            "Active (unexpired) vulnerability exceptions",
            registry=registry,
        ),
        "exceptions_expiring": Gauge(
            "aegis_exceptions_expiring_soon",
            "Exceptions expiring within the configured warning window",
            registry=registry,
        ),
    }
    return registry, gauges


def _ts(value: str) -> float:
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, TypeError):
        return 0.0


def collect_scan(
    result: ScanResult,
    decision: PolicyDecision,
    diff: Any | None = None,
) -> CollectorRegistry:
    """Build a registry describing a single just-completed scan."""
    registry, gauges = _registry()
    counts = result.counts()
    for severity in ALL_SEVERITIES:
        gauges["vulns"].labels(image=result.image, severity=severity.value).set(
            counts[severity.value]
        )
    gauges["fixable"].labels(image=result.image).set(result.fixable_count())
    gauges["suppressed"].labels(image=result.image).set(len(result.suppressed))
    gauges["pass"].labels(image=result.image).set(1 if decision.passed else 0)
    gauges["duration"].labels(image=result.image).set(result.duration_seconds)
    gauges["timestamp"].labels(image=result.image).set(_ts(result.scanned_at))
    gauges["size"].labels(image=result.image).set(result.image_size_bytes)

    if diff is not None:
        introduced = {s.value: 0 for s in ALL_SEVERITIES}
        for vuln in diff.introduced:
            introduced[vuln.severity.value] += 1
        for severity, count in introduced.items():
            gauges["introduced"].labels(image=result.image, severity=severity).set(count)
        gauges["resolved"].labels(image=result.image).set(len(diff.resolved))
    return registry


def collect_store(store: Any, exception_store: Any | None = None, warn_days: int = 14) -> bytes:
    """Build the full scrape payload from stored history (used by ``/metrics``)."""
    registry, gauges = _registry()
    rows = store.images()
    for row in rows:
        image = row["image"]
        for severity in ALL_SEVERITIES:
            gauges["vulns"].labels(image=image, severity=severity.value).set(
                row.get(severity.value.lower(), 0) or 0
            )
        gauges["fixable"].labels(image=image).set(row.get("fixable", 0) or 0)
        gauges["suppressed"].labels(image=image).set(row.get("suppressed", 0) or 0)
        gauges["pass"].labels(image=image).set(0 if row.get("verdict") == "FAIL" else 1)
        gauges["duration"].labels(image=image).set(row.get("duration_seconds", 0) or 0)
        gauges["timestamp"].labels(image=image).set(_ts(row.get("scanned_at", "")))
        gauges["size"].labels(image=image).set(row.get("image_size_bytes", 0) or 0)

    summary = store.summary()
    gauges["images"].set(summary["images_tracked"])
    gauges["scans"].set(summary["total_scans"])

    if exception_store is not None:
        active = [e for e in exception_store.entries if not e.is_expired()]
        gauges["exceptions"].set(len(active))
        gauges["exceptions_expiring"].set(len(exception_store.expiring_within(warn_days)))

    return generate_latest(registry)


def export(
    result: ScanResult,
    decision: PolicyDecision,
    config: AegisConfig,
    diff: Any | None = None,
) -> str | None:
    """Write (or push) metrics for one scan.  Returns the path/URL used."""
    if not config.metrics.enabled:
        return None
    registry = collect_scan(result, decision, diff)

    if config.metrics.pushgateway_url:
        try:
            from prometheus_client import push_to_gateway

            push_to_gateway(
                config.metrics.pushgateway_url,
                job=config.metrics.job_name,
                registry=registry,
                grouping_key={"image": result.image},
            )
            log.info("pushed metrics to %s", config.metrics.pushgateway_url)
            return config.metrics.pushgateway_url
        except Exception as exc:  # metrics must never fail a build
            log.error("pushgateway export failed: %s", exc)

    if config.metrics.textfile_path:
        # One file per image: the node_exporter textfile collector globs *.prom in
        # a directory, and a shared file would mean each image in a multi-image run
        # clobbered the previous one's metrics.
        from .reporting import safe_slug

        configured = Path(config.resolve(config.metrics.textfile_path))
        path = configured.with_name(f"{configured.stem}_{safe_slug(result.image)}{configured.suffix}")
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            write_to_textfile(str(path), registry)
            log.info("wrote metrics to %s", path)
            return str(path)
        except OSError as exc:
            log.error("could not write metrics file %s: %s", path, exc)
    return None
