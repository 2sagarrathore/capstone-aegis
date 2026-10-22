"""The scan pipeline: one function the CLI, the dashboard and CI all share.

    scan -> apply exceptions -> diff vs history -> evaluate policy
         -> persist -> render reports -> export metrics -> notify
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import metrics as metrics_module
from . import notify as notify_module
from . import reporting
from .config import AegisConfig
from .exceptions_store import ExceptionStore
from .models import PolicyDecision, ScanResult
from .policy import evaluate
from .scanner import Scanner, ScannerError, get_scanner
from .storage import ScanDiff, ScanStore

log = logging.getLogger("aegis.pipeline")


@dataclass
class ScanOutcome:
    """Everything one pipeline run produced."""

    result: ScanResult
    decision: PolicyDecision
    diff: ScanDiff | None = None
    reports: dict[str, Path] = field(default_factory=dict)
    notifications: dict[str, str] = field(default_factory=dict)
    metrics_path: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.decision.passed

    def to_dict(self) -> dict[str, Any]:
        payload = self.result.to_dict()
        payload["policy"] = self.decision.to_dict()
        if self.diff is not None:
            payload["diff"] = self.diff.to_dict()
        payload["reports"] = {k: str(v) for k, v in self.reports.items()}
        payload["notifications"] = self.notifications
        if self.error:
            payload["error"] = self.error
        return payload


def run_scan(
    image: str,
    config: AegisConfig,
    *,
    scanner: Scanner | None = None,
    store: ScanStore | None = None,
    exceptions: ExceptionStore | None = None,
    write_reports: bool = True,
    persist: bool = True,
    send_notifications: bool = True,
    export_metrics: bool = True,
    source: str = "cli",
) -> ScanOutcome:
    """Run the full pipeline for one image.

    Raises :class:`ScannerError` if the scan itself could not be performed --
    everything after the scan degrades gracefully instead of raising, so a
    broken webhook or a read-only reports directory cannot mask a clean result.
    """
    scanner = scanner or get_scanner(config)
    if exceptions is None:
        exceptions = ExceptionStore.load(config.resolve(config.exceptions.file))

    log.info("scanning %s with %s", image, scanner.name)
    result = scanner.scan(image)

    exceptions.apply(result)

    store = store if store is not None else (ScanStore(config.resolve(config.storage.database)) if persist else None)
    diff: ScanDiff | None = None
    if store is not None:
        try:
            diff = store.diff_with_previous(result)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("could not diff against history: %s", exc)

    decision = evaluate(result, config)

    if store is not None and persist:
        try:
            store.record(result, decision, source=source)
        except Exception as exc:
            log.error("could not record scan in history: %s", exc)

    outcome = ScanOutcome(result=result, decision=decision, diff=diff)

    if write_reports:
        try:
            outcome.reports = reporting.generate(result, decision, config, diff)
        except Exception as exc:
            log.error("report generation failed: %s", exc)

    if export_metrics:
        try:
            outcome.metrics_path = metrics_module.export(result, decision, config, diff)
        except Exception as exc:
            log.error("metrics export failed: %s", exc)

    if send_notifications:
        outcome.notifications = notify_module.dispatch(result, decision, config, diff)

    return outcome


def run_many(
    images: list[str],
    config: AegisConfig,
    **kwargs: Any,
) -> list[ScanOutcome]:
    """Scan several images, continuing past individual failures.

    A single unreachable image must not abandon the rest of a nightly sweep, so
    scanner errors are captured into the outcome instead of propagating.
    """
    scanner = kwargs.pop("scanner", None) or get_scanner(config)
    store = kwargs.pop("store", None)
    if store is None and kwargs.get("persist", True):
        store = ScanStore(config.resolve(config.storage.database))
    exceptions = kwargs.pop("exceptions", None) or ExceptionStore.load(
        config.resolve(config.exceptions.file)
    )

    outcomes: list[ScanOutcome] = []
    for image in images:
        try:
            outcomes.append(
                run_scan(
                    image,
                    config,
                    scanner=scanner,
                    store=store,
                    exceptions=exceptions,
                    **kwargs,
                )
            )
        except ScannerError as exc:
            log.error("scan of %s failed: %s", image, exc)
            failed = ScanResult(image=image, scanned_at=ScanResult.now(), errors=[str(exc)])
            outcomes.append(
                ScanOutcome(
                    result=failed,
                    decision=PolicyDecision(passed=False, reasons=[f"scan failed: {exc}"]),
                    error=str(exc),
                )
            )
    return outcomes
