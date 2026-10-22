"""Outbound notifications (Slack / Microsoft Teams).

Notifications are best-effort: a webhook outage must never fail a build that
the policy gate already passed, so every error here is logged and swallowed.
The return value tells the caller what actually went out.
"""

from __future__ import annotations

import logging
from typing import Any

from ..config import AegisConfig
from ..models import PolicyDecision, ScanResult, Severity
from .slack import SlackNotifier
from .teams import TeamsNotifier

log = logging.getLogger("aegis.notify")


def should_notify(
    result: ScanResult,
    decision: PolicyDecision,
    diff: Any | None,
    min_severity: str,
    notify_on_pass: bool,
) -> tuple[bool, str]:
    """Decide whether this scan is worth interrupting a channel for."""
    floor = Severity.parse(min_severity)
    if not decision.passed:
        return True, "policy gate failed"
    if diff is not None and diff.introduced_at_or_above(floor):
        count = len(diff.introduced_at_or_above(floor))
        return True, f"{count} new finding(s) at or above {floor.value}"
    if notify_on_pass:
        return True, "scan passed (notify_on_pass enabled)"
    return False, "nothing above the notification threshold"


def dispatch(
    result: ScanResult,
    decision: PolicyDecision,
    config: AegisConfig,
    diff: Any | None = None,
    force: bool = False,
) -> dict[str, str]:
    """Send to every enabled channel. Returns ``{channel: status}``."""
    outcomes: dict[str, str] = {}

    for name, settings, notifier_cls in (
        ("slack", config.notifications.slack, SlackNotifier),
        ("teams", config.notifications.teams, TeamsNotifier),
    ):
        if not settings.enabled:
            continue
        wanted, reason = should_notify(
            result, decision, diff, settings.min_severity, settings.notify_on_pass
        )
        if not (wanted or force):
            outcomes[name] = f"skipped: {reason}"
            log.debug("%s notification skipped: %s", name, reason)
            continue
        notifier = notifier_cls(settings)
        try:
            notifier.send(result, decision, diff, reason)
            outcomes[name] = "sent"
            log.info("%s notification sent (%s)", name, reason)
        except Exception as exc:  # notifications must never break the pipeline
            outcomes[name] = f"error: {exc}"
            log.error("%s notification failed: %s", name, exc)
    return outcomes


__all__ = ["dispatch", "should_notify", "SlackNotifier", "TeamsNotifier"]
