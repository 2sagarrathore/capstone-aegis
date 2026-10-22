"""Slack incoming-webhook notifier (Block Kit)."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests

from ..models import PolicyDecision, ScanResult, Severity

log = logging.getLogger("aegis.notify.slack")

ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "UNKNOWN": "⚪"}


class NotifierError(RuntimeError):
    pass


class SlackNotifier:
    def __init__(self, settings: Any) -> None:
        self.settings = settings

    def webhook_url(self) -> str:
        url = os.environ.get(self.settings.webhook_url_env, "").strip()
        if not url:
            raise NotifierError(
                f"Slack is enabled but ${self.settings.webhook_url_env} is not set"
            )
        return url

    def build_payload(
        self,
        result: ScanResult,
        decision: PolicyDecision,
        diff: Any | None = None,
        reason: str = "",
    ) -> dict[str, Any]:
        counts = result.counts()
        headline = ("❌ Vulnerability gate FAILED" if not decision.passed
                    else "✅ Image scan passed")
        severity_line = " · ".join(
            f"{ICONS[name]} {name.title()} *{counts[name]}*"
            for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        )

        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": {"type": "plain_text", "text": headline, "emoji": True}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Image*\n`{result.image}`"},
                    {"type": "mrkdwn", "text": f"*Scanned*\n{result.scanned_at}"},
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": severity_line}},
        ]

        if decision.reasons:
            bullets = "\n".join(f"• {reason_text}" for reason_text in decision.reasons[:5])
            blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Why*\n{bullets}"}}
            )

        if diff is not None and diff.introduced:
            floor = Severity.parse(self.settings.min_severity)
            notable = sorted(
                diff.introduced_at_or_above(floor), key=lambda v: -v.severity.rank
            )[:5]
            if notable:
                lines = "\n".join(
                    f"• {ICONS[v.severity.value]} `{v.vuln_id}` in `{v.package}`"
                    + (f" → fix `{v.fixed_version}`" if v.fixed_version else " → _no fix yet_")
                    for v in notable
                )
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*New since last scan ({len(diff.introduced)})*\n{lines}",
                        },
                    }
                )

        context = [
            f"{result.fixable_count()} fixable",
            f"{len(result.suppressed)} suppressed by exception",
            f"{result.scanner} {result.scanner_version}",
        ]
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": " · ".join(context)}],
            }
        )

        if self.settings.dashboard_url:
            blocks.append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Open dashboard"},
                            "url": self.settings.dashboard_url,
                        }
                    ],
                }
            )

        return {
            "text": f"{headline} — {result.image} "
            f"({counts['CRITICAL']} critical, {counts['HIGH']} high)",
            "blocks": blocks,
        }

    def send(
        self,
        result: ScanResult,
        decision: PolicyDecision,
        diff: Any | None = None,
        reason: str = "",
    ) -> None:
        url = self.webhook_url()
        payload = self.build_payload(result, decision, diff, reason)
        last: Exception | None = None
        for attempt in range(1, 4):
            try:
                response = requests.post(
                    url, json=payload, timeout=self.settings.timeout_seconds
                )
                if response.status_code < 300:
                    return
                if response.status_code == 429 or response.status_code >= 500:
                    last = NotifierError(f"HTTP {response.status_code}: {response.text[:200]}")
                else:
                    raise NotifierError(f"HTTP {response.status_code}: {response.text[:200]}")
            except requests.RequestException as exc:
                last = exc
            if attempt < 3:
                time.sleep(2 * attempt)
        raise NotifierError(f"Slack webhook failed after 3 attempts: {last}")
