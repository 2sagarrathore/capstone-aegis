"""Microsoft Teams notifier (MessageCard via incoming webhook)."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests

from ..models import PolicyDecision, ScanResult

log = logging.getLogger("aegis.notify.teams")

THEME_PASS = "0F7B4F"
THEME_FAIL = "9B1C1C"


class NotifierError(RuntimeError):
    pass


class TeamsNotifier:
    def __init__(self, settings: Any) -> None:
        self.settings = settings

    def webhook_url(self) -> str:
        url = os.environ.get(self.settings.webhook_url_env, "").strip()
        if not url:
            raise NotifierError(
                f"Teams is enabled but ${self.settings.webhook_url_env} is not set"
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
        title = "Vulnerability gate FAILED" if not decision.passed else "Image scan passed"
        facts = [
            {"name": "Image", "value": result.image},
            {"name": "Verdict", "value": decision.verdict},
            {"name": "Critical / High", "value": f"{counts['CRITICAL']} / {counts['HIGH']}"},
            {"name": "Medium / Low", "value": f"{counts['MEDIUM']} / {counts['LOW']}"},
            {"name": "Fixable", "value": str(result.fixable_count())},
            {"name": "Suppressed", "value": str(len(result.suppressed))},
            {"name": "Scanned at", "value": result.scanned_at},
        ]
        if diff is not None:
            facts.append(
                {
                    "name": "Change",
                    "value": f"+{len(diff.introduced)} introduced / -{len(diff.resolved)} resolved",
                }
            )

        card: dict[str, Any] = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": THEME_FAIL if not decision.passed else THEME_PASS,
            "summary": f"{title}: {result.image}",
            "title": title,
            "sections": [
                {
                    "activityTitle": f"`{result.image}`",
                    "facts": facts,
                    "markdown": True,
                    "text": "\n\n".join(f"- {r}" for r in decision.reasons[:5]),
                }
            ],
        }
        if self.settings.dashboard_url:
            card["potentialAction"] = [
                {
                    "@type": "OpenUri",
                    "name": "Open dashboard",
                    "targets": [{"os": "default", "uri": self.settings.dashboard_url}],
                }
            ]
        return card

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
                last = NotifierError(f"HTTP {response.status_code}: {response.text[:200]}")
                if response.status_code < 500 and response.status_code != 429:
                    raise last
            except requests.RequestException as exc:
                last = exc
            if attempt < 3:
                time.sleep(2 * attempt)
        raise NotifierError(f"Teams webhook failed after 3 attempts: {last}")
