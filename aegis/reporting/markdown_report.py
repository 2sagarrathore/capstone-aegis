"""Markdown report -- pastes cleanly into a PR comment or Slack snippet."""

from __future__ import annotations

from typing import Any

from ..config import AegisConfig
from ..models import PolicyDecision, ScanResult

ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "UNKNOWN": "⚪"}
MAX_ROWS = 40


def render_markdown(
    result: ScanResult,
    decision: PolicyDecision,
    config: AegisConfig,
    diff: Any | None = None,
) -> str:
    from . import human_size
    from ..policy import describe

    counts = result.counts()
    verdict_icon = "✅" if decision.passed else "❌"
    lines = [
        f"# {verdict_icon} Aegis scan — `{result.image}`",
        "",
        f"**Verdict:** {decision.verdict} &nbsp;·&nbsp; **Policy:** `{describe(config)}`",
        "",
        "| Critical | High | Medium | Low | Fixable | Suppressed |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| {counts['CRITICAL']} | {counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} "
        f"| {result.fixable_count()} | {len(result.suppressed)} |",
        "",
    ]

    if decision.reasons:
        lines += ["**Why this verdict**", ""]
        lines += [f"- {reason}" for reason in decision.reasons]
        lines.append("")

    if diff is not None and diff.has_changes:
        lines += [
            "## Change since previous scan",
            "",
            f"`+{len(diff.introduced)}` introduced · `-{len(diff.resolved)}` resolved "
            + (f"· {len(diff.waived)} newly waived " if diff.waived else "")
            + f"· {diff.unchanged_count} unchanged",
            "",
        ]
        for vuln in sorted(diff.introduced, key=lambda v: -v.severity.rank)[:10]:
            lines.append(
                f"- {ICONS[vuln.severity.value]} **new** `{vuln.vuln_id}` in `{vuln.package}`"
            )
        lines.append("")

    ordered = result.sorted_vulnerabilities()
    lines += [
        f"## Findings ({result.total})",
        "",
        "| Sev | CVE | Package | Installed | Fixed in |",
        "|---|---|---|---|---|",
    ]
    for vuln in ordered[:MAX_ROWS]:
        link = f"[{vuln.vuln_id}]({vuln.primary_url})" if vuln.primary_url else vuln.vuln_id
        fixed = f"`{vuln.fixed_version}`" if vuln.fixed_version else "_none_"
        lines.append(
            f"| {ICONS[vuln.severity.value]} {vuln.severity.value} | {link} "
            f"| `{vuln.package}` | `{vuln.installed_version}` | {fixed} |"
        )
    if len(ordered) > MAX_ROWS:
        lines.append(f"| … | _{len(ordered) - MAX_ROWS} more findings in the full report_ | | | |")

    lines += [
        "",
        "<details><summary>Scan metadata</summary>",
        "",
        f"- Scan ID: `{result.scan_id}`",
        f"- Scanned at: {result.scanned_at}",
        f"- Engine: {result.scanner} {result.scanner_version}",
        f"- Base OS: {result.os_family} {result.os_version}",
        f"- Image size: {human_size(result.image_size_bytes)}",
        f"- Duration: {result.duration_seconds:.1f}s",
        "",
        "</details>",
        "",
    ]
    return "\n".join(lines)
