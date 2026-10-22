"""Self-contained HTML report (no external assets, works from a file:// URL)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from ..config import AegisConfig
from ..models import PolicyDecision, ScanResult

TEMPLATE_DIR = Path(__file__).parent / "templates"

# autoescape=True unconditionally: the template is named *.html.j2, which
# select_autoescape() does NOT recognise as HTML, and CVE titles and package
# names come from the vulnerability database rather than from us.
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(
    result: ScanResult,
    decision: PolicyDecision,
    config: AegisConfig,
    diff: Any | None = None,
) -> str:
    from . import human_size
    from ..policy import describe

    limit = config.reporting.max_rows_in_html
    ordered = result.sorted_vulnerabilities()
    rows = ordered[:limit]

    template = _env.get_template("report.html.j2")
    return template.render(
        result=result,
        decision=decision,
        diff=diff,
        counts=result.counts(),
        rows=rows,
        truncated=len(ordered) > len(rows),
        policy_description=describe(config),
        include_suppressed=config.reporting.include_suppressed,
        image_size=human_size(result.image_size_bytes),
    )
