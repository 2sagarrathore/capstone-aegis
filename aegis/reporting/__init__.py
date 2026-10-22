"""Report rendering: one scan result -> JSON / HTML / Markdown artifacts."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..config import AegisConfig
from ..models import PolicyDecision, ScanResult
from .html_report import render_html
from .markdown_report import render_markdown
from .json_report import render_json

log = logging.getLogger("aegis.reporting")

RENDERERS = {
    "json": (render_json, ".json"),
    "html": (render_html, ".html"),
    "markdown": (render_markdown, ".md"),
    "md": (render_markdown, ".md"),
}


def safe_slug(image: str) -> str:
    """Turn ``registry/org/app:1.2.3`` into a filename-safe stem."""
    out = []
    for char in image:
        out.append(char if char.isalnum() or char in "-._" else "_")
    return "".join(out).strip("._") or "image"


def generate(
    result: ScanResult,
    decision: PolicyDecision,
    config: AegisConfig,
    diff: Any | None = None,
    output_dir: str | Path | None = None,
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """Write every configured report format; returns ``{format: path}``."""
    directory = Path(output_dir or config.resolve(config.reporting.output_dir))
    directory.mkdir(parents=True, exist_ok=True)
    stem = f"{safe_slug(result.image)}_{result.scanned_at.replace(':', '').replace('-', '')}"

    written: dict[str, Path] = {}
    for fmt in formats or config.reporting.formats:
        key = fmt.strip().lower()
        if key not in RENDERERS:
            log.warning("unknown report format '%s' -- skipping", fmt)
            continue
        renderer, suffix = RENDERERS[key]
        path = directory / f"{stem}{suffix}"
        path.write_text(renderer(result, decision, config, diff), encoding="utf-8")
        written[key] = path
        log.info("wrote %s report to %s", key, path)

    # Stable "latest" pointers so a dashboard or CI artifact link never goes stale.
    for key, path in list(written.items()):
        latest = directory / f"latest_{safe_slug(result.image)}{path.suffix}"
        latest.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return written


def human_size(num_bytes: int) -> str:
    if not num_bytes:
        return "unknown"
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


__all__ = ["generate", "render_html", "render_markdown", "render_json", "human_size", "safe_slug"]
