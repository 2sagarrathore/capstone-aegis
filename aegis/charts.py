"""Server-rendered SVG charts for the dashboard.

Rendered on the server so the dashboard has no JavaScript charting dependency
and works offline inside an air-gapped network.

Colour: severity is an *ordinal* scale (swapping the order changes the meaning),
so it uses a single-hue red ramp with monotone lightness rather than four
unrelated categorical hues -- the reader sees the order in the colour.  Both
mode ramps were checked against the surface they render on (light end 2.14:1
light / 2.91:1 dark, adjacent lightness gaps >= 0.06).  Severity is additionally
carried by the legend, the axis labels and the table view, never by colour alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# CSS custom property names; the actual hexes live in the stylesheet so that
# light and dark steps swap in one place.
SEVERITY_VAR = {name: f"var(--sev-{name.lower()})" for name in SEVERITY_ORDER}

GRID = "var(--grid)"
AXIS = "var(--axis)"
MUTED = "var(--muted)"

SEGMENT_GAP = 2.0   # surface gap between stacked segments
CORNER = 4.0        # rounded data-end


def _esc(text: object) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _nice_ticks(maximum: float, count: int = 4) -> list[int]:
    """Round axis ticks to 1/2/5 x 10^n so labels stay readable."""
    if maximum <= 0:
        return [0, 1]
    raw = maximum / count
    magnitude = 10 ** (len(str(int(raw))) - 1) if raw >= 1 else 1
    for multiple in (1, 2, 2.5, 5, 10):
        step = multiple * magnitude
        if step * count >= maximum:
            break
    return [int(step * i) for i in range(count + 1)]


@dataclass
class StackedBar:
    """One column: a label plus a severity histogram."""

    label: str
    values: dict[str, int]
    sublabel: str = ""

    @property
    def total(self) -> int:
        return sum(self.values.values())


def empty_state(message: str, height: int = 180) -> str:
    return (
        f'<div class="chart-empty" style="height:{height}px" role="status">{_esc(message)}</div>'
    )


def legend(severities: Sequence[str] = SEVERITY_ORDER) -> str:
    items = "".join(
        f'<span class="legend-item"><span class="swatch" style="background:{SEVERITY_VAR[s]}"></span>'
        f"{s.title()}</span>"
        for s in severities
    )
    return f'<div class="legend">{items}</div>'


def stacked_bars(
    bars: Sequence[StackedBar],
    *,
    width: int = 760,
    height: int = 230,
    title: str = "",
    max_labels: int = 12,
) -> str:
    """Vertical stacked bar chart of severity counts over a sequence of columns."""
    if not bars:
        return empty_state("No scans in this window yet.")

    pad_left, pad_right, pad_top, pad_bottom = 42, 8, 12, 34
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom
    maximum = max((bar.total for bar in bars), default=0)
    ticks = _nice_ticks(maximum)
    top = ticks[-1] or 1

    slot = plot_w / len(bars)
    bar_w = min(46.0, max(6.0, slot * 0.62))
    label_every = max(1, len(bars) // max_labels + (1 if len(bars) % max_labels else 0))

    parts: list[str] = [
        f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" '
        f'aria-label="{_esc(title or "Vulnerabilities by severity")}" preserveAspectRatio="xMidYMid meet">'
    ]

    for tick in ticks:
        y = pad_top + plot_h - (tick / top) * plot_h
        parts.append(
            f'<line x1="{pad_left}" y1="{y:.1f}" x2="{width - pad_right}" y2="{y:.1f}" '
            f'stroke="{GRID}" stroke-width="1" />'
        )
        parts.append(
            f'<text x="{pad_left - 8}" y="{y + 4:.1f}" text-anchor="end" class="tick">{tick}</text>'
        )

    for index, bar in enumerate(bars):
        x = pad_left + slot * index + (slot - bar_w) / 2
        cursor = pad_top + plot_h
        drawn = 0
        for severity in SEVERITY_ORDER:
            count = bar.values.get(severity, 0)
            if not count:
                continue
            seg_h = (count / top) * plot_h
            if seg_h <= 0:
                continue
            visible = max(1.5, seg_h - (SEGMENT_GAP if drawn else 0))
            y = cursor - visible
            radius = CORNER if drawn == 0 else 0
            # Only the top-most segment of the stack gets rounded ends.
            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{visible:.1f}" '
                f'rx="{radius}" fill="{SEVERITY_VAR[severity]}" class="seg" '
                f'data-tip="{_esc(bar.label)} · {severity.title()}: {count}" tabindex="0">'
                f"<title>{_esc(bar.label)} — {severity.title()}: {count}</title></rect>"
            )
            cursor -= visible + (SEGMENT_GAP if drawn == 0 else SEGMENT_GAP)
            drawn += 1

        if index % label_every == 0:
            parts.append(
                f'<text x="{x + bar_w / 2:.1f}" y="{height - 12}" text-anchor="middle" '
                f'class="tick">{_esc(bar.label)}</text>'
            )

    parts.append(
        f'<line x1="{pad_left}" y1="{pad_top + plot_h}" x2="{width - pad_right}" '
        f'y2="{pad_top + plot_h}" stroke="{AXIS}" stroke-width="1" />'
    )
    parts.append("</svg>")
    return "".join(parts)


def horizontal_bars(
    bars: Sequence[StackedBar],
    *,
    width: int = 760,
    row_height: int = 28,
    label_width: int = 170,
) -> str:
    """Horizontal stacked bars -- used for 'most affected packages'."""
    if not bars:
        return empty_state("Nothing to rank yet.", height=120)

    # A ranked bar chart must read top-to-bottom by length, or the eye has to
    # re-sort it manually.
    bars = sorted(bars, key=lambda bar: -bar.total)
    height = row_height * len(bars) + 26
    plot_w = width - label_width - 70
    maximum = max((bar.total for bar in bars), default=1) or 1
    bar_h = min(16, row_height - 10)

    parts = [
        f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" '
        f'aria-label="Most affected packages" preserveAspectRatio="xMidYMid meet">'
    ]
    for index, bar in enumerate(bars):
        y = index * row_height + 10
        parts.append(
            f'<text x="{label_width - 10}" y="{y + bar_h - 3}" text-anchor="end" '
            f'class="rowlabel">{_esc(bar.label[:26])}</text>'
        )
        cursor = float(label_width)
        drawn = 0
        for severity in SEVERITY_ORDER:
            count = bar.values.get(severity, 0)
            if not count:
                continue
            seg_w = max(2.0, (count / maximum) * plot_w - (SEGMENT_GAP if drawn else 0))
            is_last = severity == next(
                (s for s in reversed(SEVERITY_ORDER) if bar.values.get(s, 0)), ""
            )
            parts.append(
                f'<rect x="{cursor:.1f}" y="{y}" width="{seg_w:.1f}" height="{bar_h}" '
                f'rx="{CORNER if is_last else 0}" fill="{SEVERITY_VAR[severity]}" class="seg" '
                f'data-tip="{_esc(bar.label)} · {severity.title()}: {count}" tabindex="0">'
                f"<title>{_esc(bar.label)} — {severity.title()}: {count}</title></rect>"
            )
            cursor += seg_w + SEGMENT_GAP
            drawn += 1
        parts.append(
            f'<text x="{cursor + 8:.1f}" y="{y + bar_h - 3}" class="rowvalue">{bar.total}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def sparkline(values: Sequence[int], *, width: int = 120, height: int = 28) -> str:
    """Tiny trend line for a table row.  One series, so no legend is needed."""
    if len(values) < 2:
        return '<span class="spark-empty">—</span>'
    maximum = max(values) or 1
    step = width / (len(values) - 1)
    points = " ".join(
        f"{index * step:.1f},{height - 2 - (value / maximum) * (height - 4):.1f}"
        for index, value in enumerate(values)
    )
    return (
        f'<svg viewBox="0 0 {width} {height}" class="spark" aria-hidden="true">'
        f'<polyline points="{points}" fill="none" stroke="var(--sev-high)" '
        f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" /></svg>'
    )
