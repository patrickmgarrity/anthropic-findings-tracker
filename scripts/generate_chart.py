#!/usr/bin/env python3
"""
Generate a cumulative-records-over-time chart from data/advisories.csv.

The chart plots the cumulative number of advisories observed in the ledger,
ordered by the `committed_at` date column. Each calendar day that has at
least one commit produces a step in the line.

Default output is a self-contained SVG (no third-party dependencies). If
matplotlib is available, you can additionally emit a PNG by passing --png.

Usage:
    python scripts/generate_chart.py
    python scripts/generate_chart.py --output data/cumulative.svg --title "My title"
    python scripts/generate_chart.py --theme dark
    python scripts/generate_chart.py --png data/cumulative.png   # requires matplotlib

The SVG path is the supported, dependency-free default. The PNG path is a
convenience that imports matplotlib lazily so the rest of the project never
depends on it.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import math
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CSV = ROOT / "data" / "advisories.csv"
DEFAULT_SVG = ROOT / "data" / "cumulative.svg"
DEFAULT_DISCLOSURE_SVG = ROOT / "data" / "disclosure.svg"
DEFAULT_STATUS_SVG = ROOT / "data" / "status_pie.svg"

# Anthropic's coordinated-disclosure timeline. A finding's disclosure
# deadline is its committed_at date plus this many days.
DISCLOSURE_WINDOW_DAYS = 90


# --------------------------------------------------------------------------- #
# Data                                                                        #
# --------------------------------------------------------------------------- #


def load_cumulative_series(
    csv_path: Path, column: str = "committed_at", offset_days: int = 0
) -> list[tuple[dt.date, int]]:
    """
    Read the CSV and return a sorted list of (date, cumulative_count) pairs,
    one per distinct date value found in `column`. Rows with an empty or
    malformed value in that column are skipped.

    If `offset_days` is non-zero, that many days are added to each parsed date
    before bucketing. This is used to project the 90-day disclosure deadline
    from each finding's `committed_at` date.

    Returns an empty list if the column exists but has no usable values --
    the caller decides whether that is fatal (for the primary series) or
    acceptable (for an optional secondary series).
    """
    per_day: Counter[dt.date] = Counter()
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if column not in (reader.fieldnames or []):
            raise SystemExit(
                f"CSV {csv_path} does not contain a {column!r} column; "
                "regenerate it with scripts/fetch_ledger.py first."
            )
        for row in reader:
            raw = (row.get(column) or "").strip()
            if not raw:
                continue
            try:
                day = dt.date.fromisoformat(raw)
            except ValueError:
                continue
            if offset_days:
                day += dt.timedelta(days=offset_days)
            per_day[day] += 1

    cumulative: list[tuple[dt.date, int]] = []
    running = 0
    for day in sorted(per_day):
        running += per_day[day]
        cumulative.append((day, running))
    return cumulative


def load_status_counts(csv_path: Path) -> list[tuple[str, int]]:
    """
    Read the CSV and return a list of (status, count) pairs sorted by count
    descending (ties broken by label). Empty/missing values are bucketed as
    'unknown' so every finding ends up in exactly one slice.
    """
    counts: Counter[str] = Counter()
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if "status" not in (reader.fieldnames or []):
            raise SystemExit(
                f"CSV {csv_path} does not contain a 'status' column; "
                "regenerate it with scripts/fetch_ledger.py first."
            )
        for row in reader:
            raw = (row.get("status") or "").strip().lower()
            counts[raw or "unknown"] += 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


# --------------------------------------------------------------------------- #
# SVG rendering                                                               #
# --------------------------------------------------------------------------- #

THEMES = {
    "light": {
        "bg":     "#ffffff",
        "fg":     "#1a1a1a",
        "muted":  "#777777",
        "grid":   "#e6e6e6",
        "axis":   "#333333",
        # Series colors -- keep the warm accent for the headline series, then
        # pick two more colors with enough hue distance that they read
        # distinctly even when partially overlapping.
        "series": {
            "committed": {"line": "#c4452f", "fill": "#c4452f22", "dot": "#c4452f"},
            "patched":   {"line": "#3a7bd5", "fill": "#3a7bd522", "dot": "#3a7bd5"},
            "released":  {"line": "#2ea043", "fill": "#2ea04322", "dot": "#2ea043"},
        },
        # Status slice colors. Known statuses get a stable hue; any new
        # status the ledger introduces falls back to the rotating palette
        # below so the chart still renders without code changes.
        "status": {
            "disclosed": "#3a7bd5",
            "fixed":     "#2ea043",
            "unknown":   "#9a9a9a",
        },
        "status_fallback": ["#c4452f", "#a14fb5", "#d98e00", "#0f9b8e", "#6b6b6b"],
    },
    "dark": {
        "bg":     "#0f0f0f",
        "fg":     "#eaeaea",
        "muted":  "#9a9a9a",
        "grid":   "#2a2a2a",
        "axis":   "#cccccc",
        "series": {
            "committed": {"line": "#ff6f5e", "fill": "#ff6f5e26", "dot": "#ff6f5e"},
            "patched":   {"line": "#6aa9ff", "fill": "#6aa9ff26", "dot": "#6aa9ff"},
            "released":  {"line": "#4ade80", "fill": "#4ade8026", "dot": "#4ade80"},
        },
        "status": {
            "disclosed": "#6aa9ff",
            "fixed":     "#4ade80",
            "unknown":   "#6e6e6e",
        },
        "status_fallback": ["#ff6f5e", "#c084fc", "#fbbf24", "#22d3ee", "#94a3b8"],
    },
}


def _nice_y_max(value: int) -> int:
    """Round up to a 'nice' number above value so the y-axis ends cleanly."""
    if value <= 10:
        return max(value, 1)
    # Choose a step size that yields ~5 gridlines.
    target_steps = 5
    raw_step = value / target_steps
    # Round step up to 1, 2, 5 * 10^n
    magnitude = 10 ** (len(str(int(raw_step))) - 1)
    for m in (1, 2, 2.5, 5, 10):
        step = m * magnitude
        if step >= raw_step:
            break
    return int(((value + step - 1) // step) * step)


def _date_ticks(first: dt.date, last: dt.date, max_ticks: int = 8) -> list[dt.date]:
    """Pick a small set of evenly-spaced tick dates spanning [first, last].

    Always includes the last date; drops any auto-generated tick that lands
    within `min_gap_days` of the last so labels don't visually collide.
    """
    span_days = (last - first).days
    if span_days <= 0:
        return [first]
    step = max(1, span_days // max(1, max_ticks - 1))
    # Don't allow a regular tick within ~6% of the right edge -- the final
    # date is always drawn as its own tick.
    min_gap_days = max(2, span_days // 16)

    ticks = []
    d = first
    while d < last:
        if (last - d).days < min_gap_days:
            break
        ticks.append(d)
        d += dt.timedelta(days=step)
    ticks.append(last)
    return ticks


def render_svg(
    series_map: dict[str, dict],
    *,
    width: int = 960,
    height: int = 520,
    title: str = "Anthropic Mythos ledger — cumulative findings over time",
    theme: str = "dark",
    x_label: str = "Ledger Commit Date",
    point_noun: str = "commit dates",
) -> str:
    """
    Render a cumulative step-line chart with one or more series.

    `series_map` is a dict like:
        {
            "committed": {
                "label": "Committed",
                "data": [(date, cumulative), ...],
                "style_key": "committed",   # which color slot in THEMES["series"]
                "dasharray": "",            # "" for solid; e.g. "5 3" for dashed
                "annotate": True,           # draw end-of-line label
            },
            ...
        }
    The series in `series_map` are drawn back-to-front in dict order, so put
    the smallest / most-important series last to keep it on top.
    """
    if theme not in THEMES:
        raise SystemExit(f"Unknown theme {theme!r}; choose from {list(THEMES)}")
    c = THEMES[theme]

    # Plot area margins. Extra bottom space leaves room for the legend; extra
    # right space leaves room for small-series labels placed past the line end.
    m_left, m_right, m_top, m_bottom = 70, 130, 56, 104
    plot_w = width - m_left - m_right
    plot_h = height - m_top - m_bottom

    # Compute the overall date range across all non-empty series. A series
    # may also declare an explicit `extend_to` date (e.g. "today") that its
    # flat tail reaches even though it has no data point there -- include
    # those so the x-axis spans far enough to show the endpoint.
    all_dates = [d for s in series_map.values() for d, _ in s["data"]]
    all_dates += [s["extend_to"] for s in series_map.values() if s.get("extend_to")]
    if not all_dates:
        raise SystemExit("No data to plot.")
    first_date = min(all_dates)
    last_date = max(all_dates)
    span_days = max(1, (last_date - first_date).days)

    # Y-axis scale: the largest cumulative value across all series.
    max_y = max((v for s in series_map.values() for _, v in s["data"]), default=0)
    y_max_nice = _nice_y_max(max_y)
    y_step = max(1, y_max_nice // 5)

    def x_for(d: dt.date) -> float:
        return m_left + ((d - first_date).days / span_days) * plot_w

    def y_for(v: int) -> float:
        if y_max_nice == 0:
            return m_top + plot_h
        return m_top + plot_h - (v / y_max_nice) * plot_h

    def build_step_path(
        data: list[tuple[dt.date, int]], end_date: dt.date | None = None
    ) -> tuple[str, str]:
        """Return (line_path, area_path) for a cumulative step series.

        The step rises only on the date a new value lands, so days with no
        activity sit on the previous value (true cumulative shape).

        The flat tail runs to `end_date`; series that should stop before the
        chart's right edge (e.g. patch-released, which has no data past today)
        pass their own endpoint here instead of the global last date.
        """
        if not data:
            return "", ""
        if end_date is None:
            end_date = last_date
        parts: list[str] = []
        # Start at (first overall date, 0) so the line begins at the baseline
        # even when this series starts later than other series.
        parts.append(f"M {x_for(first_date):.2f} {y_for(0):.2f}")
        prev_y = 0
        for d, v in data:
            parts.append(f"L {x_for(d):.2f} {y_for(prev_y):.2f}")
            parts.append(f"L {x_for(d):.2f} {y_for(v):.2f}")
            prev_y = v
        # Extend a flat segment to `end_date` so the line doesn't end
        # mid-chart for series whose last observation is earlier.
        parts.append(f"L {x_for(end_date):.2f} {y_for(prev_y):.2f}")
        line_path = " ".join(parts)
        area_path = line_path + f" L {x_for(end_date):.2f} {y_for(0):.2f} Z"
        return line_path, area_path

    # Date axis ticks
    x_ticks = _date_ticks(first_date, last_date)
    x_tick_lines: list[str] = []
    x_tick_labels: list[str] = []
    for i, t in enumerate(x_ticks):
        x = x_for(t)
        x_tick_lines.append(
            f'<line x1="{x:.2f}" y1="{m_top + plot_h}" '
            f'x2="{x:.2f}" y2="{m_top + plot_h + 6}" '
            f'stroke="{c["axis"]}" stroke-width="1"/>'
        )
        anchor = (
            "start" if i == 0
            else "end" if i == len(x_ticks) - 1
            else "middle"
        )
        x_tick_labels.append(
            f'<text x="{x:.2f}" y="{m_top + plot_h + 22}" '
            f'text-anchor="{anchor}" fill="{c["muted"]}" '
            f'font-size="11">{t.isoformat()}</text>'
        )

    # Y-axis ticks + gridlines
    y_tick_lines: list[str] = []
    y_tick_labels: list[str] = []
    y_grid_lines: list[str] = []
    v = 0
    while v <= y_max_nice:
        y = y_for(v)
        y_grid_lines.append(
            f'<line x1="{m_left}" y1="{y:.2f}" '
            f'x2="{m_left + plot_w}" y2="{y:.2f}" '
            f'stroke="{c["grid"]}" stroke-width="1"/>'
        )
        y_tick_lines.append(
            f'<line x1="{m_left - 6}" y1="{y:.2f}" '
            f'x2="{m_left}" y2="{y:.2f}" '
            f'stroke="{c["axis"]}" stroke-width="1"/>'
        )
        y_tick_labels.append(
            f'<text x="{m_left - 10}" y="{y + 4:.2f}" '
            f'text-anchor="end" fill="{c["muted"]}" '
            f'font-size="11">{v:,}</text>'
        )
        v += y_step

    # Build each series' paths, annotations, and legend item.
    area_svg_parts: list[str] = []
    line_svg_parts: list[str] = []
    annotation_parts: list[str] = []
    legend_items: list[tuple[str, dict, str]] = []   # (label, colors, dasharray)
    small_label_index = 0   # used to offset stacked small-series labels

    for name, s in series_map.items():
        colors = c["series"][s["style_key"]]
        dash = s.get("dasharray", "")
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        legend_items.append((s["label"], colors, dash))

        if not s["data"]:
            continue
        # A series may stop short of the chart's right edge (e.g. patch
        # released, which has no data after today). `extend_to` is that
        # stopping point; absent it, the series runs to the global last date.
        series_end = s.get("extend_to") or last_date
        line_path, area_path = build_step_path(s["data"], series_end)
        # Only fill behind the headline (committed) series, otherwise stacked
        # translucent fills muddle the picture.
        if s.get("fill", False):
            area_svg_parts.append(
                f'<path d="{area_path}" fill="{colors["fill"]}" stroke="none"/>'
            )
        line_svg_parts.append(
            f'<path d="{line_path}" fill="none" stroke="{colors["line"]}" '
            f'stroke-width="2" stroke-linejoin="miter" stroke-linecap="butt"'
            f'{dash_attr}/>'
        )

        if s.get("annotate", False):
            final_v = s["data"][-1][1]
            fx = x_for(series_end)       # snap to the series' own line end
            fy = y_for(final_v)
            # For the headline series (filled area), keep the label inside
            # the plot, right-anchored, above the dot.
            # For small series sitting near the x-axis, place the label
            # to the RIGHT of the line endpoint (start-anchored) so it
            # doesn't crash into the headline label.
            if s.get("fill", False):
                label_below = fy < m_top + 24
                ly = fy + 18 if label_below else fy - 10
                lx = fx - 6
                anchor = "end"
                text = f"{final_v:,} {s['label'].lower()}"
            else:
                # Small series: label to the right of the endpoint. When
                # multiple small series share the same endpoint coordinates,
                # stack their labels vertically (alternate above / below the
                # dot) so they remain readable. If a date label is going
                # above this dot, keep the count below it to avoid overlap.
                if s.get("annotate_date", False):
                    stack_offset = 16
                else:
                    stack_offset = (-12 if small_label_index % 2 == 0 else 12)
                    small_label_index += 1
                ly = fy + 4 + stack_offset
                lx = fx + 8
                anchor = "start"
                text = f"{final_v:,} {s['label'].lower()}"
            annotation_parts.append(
                f'<circle cx="{fx:.2f}" cy="{fy:.2f}" r="3.5" fill="{colors["dot"]}"/>'
            )
            annotation_parts.append(
                f'<text x="{lx:.2f}" y="{ly:.2f}" text-anchor="{anchor}" '
                f'fill="{colors["line"]}" font-size="11" font-weight="600">'
                f'{_xml_escape(text)}</text>'
            )
            # Optional date label centered above the endpoint dot, marking the
            # date the line stops at (e.g. "current as of" for patch released).
            if s.get("annotate_date", False):
                annotation_parts.append(
                    f'<text x="{fx:.2f}" y="{fy - 10:.2f}" text-anchor="middle" '
                    f'fill="{colors["line"]}" font-size="11" font-weight="600">'
                    f'{_xml_escape(series_end.isoformat())}</text>'
                )

    # Legend layout: horizontal row in the bottom margin, below the x-axis
    # label. Sits inside the canvas (positioned relative to plot bottom).
    legend_y = m_top + plot_h + 76
    legend_x = m_left
    legend_svg_parts: list[str] = []
    for label, colors, dash in legend_items:
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        # Color swatch (short line, matching the actual line style)
        legend_svg_parts.append(
            f'<line x1="{legend_x}" y1="{legend_y - 4}" '
            f'x2="{legend_x + 22}" y2="{legend_y - 4}" '
            f'stroke="{colors["line"]}" stroke-width="2"{dash_attr}/>'
        )
        legend_svg_parts.append(
            f'<circle cx="{legend_x + 11}" cy="{legend_y - 4}" r="2.5" '
            f'fill="{colors["dot"]}"/>'
        )
        legend_svg_parts.append(
            f'<text x="{legend_x + 30}" y="{legend_y}" fill="{c["fg"]}" '
            f'font-size="11">{_xml_escape(label)}</text>'
        )
        # Advance horizontally; approximate label width based on character count.
        legend_x += 30 + len(label) * 6.5 + 24

    # Subtitle: data span + generated-at
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    primary_series = next(iter(series_map.values()))
    subtitle = (
        f"{first_date.isoformat()} → {last_date.isoformat()}  ·  "
        f"{len(primary_series['data'])} {point_noun}  ·  generated {generated_at}"
    )

    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}"
     width="{width}" height="{height}"
     font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif">
  <rect width="100%" height="100%" fill="{c["bg"]}"/>

  <!-- title -->
  <text x="{m_left}" y="26" fill="{c["fg"]}" font-size="16" font-weight="700">{_xml_escape(title)}</text>
  <text x="{m_left}" y="44" fill="{c["muted"]}" font-size="11">{_xml_escape(subtitle)}</text>

  <!-- gridlines -->
  {"".join(y_grid_lines)}

  <!-- area fills (behind lines) -->
  {"".join(area_svg_parts)}

  <!-- step lines -->
  {"".join(line_svg_parts)}

  <!-- axes -->
  <line x1="{m_left}" y1="{m_top}" x2="{m_left}" y2="{m_top + plot_h}"
        stroke="{c["axis"]}" stroke-width="1"/>
  <line x1="{m_left}" y1="{m_top + plot_h}" x2="{m_left + plot_w}" y2="{m_top + plot_h}"
        stroke="{c["axis"]}" stroke-width="1"/>

  <!-- y ticks + label -->
  {"".join(y_tick_lines)}
  {"".join(y_tick_labels)}
  <text x="14" y="{m_top + plot_h / 2:.2f}" fill="{c["muted"]}" font-size="11"
        transform="rotate(-90 14 {m_top + plot_h / 2:.2f})" text-anchor="middle">Cumulative Findings</text>

  <!-- x ticks + label -->
  {"".join(x_tick_lines)}
  {"".join(x_tick_labels)}
  <text x="{m_left + plot_w / 2:.2f}" y="{m_top + plot_h + 50}" fill="{c["muted"]}" font-size="11"
        text-anchor="middle">{_xml_escape(x_label)}</text>

  <!-- annotations -->
  {"".join(annotation_parts)}

  <!-- legend -->
  {"".join(legend_svg_parts)}
</svg>
'''
    return svg


def _status_color(theme_colors: dict, label: str, fallback_index: int) -> str:
    """Return the slice color for a status label, falling back to a rotating
    palette for any status not in the theme's known-status map."""
    known = theme_colors["status"]
    if label in known:
        return known[label]
    palette = theme_colors["status_fallback"]
    return palette[fallback_index % len(palette)]


def render_status_pie_svg(
    counts: list[tuple[str, int]],
    *,
    width: int = 720,
    height: int = 420,
    title: str = "Anthropic Mythos ledger — findings by status",
    theme: str = "dark",
) -> str:
    """Render a pie chart of findings grouped by status, with a legend."""
    if theme not in THEMES:
        raise SystemExit(f"Unknown theme {theme!r}; choose from {list(THEMES)}")
    c = THEMES[theme]
    if not counts:
        raise SystemExit("No status data to plot.")

    total = sum(n for _, n in counts)

    # Layout: pie on the left, legend on the right.
    pad_top = 56
    pad_bottom = 24
    pie_area_w = int(width * 0.55)
    cx = pie_area_w / 2 + 20
    cy = pad_top + (height - pad_top - pad_bottom) / 2
    r = min(pie_area_w / 2 - 20, (height - pad_top - pad_bottom) / 2 - 8)

    # Pie slices. SVG arcs are drawn in screen-space (y grows downward), so
    # angles increase clockwise — that matches the natural reading direction.
    slice_parts: list[str] = []
    label_parts: list[str] = []
    start_angle = -math.pi / 2  # start at 12 o'clock
    fallback_idx = 0
    legend_rows: list[tuple[str, str, int, float]] = []  # (label, color, count, pct)

    for i, (label, n) in enumerate(counts):
        frac = n / total if total else 0
        sweep = frac * 2 * math.pi
        end_angle = start_angle + sweep
        color = _status_color(c, label, fallback_idx)
        if label not in c["status"]:
            fallback_idx += 1

        # When a single slice is the whole pie, an arc with start==end draws
        # nothing — emit a full circle instead.
        if len(counts) == 1 or frac >= 0.999:
            slice_parts.append(
                f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r:.2f}" '
                f'fill="{color}" stroke="{c["bg"]}" stroke-width="2"/>'
            )
        else:
            sx = cx + r * math.cos(start_angle)
            sy = cy + r * math.sin(start_angle)
            ex = cx + r * math.cos(end_angle)
            ey = cy + r * math.sin(end_angle)
            large = 1 if sweep > math.pi else 0
            d = (
                f"M {cx:.2f} {cy:.2f} "
                f"L {sx:.2f} {sy:.2f} "
                f"A {r:.2f} {r:.2f} 0 {large} 1 {ex:.2f} {ey:.2f} Z"
            )
            slice_parts.append(
                f'<path d="{d}" fill="{color}" stroke="{c["bg"]}" stroke-width="2"/>'
            )

        # Inline percent labels for slices large enough to fit readable text.
        if frac >= 0.04:
            mid = start_angle + sweep / 2
            lx = cx + r * 0.62 * math.cos(mid)
            ly = cy + r * 0.62 * math.sin(mid)
            label_parts.append(
                f'<text x="{lx:.2f}" y="{ly + 4:.2f}" text-anchor="middle" '
                f'fill="#ffffff" font-size="12" font-weight="700">'
                f'{frac * 100:.1f}%</text>'
            )

        legend_rows.append((label, color, n, frac * 100))
        start_angle = end_angle

    # Legend: vertical list to the right of the pie.
    legend_x = pie_area_w + 40
    legend_y = pad_top + 6
    legend_parts: list[str] = []
    for label, color, n, pct in legend_rows:
        legend_parts.append(
            f'<rect x="{legend_x}" y="{legend_y - 10}" width="14" height="14" '
            f'rx="2" ry="2" fill="{color}"/>'
        )
        legend_parts.append(
            f'<text x="{legend_x + 22}" y="{legend_y + 1}" fill="{c["fg"]}" '
            f'font-size="12" font-weight="600">{_xml_escape(label)}</text>'
        )
        legend_parts.append(
            f'<text x="{legend_x + 22}" y="{legend_y + 18}" fill="{c["muted"]}" '
            f'font-size="11">{n:,} ({pct:.1f}%)</text>'
        )
        legend_y += 38

    generated_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    subtitle = f"{total:,} findings  ·  generated {generated_at}"

    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}"
     width="{width}" height="{height}"
     font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif">
  <rect width="100%" height="100%" fill="{c["bg"]}"/>

  <text x="24" y="26" fill="{c["fg"]}" font-size="16" font-weight="700">{_xml_escape(title)}</text>
  <text x="24" y="44" fill="{c["muted"]}" font-size="11">{_xml_escape(subtitle)}</text>

  {"".join(slice_parts)}
  {"".join(label_parts)}
  {"".join(legend_parts)}
</svg>
'''
    return svg


def render_status_pie_png(
    counts: list[tuple[str, int]],
    output: Path,
    *,
    title: str,
    theme: str,
) -> None:
    """Optional: write a PNG status pie chart using matplotlib if installed."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise SystemExit(
            "matplotlib is not installed; PNG output requires it. "
            "Run `pip install matplotlib`, or pass --no-png to skip the PNG."
        )

    c = THEMES[theme]
    total = sum(n for _, n in counts) or 1

    labels = [label for label, _ in counts]
    sizes = [n for _, n in counts]
    colors: list[str] = []
    fallback_idx = 0
    for label in labels:
        colors.append(_status_color(c, label, fallback_idx))
        if label not in c["status"]:
            fallback_idx += 1

    plt.rcParams.update({
        "figure.facecolor": c["bg"],
        "axes.facecolor": c["bg"],
        "text.color": c["fg"],
    })

    fig, ax = plt.subplots(figsize=(7.2, 4.2), dpi=150)
    wedges, _ = ax.pie(
        sizes,
        colors=colors,
        startangle=90,
        counterclock=False,
        wedgeprops={"edgecolor": c["bg"], "linewidth": 2},
    )
    # Inline percent labels (only for slices large enough to read).
    for wedge, n in zip(wedges, sizes):
        frac = n / total
        if frac < 0.04:
            continue
        ang = (wedge.theta1 + wedge.theta2) / 2
        x = 0.62 * math.cos(math.radians(ang))
        y = 0.62 * math.sin(math.radians(ang))
        ax.text(x, y, f"{frac * 100:.1f}%", ha="center", va="center",
                color="#ffffff", fontsize=10, fontweight="bold")

    ax.set_title(title, color=c["fg"], fontweight="bold", loc="left")
    legend_labels = [
        f"{label} — {n:,} ({n / total * 100:.1f}%)"
        for label, n in counts
    ]
    ax.legend(
        wedges,
        legend_labels,
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
        frameon=False,
        fontsize=10,
        labelcolor=c["fg"],
    )
    ax.set(aspect="equal")
    fig.tight_layout()
    fig.savefig(output, facecolor=c["bg"], bbox_inches="tight")
    plt.close(fig)


def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


# --------------------------------------------------------------------------- #
# Optional PNG via matplotlib                                                 #
# --------------------------------------------------------------------------- #


def render_png(
    series_map: dict[str, dict],
    output: Path,
    *,
    title: str,
    theme: str,
    x_label: str = "Ledger Commit Date",
) -> None:
    """Optional: write a PNG using matplotlib if it is installed."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.dates as mdates
        import matplotlib.pyplot as plt
    except ImportError:
        raise SystemExit(
            "matplotlib is not installed; PNG output requires it. "
            "Run `pip install matplotlib`, or pass --no-png to skip the PNG."
        )

    c = THEMES[theme]
    plt.rcParams.update({
        "figure.facecolor": c["bg"],
        "axes.facecolor": c["bg"],
        "axes.edgecolor": c["axis"],
        "axes.labelcolor": c["muted"],
        "xtick.color": c["muted"],
        "ytick.color": c["muted"],
        "text.color": c["fg"],
        "grid.color": c["grid"],
    })

    fig, ax = plt.subplots(figsize=(10, 5.4), dpi=150)
    small_label_index = 0

    # Compute the global last date so we can flat-extend each shorter series
    # to that date. Without this, matplotlib stops each line at its own last
    # data point, which makes endpoints visually offset when the two series
    # genuinely end on different dates -- and the offset reads as "the chart
    # is wrong" rather than as a real 1-day gap.
    candidate_dates = [s["data"][-1][0] for s in series_map.values() if s["data"]]
    candidate_dates += [
        s["extend_to"] for s in series_map.values() if s.get("extend_to")
    ]
    global_last_date = max(candidate_dates, default=None)

    for name, s in series_map.items():
        if not s["data"]:
            continue
        colors = c["series"][s["style_key"]]
        dates = [d for d, _ in s["data"]]
        counts = [v for _, v in s["data"]]

        # Where this series' flat tail stops. A series with `extend_to` (e.g.
        # patch released, with no data after today) ends there rather than at
        # the chart's right edge.
        series_end = s.get("extend_to") or global_last_date

        # Flat-extend this series to its endpoint if it ends earlier. The
        # cumulative value doesn't change -- we're just drawing a horizontal
        # segment. Annotations and the endpoint dot use this same endpoint.
        plot_dates = list(dates)
        plot_counts = list(counts)
        if series_end is not None and dates[-1] < series_end:
            plot_dates.append(series_end)
            plot_counts.append(counts[-1])

        linestyle = "--" if s.get("dasharray") else "-"
        if s.get("fill", False):
            ax.fill_between(plot_dates, plot_counts, step="post", color=colors["fill"])
        ax.step(
            plot_dates, plot_counts,
            where="post",
            color=colors["line"],
            linewidth=2,
            linestyle=linestyle,
            label=s["label"],
        )
        if s.get("annotate", False):
            # Anchor the endpoint dot and label to where this series' line
            # actually ends (its extend_to date, or the global last date),
            # not the underlying real data point -- otherwise the dot would
            # float in the middle of the chart for series that end early.
            endpoint_x = series_end if series_end is not None else dates[-1]
            ax.scatter([endpoint_x], [counts[-1]], color=colors["dot"], zorder=5, s=30)
            # Optional date label centered above the endpoint dot.
            if s.get("annotate_date", False):
                ax.annotate(
                    series_end.isoformat(),
                    xy=(endpoint_x, counts[-1]),
                    xytext=(0, 10),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=10,
                    fontweight="600",
                    color=colors["line"],
                )
            if s.get("fill", False):
                ax.annotate(
                    f"{counts[-1]:,} {s['label'].lower()}",
                    xy=(endpoint_x, counts[-1]),
                    xytext=(-8, -14),
                    textcoords="offset points",
                    ha="right",
                    va="top",
                    fontsize=10,
                    fontweight="bold",
                    color=c["fg"],
                )
            else:
                # Keep the count below the dot when a date label sits above
                # it; otherwise alternate above/below for stacked series.
                if s.get("annotate_date", False):
                    vertical_offset = -16
                else:
                    vertical_offset = 14 if small_label_index % 2 == 0 else -14
                    small_label_index += 1
                ax.annotate(
                    f"{counts[-1]:,} {s['label'].lower()}",
                    xy=(endpoint_x, counts[-1]),
                    xytext=(-8, vertical_offset),
                    textcoords="offset points",
                    ha="right",
                    va="center",
                    fontsize=10,
                    fontweight="600",
                    color=colors["line"],
                )

    ax.set_title(title, color=c["fg"], fontweight="bold", loc="left")
    ax.set_xlabel(x_label)
    ax.set_ylabel("Cumulative Findings")
    ax.grid(True, axis="y")
    ax.xaxis.set_major_locator(mdates.AutoDateLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
    ax.legend(loc="upper left", frameon=False, fontsize=10)
    # Pin the y-axis to start exactly at zero with no padding gap below it.
    ax.set_ylim(bottom=0)
    ax.margins(y=0)
    # Pin the x-axis tightly to the data so the chart fills its area, then
    # nudge a touch on the right so right-edge annotations have room.
    ax.margins(x=0.01)
    fig.autofmt_xdate(rotation=30, ha="right")

    fig.tight_layout()
    fig.savefig(output, facecolor=c["bg"])
    plt.close(fig)


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV,
                        help=f"Input CSV (default: {DEFAULT_CSV})")
    parser.add_argument("--output", "-o", type=Path, default=DEFAULT_SVG,
                        help=f"Output SVG path (default: {DEFAULT_SVG})")
    parser.add_argument("--title", default="Anthropic Mythos ledger — cumulative findings over time",
                        help="Chart title")
    parser.add_argument("--theme", choices=list(THEMES), default="dark",
                        help="Color theme")
    parser.add_argument("--width", type=int, default=960)
    parser.add_argument("--height", type=int, default=520)
    parser.add_argument("--png", type=Path, default=None,
                        help="PNG output path (default: same as --output with .png extension)")
    parser.add_argument("--no-png", action="store_true",
                        help="Skip the PNG output (SVG only)")
    parser.add_argument("--disclosure-output", type=Path, default=DEFAULT_DISCLOSURE_SVG,
                        help=f"Output SVG path for the 90-day disclosure-deadline "
                             f"chart (default: {DEFAULT_DISCLOSURE_SVG})")
    parser.add_argument("--disclosure-png", type=Path, default=None,
                        help="PNG output path for the disclosure-deadline chart "
                             "(default: same as --disclosure-output with .png extension)")
    parser.add_argument("--no-disclosure", action="store_true",
                        help="Skip the 90-day disclosure-deadline chart")
    parser.add_argument("--status-output", type=Path, default=DEFAULT_STATUS_SVG,
                        help=f"Output SVG path for the status pie chart "
                             f"(default: {DEFAULT_STATUS_SVG})")
    parser.add_argument("--status-png", type=Path, default=None,
                        help="PNG output path for the status pie chart "
                             "(default: same as --status-output with .png extension)")
    parser.add_argument("--no-status-pie", action="store_true",
                        help="Skip the status pie chart")
    args = parser.parse_args()

    if not args.csv.exists():
        print(f"error: input CSV {args.csv} does not exist. "
              f"Run scripts/fetch_ledger.py first.", file=sys.stderr)
        return 1

    committed = load_cumulative_series(args.csv, "committed_at")
    if not committed:
        raise SystemExit(
            f"No usable committed_at dates found in {args.csv}. "
            "Has the tracker been run yet?"
        )
    released = load_cumulative_series(args.csv, "patch_released_at")

    # Series are drawn back-to-front in dict order. Put the headline
    # (committed) line first so the smaller patch-released line renders
    # on top and stays readable.
    series_map: dict[str, dict] = {
        "committed": {
            "label": "Findings committed",
            "data": committed,
            "style_key": "committed",
            "dasharray": "",
            "fill": True,
            "annotate": True,
        },
        "released": {
            "label": "Patch released",
            "data": released,
            "style_key": "released",
            "dasharray": "",   # solid -- nothing to disambiguate from
            "fill": False,
            "annotate": True,
        },
    }

    svg = render_svg(
        series_map,
        width=args.width,
        height=args.height,
        title=args.title,
        theme=args.theme,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(svg, encoding="utf-8")
    print(
        f"wrote {args.output} "
        f"(committed={len(committed)} pts → {committed[-1][1]:,}, "
        f"released={len(released)} pts"
        f"{' → ' + format(released[-1][1], ',') if released else ''})"
    )

    # PNG output. Default: write `<output_stem>.png` alongside the SVG.
    # Opt out with --no-png. If matplotlib isn't installed we skip with a
    # clear message rather than failing the run -- the SVG is the contract;
    # the PNG is a convenience.
    if not args.no_png:
        png_path = args.png or args.output.with_suffix(".png")
        try:
            render_png(series_map, png_path, title=args.title, theme=args.theme)
            print(f"wrote {png_path}")
        except SystemExit as e:
            # render_png raises SystemExit when matplotlib is missing.
            print(f"note: {e}", file=sys.stderr)

    # Second chart: the 90-day disclosure deadline curve (each finding's
    # committed_at + 90 days) against the patch-released curve. This shows how
    # the schedule of disclosure deadlines compares with the pace of patches
    # actually shipping. The disclosure line projects past today because some
    # findings' deadlines fall in the future.
    if not args.no_disclosure:
        disclosure = load_cumulative_series(
            args.csv, "committed_at", offset_days=DISCLOSURE_WINDOW_DAYS
        )
        if not disclosure:
            print("note: no usable committed_at dates for the disclosure chart; "
                  "skipping.", file=sys.stderr)
        else:
            # The deadline line runs ~90 days into the future, but patch-
            # released data only exists up to today -- stop that line at the
            # current date and label it, rather than drawing a flat line out
            # to the future right edge.
            today = dt.datetime.now(dt.timezone.utc).date()
            disclosure_series: dict[str, dict] = {
                "deadline": {
                    "label": f"{DISCLOSURE_WINDOW_DAYS}-day disclosure deadline",
                    "data": disclosure,
                    "style_key": "committed",
                    "dasharray": "",
                    "fill": True,
                    "annotate": True,
                },
                "released": {
                    "label": "Patch released",
                    "data": released,
                    "style_key": "released",
                    "dasharray": "",
                    "fill": False,
                    "annotate": True,
                    "extend_to": today,
                    "annotate_date": True,
                },
            }
            disclosure_title = (
                f"Anthropic Mythos ledger — {DISCLOSURE_WINDOW_DAYS}-day "
                f"disclosure deadline vs. patch released"
            )
            disclosure_svg = render_svg(
                disclosure_series,
                width=args.width,
                height=args.height,
                title=disclosure_title,
                theme=args.theme,
                x_label="Date",
                point_noun="disclosure dates",
            )
            args.disclosure_output.parent.mkdir(parents=True, exist_ok=True)
            args.disclosure_output.write_text(disclosure_svg, encoding="utf-8")
            print(
                f"wrote {args.disclosure_output} "
                f"(deadline={len(disclosure)} pts → {disclosure[-1][1]:,}, "
                f"released={len(released)} pts"
                f"{' → ' + format(released[-1][1], ',') if released else ''})"
            )

            if not args.no_png:
                disclosure_png_path = (
                    args.disclosure_png or args.disclosure_output.with_suffix(".png")
                )
                try:
                    render_png(
                        disclosure_series, disclosure_png_path,
                        title=disclosure_title, theme=args.theme, x_label="Date",
                    )
                    print(f"wrote {disclosure_png_path}")
                except SystemExit as e:
                    print(f"note: {e}", file=sys.stderr)

    if not args.no_status_pie:
        status_counts = load_status_counts(args.csv)
        if status_counts:
            status_title = "Anthropic Mythos ledger — findings by status"
            status_svg = render_status_pie_svg(
                status_counts, title=status_title, theme=args.theme,
            )
            args.status_output.parent.mkdir(parents=True, exist_ok=True)
            args.status_output.write_text(status_svg, encoding="utf-8")
            summary = ", ".join(f"{label}={n}" for label, n in status_counts)
            print(f"wrote {args.status_output} ({summary})")

            if not args.no_png:
                status_png_path = (
                    args.status_png or args.status_output.with_suffix(".png")
                )
                try:
                    render_status_pie_png(
                        status_counts, status_png_path,
                        title=status_title, theme=args.theme,
                    )
                    print(f"wrote {status_png_path}")
                except SystemExit as e:
                    print(f"note: {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
