#!/usr/bin/env python3
"""
Rewrite the metrics block in README.md from the data/ snapshot.

Reads:
  data/advisories.sqlite   -- advisories + changes tables written by fetch_ledger.py
  data/state.json          -- last_change_utc (set when a run produces new/updated rows)

Updates README.md in place between the markers:
  <!-- METRICS:START -->
  <!-- METRICS:END -->

If README.md does not exist, a minimal one is created. If the markers are
missing, the block is appended.

Standard library only.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
README_PATH = ROOT / "README.md"
SQLITE_PATH = DATA_DIR / "advisories.sqlite"
STATE_PATH = DATA_DIR / "state.json"

START_MARKER = "<!-- METRICS:START -->"
END_MARKER = "<!-- METRICS:END -->"


def days_since_last_change(state: dict, now: dt.datetime) -> str:
    last = state.get("last_change_utc")
    if not last:
        return "—"
    try:
        last_dt = dt.datetime.fromisoformat(last)
    except ValueError:
        return "—"
    if last_dt.tzinfo is None:
        last_dt = last_dt.replace(tzinfo=dt.timezone.utc)
    return str(max(0, (now - last_dt).days))


def load_state() -> dict:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text())
    except json.JSONDecodeError:
        return {}


def query_metrics(now: dt.datetime) -> tuple[int, int, int, int]:
    """Return (total_findings, added_7d, changed_7d, fixed_7d).

    All three windowed counts use changes.observed_utc — the timestamp of
    the run that first recorded the change in our mirror. This means a
    cold-start backfill will report every historical entry as "added" in
    the current window; the metric becomes meaningful as a measure of
    upstream activity after the mirror has been running for a full week.
    """
    seven_days_ago_iso = (now - dt.timedelta(days=7)).isoformat(timespec="seconds")
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        total = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
        added = conn.execute(
            "SELECT COUNT(*) FROM changes "
            "WHERE change_kind = 'new' AND observed_utc >= ?",
            (seven_days_ago_iso,),
        ).fetchone()[0]
        # "Changed" = distinct findings that had at least one field updated
        # in the window. Excludes brand-new arrivals (already in "added") so
        # the two metrics don't overlap.
        changed = conn.execute(
            "SELECT COUNT(DISTINCT hash) FROM changes "
            "WHERE change_kind = 'updated' AND observed_utc >= ?",
            (seven_days_ago_iso,),
        ).fetchone()[0]
        # A finding counts as "fixed in the window" if we observed it
        # entering the fixed state during the window — either an existing
        # record's status flipped to 'fixed', OR a brand-new record arrived
        # already at status='fixed' (the more common case for backfilled or
        # late-revealed entries that were already patched upstream).
        # COUNT(DISTINCT hash) dedupes both shapes.
        fixed = conn.execute(
            "SELECT COUNT(DISTINCT c.hash) FROM changes c "
            "JOIN advisories a ON a.hash = c.hash "
            "WHERE c.observed_utc >= ? AND ("
            "  (c.change_kind = 'updated' AND c.field = 'status' AND c.new_value = 'fixed')"
            "  OR (c.change_kind = 'new' AND a.status = 'fixed')"
            ")",
            (seven_days_ago_iso,),
        ).fetchone()[0]
    finally:
        conn.close()
    return total, added, changed, fixed


def render_block(days: str, added_7d: int, changed_7d: int, fixed_7d: int, total: int) -> str:
    return (
        f"{START_MARKER}\n"
        f"| Total findings (all-time) | Findings added (last 7 days) | Findings fixed (last 7 days) |\n"
        f"| :---: | :---: | :---: |\n"
        f"| {total:,} | {added_7d:,} | {fixed_7d:,} |\n"
        f"\n"
        f"| Findings changed (last 7 days) | Days since last change |\n"
        f"| :---: | :---: |\n"
        f"| {changed_7d:,} | {days} |\n"
        f"{END_MARKER}"
    )


def splice_block(existing: str, block: str) -> str:
    pattern = re.compile(
        re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER),
        re.DOTALL,
    )
    if pattern.search(existing):
        return pattern.sub(block, existing)
    return existing.rstrip() + "\n\n" + block + "\n"


def default_readme(block: str) -> str:
    return (
        "# Anthropic Mythos Findings Tracker\n"
        "\n"
        "Mirrors the public Anthropic Mythos disclosure ledger at\n"
        "<https://red.anthropic.com/2026/cvd/> into versioned CSV/JSONL/SQLite\n"
        "snapshots under `data/`. The metrics below are regenerated each run.\n"
        "\n"
        f"{block}\n"
    )


def main() -> int:
    if not SQLITE_PATH.exists():
        print(
            f"error: {SQLITE_PATH} does not exist; run scripts/fetch_ledger.py first.",
            file=sys.stderr,
        )
        return 1

    now = dt.datetime.now(dt.timezone.utc)
    state = load_state()
    total, added_7d, changed_7d, fixed_7d = query_metrics(now)
    block = render_block(
        days_since_last_change(state, now),
        added_7d,
        changed_7d,
        fixed_7d,
        total,
    )

    if README_PATH.exists():
        README_PATH.write_text(splice_block(README_PATH.read_text(), block))
    else:
        README_PATH.write_text(default_readme(block))

    print(
        f"updated {README_PATH} "
        f"(total={total:,} added_7d={added_7d:,} changed_7d={changed_7d:,} fixed_7d={fixed_7d:,})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
