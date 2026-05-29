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


def days_since_last_addition(now: dt.datetime) -> str:
    """Days since the most recent finding was committed to the ledger.

    Uses MAX(committed_at) -- the newest commit date present in the mirror --
    rather than our observation timestamps, so it reflects upstream activity
    on the ledger itself. committed_at is a YYYY-MM-DD string; an empty table
    or all-empty values yield an em dash.
    """
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        latest = conn.execute(
            "SELECT MAX(committed_at) FROM advisories WHERE committed_at != ''"
        ).fetchone()[0]
    finally:
        conn.close()
    if not latest:
        return "—"
    try:
        latest_date = dt.date.fromisoformat(latest)
    except ValueError:
        return "—"
    return str(max(0, (now.date() - latest_date).days))


def deadline_reached(now: dt.datetime, days: int = 90) -> tuple[int, int]:
    """Findings whose 90-day disclosure deadline has been reached, split by
    whether they have been publicly revealed yet.

    Anthropic's coordinated-disclosure timeline is `days` days, so a finding's
    deadline is reached once its commit date is that many days before today.
    Returns (revealed, not_revealed) counts for those findings -- the gap
    between them is the set of findings whose window has elapsed but which the
    ledger has not yet revealed.

    committed_at is a YYYY-MM-DD string and sorts lexically, so the cutoff
    comparison is exact. Empty committed_at values are excluded.
    """
    cutoff = (now.date() - dt.timedelta(days=days)).isoformat()
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        revealed = conn.execute(
            "SELECT COUNT(*) FROM advisories "
            "WHERE committed_at != '' AND committed_at < ? AND revealed = 1",
            (cutoff,),
        ).fetchone()[0]
        not_revealed = conn.execute(
            "SELECT COUNT(*) FROM advisories "
            "WHERE committed_at != '' AND committed_at < ? AND revealed != 1",
            (cutoff,),
        ).fetchone()[0]
    finally:
        conn.close()
    return revealed, not_revealed


def upcoming_deadlines(
    now: dt.datetime,
    windows: tuple[int, ...] = (1, 3, 7, 30),
    days: int = 90,
) -> dict[int, int]:
    """Count findings whose 90-day disclosure deadline falls within the next
    N days, for each N in `windows`.

    A finding's deadline is committed_at + `days`. "Within the next N days"
    means the deadline lands from today (inclusive -- not yet past) through
    today + N. Rearranged against the stored committed_at date that is:
        today - days <= committed_at <= today + N - days
    The lower bound (deadline == today) dovetails with past_disclosure_window,
    which counts deadlines strictly before today, so the two never overlap.
    committed_at is a YYYY-MM-DD string and sorts lexically, so the date
    bounds compare exactly. Empty committed_at values are excluded.
    """
    today = now.date()
    low = (today - dt.timedelta(days=days)).isoformat()
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        result: dict[int, int] = {}
        for n in windows:
            high = (today + dt.timedelta(days=n - days)).isoformat()
            result[n] = conn.execute(
                "SELECT COUNT(*) FROM advisories "
                "WHERE committed_at != '' AND committed_at >= ? AND committed_at <= ?",
                (low, high),
            ).fetchone()[0]
        return result
    finally:
        conn.close()


def load_state() -> dict:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text())
    except json.JSONDecodeError:
        return {}


def query_metrics(now: dt.datetime) -> tuple[int, int, int, int, int, int]:
    """Return (total, added_7d, changed_7d, fixed_7d, fixed_all, changed_all).

    `total` doubles as "findings added (all-time)" — every finding entered
    the mirror via a `new` change at some point, so the two are identical
    by construction; we report it once.

    The 7-day windowed counts use changes.observed_utc — the timestamp of
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
        # All-time fixed: snapshot of how many findings currently sit at
        # status='fixed'. Reads from advisories rather than changes so it
        # reflects the current state, not the cumulative count of fix events.
        fixed_all = conn.execute(
            "SELECT COUNT(*) FROM advisories WHERE status = 'fixed'"
        ).fetchone()[0]
        # All-time changed: distinct findings that have ever had any field
        # updated (excludes 'new' rows by definition of change_kind).
        changed_all = conn.execute(
            "SELECT COUNT(DISTINCT hash) FROM changes WHERE change_kind = 'updated'"
        ).fetchone()[0]
    finally:
        conn.close()
    return total, added, changed, fixed, fixed_all, changed_all


def render_block(
    days: str,
    days_since_addition: str,
    added_7d: int,
    changed_7d: int,
    fixed_7d: int,
    total: int,
    fixed_all: int,
    changed_all: int,
    deadline_revealed: int,
    deadline_not_revealed: int,
    deadlines: dict[int, int],
) -> str:
    # `total` == findings added all-time (every finding entered via a `new`
    # change), so we use it directly in the all-time row's "added" cell.
    deadline_total = deadline_revealed + deadline_not_revealed
    return (
        f"{START_MARKER}\n"
        f"|  | Findings added | Findings fixed | Findings changed |\n"
        f"| :--- | :---: | :---: | :---: |\n"
        f"| **All-time** | {total:,} | {fixed_all:,} | {changed_all:,} |\n"
        f"| **Last 7 days** | {added_7d:,} | {fixed_7d:,} | {changed_7d:,} |\n"
        f"\n"
        f"| Days since last change | Days since last addition |\n"
        f"| :---: | :---: |\n"
        f"| {days} | {days_since_addition} |\n"
        f"\n"
        f"| Disclosure deadline reached | Total | Revealed | Not yet revealed |\n"
        f"| :--- | :---: | :---: | :---: |\n"
        f"| **Findings** | {deadline_total:,} | {deadline_revealed:,} | {deadline_not_revealed:,} |\n"
        f"\n"
        f"| Disclosure deadlines expected | Next 1 day | Next 3 days | Next 7 days | Next 30 days |\n"
        f"| :--- | :---: | :---: | :---: | :---: |\n"
        f"| **Findings** | {deadlines[1]:,} | {deadlines[3]:,} | {deadlines[7]:,} | {deadlines[30]:,} |\n"
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
    total, added_7d, changed_7d, fixed_7d, fixed_all, changed_all = query_metrics(now)
    deadline_revealed, deadline_not_revealed = deadline_reached(now)
    deadlines = upcoming_deadlines(now)
    block = render_block(
        days_since_last_change(state, now),
        days_since_last_addition(now),
        added_7d,
        changed_7d,
        fixed_7d,
        total,
        fixed_all,
        changed_all,
        deadline_revealed,
        deadline_not_revealed,
        deadlines,
    )

    if README_PATH.exists():
        README_PATH.write_text(splice_block(README_PATH.read_text(), block))
    else:
        README_PATH.write_text(default_readme(block))

    print(
        f"updated {README_PATH} "
        f"(total={total:,} added_7d={added_7d:,} changed_7d={changed_7d:,} "
        f"fixed_7d={fixed_7d:,} fixed_all={fixed_all:,} changed_all={changed_all:,} "
        f"deadline_reached={deadline_revealed + deadline_not_revealed:,} "
        f"(revealed={deadline_revealed:,} not_revealed={deadline_not_revealed:,}) "
        f"deadlines_1/3/7/30d={deadlines[1]}/{deadlines[3]}/{deadlines[7]}/{deadlines[30]})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
