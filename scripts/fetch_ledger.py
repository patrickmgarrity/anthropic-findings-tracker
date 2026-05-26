#!/usr/bin/env python3
"""
Anthropic Mythos disclosure-ledger tracker.

Pulls the public ledger and aggregate payload from
https://red.anthropic.com/2026/cvd/ and normalizes every finding into a single
flat record. Output is written to:

  data/advisories.csv      -- flat CSV, one row per finding, fully replaced each run
  data/advisories.jsonl    -- same data, one JSON object per line
  data/advisories.sqlite   -- SQLite snapshot of current state + history table
  data/state.json          -- ETags + last-run metadata for conditional GET
  data/changes.log         -- append-only human-readable diff log

No AI, no third-party services. Standard library only.
"""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import logging
import os
import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #

BASE_URL = "https://red.anthropic.com/2026/cvd"
LEDGER_URL = f"{BASE_URL}/data/ledger.json"
PAYLOAD_URL = f"{BASE_URL}/data/payload.json"
LEDGER_HTML_URL = f"{BASE_URL}/ledger/"
FINDING_URL_TMPL = f"{BASE_URL}/findings/{{ant_id}}.html"

USER_AGENT = "anthropic-mythos-tracker/1.0 (+https://github.com/)"
REQUEST_TIMEOUT = 30  # seconds

# Timeline labels found on per-finding pages, mapped to column names.
# Labels are matched case-insensitively against the published markup.
TIMELINE_LABELS = {
    "reported to tracker":     "reported_to_tracker_at",
    "sent to maintainer":      "sent_to_maintainer_at",
    "patch released":          "patch_released_at",
    "maintainer acknowledged": "maintainer_acknowledged_at",
    "publicly revealed":       "publicly_revealed_at",
}

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

CSV_PATH = DATA_DIR / "advisories.csv"
JSONL_PATH = DATA_DIR / "advisories.jsonl"
SQLITE_PATH = DATA_DIR / "advisories.sqlite"
STATE_PATH = DATA_DIR / "state.json"
CHANGES_LOG = DATA_DIR / "changes.log"

DISCOVERED_BY = "Anthropic Mythos"

# Columns are deliberately ordered to match what the user asked for.
CSV_COLUMNS = [
    "hash",                       # SHA-3-512 of the sealed report
    "ant_id",                     # Anthropic identifier (ANT-YYYY-XXXXXXXX)
    "cve_ids",                    # |-joined list
    "ghsa_ids",                   # |-joined list
    "project",
    "bug_class",
    "title",                      # from payload.json cve/ghsa records, when revealed
    "claude_severity",
    "vendor_severity",            # external security-research-firm severity
    "maintainer_severity",
    "status",                     # disclosed / fixed / pre-disclosure / withdrawn
    "reveal_tier",                # discovered / sent / acknowledged_by_maintainer / revealed
    "revealed",                   # bool
    "vendor_confirmed",           # bool -- best proxy for "acknowledgement"
    "passed_triage",              # bool
    "was_disclosed",              # bool
    "patched",                    # bool
    "is_fixed_in_response",       # bool
    "committed_at",               # date the hash was committed to the ledger
    "revealed_at",                # date identifier/project/etc were revealed
    "patched_at",                 # date patch landed upstream (from ledger.json)
    # Timeline dates parsed from the per-finding page (revealed entries only):
    "reported_to_tracker_at",
    "sent_to_maintainer_at",
    "patch_released_at",
    "maintainer_acknowledged_at",
    "publicly_revealed_at",
    "discovered_by",              # parsed from the Acknowledgement section when available
    "acknowledgement",            # full Acknowledgement paragraph from finding page
    "advisory_url",               # link to the per-finding HTML page when revealed, otherwise ledger anchor
    "project_url",                # constructed GitHub URL if project is owner/repo
    "cve_urls",                   # |-joined NVD URLs
    "ghsa_urls",                  # |-joined GHSA URLs
    "first_seen_utc",             # when this tracker first observed the entry
    "last_seen_utc",              # when this tracker last observed the entry
]

# --------------------------------------------------------------------------- #
# Logging                                                                     #
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("mythos")

# --------------------------------------------------------------------------- #
# HTTP                                                                        #
# --------------------------------------------------------------------------- #


def http_get_json(url: str, etag: str | None) -> tuple[Any | None, str | None, int]:
    """Conditional GET. Returns (json_body_or_None_if_304, new_etag, status_code)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    if etag:
        req.add_header("If-None-Match", etag)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            status = resp.status
            new_etag = resp.headers.get("ETag")
            body = resp.read()
            return json.loads(body.decode("utf-8")), new_etag, status
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return None, etag, 304
        log.error("HTTP %s for %s: %s", e.code, url, e.reason)
        raise


def http_get_text(url: str) -> tuple[str | None, int]:
    """Unconditional GET for HTML. Returns (text, status). Returns (None, status) on 404."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, 404
        log.warning("HTTP %s for %s: %s", e.code, url, e.reason)
        return None, e.code


# --------------------------------------------------------------------------- #
# Finding-detail HTML parsing                                                 #
# --------------------------------------------------------------------------- #

import html as _html
from html.parser import HTMLParser


class _FindingParser(HTMLParser):
    """
    Pulls structured data out of a per-finding page:

      * Timeline rows: <li class="timeline-pt"> with nested
        <span class="timeline-date"> and <span class="timeline-label">.
      * Acknowledgement: the <p> directly after <h2>Acknowledgement</h2>.

    Designed to be tolerant: unknown labels are ignored, extra whitespace is
    collapsed, attribute order doesn't matter, and case is normalized for
    label matching.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.timeline: dict[str, str] = {}      # column_name -> date
        self.acknowledgement: str | None = None

        # State machine for timeline parsing
        self._in_timeline_pt = False
        self._current_span: str | None = None   # 'date' | 'label' | None
        self._cur_date: str = ""
        self._cur_label: str = ""

        # State machine for acknowledgement parsing
        self._next_p_is_ack = False
        self._in_ack_p = False
        self._ack_buf: list[str] = []
        self._in_h2 = False
        self._h2_buf: list[str] = []

    @staticmethod
    def _classes(attrs: list[tuple[str, str | None]]) -> set[str]:
        for name, value in attrs:
            if name == "class" and value:
                return set(value.split())
        return set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = self._classes(attrs)

        if tag == "li" and "timeline-pt" in classes:
            self._in_timeline_pt = True
            self._cur_date = ""
            self._cur_label = ""
            return

        if self._in_timeline_pt and tag == "span":
            if "timeline-date" in classes:
                self._current_span = "date"
            elif "timeline-label" in classes:
                self._current_span = "label"
            return

        if tag == "h2":
            self._in_h2 = True
            self._h2_buf = []
            return

        if tag == "p" and self._next_p_is_ack:
            self._in_ack_p = True
            self._ack_buf = []
            self._next_p_is_ack = False
            return

    def handle_endtag(self, tag: str) -> None:
        if tag == "li" and self._in_timeline_pt:
            self._record_timeline_point()
            self._in_timeline_pt = False
            self._current_span = None
            return
        if tag == "span" and self._current_span is not None:
            self._current_span = None
            return
        if tag == "h2" and self._in_h2:
            heading = "".join(self._h2_buf).strip().lower()
            self._in_h2 = False
            if heading == "acknowledgement":
                self._next_p_is_ack = True
            return
        if tag == "p" and self._in_ack_p:
            self._in_ack_p = False
            text = " ".join("".join(self._ack_buf).split()).strip()
            if text and self.acknowledgement is None:
                self.acknowledgement = text
            return

    def handle_data(self, data: str) -> None:
        if self._in_timeline_pt and self._current_span == "date":
            self._cur_date += data
        elif self._in_timeline_pt and self._current_span == "label":
            self._cur_label += data
        elif self._in_h2:
            self._h2_buf.append(data)
        elif self._in_ack_p:
            self._ack_buf.append(data)

    def _record_timeline_point(self) -> None:
        date = self._cur_date.strip()
        label = self._cur_label.strip().lower()
        column = TIMELINE_LABELS.get(label)
        if column and date and column not in self.timeline:
            self.timeline[column] = date


def parse_finding_html(html_text: str) -> dict:
    """Return {column: value} for known timeline + acknowledgement fields."""
    p = _FindingParser()
    try:
        p.feed(html_text)
    except Exception as e:  # parser is best-effort; never let it crash the run
        log.warning("Finding HTML parse error: %s", e)
        return {}

    result: dict[str, str] = dict(p.timeline)
    if p.acknowledgement:
        result["acknowledgement"] = p.acknowledgement
        # Refine discovered_by: pull the named discoverer out of the
        # standard "This vulnerability was discovered by X" sentence.
        m_ack = p.acknowledgement
        prefix = "this vulnerability was discovered by "
        lower = m_ack.lower()
        if prefix in lower:
            tail = m_ack[lower.index(prefix) + len(prefix):]
            # Cut at the first comma or period.
            for sep in (",", "."):
                idx = tail.find(sep)
                if idx != -1:
                    tail = tail[:idx]
                    break
            disc = tail.strip()
            if disc:
                result["discovered_by"] = disc
    return result


def fetch_finding_details(
    ant_ids: list[str],
    cache: dict,
    now_iso: str,
) -> dict[str, dict]:
    """
    For each revealed ant_id, fetch the per-finding page (with a content-hash
    cache so we re-parse only when the upstream HTML changed). Returns
    {ant_id: parsed_fields_dict}.

    `cache` is the persistent "finding_pages" sub-dict from state.json. It
    stores {ant_id: {"sha256": "...", "fields": {...}, "fetched_utc": "..."}}.
    """
    out: dict[str, dict] = {}
    for ant_id in ant_ids:
        url = FINDING_URL_TMPL.format(ant_id=ant_id)
        text, status = http_get_text(url)
        if status == 404:
            log.info("Finding page not yet published: %s", ant_id)
            continue
        if text is None:
            # Network hiccup -- fall back to cached parse if we have one.
            cached = cache.get(ant_id)
            if cached and "fields" in cached:
                out[ant_id] = cached["fields"]
            continue

        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        cached = cache.get(ant_id)
        if cached and cached.get("sha256") == digest:
            out[ant_id] = cached.get("fields", {})
            continue

        fields = parse_finding_html(text)
        out[ant_id] = fields
        cache[ant_id] = {
            "sha256": digest,
            "fields": fields,
            "fetched_utc": now_iso,
        }
        log.info("Parsed finding page %s (%d fields)", ant_id, len(fields))
    return out


# --------------------------------------------------------------------------- #
# State (ETag cache + last run)                                               #
# --------------------------------------------------------------------------- #


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except json.JSONDecodeError:
            log.warning("state.json corrupt, resetting")
    return {}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True))


# --------------------------------------------------------------------------- #
# Normalization                                                               #
# --------------------------------------------------------------------------- #


def build_title_index(payload: dict | None) -> dict[str, str]:
    """Map ant_id -> title using the cve_records + ghsa_records in payload.json."""
    titles: dict[str, str] = {}
    if not payload:
        return titles
    for bucket in ("cve_records", "ghsa_records"):
        for rec in payload.get(bucket, []) or []:
            for finding in rec.get("findings", []) or []:
                ant_id = finding.get("ant_id")
                title = (finding.get("title") or "").strip()
                if ant_id and title and ant_id not in titles:
                    titles[ant_id] = title
    return titles


def join_list(values: Iterable[str] | None) -> str:
    return "|".join(values) if values else ""


def advisory_url(entry: dict) -> str:
    """
    Canonical link to the advisory. For revealed entries this is the
    dedicated per-finding HTML page; for still-withheld entries it's the
    ledger page anchored by the hash prefix (the only addressable surface).
    """
    ant_id = entry.get("ant_id")
    if ant_id:
        return FINDING_URL_TMPL.format(ant_id=ant_id)
    h = entry.get("hash") or ""
    return f"{LEDGER_HTML_URL}#{h[:16]}" if h else LEDGER_HTML_URL


def project_url(project: str | None) -> str:
    if not project:
        return ""
    # Heuristic: GitHub repos appear as "owner/repo".
    if "/" in project and " " not in project:
        return f"https://github.com/{project}"
    return ""


def cve_urls(cve_ids: list[str]) -> list[str]:
    return [f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cve_ids or []]


def ghsa_urls(ghsa_ids: list[str]) -> list[str]:
    return [f"https://github.com/advisories/{g}" for g in ghsa_ids or []]


def normalize(
    entry: dict,
    titles: dict[str, str],
    finding_details: dict[str, dict],
    now_iso: str,
) -> dict:
    ant_id = entry.get("ant_id")
    title = titles.get(ant_id or "", "")
    details = finding_details.get(ant_id or "", {}) if ant_id else {}

    discovered_by = details.get("discovered_by") or DISCOVERED_BY
    acknowledgement = details.get("acknowledgement", "")

    return {
        "hash": entry.get("hash", ""),
        "ant_id": ant_id or "",
        "cve_ids": join_list(entry.get("cve_ids")),
        "ghsa_ids": join_list(entry.get("ghsa_ids")),
        "project": entry.get("project") or "",
        "bug_class": entry.get("bug_class") or "",
        "title": title,
        "claude_severity": entry.get("claude_severity") or "",
        "vendor_severity": entry.get("vendor_severity") or "",
        "maintainer_severity": entry.get("maintainer_severity") or "",
        "status": entry.get("status") or "pre-disclosure",
        "reveal_tier": entry.get("reveal_tier") or "",
        "revealed": bool(entry.get("revealed")),
        "vendor_confirmed": bool(entry.get("vendor_confirmed")),
        "passed_triage": bool(entry.get("passed_triage")),
        "was_disclosed": bool(entry.get("was_disclosed")),
        "patched": bool(entry.get("patched")),
        "is_fixed_in_response": bool(entry.get("is_fixed_in_response")),
        "committed_at": entry.get("committed_at") or "",
        "revealed_at": entry.get("revealed_at") or "",
        "patched_at": entry.get("patched_at") or "",
        "reported_to_tracker_at": details.get("reported_to_tracker_at", ""),
        "sent_to_maintainer_at": details.get("sent_to_maintainer_at", ""),
        "patch_released_at": details.get("patch_released_at", ""),
        "maintainer_acknowledged_at": details.get("maintainer_acknowledged_at", ""),
        "publicly_revealed_at": details.get("publicly_revealed_at", ""),
        "discovered_by": discovered_by,
        "acknowledgement": acknowledgement,
        "advisory_url": advisory_url(entry),
        "project_url": project_url(entry.get("project")),
        "cve_urls": join_list(cve_urls(entry.get("cve_ids") or [])),
        "ghsa_urls": join_list(ghsa_urls(entry.get("ghsa_ids") or [])),
        "first_seen_utc": now_iso,   # may be overwritten in merge_first_seen
        "last_seen_utc": now_iso,
    }


# --------------------------------------------------------------------------- #
# SQLite                                                                      #
# --------------------------------------------------------------------------- #

SCHEMA_TABLES = """
CREATE TABLE IF NOT EXISTS advisories (
    hash TEXT PRIMARY KEY,
    ant_id TEXT,
    cve_ids TEXT,
    ghsa_ids TEXT,
    project TEXT,
    bug_class TEXT,
    title TEXT,
    claude_severity TEXT,
    vendor_severity TEXT,
    maintainer_severity TEXT,
    status TEXT,
    reveal_tier TEXT,
    revealed INTEGER,
    vendor_confirmed INTEGER,
    passed_triage INTEGER,
    was_disclosed INTEGER,
    patched INTEGER,
    is_fixed_in_response INTEGER,
    committed_at TEXT,
    revealed_at TEXT,
    patched_at TEXT,
    reported_to_tracker_at TEXT,
    sent_to_maintainer_at TEXT,
    patch_released_at TEXT,
    maintainer_acknowledged_at TEXT,
    publicly_revealed_at TEXT,
    discovered_by TEXT,
    acknowledgement TEXT,
    advisory_url TEXT,
    project_url TEXT,
    cve_urls TEXT,
    ghsa_urls TEXT,
    first_seen_utc TEXT,
    last_seen_utc TEXT
);

CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_utc TEXT NOT NULL,
    hash TEXT NOT NULL,
    ant_id TEXT,
    change_kind TEXT NOT NULL,   -- 'new' | 'updated'
    field TEXT,                  -- NULL for 'new'
    old_value TEXT,
    new_value TEXT
);
"""

SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_ant_id ON advisories(ant_id);
CREATE INDEX IF NOT EXISTS idx_status ON advisories(status);
CREATE INDEX IF NOT EXISTS idx_revealed ON advisories(revealed);
CREATE INDEX IF NOT EXISTS idx_committed_at ON advisories(committed_at);
CREATE INDEX IF NOT EXISTS idx_changes_hash ON changes(hash);
CREATE INDEX IF NOT EXISTS idx_changes_observed ON changes(observed_utc);
"""

TRACKED_FIELDS_FOR_DIFF = [
    "ant_id", "cve_ids", "ghsa_ids", "project", "bug_class", "title",
    "claude_severity", "vendor_severity", "maintainer_severity",
    "status", "reveal_tier", "revealed", "vendor_confirmed",
    "passed_triage", "was_disclosed", "patched", "is_fixed_in_response",
    "committed_at", "revealed_at", "patched_at",
    "reported_to_tracker_at", "sent_to_maintainer_at", "patch_released_at",
    "maintainer_acknowledged_at", "publicly_revealed_at",
    "discovered_by", "acknowledgement",
]


def open_db() -> sqlite3.Connection:
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    # Step 1: create tables (CREATE IF NOT EXISTS is a no-op on existing tables).
    conn.executescript(SCHEMA_TABLES)
    # Step 2: migrate old DBs by adding any missing columns. We do this BEFORE
    # creating indexes so an index that references a not-yet-added column
    # can succeed.
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(advisories)")}
    integer_cols = {
        "revealed", "vendor_confirmed", "passed_triage",
        "was_disclosed", "patched", "is_fixed_in_response",
    }
    for col in CSV_COLUMNS:
        if col in existing_cols:
            continue
        col_type = "INTEGER" if col in integer_cols else "TEXT"
        conn.execute(f"ALTER TABLE advisories ADD COLUMN {col} {col_type}")
    # Step 3: create indexes now that every column exists.
    conn.executescript(SCHEMA_INDEXES)
    conn.commit()
    return conn


def merge_and_diff(conn: sqlite3.Connection, records: list[dict], now_iso: str) -> tuple[int, int, list[str]]:
    """Insert/update records; log changes. Returns (new_count, updated_count, summary_lines)."""
    cur = conn.cursor()
    new_count = 0
    updated_count = 0
    summary: list[str] = []

    for r in records:
        cur.execute("SELECT * FROM advisories WHERE hash = ?", (r["hash"],))
        existing = cur.fetchone()

        if existing is None:
            cur.execute(
                f"INSERT INTO advisories ({', '.join(CSV_COLUMNS)}) "
                f"VALUES ({', '.join(['?'] * len(CSV_COLUMNS))})",
                tuple(_coerce(r[c]) for c in CSV_COLUMNS),
            )
            cur.execute(
                "INSERT INTO changes (observed_utc, hash, ant_id, change_kind, field, old_value, new_value) "
                "VALUES (?, ?, ?, 'new', NULL, NULL, NULL)",
                (now_iso, r["hash"], r["ant_id"] or None),
            )
            new_count += 1
            summary.append(f"NEW   {r['hash'][:16]}… committed={r['committed_at']} status={r['status']}")
        else:
            # Preserve first_seen_utc, refresh last_seen_utc.
            r["first_seen_utc"] = existing["first_seen_utc"] or now_iso
            diffs: list[tuple[str, Any, Any]] = []
            for f in TRACKED_FIELDS_FOR_DIFF:
                old = existing[f]
                new = _coerce(r[f])
                if (old or "") != (new if new is not None else ""):
                    if isinstance(old, int) and isinstance(new, int):
                        if old == new:
                            continue
                    diffs.append((f, old, new))

            cur.execute(
                f"UPDATE advisories SET {', '.join(f'{c} = ?' for c in CSV_COLUMNS if c != 'hash')} "
                f"WHERE hash = ?",
                tuple(_coerce(r[c]) for c in CSV_COLUMNS if c != "hash") + (r["hash"],),
            )

            if diffs:
                updated_count += 1
                for field, old, new in diffs:
                    cur.execute(
                        "INSERT INTO changes (observed_utc, hash, ant_id, change_kind, field, old_value, new_value) "
                        "VALUES (?, ?, ?, 'updated', ?, ?, ?)",
                        (now_iso, r["hash"], r["ant_id"] or None, field, str(old) if old is not None else "", str(new) if new is not None else ""),
                    )
                    summary.append(
                        f"UPD   {r['hash'][:16]}… {field}: {old!r} -> {new!r}"
                    )

    conn.commit()
    return new_count, updated_count, summary


def _coerce(v: Any) -> Any:
    if isinstance(v, bool):
        return 1 if v else 0
    return v


# --------------------------------------------------------------------------- #
# Writers                                                                     #
# --------------------------------------------------------------------------- #


def write_csv(records: list[dict]) -> None:
    """Re-render the CSV from the in-memory normalized list each run."""
    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for r in records:
            row = {k: r.get(k, "") for k in CSV_COLUMNS}
            for k, v in row.items():
                if isinstance(v, bool):
                    row[k] = "true" if v else "false"
            writer.writerow(row)


def write_jsonl(records: list[dict]) -> None:
    with JSONL_PATH.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def append_changes_log(now_iso: str, new_count: int, updated_count: int, summary_lines: list[str]) -> None:
    if not summary_lines:
        return
    with CHANGES_LOG.open("a", encoding="utf-8") as f:
        f.write(f"\n=== {now_iso}  (+{new_count} new, ~{updated_count} updated) ===\n")
        for line in summary_lines:
            f.write(line + "\n")


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #


def main() -> int:
    now_iso = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    state = load_state()
    log.info("Run start %s", now_iso)

    # Ledger
    ledger_data, ledger_etag, ledger_status = http_get_json(
        LEDGER_URL, state.get("ledger_etag")
    )
    log.info("ledger.json HTTP %s", ledger_status)

    # Payload (titles, supplementary metadata)
    payload_data, payload_etag, payload_status = http_get_json(
        PAYLOAD_URL, state.get("payload_etag")
    )
    log.info("payload.json HTTP %s", payload_status)

    # NOTE: we don't early-exit on (ledger 304 AND payload 304), because the
    # per-finding HTML pages don't send ETags and their timeline content can
    # change independently of ledger.json. They're cheap to recheck (~30
    # small files today) and the content-hash cache short-circuits parsing.
    #
    # We also need the full ledger + payload bodies in memory each run so we
    # can rewrite the CSV/JSONL/SQLite outputs. A 304 means the server
    # confirmed our cached copy is current -- but we don't keep that cached
    # copy on disk, so re-fetch unconditionally if we got a 304.
    if ledger_data is None:
        log.debug("Ledger returned 304; re-fetching for full body.")
        ledger_data, ledger_etag, ledger_status = http_get_json(LEDGER_URL, None)

    if payload_data is None:
        log.debug("Payload returned 304; re-fetching for full body.")
        payload_data, payload_etag, _ = http_get_json(PAYLOAD_URL, None)
        if payload_data is None:
            payload_data = {}

    titles = build_title_index(payload_data)
    log.info("title index has %d entries", len(titles))

    # Collect every revealed ant_id and fetch its per-finding page (cached
    # by content hash in state.json so re-parsing is cheap on repeat runs).
    finding_cache = state.setdefault("finding_pages", {})
    revealed_ant_ids = [
        e["ant_id"] for e in ledger_data
        if e.get("ant_id") and (e.get("revealed") or e.get("reveal_tier") == "revealed")
    ]
    log.info("fetching %d revealed finding pages", len(revealed_ant_ids))
    finding_details = fetch_finding_details(revealed_ant_ids, finding_cache, now_iso)

    records = [normalize(e, titles, finding_details, now_iso) for e in ledger_data]
    records.sort(key=lambda r: (r["committed_at"] or "", r["hash"]), reverse=True)

    log.info("normalized %d ledger entries", len(records))

    # Compute a content hash so we can short-circuit later if structure is stable.
    digest = hashlib.sha256(
        json.dumps(ledger_data, sort_keys=True).encode("utf-8")
    ).hexdigest()

    # Persist
    conn = open_db()
    new_count, updated_count, summary_lines = merge_and_diff(conn, records, now_iso)
    conn.close()

    write_csv(records)
    write_jsonl(records)
    append_changes_log(now_iso, new_count, updated_count, summary_lines)

    state["ledger_etag"] = ledger_etag
    state["payload_etag"] = payload_etag
    state["ledger_sha256"] = digest
    state["last_run_utc"] = now_iso
    state["entry_count"] = len(records)
    if new_count or updated_count:
        state["last_change_utc"] = now_iso
    save_state(state)

    log.info(
        "Done. total=%d new=%d updated=%d", len(records), new_count, updated_count
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
