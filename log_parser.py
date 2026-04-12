"""
log_parser.py – Windows Event Log CSV parser.

Exports a single function:
    parse_event_log(file_path) -> list[dict[str, str]]

Reads a CSV exported from Windows Event Viewer, keeps only rows whose
severity level is 'Error' or 'Critical', and returns them as a clean
list of dictionaries.  Handles common real-world issues:
  • UTF-8 and UTF-16-LE (with BOM) encodings
  • Byte-order marks left in header names
  • Missing or renamed "Level" column (case-insensitive fuzzy match)
  • Blank / malformed rows
  • Non-CSV or corrupt file payloads
"""

import csv
import io
import os
from typing import List, Dict


# Severity values we want to keep (lowercase for comparison).
_TARGET_LEVELS = {"error", "critical"}


class LogParseError(Exception):
    """Raised when the CSV cannot be meaningfully parsed."""


# ------------------------------------------------------------------
#  Public API
# ------------------------------------------------------------------

def parse_event_log(file_path: str) -> List[Dict[str, str]]:
    """Parse a Windows Event Log ``.csv`` and return error / critical rows.

    Parameters
    ----------
    file_path : str
        Absolute or relative path to the CSV file.

    Returns
    -------
    list[dict[str, str]]
        Each dict maps column headers to cell values for one
        matching row.  All values are stripped strings.

    Raises
    ------
    FileNotFoundError
        If *file_path* does not point to an existing file.
    LogParseError
        If the file is empty, unreadable, has no recognisable
        "Level" column, or is otherwise too broken to parse.
    """
    # ── 1. Validate the path ─────────────────────────────────────────
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # ── 1b. Reject known binary formats early ────────────────────────
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".evtx":
        raise LogParseError(
            "This is a .evtx file (Windows binary Event Log format).\n"
            "Please export it as CSV first:\n"
            "  Event Viewer > right-click the log > 'Save All Events As...'\n"
            "  > set 'Save as type' to 'CSV (Comma Separated Value)'.\n"
            "  Then load the resulting .csv file here."
        )
    if ext in (".evtx", ".evt", ".etl"):
        raise LogParseError(
            f"'{ext}' is a binary Event Log format and cannot be parsed directly.\n"
            "Please export the log as CSV from Event Viewer first."
        )

    # ── 2. Read raw bytes & detect encoding ──────────────────────────
    try:
        raw = _read_bytes(file_path)
    except OSError as exc:
        raise LogParseError(f"Could not read file: {exc}") from exc

    if not raw.strip():
        raise LogParseError("File is empty.")

    # Check for null bytes — a strong indicator of a binary file.
    if b"\x00" in raw[:8192] and raw[:2] not in (b"\xff\xfe", b"\xfe\xff"):
        raise LogParseError(
            "This file appears to be binary, not a CSV.\n"
            "If this is an Event Log, export it as CSV from Event Viewer first."
        )

    text = _decode(raw)

    # ── 3. Parse CSV rows ────────────────────────────────────────────
    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        raise LogParseError("CSV has no header row.")

    # Clean up header names (strip whitespace, BOM artefacts).
    reader.fieldnames = [_clean_header(h) for h in reader.fieldnames]

    # ── 4. Locate the "Level" column ─────────────────────────────────
    level_col = _find_level_column(reader.fieldnames)
    if level_col is None:
        raise LogParseError(
            f"No 'Level' column found.  Headers detected: {reader.fieldnames}"
        )

    # ── 5. Filter and collect matching rows ──────────────────────────
    results: List[Dict[str, str]] = []
    skipped = 0

    try:
        for row_num, row in enumerate(reader, start=2):  # row 1 = header
            try:
                level_value = (row.get(level_col) or "").strip().lower()
                if level_value in _TARGET_LEVELS:
                    clean = {k: (v or "").strip() for k, v in row.items() if k is not None}
                    results.append(clean)
            except Exception:
                skipped += 1
                continue
    except csv.Error as exc:
        raise LogParseError(
            f"CSV parsing failed: {exc}\n"
            "Make sure this is a properly formatted CSV file."
        ) from exc

    if skipped:
        # Non-fatal: some rows were malformed but we got usable data.
        import warnings
        warnings.warn(f"Skipped {skipped} malformed row(s) in {file_path}.")

    return results


# ------------------------------------------------------------------
#  Internal helpers
# ------------------------------------------------------------------

def _read_bytes(path: str) -> bytes:
    """Read the entire file as raw bytes."""
    with open(path, "rb") as fh:
        return fh.read()


def _decode(raw: bytes) -> str:
    """Decode raw bytes, auto-detecting UTF-16-LE (BOM) vs UTF-8."""
    # Windows Event Viewer exports in UTF-16-LE with BOM by default
    # when using "Save All Events As…" in some locales.
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")

    # UTF-8 BOM
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8")

    # Plain UTF-8 (or ASCII-compatible)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        # Last resort: Windows-1252 (common on Western-locale machines).
        return raw.decode("cp1252", errors="replace")


def _clean_header(name: str) -> str:
    """Strip BOM leftovers, whitespace, and quotes from a header cell."""
    return name.strip().strip("\ufeff").strip('"').strip()


def _find_level_column(headers: list) -> str | None:
    """Return the header string that represents the severity level.

    Handles common variants exported by the English and localised
    versions of Event Viewer:
        Level, level, EVENT LEVEL, Severity, Type, …
    """
    # Priority-ordered list of candidate names (lowercase).
    candidates = ["level", "event level", "severity", "type"]

    lookup = {h.lower(): h for h in headers if h}
    for candidate in candidates:
        if candidate in lookup:
            return lookup[candidate]
    return None


# ------------------------------------------------------------------
#  Quick self-test / demo
# ------------------------------------------------------------------
if __name__ == "__main__":
    import textwrap, tempfile, json

    sample_csv = textwrap.dedent("""\
        Level,Date and Time,Source,Event ID,Task Category
        Information,2026-04-10 08:12:01,Service Control Manager,7036,None
        Error,2026-04-10 08:13:45,Application Error,1000,Application Crashing
        Warning,2026-04-10 08:14:22,Disk,153,None
        Critical,2026-04-10 08:15:03,Kernel-Power,41,System Reboot
        Error,2026-04-10 08:15:55,DCOM,10016,Permission Issue
        Information,2026-04-10 08:16:10,Windows Update,19,Installation
    """)

    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as f:
        f.write(sample_csv)
        tmp_path = f.name

    try:
        rows = parse_event_log(tmp_path)
        print(f"Found {len(rows)} Error/Critical row(s):\n")
        print(json.dumps(rows, indent=2))
    finally:
        os.remove(tmp_path)
