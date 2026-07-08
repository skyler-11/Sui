"""
app/core/log_reader.py — Read-side backend for the superadmin log viewer.

This module is intentionally Streamlit-free: it deals only with on-disk log
files, parsing, filtering, and redaction. The UI layer in
``pages/admin_log_viewer.py`` is responsible for role gating, rate limiting,
and surfacing audit events around every call into here.

Security boundaries enforced here:

  * **Path traversal (CWE-22)** — every filename argument is checked against
    a dynamically-built allow-set rooted at ``_resolve_log_dir()``. The
    resolved path must also live inside that directory; symlink escapes,
    absolute paths from the caller, and ``..`` components are rejected.
  * **Information disclosure (CWE-200)** — a mandatory redaction layer masks
    Bearer tokens, JWT-shaped values, and ``password=``/``secret=``/
    ``token=``/``api_key=`` key-value pairs before any line leaves this
    module. PII redaction (emails, user_id-shaped strings) is opt-in via
    ``mask_pii=True`` so superadmins retain enough signal to investigate
    audit events.
  * **Resource exhaustion (CWE-400)** — ``tail_lines`` caps both bytes
    consumed and lines returned, walking the file backward from EOF rather
    than slurping it whole. Callers pass their own hard caps in addition.
"""

from __future__ import annotations

import datetime as _dt
import io
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from app.core.logging import _resolve_log_dir


# ── Configuration constants ──────────────────────────────────────────────────
# Hard ceilings — UI selectboxes should never exceed these. They are duplicated
# here defensively so a future UI change cannot accidentally request 50 MB.

MAX_BYTES_HARD_CAP = 5 * 1024 * 1024   # 5 MB per render
MAX_LINES_HARD_CAP = 10_000

# Allowed base stream names (active files). Dated archives derive from these.
_BASE_STREAMS = frozenset({"app.log", "audit.log", "app.json.log"})

# A rotated archive is "<base>.YYYY-MM-DD" — matches TimedRotatingFileHandler's
# suffix= we configured in app/core/logging.py.
_ARCHIVE_SUFFIX_RE = re.compile(r"^(?P<base>[\w.]+\.log)\.(?P<date>\d{4}-\d{2}-\d{2})$")


# ── Public data classes ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class ArchiveMeta:
    """One row in the archive selector dropdown."""
    filename: str           # e.g. "app.log" or "app.log.2026-05-13"
    stream: str             # "app" | "audit" | "app.json"
    date_label: str         # "Today (live)" | "2026-05-13"
    size_bytes: int


@dataclass(frozen=True)
class ParsedRecord:
    """One filterable, renderable log line."""
    ts: str                 # ISO-ish timestamp from the line (raw substring)
    level: str              # DEBUG / INFO / WARNING / ERROR / CRITICAL / "" if unknown
    logger: str             # logger name; "" for audit / unknown
    trace_id: str
    message: str
    raw: str                # original line (post-redaction), useful for export


# ── Path hardening ───────────────────────────────────────────────────────────

def _log_dir() -> Path:
    """Resolve the on-disk log directory at call time (not import time).

    Tests monkeypatch ``MANNING_LOG_DIR`` via ``tmp_path``; resolving on every
    call avoids stale captures.
    """
    return _resolve_log_dir().resolve()


def _allow_set(log_dir: Path) -> set[str]:
    """Compute the dynamic allow-set of filenames in ``log_dir``.

    Always includes the base stream names. Adds any file whose name parses as
    ``<base>.YYYY-MM-DD`` for a base in ``_BASE_STREAMS``. Files outside the
    pattern are silently excluded — they cannot be opened via this module.
    """
    allowed = set(_BASE_STREAMS)
    if not log_dir.is_dir():
        return allowed
    for child in log_dir.iterdir():
        if not child.is_file():
            continue
        name = child.name
        if name in _BASE_STREAMS:
            continue
        m = _ARCHIVE_SUFFIX_RE.match(name)
        if m and m.group("base") in _BASE_STREAMS:
            allowed.add(name)
    return allowed


def _resolve_safe(filename: str) -> Path:
    """Resolve ``filename`` inside the log dir or raise ``ValueError``.

    Defensive in depth:
      1. Reject any path-shaped input — only bare names allowed (no separators,
         no drive letters, no leading ``.``).
      2. Reject names not in the allow-set built from a directory listing.
      3. Verify the resolved path is still inside the log dir (catches
         symlinks pointing elsewhere).
    """
    if not filename or os.sep in filename or "/" in filename or ".." in filename:
        raise ValueError(f"invalid log filename: {filename!r}")
    if os.altsep and os.altsep in filename:
        raise ValueError(f"invalid log filename: {filename!r}")

    log_dir = _log_dir()
    if filename not in _allow_set(log_dir):
        raise ValueError(f"log file not in allow-set: {filename!r}")

    path = (log_dir / filename).resolve()
    try:
        path.relative_to(log_dir)
    except ValueError as e:
        raise ValueError(
            f"resolved path escapes log dir: {filename!r}"
        ) from e
    return path


# ── Archive enumeration ──────────────────────────────────────────────────────

def list_archives() -> list[ArchiveMeta]:
    """Return ArchiveMeta rows newest-first, suitable for a Streamlit selectbox.

    Active files (``app.log``, ``audit.log``, ``app.json.log``) appear at the
    top with label ``"Today (live)"``. Dated archives follow in descending
    date order. Files that exist on disk but are not in the allow-set are
    excluded.
    """
    log_dir = _log_dir()
    if not log_dir.is_dir():
        return []

    rows: list[ArchiveMeta] = []
    allowed = _allow_set(log_dir)

    for name in sorted(allowed):
        path = log_dir / name
        if not path.is_file():
            continue
        if name in _BASE_STREAMS:
            stream = name.rsplit(".log", 1)[0]
            rows.append(ArchiveMeta(
                filename=name,
                stream=stream,
                date_label="Today (live)",
                size_bytes=path.stat().st_size,
            ))
            continue
        m = _ARCHIVE_SUFFIX_RE.match(name)
        if not m:
            continue
        base = m.group("base")
        rows.append(ArchiveMeta(
            filename=name,
            stream=base.rsplit(".log", 1)[0],
            date_label=m.group("date"),
            size_bytes=path.stat().st_size,
        ))

    # Sort: active first (date_label == "Today (live)"), then by date desc.
    def _sort_key(meta: ArchiveMeta) -> tuple[int, str, str]:
        is_live = 0 if meta.date_label == "Today (live)" else 1
        # invert date string for descending: a later date sorts first by
        # negating via subtraction from "9999-99-99".
        return (is_live, meta.stream, _invert_date(meta.date_label))

    rows.sort(key=_sort_key)
    return rows


def _invert_date(label: str) -> str:
    if label == "Today (live)":
        return ""
    # Lexically invert YYYY-MM-DD so newer dates sort first.
    try:
        d = _dt.date.fromisoformat(label)
        return str(_dt.date.max.toordinal() - d.toordinal()).zfill(10)
    except ValueError:
        return label


# ── Redaction ────────────────────────────────────────────────────────────────
# Patterns applied in order. Each replacement substitutes the sensitive value
# with literal ``***`` while preserving surrounding context, so a filtered
# slice remains diff-readable.

_REDACT_PATTERNS_ALWAYS: tuple[tuple[re.Pattern[str], str], ...] = (
    # OAuth Bearer tokens — case-insensitive.
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-]+"), "Bearer ***"),
    # JWT-shaped: three base64url segments separated by dots.
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "***jwt***"),
    # OAuth-specific compound keys. The generic key=value rule below does
    # NOT match these because the leading word ends in ``_`` (e.g. the
    # ``\b`` in ``\btoken\b`` does not fire inside ``refresh_token``).
    # Order matters: these must run BEFORE the generic rule so the more
    # specific match wins and we don't double-rewrite.
    (re.compile(
        r"(?i)\b(client_secret|refresh_token|access_token|id_token|"
        r"code_verifier|client_assertion)\s*=\s*\"?[^\s\"'&]+\"?"
    ), r'\1="***"'),
    # OAuth authorization ``code=`` is short-lived but single-use and
    # uniquely tied to a session — leaking it post-exchange still has
    # forensic value to an attacker. Anchor to URL/query-string context
    # (preceded by ``?`` or ``&``) so we don't accidentally redact prose
    # like "error code=42" in application logs.
    (re.compile(r"(?i)([?&])code=([^\s&\"']+)"), r'\1code=***'),
    # key=value secrets, including api_key / api-key variants.
    (re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_\-]?key)\s*=\s*\"?[^\s\"']+\"?"
    ), r'\1="***"'),
)

# PII patterns are opt-in. Keeping user_id visible is the default because the
# log viewer's primary job is investigating "what did user X do" — masking it
# defeats the purpose. We still expose a mask_pii=True path for screen-share.
_REDACT_PATTERNS_PII: tuple[tuple[re.Pattern[str], str], ...] = (
    # email-shaped
    (re.compile(r"\b[\w.+\-]+@[\w\-]+\.[\w.\-]+\b"), "***@***"),
)


def _redact(line: str, *, mask_pii: bool) -> str:
    out = line
    for pat, repl in _REDACT_PATTERNS_ALWAYS:
        out = pat.sub(repl, out)
    if mask_pii:
        for pat, repl in _REDACT_PATTERNS_PII:
            out = pat.sub(repl, out)
    return out


# ── Reverse-chunk tail ───────────────────────────────────────────────────────

def tail_lines(
    filename: str,
    *,
    max_bytes: int = 1 * 1024 * 1024,
    max_lines: int = 2_000,
    mask_pii: bool = False,
) -> list[str]:
    """Return up to ``max_lines`` lines from the end of ``filename``.

    Reads the file in 64 KB chunks walking backward from EOF, so a 90-day
    archive on disk is never fully loaded. Decoding happens once at the end
    with ``errors="replace"`` so a chunk boundary that lands mid-UTF-8
    sequence cannot crash the viewer.

    Always applies the mandatory redaction layer; PII masking is opt-in.
    """
    max_bytes = max(1, min(max_bytes, MAX_BYTES_HARD_CAP))
    max_lines = max(1, min(max_lines, MAX_LINES_HARD_CAP))
    path = _resolve_safe(filename)

    chunk_size = 64 * 1024
    buf = bytearray()
    bytes_read = 0
    newline_count = 0

    with path.open("rb") as fh:
        fh.seek(0, io.SEEK_END)
        pos = fh.tell()
        while pos > 0 and bytes_read < max_bytes and newline_count <= max_lines:
            step = min(chunk_size, pos, max_bytes - bytes_read)
            pos -= step
            fh.seek(pos)
            chunk = fh.read(step)
            buf[:0] = chunk
            bytes_read += step
            newline_count = buf.count(b"\n")

    text = buf.decode("utf-8", errors="replace")
    lines = text.splitlines()
    # Drop the first line if we did not reach BOF — it was likely truncated
    # mid-record by the chunk boundary.
    if pos > 0 and lines:
        lines = lines[1:]
    if len(lines) > max_lines:
        lines = lines[-max_lines:]

    return [_redact(line, mask_pii=mask_pii) for line in lines]


# ── Parsing ──────────────────────────────────────────────────────────────────

_TEXT_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*\|\s*"
    r"(?P<level>[A-Z]+)\s*\|\s*"
    r"(?P<logger>[^|]+?)\s*\|\s*"
    r"trace_id=(?P<trace>\S+)\s*\|\s*"
    r"(?P<msg>.*)$"
)

_AUDIT_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*\|\s*AUDIT\s*\|\s*"
    r"trace_id=(?P<trace>\S+)\s*\|\s*"
    r"(?P<msg>.*)$"
)


def _parse_line(line: str) -> ParsedRecord:
    """Best-effort parse of one log line into a ParsedRecord.

    Tries JSON first if the line starts with ``{``. Falls back to the app-text
    and audit-text formats from ``_app_formatter`` / ``_audit_formatter`` in
    ``app/core/logging.py``. Unparseable lines surface as raw with level="".
    """
    stripped = line.lstrip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            return ParsedRecord(
                ts=str(obj.get("ts", "")),
                level=str(obj.get("level", "")),
                logger=str(obj.get("logger", "")),
                trace_id=str(obj.get("trace_id", "")),
                message=str(obj.get("message", "")),
                raw=line,
            )
        except json.JSONDecodeError:
            pass  # fall through to text parsers

    m = _TEXT_LINE_RE.match(line)
    if m:
        return ParsedRecord(
            ts=m.group("ts"),
            level=m.group("level"),
            logger=m.group("logger").strip(),
            trace_id=m.group("trace"),
            message=m.group("msg"),
            raw=line,
        )

    m = _AUDIT_LINE_RE.match(line)
    if m:
        return ParsedRecord(
            ts=m.group("ts"),
            level="INFO",            # audit logger is fixed at INFO
            logger="manning.audit",
            trace_id=m.group("trace"),
            message=m.group("msg"),
            raw=line,
        )

    return ParsedRecord(
        ts="", level="", logger="", trace_id="", message=line, raw=line,
    )


# ── Filtering ────────────────────────────────────────────────────────────────

def filter_lines(
    lines: Iterable[str],
    *,
    levels: Sequence[str] | None = None,
    since: _dt.datetime | None = None,
    until: _dt.datetime | None = None,
    trace_id: str | None = None,
    grep: str | None = None,
    regex: bool = False,
) -> Iterator[ParsedRecord]:
    """Yield ParsedRecord rows matching every supplied criterion.

    All criteria combine with AND. A criterion left as ``None`` / empty is a
    no-op. Regex compilation errors raise ``re.error`` to the UI so the user
    can fix their pattern; we do not silently drop the filter.
    """
    level_set: frozenset[str] | None = (
        frozenset(s.upper() for s in levels) if levels else None
    )
    needle: re.Pattern[str] | None = None
    if grep:
        needle = re.compile(grep, re.IGNORECASE) if regex \
            else re.compile(re.escape(grep), re.IGNORECASE)

    for raw_line in lines:
        if not raw_line.strip():
            continue
        rec = _parse_line(raw_line)

        if level_set is not None and rec.level and rec.level not in level_set:
            continue

        if since is not None or until is not None:
            ts = _parse_ts(rec.ts)
            if ts is None:
                # Unparseable timestamp — keep it only when no time filter is set.
                continue
            if since is not None and ts < since:
                continue
            if until is not None and ts > until:
                continue

        if trace_id and trace_id not in rec.trace_id:
            continue

        if needle is not None and not needle.search(rec.raw):
            continue

        yield rec


def parse_ts(ts: str) -> _dt.datetime | None:
    """Parse a log timestamp substring into a ``datetime``, or ``None``.

    Accepts the two formats the loggers emit — space-separated
    ``"%Y-%m-%d %H:%M:%S"`` and ISO ``"%Y-%m-%dT%H:%M:%S"``. Sub-second and
    timezone suffixes are not expected in our log lines and parse to ``None``;
    callers (time-window filtering, the histogram) treat ``None`` as
    "no usable timestamp" and skip the row.
    """
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return _dt.datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


# Internal alias retained so existing call-sites keep working after the
# function was promoted to the public API.
_parse_ts = parse_ts


# ── Export ───────────────────────────────────────────────────────────────────

def export_filtered(records: Iterable[ParsedRecord]) -> bytes:
    """Render a filtered slice as UTF-8 bytes for st.download_button.

    Uses the post-redaction raw line so the exported file matches what the
    superadmin saw on screen — no secret leaks via download.
    """
    out: list[str] = [rec.raw for rec in records]
    return ("\n".join(out) + "\n").encode("utf-8")
