"""
Logging configuration for Manning Simulator.

App logs   → <LOG_DIR>/app.log    (developer / ops audience)
Audit logs → <LOG_DIR>/audit.log  (compliance / security audience)

Both streams roll over at midnight (local time). Yesterday's content moves to
<LOG_DIR>/<stream>.log.YYYY-MM-DD; the active file keeps the bare name. The
retention window is controlled by MANNING_LOG_RETENTION_DAYS (default 90).

LOG DESTINATION:
    By default <LOG_DIR> resolves to `<repo>/app/logs/` (the directory next
    to this file's package). Override either of the following to relocate:

      1. Code default — edit `_DEFAULT_LOG_DIR` below (module constant).
      2. Env var      — set MANNING_LOG_DIR (absolute or repo-relative path).

    The env var wins over the code default. Relative paths are resolved
    against the repo root (the parent of the `app/` package).

    Examples:
      set  MANNING_LOG_DIR=D:\manning\logs           (Windows cmd, absolute)
      $env:MANNING_LOG_DIR = "C:\logs\manning"       (PowerShell, absolute)
      export MANNING_LOG_DIR=/var/log/manning        (Linux/macOS, absolute)
      set  MANNING_LOG_DIR=logs                       (repo-root relative)

Log level is controlled by the MANNING_LOG_LEVEL environment variable.
Valid values: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)

Log format is controlled by MANNING_LOG_FORMAT:
    "json"  → newline-delimited JSON (Splunk/Datadog ingestion)
    other   → human-readable text format (default)

IMPORTANT — import-time resolution:
    _LOG_LEVEL, _USE_JSON, and _LOG_DIR are read once when this module is
    first imported. If the env vars are set AFTER import (e.g. mid-process
    in tests), the new values will NOT take effect for existing loggers.
    Always set the env vars before the Python process starts.

Usage:
    Windows (cmd):    set MANNING_LOG_LEVEL=DEBUG
    Windows (PS):     $env:MANNING_LOG_LEVEL = "DEBUG"
    Linux/macOS:      export MANNING_LOG_LEVEL=DEBUG

SECURITY — Log Injection Protection:
    All user-supplied values passed to audit_logger.info() are sanitized
    via _sanitize() before reaching the formatter. This prevents an attacker
    from injecting fake log entries by embedding newline characters in their
    username, file names, or other inputs.

TRACE PROPAGATION:
    A contextvars-backed trace_id is automatically injected into every log
    record via TraceFilter, so callers do not need to pass trace_id manually
    on every log line. Call set_trace_id(...) once per Streamlit re-run
    (typically in init_session_state) and every subsequent log line in that
    same execution context will carry it.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import platform
import re
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler


def _diagnose_python_processes() -> str:
    """Best-effort enumeration of python.exe processes on this Windows host.

    Used by ``_SafeTimedRotatingFileHandler.doRollover`` to tell the operator
    WHICH process is likely holding the log file open when midnight rotation
    fails with ``WinError 32``. Pure-stdlib via PowerShell; no extra deps.

    Contract: this MUST NEVER raise. Any failure (PowerShell missing on the
    host, timeout, JSON parse error, permission denial) returns a single
    string `(diagnostic unavailable: <reason>)` so the warn print still
    delivers something readable.
    """
    if sys.platform != "win32":
        return "(diagnostic skipped: non-Windows host)"
    try:
        import subprocess
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" "
                "| Select-Object ProcessId, CreationDate, CommandLine "
                "| ConvertTo-Json -Compress",
            ],
            capture_output=True, text=True, timeout=3.0,
        )
        raw = (result.stdout or "").strip()
        if not raw:
            return "(no python.exe processes found via PowerShell)"
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        own_pid = os.getpid()
        lines: list[str] = [
            f"       likely lockers (python.exe processes on this host; "
            f"own pid is {own_pid}):",
        ]

        def _fmt_started(raw: object) -> str:
            """PowerShell CIM dates serialize to /Date(<unix_ms>)/. Convert
            to a readable local time; fall back to the raw string."""
            import datetime as _dt
            import re as _re
            s = str(raw or "")
            m = _re.search(r"\\?/Date\((\d+)", s)
            if m:
                try:
                    return _dt.datetime.fromtimestamp(
                        int(m.group(1)) / 1000,
                    ).strftime("%Y-%m-%d %H:%M:%S")
                except (OverflowError, OSError, ValueError):
                    pass
            return s[:19] if s else "?"

        for entry in data[:5]:
            pid = entry.get("ProcessId", "?")
            cmd = str(entry.get("CommandLine") or "")[:120]
            ts = _fmt_started(entry.get("CreationDate"))
            marker = "  <-- this process" if pid == own_pid else ""
            lines.append(
                f"         pid={pid} started={ts} cmd={cmd!r}{marker}"
            )
        if len(data) > 5:
            lines.append(f"         (+{len(data) - 5} more not shown)")
        return "\n".join(lines)
    except Exception as e:
        return f"(diagnostic unavailable: {type(e).__name__}: {str(e)[:100]})"


class _SafeTimedRotatingFileHandler(TimedRotatingFileHandler):
    """Windows-safe rotation: retries on transient PermissionError and
    suppresses the noisy stderr trace when a peer process briefly holds
    the log file open.

    Windows refuses to rename or open a file that another process holds
    open. Three pain points the stock handler exposes on Windows:

      1. **Rollover rename** (`os.rename`) — fails with ``WinError 32``.
      2. **Post-rollover re-open** (`self._open()`) — same error window.
      3. **Subsequent emit()** — if rollover left ``self.stream = None``,
         ``StreamHandler.emit`` writes to None → `Handler.handleError`
         prints ``--- Logging error ---`` plus a traceback to stderr,
         which is what shows up in the bat console as the orange WinError
         line.

    This subclass plugs all three:
      * Bounded retry around `super().doRollover()` (200ms · 400ms · 600ms).
      * On give-up, attempt to re-open the active baseFilename so the
        next emit has a working stream. If even that fails, fall back to
        ``os.devnull`` — logs are dropped for one cycle, but the app
        keeps running and the console stays clean.
      * Override `handleError` to silently swallow ``OSError`` with
        ``winerror == 32`` (file-lock). All other errors fall through to
        the stock behavior so real bugs still surface.
    """

    _MAX_ATTEMPTS = 3
    _LOCK_WINERROR = 32  # ERROR_SHARING_VIOLATION
    # Cooldown (seconds) between the expensive PowerShell lock diagnostics so a
    # persistent locker can't make us spawn a subprocess on a tight loop.
    _DIAG_COOLDOWN_S = 300.0

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Last time we ran (or skipped) the WARN+diagnostic for a failed
        # rollover. ``0.0`` means "never", so the first failure always reports.
        self._last_diag_at: float = 0.0

    def doRollover(self) -> None:
        import time as _time
        last_err: Exception | None = None
        for attempt in range(self._MAX_ATTEMPTS):
            try:
                super().doRollover()
                return
            except PermissionError as e:
                last_err = e
                _time.sleep(0.2 * (attempt + 1))

        # Retries exhausted — the peer process still holds the file. Advance
        # rolloverAt to the next boundary FIRST: the stock handler only does
        # this inside a successful super().doRollover(), so leaving it stale
        # makes shouldRollover() return True on every subsequent emit, turning
        # one locked rollover into a per-log-line retry storm (and, with the
        # diagnostic below, a PowerShell subprocess per line). Backing off to
        # the next interval is the key fix.
        now = int(_time.time())
        new_rollover = self.computeRollover(now)
        # computeRollover can return a time already in the past if the clock is
        # well beyond the missed boundary; keep stepping until it's in the
        # future so we don't immediately re-fire.
        while new_rollover <= now:
            new_rollover = self.computeRollover(new_rollover)
        self.rolloverAt = new_rollover

        # Throttle the WARN + PowerShell diagnostic: report at most once per
        # cooldown window. The diagnostic helper names the python.exe processes
        # on this host so ops can identify the locker, but it runs a ~3s
        # subprocess, so it must never run on a hot path.
        wall = _time.time()
        if wall - self._last_diag_at >= self._DIAG_COOLDOWN_S:
            self._last_diag_at = wall
            print(
                f"WARN: log rotation skipped due to file lock "
                f"({self.baseFilename}): {last_err}\n"
                f"{_diagnose_python_processes()}",
                file=sys.stderr,
            )
        try:
            self.stream = self._open()
        except OSError:
            try:
                self.stream = open(os.devnull, "a", encoding="utf-8")
                print(
                    f"WARN: log handler fell back to os.devnull for "
                    f"{self.baseFilename} until lock clears",
                    file=sys.stderr,
                )
            except OSError:
                self.stream = None  # genuinely nothing we can do

    def handleError(self, record: logging.LogRecord) -> None:
        """Silently drop the noisy stderr traceback when a write hits the
        Windows file-lock error. Any other logging error falls through to
        the stock handler so real bugs still surface."""
        exc = sys.exc_info()[1]
        if isinstance(exc, OSError) and getattr(
            exc, "winerror", None,
        ) == self._LOCK_WINERROR:
            return
        super().handleError(record)


# ── LEVEL RESOLUTION ─────────────────────────────────────────────────────────

_ENV_LEVEL = os.environ.get("MANNING_LOG_LEVEL", "INFO").strip().upper()
_LOG_LEVEL: int = getattr(logging, _ENV_LEVEL, logging.INFO)

_ENV_FORMAT = os.environ.get("MANNING_LOG_FORMAT", "JSON").strip().lower()
_USE_JSON: bool = _ENV_FORMAT == "json"


# ── LOG DIRECTORY (editable) ─────────────────────────────────────────────────
#
# EDIT THIS to change where app.log / audit.log are written.
#   - Path is resolved at import time.
#   - May be an absolute Path or a string relative to the repo root.
#   - Env var MANNING_LOG_DIR overrides this default at runtime.
#
# Repo root = parent of the `app/` package = `Path(__file__).parents[2]`.
# Default `<repo>/app/logs` matches the historical on-disk location.
_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_DEFAULT_LOG_DIR: Path = _REPO_ROOT / "app" / "logs"


def _resolve_log_dir() -> Path:
    """Env var MANNING_LOG_DIR wins; relative paths anchor at the repo root."""
    raw = os.environ.get("MANNING_LOG_DIR", "").strip()
    if not raw:
        return _DEFAULT_LOG_DIR
    p = Path(raw)
    return p if p.is_absolute() else (_REPO_ROOT / p)


_LOG_DIR: Path = _resolve_log_dir()


# ── RETENTION ────────────────────────────────────────────────────────────────
# Per-day archives are produced by TimedRotatingFileHandler (when="midnight").
# Override the retention window via MANNING_LOG_RETENTION_DAYS (integer days,
# default 90). 90 days × ~5 MB/day worst case ≈ 450 MB per stream — dial down
# on small VMs.
def _resolve_retention_days() -> int:
    raw = os.environ.get("MANNING_LOG_RETENTION_DAYS", "").strip()
    if not raw:
        return 90
    try:
        n = int(raw)
        return n if n >= 0 else 90
    except ValueError:
        return 90


_LOG_RETENTION_DAYS: int = _resolve_retention_days()


# ── LOG INJECTION SANITIZATION ────────────────────────────────────────────────

# Control characters that could be used to inject fake log lines.
# Covers \n, \r, \t, and all other ASCII control chars (0x00–0x1F, 0x7F).
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize(value: object) -> object:
    if isinstance(value, str):
        return _CONTROL_CHAR_RE.sub("", value)
    if isinstance(value, (list, tuple)):
        cleaned = [_sanitize(v) for v in value]
        return type(value)(cleaned)
    if isinstance(value, set):
        return {_sanitize(v) for v in value}
    if isinstance(value, dict):
        return {_sanitize(k): _sanitize(v) for k, v in value.items()}
    return value  # int, float, bool, None, etc. — pass through unchanged


# ── TRACE ID PROPAGATION (contextvars) ────────────────────────────────────────
#
# Streamlit reruns its script for every interaction. A trace_id stored on
# the contextvar lets every log call within that execution carry the same
# correlation ID without callers passing it on every log line.

_trace_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "trace_id", default="no-trace"
)


def set_trace_id(trace_id: str) -> None:
    """Set the active trace_id for the current execution context."""
    _trace_id_var.set(trace_id)


def get_trace_id() -> str:
    """Return the current execution context's trace_id (or 'no-trace')."""
    return _trace_id_var.get()


class TraceFilter(logging.Filter):
    """
    Injects the contextvar trace_id into every LogRecord as `trace_id`,
    so the formatter can render it via %(trace_id)s without the caller
    having to pass it explicitly.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "trace_id") or not getattr(record, "trace_id", None):
            record.trace_id = _trace_id_var.get()
        return True


# ── FORMATTERS ────────────────────────────────────────────────────────────────

def _app_formatter() -> logging.Formatter:
    """Standard formatter for application logs — includes logger name + trace."""
    return logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | trace_id=%(trace_id)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _audit_formatter() -> logging.Formatter:
    """Compact formatter for audit logs — action-focused."""
    return logging.Formatter(
        fmt="%(asctime)s | AUDIT | trace_id=%(trace_id)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


class _JsonFormatter(logging.Formatter):
    """
    Newline-delimited JSON formatter for SIEM/log aggregator ingestion.

    Includes standard fields (timestamp, level, logger, message, trace_id)
    and any extra structured fields attached to the LogRecord. The message
    is emitted post-format (so % args have already been substituted).
    """

    _STD_KEYS = {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "message", "module",
        "msecs", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "taskName", "thread", "threadName",
        "trace_id",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts":        self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level":     record.levelname,
            "logger":    record.name,
            "trace_id":  getattr(record, "trace_id", "no-trace"),
            "message":   record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Surface any user-attached extras
        for k, v in record.__dict__.items():
            if k not in self._STD_KEYS and not k.startswith("_"):
                try:
                    json.dumps(v)  # ensure serialisable
                    payload[k] = v
                except Exception:
                    payload[k] = str(v)
        return json.dumps(payload, ensure_ascii=False, default=str)


def _select_app_formatter() -> logging.Formatter:
    return _JsonFormatter() if _USE_JSON else _app_formatter()


def _select_audit_formatter() -> logging.Formatter:
    return _JsonFormatter() if _USE_JSON else _audit_formatter()


# ── FILE HANDLER FACTORY ──────────────────────────────────────────────────────

def _try_file_handler(filename: str) -> logging.FileHandler | None:
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)

        # Per-day archives — active file stays at `<filename>`; rotated files
        # gain a `.YYYY-MM-DD` suffix matching the date they cover. The log
        # viewer's archive enumerator (`app.core.log_reader.list_archives`)
        # depends on this exact suffix format. We use the Windows-safe
        # subclass so a midnight rollover that loses a rename race against a
        # second writer logs a warning instead of crashing.
        handler = _SafeTimedRotatingFileHandler(
            _LOG_DIR / filename,
            when="midnight",
            interval=1,
            backupCount=_LOG_RETENTION_DAYS,
            encoding="utf-8",
            utc=False,
        )
        handler.suffix = "%Y-%m-%d"
        return handler
    except Exception as e:
        # stderr survives `start /B` redirection better than stdout, and
        # surfaces silent permission/lock failures during IIS-launched runs.
        print(
            f"CRITICAL LOGGING ERROR: Could not create {_LOG_DIR / filename} → {e}",
            file=sys.stderr,
        )
        return None


# ── SANITIZING ADAPTER ────────────────────────────────────────────────────────

class _SanitizingAdapter(logging.LoggerAdapter):
    """
    Wraps a logger and sanitizes all positional % args before they are
    formatted into the log message. This intercepts user-supplied values
    (usernames, filenames, action strings) at the boundary where they enter
    the logging system, regardless of which log call site invoked it.
    """

    def process(self, msg, kwargs):
        return msg, kwargs

    def info(self, msg, *args, **kwargs):
        clean_args = tuple(_sanitize(a) for a in args)
        self.logger.info(msg, *clean_args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        clean_args = tuple(_sanitize(a) for a in args)
        self.logger.warning(msg, *clean_args, **kwargs)

    def error(self, msg, *args, **kwargs):
        clean_args = tuple(_sanitize(a) for a in args)
        self.logger.error(msg, *clean_args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        clean_args = tuple(_sanitize(a) for a in args)
        self.logger.exception(msg, *clean_args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        clean_args = tuple(_sanitize(a) for a in args)
        self.logger.critical(msg, *clean_args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        clean_args = tuple(_sanitize(a) for a in args)
        self.logger.debug(msg, *clean_args, **kwargs)


# ── PUBLIC API ────────────────────────────────────────────────────────────────

def _attach_trace_filter(handler: logging.Handler) -> None:
    """Idempotently attach a TraceFilter to a handler."""
    if not any(isinstance(f, TraceFilter) for f in handler.filters):
        handler.addFilter(TraceFilter())


def get_logger(name: str) -> _SanitizingAdapter:
    """
    Returns a configured application logger wrapped in a sanitizing adapter.

    - Respects MANNING_LOG_LEVEL env var (resolved at import time).
    - Writes to console (always) and logs/app.log (if filesystem allows).
    - Safe to call multiple times for the same name — handlers not duplicated.
    - All % args are sanitized against log injection before formatting.
    - All records carry a `trace_id` field via TraceFilter.
    """
    raw_logger = logging.getLogger(name)
    if not raw_logger.handlers:
        raw_logger.setLevel(_LOG_LEVEL)
        raw_logger.propagate = False

        formatter = _select_app_formatter()

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        _attach_trace_filter(stream_handler)
        raw_logger.addHandler(stream_handler)

        file_handler = _try_file_handler("app.log")
        if file_handler:
            file_handler.setFormatter(formatter)
            _attach_trace_filter(file_handler)
            raw_logger.addHandler(file_handler)
        else:
            raw_logger.warning(
                "Could not open logs/app.log — running in console-only mode."
            )

    return _SanitizingAdapter(raw_logger, {})


def get_audit_logger() -> _SanitizingAdapter:
    """
    Returns a dedicated audit logger for user action events.

    - Fixed at INFO — audit records are never DEBUG-level noise.
    - Writes to logs/audit.log (separate from app.log for independent retention).
    - All % args are sanitized against log injection before formatting.
    - All records carry a `trace_id` field via TraceFilter.
    """
    name = "manning.audit"
    raw_logger = logging.getLogger(name)

    if not raw_logger.handlers:
        raw_logger.setLevel(logging.INFO)
        raw_logger.propagate = False

        formatter = _select_audit_formatter()

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        _attach_trace_filter(stream_handler)
        raw_logger.addHandler(stream_handler)

        file_handler = _try_file_handler("audit.log")
        if file_handler:
            file_handler.setFormatter(formatter)
            _attach_trace_filter(file_handler)
            raw_logger.addHandler(file_handler)
        else:
            raw_logger.warning(
                "Could not open logs/audit.log — audit events will only appear in console."
            )

    return _SanitizingAdapter(raw_logger, {})


def get_json_logger(name: str) -> _SanitizingAdapter:
    """
    Returns a logger that always emits newline-delimited JSON, regardless of
    the MANNING_LOG_FORMAT env var. Useful for components that must guarantee
    machine-parseable output (e.g. forwarder integrations).

    Existing callers of get_logger() are unaffected — this is purely additive.
    """
    raw_logger = logging.getLogger(f"{name}.json")
    if not raw_logger.handlers:
        raw_logger.setLevel(_LOG_LEVEL)
        raw_logger.propagate = False

        formatter = _JsonFormatter()

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        _attach_trace_filter(stream_handler)
        raw_logger.addHandler(stream_handler)

        file_handler = _try_file_handler("app.json.log")
        if file_handler:
            file_handler.setFormatter(formatter)
            _attach_trace_filter(file_handler)
            raw_logger.addHandler(file_handler)

    return _SanitizingAdapter(raw_logger, {})


# ── PERFORMANCE TIMING CONTEXT MANAGER ───────────────────────────────────────

@contextmanager
def timing(logger_instance, operation: str, **ctx):
    """
    Context manager that logs elapsed time at DEBUG level on exit.

    Usage:
        with timing(logger, "parse_file", filename=name, size_kb=42.1):
            do_work()

    Output:
        '... | DEBUG | ... | operation="parse_file" elapsed_ms=142.3 filename="..." size_kb="42.1"'
    """
    t0 = time.perf_counter()
    try:
        yield
    finally:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        extra = " ".join(f'{k}="{v}"' for k, v in ctx.items())
        logger_instance.debug(
            'operation="%s" elapsed_ms=%.1f %s',
            operation, elapsed_ms, extra,
        )


# ── STARTUP BANNER ────────────────────────────────────────────────────────────

def log_startup_banner(version: str) -> None:
    """
    Emits a one-time INFO banner so ops can correlate process boots with
    log files. Includes app version, Python version, platform, PID, and
    the configured log level.
    """
    banner_logger = get_logger("forge.boot")
    banner_logger.info(
        'startup app_version="%s" python="%s" platform="%s" pid=%d log_level="%s" log_format="%s"',
        version,
        sys.version.split()[0],
        platform.platform(),
        os.getpid(),
        _ENV_LEVEL,
        "json" if _USE_JSON else "text",
    )
