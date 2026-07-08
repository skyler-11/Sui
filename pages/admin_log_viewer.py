"""
pages/admin_log_viewer.py — SuperAdmin: Log Viewer view.

Exposes a ``render()`` function consumed by ``pages/admin_console.py`` inside
a tab. The backend in ``app.core.log_reader`` does the heavy lifting — path
hardening, reverse-chunk tail, parsing, filtering, redaction. This module is
the thin Streamlit shell that exposes filter controls and audits every
interaction.

Gating: the role gate is the first executable line of ``render()`` so any
direct call (script, repl, test) still trips the deny screen.

Audit instrumentation (every interaction):
  * First open per session  → ``action="log_viewer_opened"``
  * Filter submit           → ``action="log_viewer_search"`` + filter terms
  * Export                  → ``action="log_viewer_export"``
  * Role denial             → ``action="log_viewer_access_denied"``
                              (emitted from ``require_role``)
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import cast

import pandas as pd
import streamlit as st

from app import ui
from app.auth import require_role
from app.core.log_reader import (
    MAX_LINES_HARD_CAP,
    export_filtered,
    filter_lines,
    list_archives,
    parse_ts,
    tail_lines,
)
from app.core.logging import get_audit_logger, get_logger
from app.core.roles import MANNING_SUPERADMIN
from app.utils import log_user_action

logger = get_logger("forge.log_viewer")
audit_logger = get_audit_logger()


def _sanitize_filter_term(s: str, *, limit: int = 200) -> str:
    """Trim and strip control chars before letting a filter value reach
    the audit log."""
    s = (s or "")[:limit]
    return re.sub(r"[\x00-\x1f\x7f]", "", s)


_HIST_LEVELS = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")

# Level → (background, text) for the grid's Level cell, per theme. Mirrors the
# ``--c-*-bg`` / ``--c-*-text`` chip token pairs in style.css (AA-legible on
# both surfaces). The st.dataframe grid is canvas-rendered and won't follow the
# in-app theme toggle for its chrome, but these explicit Styler colours always
# render, so severity stays readable in light *and* dark.
_GRID_LEVEL_STYLE: dict[str, dict[str, tuple[str, str]]] = {
    "light": {
        "CRITICAL": ("#fef2f2", "#991b1b"),
        "ERROR":    ("#fef2f2", "#991b1b"),
        "WARNING":  ("#fffbeb", "#92400e"),
        "INFO":     ("#eff6ff", "#1e40af"),
        "DEBUG":    ("#f1f5f9", "#475569"),
    },
    "dark": {
        "CRITICAL": ("#2a1212", "#fca5a5"),
        "ERROR":    ("#2a1212", "#fca5a5"),
        "WARNING":  ("#2a1f04", "#fcd34d"),
        "INFO":     ("#0c1a3a", "#93c5fd"),
        "DEBUG":    ("#1f2937", "#cbd5e1"),
    },
}


def _coerce_level(level: str) -> str:
    """Normalise a record level to one of the five known severities.

    Unparsed/blank levels fall back to ``DEBUG`` so they still bin into the
    histogram and tint in the grid instead of dropping out silently.
    """
    lvl = (level or "").upper()
    return lvl if lvl in _HIST_LEVELS else "DEBUG"


def render() -> None:
    """Render the Log Viewer view. Called from admin_console.py."""

    # ── Defense-in-depth ────────────────────────────────────────────────
    require_role(MANNING_SUPERADMIN, audit_action="log_viewer_access_denied")

    # ── First-render audit (once per session) ───────────────────────────
    if not st.session_state.get("_log_viewer_opened_logged"):
        log_user_action("log_viewer_opened")
        st.session_state._log_viewer_opened_logged = True

    # ── Archive enumeration ─────────────────────────────────────────────
    archives = list_archives()
    if not archives:
        st.info(
            "📭 No log files found in the configured log directory yet."
        )
        return

    # ── Stream + archive selectors ──────────────────────────────────────
    top_a, top_b, top_c = st.columns([1, 2, 1], gap="medium")
    with top_a:
        stream_filter = st.segmented_control(
            "Stream",
            options=["app", "audit"],
            default="app",
            help="`app` = developer/ops logs · "
                 "`audit` = compliance/security events.",
        )
        if stream_filter is None:
            stream_filter = "app"

    stream_archives = [a for a in archives if a.stream == stream_filter]
    if not stream_archives:
        st.info(f"📭 No archives found for stream `{stream_filter}`.")
        return

    label_to_meta = {
        f"{a.date_label}  ·  {a.size_bytes / 1024:.1f} KB": a
        for a in stream_archives
    }

    with top_b:
        selected_label = st.selectbox(
            "Date archive",
            options=list(label_to_meta.keys()),
            index=0,
            help="`Today (live)` reads the current active file. Older "
                 "entries are dated archives produced at midnight rotation.",
        )
        selected = label_to_meta[selected_label]

    with top_c:
        # Vertical alignment with the two adjacent selectors. Streamlit
        # widgets carry a built-in label slot above them; emit an empty
        # label of matching height instead of an &nbsp; markdown hack.
        st.markdown(
            '<div class="ms-label-spacer" aria-hidden="true">&nbsp;</div>',
            unsafe_allow_html=True,
        )
        if st.button(
            "🔄 Refresh", width="stretch", help="Re-tail the selected file.",
            key="logv_refresh_btn",
        ):
            st.rerun()

    # ── Filter panel ────────────────────────────────────────────────────
    with st.expander("🔍 Filters", expanded=False):
        with st.container(key="logv_filterbar"):
            with st.form("log_viewer_filters", clear_on_submit=False):
                row1_a, row1_b = st.columns([2, 1], gap="medium")
                with row1_a:
                    levels = st.multiselect(
                        "Level",
                        options=[
                            "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL",
                        ],
                        default=["INFO", "WARNING", "ERROR", "CRITICAL"],
                    )
                with row1_b:
                    max_bytes_label = st.selectbox(
                        "Max bytes per render",
                        options=["256 KB", "1 MB", "5 MB"],
                        index=1,
                    )

                row2_a, row2_b = st.columns(2, gap="medium")
                with row2_a:
                    grep_q = st.text_input(
                        "Grep / regex", value="",
                        placeholder="search text or pattern…",
                    )
                with row2_b:
                    trace_id_q = st.text_input(
                        "Trace ID contains", value="",
                        placeholder="e.g. sesh-19fb1963b2",
                    )

                row3_a, row3_b, row3_c = st.columns(3, gap="medium")
                with row3_a:
                    regex_mode = st.checkbox("Regex mode", value=False)
                with row3_b:
                    mask_pii = st.checkbox(
                        "Mask PII (emails)", value=False,
                        help="Always-on: Bearer tokens, JWTs, password=/"
                             "secret=/token= are masked. Turn this on to "
                             "also mask emails — useful when screen-sharing.",
                    )
                with row3_c:
                    max_lines = st.number_input(
                        "Max lines",
                        min_value=100,
                        max_value=MAX_LINES_HARD_CAP,
                        value=2_000,
                        step=100,
                    )

                # Time-of-day window scoped to the selected archive's date.
                if selected.date_label == "Today (live)":
                    archive_date = _dt.date.today()
                else:
                    try:
                        archive_date = _dt.date.fromisoformat(
                            selected.date_label,
                        )
                    except ValueError:
                        archive_date = _dt.date.today()

                row4_a, row4_b = st.columns(2, gap="medium")
                with row4_a:
                    time_since = st.time_input(
                        "From (time of day, optional)",
                        value=_dt.time(0, 0),
                    )
                with row4_b:
                    time_until = st.time_input(
                        "To (time of day, optional)",
                        value=_dt.time(23, 59),
                    )

                submitted = st.form_submit_button(
                    "🔍 Apply filters", type="primary", width="stretch",
                )

    # ── Resolve filter values ───────────────────────────────────────────
    _BYTES_MAP = {
        "256 KB": 256 * 1024,
        "1 MB":   1024 * 1024,
        "5 MB":   5 * 1024 * 1024,
    }
    max_bytes = _BYTES_MAP[max_bytes_label]

    since_dt = (
        _dt.datetime.combine(archive_date, time_since)
        if time_since != _dt.time(0, 0) else None
    )
    until_dt = (
        _dt.datetime.combine(archive_date, time_until)
        if time_until != _dt.time(23, 59) else None
    )

    # ── Audit the search (only on form submit) ──────────────────────────
    if submitted:
        log_user_action(
            "log_viewer_search",
            stream=stream_filter,
            archive=selected.filename,
            levels=",".join(levels) if levels else "ALL",
            trace_filter=_sanitize_filter_term(trace_id_q),
            grep=_sanitize_filter_term(grep_q),
            regex=str(regex_mode).lower(),
            mask_pii=str(mask_pii).lower(),
        )

    # ── Read + filter ───────────────────────────────────────────────────
    try:
        raw_lines = tail_lines(
            selected.filename,
            max_bytes=max_bytes,
            max_lines=int(max_lines),
            mask_pii=mask_pii,
        )
    except ValueError as e:
        logger.error('log_viewer_read_rejected error="%s"', str(e)[:200])
        st.error(
            "Could not open that log file. The selection is no longer valid."
        )
        return
    except OSError as e:
        logger.error('log_viewer_read_failed error="%s"', str(e)[:200])
        st.error("Could not read the log file. Check the server log directory.")
        return

    try:
        records = list(filter_lines(
            raw_lines,
            levels=levels or None,
            since=since_dt,
            until=until_dt,
            trace_id=cast(str, _sanitize_filter_term(trace_id_q)) or None,
            grep=cast(str, _sanitize_filter_term(grep_q)) or None,
            regex=regex_mode,
        ))
    except re.error as e:
        st.error(f"Invalid regex: {e}")
        return

    # ── KPI row ─────────────────────────────────────────────────────────
    errors_n = sum(1 for r in records if r.level in ("ERROR", "CRITICAL"))
    warnings_n = sum(1 for r in records if r.level == "WARNING")

    with st.container(key="admin_kpi_row_logs"):
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Matching lines", f"{len(records):,}")
        k2.metric(
            "Errors / Critical", f"{errors_n:,}",
            delta="!" if errors_n else "ok",
            delta_color="inverse" if errors_n else "off",
        )
        k3.metric("Warnings", f"{warnings_n:,}", delta_color="off")
        k4.metric(
            "File on disk", f"{selected.size_bytes / 1024:.1f} KB",
            delta=selected.filename, delta_color="off",
        )

    # ── Telescope dashboard: histogram → full-width grid → detail ────────
    if not records:
        st.info("No lines match the current filter.")
    else:
        # Time-distribution histogram (events over time, stacked by severity).
        # Rows whose timestamp can't be parsed are excluded from the chart but
        # still appear in the grid below.
        hist_rows = [
            {"ts": dt, "level": _coerce_level(r.level)}
            for r in records
            if (dt := parse_ts(r.ts)) is not None
        ]
        if hist_rows:
            ui.severity_histogram(
                pd.DataFrame(hist_rows), theme=ui.get_theme(),
            )

        # Full-width selectable log grid. Positional row order matches
        # ``records`` exactly, so the selection index maps straight back.
        grid_df = pd.DataFrame(
            [
                {
                    "Level": _coerce_level(r.level),
                    "Time": r.ts or "—",
                    "Logger": r.logger or "—",
                    "Trace": r.trace_id or "—",
                    "Message": (r.message or "").replace("\n", " "),
                }
                for r in records
            ]
        )

        level_style = _GRID_LEVEL_STYLE.get(
            ui.get_theme(), _GRID_LEVEL_STYLE["light"]
        )

        def _level_cell_css(level: str) -> str:
            bg, fg = level_style.get(level, level_style["DEBUG"])
            return f"background-color:{bg};color:{fg};font-weight:600"

        styled = grid_df.style.map(_level_cell_css, subset=["Level"])

        st.caption(f"Results · {len(records):,} lines · click a row to inspect")
        event = st.dataframe(
            styled,
            key="logv_grid",
            on_select="rerun",
            selection_mode="single-row",
            hide_index=True,
            width="stretch",
            height=440,
            column_config={
                "Level": st.column_config.TextColumn("Level", width="small"),
                "Time": st.column_config.TextColumn("Time", width="small"),
                "Logger": st.column_config.TextColumn("Logger", width="medium"),
                "Trace": st.column_config.TextColumn("Trace", width="small"),
                "Message": st.column_config.TextColumn(
                    "Message", width="large",
                ),
            },
        )

        # Detail card for the selected row, full width below the grid.
        selected_rows = list(getattr(event.selection, "rows", []) or [])
        if selected_rows:
            r = records[selected_rows[0]]
            ui.log_detail(
                ts=r.ts,
                level=r.level,
                logger_name=r.logger,
                trace_id=r.trace_id,
                message=r.message,
                extra_meta={
                    "Stream": stream_filter,
                    "Archive": selected.filename,
                },
            )
        else:
            st.caption("Select a row above to inspect the full entry.")

    # ── Export ──────────────────────────────────────────────────────────
    if records:
        user_id = st.session_state.get("user_id", "anonymous")
        safe_user_id = re.sub(r"[^A-Za-z0-9_.\-]", "_", user_id)[:40]
        ts_for_name = _dt.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        fname = (
            f"manning-logs_{stream_filter}_"
            f"{selected.date_label.replace(' ', '_')}_"
            f"{safe_user_id}_{ts_for_name}.txt"
        )

        payload = export_filtered(records)

        col_dl, _ = st.columns([1, 3])
        with col_dl:
            if st.download_button(
                "⬇️ Download filtered slice",
                data=payload,
                file_name=fname,
                mime="text/plain",
                width="stretch",
                type="secondary",
            ):
                log_user_action(
                    "log_viewer_export",
                    stream=stream_filter,
                    archive=selected.filename,
                    lines=len(records),
                    bytes=len(payload),
                    mask_pii=str(mask_pii).lower(),
                )
