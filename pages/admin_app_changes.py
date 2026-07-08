"""
pages/admin_app_changes.py — SuperAdmin: Application Changes view.

Exposes a ``render()`` function consumed by ``pages/admin_console.py`` inside
a tab. Where the Log Viewer is a raw-line tail of every stream, this view is a
*purpose-built* feed: it reads the ``audit`` stream and surfaces only the
admin changes to validation rules and defaults — threshold edits, active-rule
pins/unpins, and factory resets — as friendly, human-readable rows.

It leans on the same read-side backend as the Log Viewer
(``app.core.log_reader``) so path hardening, reverse-chunk tail, and the
mandatory redaction layer all apply for free. This module is the thin
Streamlit shell that picks the relevant events, parses each into a change
row, and audits every interaction.

The change events originate in ``pages/admin_validation_defaults.py``, which
emits these audit actions directly via the audit logger:

  * ``admin_defaults_saved``            — threshold and/or active-rule save
                                          (carries ``thresholds=`` and
                                          ``active_rule_keys=``)
  * ``admin_defaults_reset_to_factory`` — danger-zone reset
  * ``admin_defaults_save_failed``      — save error
  * ``admin_defaults_reset_failed``     — reset error

Gating: the role gate is the first executable line of ``render()`` so any
direct call (script, repl, test) still trips the deny screen.

Audit instrumentation (every interaction):
  * First open per session  → ``action="app_changes_opened"``
  * Filter submit           → ``action="app_changes_search"`` + filter terms
  * Export                  → ``action="app_changes_export"``
  * Role denial             → ``action="app_changes_access_denied"``
                              (emitted from ``require_role``)

Known limitation — add/remove diffing is best-effort. The audit log records a
*snapshot* of ``active_rule_keys`` on each save, not a delta. This view
reconstructs "pinned"/"unpinned" deltas by comparing each save against the
chronologically-previous one *within the currently loaded archive window*.
A delta that straddles a midnight rotation (previous snapshot lives in
yesterday's archive) is reported as an absolute snapshot ("Pinned set: N
rules") rather than a delta, since the prior state is not in view.
"""

from __future__ import annotations

import ast
import datetime as _dt
import re
from dataclasses import dataclass

import pandas as pd
import streamlit as st

from app import ui
from app.auth import require_role
from app.core.log_reader import (
    MAX_LINES_HARD_CAP,
    filter_lines,
    list_archives,
    tail_lines,
)
from app.core.logging import get_audit_logger, get_logger
from app.core.roles import MANNING_SUPERADMIN
from app.core.rules import AVAILABLE_RULES
from app.utils import log_user_action

logger = get_logger("forge.app_changes")
audit_logger = get_audit_logger()


# ── Constants ──────────────────────────────────────────────────────────────
# The audit-action strings emitted by admin_validation_defaults.py that this
# view recognizes. Kept as a module constant so a grep for the producer side
# (action="admin_defaults_) lines up with the consumer side here.

_CHANGE_ACTIONS: frozenset[str] = frozenset({
    "admin_defaults_saved",
    "admin_defaults_reset_to_factory",
    "admin_defaults_save_failed",
    "admin_defaults_reset_failed",
})

# Friendly labels for the action-filter dropdown. Order is display order.
_ACTION_FILTER_LABELS: dict[str, str] = {
    "ALL": "All change types",
    "admin_defaults_saved": "Saves (thresholds / active rules)",
    "admin_defaults_reset_to_factory": "Factory resets",
    "admin_defaults_save_failed": "Failed saves",
    "admin_defaults_reset_failed": "Failed resets",
}

# Action → (friendly grid label, detail-card tone). Drives the styled "Type"
# cell in the selectable grid and the tone pill on the change-detail card.
_TYPE_MAP: dict[str, tuple[str, str]] = {
    "admin_defaults_saved": ("Save", "success"),
    "admin_defaults_reset_to_factory": ("Reset", "warn"),
    "admin_defaults_save_failed": ("Failed save", "danger"),
    "admin_defaults_reset_failed": ("Failed reset", "danger"),
}

# Friendly label → (background, text) for the grid's Type cell, per theme.
# Mirrors the Log Viewer's _GRID_LEVEL_STYLE and the ``--c-*-bg`` / ``--c-*-text``
# token pairs in style.css (AA-legible on both surfaces). The st.dataframe grid
# is canvas-rendered and won't follow the in-app theme toggle for its chrome,
# but these explicit Styler colours always render, so the Type cell stays
# readable in light *and* dark.
_CHANGE_CELL_STYLE: dict[str, dict[str, tuple[str, str]]] = {
    "light": {
        "Save":         ("#f0fdf4", "#166534"),
        "Reset":        ("#fffbeb", "#92400e"),
        "Failed save":  ("#fef2f2", "#991b1b"),
        "Failed reset": ("#fef2f2", "#991b1b"),
    },
    "dark": {
        "Save":         ("#0a2418", "#86efac"),
        "Reset":        ("#2a1f04", "#fcd34d"),
        "Failed save":  ("#2a1212", "#fca5a5"),
        "Failed reset": ("#2a1212", "#fca5a5"),
    },
}
# Fallback tint for an unrecognized label, per theme.
_CHANGE_CELL_DEFAULT: dict[str, tuple[str, str]] = {
    "light": ("#f1f5f9", "#475569"),
    "dark":  ("#1f2937", "#cbd5e1"),
}

# key=value field extractors. The producer emits double-quoted string values
# for action/user_id and bare Python reprs for thresholds/active_rule_keys.
_ACTION_RE = re.compile(r'action="(?P<v>[^"]*)"')
_USER_ID_RE = re.compile(r'user_id="(?P<v>[^"]*)"')
_ERROR_RE = re.compile(r'error="(?P<v>[^"]*)"')
# thresholds=...  up to the next  active_rule_keys=  (or EOL). Python dict repr
# never contains the literal substring " active_rule_keys=", so this is safe.
_THRESHOLDS_RE = re.compile(r"thresholds=(?P<v>.+?)(?:\s+active_rule_keys=|$)")
_ACTIVE_KEYS_RE = re.compile(r"active_rule_keys=(?P<v>.+?)\s*$")

# Map rule key → human name once at import (registry is static).
_KEY_TO_NAME: dict[str, str] = {r.key: r.name for r in AVAILABLE_RULES}


# ── Parsed change row ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class ChangeRow:
    """One human-readable row in the Application Changes feed.

    Attributes:
        ts: ISO-ish timestamp lifted from the audit line.
        user_id: who performed the change (post-redaction; PII masking is
            opt-in upstream).
        action: the raw audit action string (e.g. ``admin_defaults_saved``).
        summary: friendly one-line description of what changed.
        detail: secondary context — the threshold values, the added/removed
            rule names, or the error text. May be empty.
        raw: the original (post-redaction) audit message, kept for export so
            the download matches the on-disk forensic record.
    """
    ts: str
    user_id: str
    action: str
    summary: str
    detail: str
    raw: str


# ── Field parsing helpers ──────────────────────────────────────────────────

def _literal_or_none(text: str) -> object | None:
    """Safely evaluate a Python literal repr, returning ``None`` on failure.

    SEC [CWE-95]: uses ``ast.literal_eval`` — never ``eval`` — so a forged log
    line cannot execute code. Only literals (dict/list/str/num/None) parse;
    anything else (a function call, a name) raises and we fall back to None.

    Args:
        text: the raw repr substring captured from the audit line.

    Returns:
        The parsed literal, or ``None`` if it is not a safe literal.
    """
    text = (text or "").strip()
    if not text or text == "None":
        return None
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return None


def _extract(pattern: re.Pattern[str], message: str) -> str:
    """Return the first ``v`` group of ``pattern`` in ``message`` or ``''``."""
    m = pattern.search(message)
    return m.group("v") if m else ""


def _names_for_keys(keys: list[str]) -> list[str]:
    """Map rule keys to friendly names, falling back to the raw key.

    A key present in an old log line but since removed from the registry
    surfaces as its bare key rather than vanishing — preserving the audit
    trail's fidelity.
    """
    return [_KEY_TO_NAME.get(k, k) for k in keys]


def _summarize_save(
    thresholds: object | None,
    active_keys: object | None,
    prev_active_keys: object | None,
) -> tuple[str, str]:
    """Build (summary, detail) for an ``admin_defaults_saved`` event.

    Reconstructs a pin/unpin delta against the chronologically-previous save
    when one is available *in the loaded window*. When ``prev_active_keys`` is
    a sentinel meaning "no prior snapshot in view", reports the absolute
    snapshot instead (see module docstring — best-effort diffing).

    Args:
        thresholds: parsed ``thresholds`` dict (or None).
        active_keys: parsed ``active_rule_keys`` list (or None == "use code
            defaults").
        prev_active_keys: the previous save's ``active_rule_keys`` for delta
            computation, or the ``_NO_PREV`` sentinel when none is in view.

    Returns:
        A ``(summary, detail)`` pair of display strings.
    """
    parts: list[str] = []
    detail_parts: list[str] = []

    if isinstance(thresholds, dict) and thresholds:
        parts.append("Thresholds updated")
        detail_parts.append(
            ", ".join(f"{k}={v}" for k, v in thresholds.items())
        )

    # active_rule_keys is one of: None (use code defaults) or list[str].
    if active_keys is None:
        parts.append("Active rules set to code defaults")
    elif isinstance(active_keys, list):
        cur = [k for k in active_keys if isinstance(k, str)]
        if prev_active_keys is _NO_PREV:
            # No comparable prior snapshot — report the absolute set.
            parts.append(f"Pinned set: {len(cur)} active rule(s)")
            detail_parts.append(", ".join(_names_for_keys(cur)))
        elif prev_active_keys is None:
            # Went from code-defaults → an explicit pinned set.
            parts.append(f"Pinned {len(cur)} active rule(s)")
            detail_parts.append(", ".join(_names_for_keys(cur)))
        elif isinstance(prev_active_keys, list):
            prev = [k for k in prev_active_keys if isinstance(k, str)]
            added = [k for k in cur if k not in prev]
            removed = [k for k in prev if k not in cur]
            if added:
                parts.append(f"Pinned {len(added)} rule(s)")
                detail_parts.append(
                    "added: " + ", ".join(_names_for_keys(added))
                )
            if removed:
                parts.append(f"Unpinned {len(removed)} rule(s)")
                detail_parts.append(
                    "removed: " + ", ".join(_names_for_keys(removed))
                )
            if not added and not removed:
                parts.append("Saved (no active-rule change)")

    if not parts:
        parts.append("Defaults saved")

    return " · ".join(parts), " — ".join(p for p in detail_parts if p)


# Sentinel distinguishing "no previous snapshot in the loaded window" from the
# legitimate value None ("previous save used code defaults").
_NO_PREV: object = object()


def _to_change_row(
    ts: str,
    message: str,
    prev_active_keys: object,
) -> ChangeRow:
    """Parse one audit message into a :class:`ChangeRow`.

    Args:
        ts: timestamp from the parent :class:`ParsedRecord`.
        message: the audit message body (post-redaction).
        prev_active_keys: previous save's active keys for delta context, or
            the ``_NO_PREV`` sentinel.

    Returns:
        A fully-populated :class:`ChangeRow`.
    """
    action = _extract(_ACTION_RE, message)
    user_id = _extract(_USER_ID_RE, message) or "unknown"

    if action == "admin_defaults_saved":
        thresholds = _literal_or_none(_extract(_THRESHOLDS_RE, message))
        active_keys = _literal_or_none(_extract(_ACTIVE_KEYS_RE, message))
        summary, detail = _summarize_save(
            thresholds, active_keys, prev_active_keys,
        )
    elif action == "admin_defaults_reset_to_factory":
        summary = "Reset to factory defaults"
        detail = "All thresholds restored; active rules set to code defaults."
    elif action == "admin_defaults_save_failed":
        summary = "⚠️ Save FAILED"
        detail = _extract(_ERROR_RE, message)
    elif action == "admin_defaults_reset_failed":
        summary = "⚠️ Reset FAILED"
        detail = _extract(_ERROR_RE, message)
    else:  # pragma: no cover — guarded by _CHANGE_ACTIONS prefilter
        summary = action or "Unknown change"
        detail = ""

    return ChangeRow(
        ts=ts,
        user_id=user_id,
        action=action,
        summary=summary,
        detail=detail,
        raw=message,
    )


def _build_change_feed(
    records: list,
    action_filter: str,
) -> list[ChangeRow]:
    """Turn filtered audit records into an ordered change feed.

    Records arrive newest-last from ``filter_lines`` (file order). We walk them
    oldest→newest so each save can diff against the previous save's
    ``active_rule_keys``, then return the feed newest-first for display.

    Args:
        records: ``ParsedRecord`` rows already narrowed to change events.
        action_filter: ``"ALL"`` or a specific action string. The delta walk
            always uses *all* saves for correctness, then filters the output —
            so filtering to "Factory resets" never corrupts a neighbouring
            save's add/remove diff.

    Returns:
        Change rows, newest-first.
    """
    rows: list[ChangeRow] = []
    prev_active: object = _NO_PREV

    for rec in records:
        action = _extract(_ACTION_RE, rec.message)
        if action not in _CHANGE_ACTIONS:
            continue

        # Diff context only advances on a real save snapshot.
        prev_for_this = prev_active
        row = _to_change_row(rec.ts, rec.message, prev_for_this)
        rows.append(row)

        if action == "admin_defaults_saved":
            parsed = _literal_or_none(_extract(_ACTIVE_KEYS_RE, rec.message))
            # None is a legitimate snapshot value; store it as-is.
            prev_active = parsed
        elif action == "admin_defaults_reset_to_factory":
            # Reset always sets active_rule_keys to None (code defaults).
            prev_active = None

    if action_filter != "ALL":
        rows = [r for r in rows if r.action == action_filter]

    rows.reverse()  # newest-first for display
    return rows


def _sanitize_filter_term(s: str, *, limit: int = 200) -> str:
    """Trim and strip control chars before a filter value reaches the audit
    log (mirrors the Log Viewer's boundary scrub — SEC [CWE-117])."""
    s = (s or "")[:limit]
    return re.sub(r"[\x00-\x1f\x7f]", "", s)


def _export_changes(rows: list[ChangeRow]) -> bytes:
    """Render the change feed as UTF-8 TSV bytes for ``st.download_button``.

    Tab-separated (not CSV) because ``detail`` legitimately contains commas
    (rule-name lists). Values are already control-char-scrubbed by the
    redaction layer + ``_sanitize_filter_term``; we additionally strip tabs
    from each cell so the column layout cannot be forged.

    Args:
        rows: the change rows currently displayed (post-filter).

    Returns:
        UTF-8 encoded TSV with a header line.
    """
    def _cell(v: str) -> str:
        return v.replace("\t", " ").replace("\n", " ")

    header = "timestamp\tuser_id\taction\tsummary\tdetail"
    lines = [header]
    for r in rows:
        lines.append(
            "\t".join((
                _cell(r.ts), _cell(r.user_id), _cell(r.action),
                _cell(r.summary), _cell(r.detail),
            ))
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


# ── Render ─────────────────────────────────────────────────────────────────

def render() -> None:
    """Render the Application Changes view. Called from admin_console.py."""

    # ── Defense-in-depth ────────────────────────────────────────────────
    require_role(MANNING_SUPERADMIN, audit_action="app_changes_access_denied")

    # ── First-render audit (once per session) ───────────────────────────
    if not st.session_state.get("_app_changes_opened_logged"):
        log_user_action("app_changes_opened")
        st.session_state._app_changes_opened_logged = True

    st.caption(
        "A human-readable feed of admin changes to validation rules and "
        "defaults — threshold edits, active-rule pins/unpins, and factory "
        "resets — reconstructed from the audit stream. "
        "Use the 🪵 Log Viewer for the raw lines."
    )

    # ── Audit-archive enumeration (audit stream only) ───────────────────
    audit_archives = [a for a in list_archives() if a.stream == "audit"]
    if not audit_archives:
        ui.empty_state(
            "🛠️",
            "No audit archives yet",
            "Once an admin saves or resets validation defaults, those "
            "changes will appear here.",
        )
        return

    label_to_meta = {
        f"{a.date_label}  ·  {a.size_bytes / 1024:.1f} KB": a
        for a in audit_archives
    }

    # ── Archive selector + refresh ──────────────────────────────────────
    top_a, top_b = st.columns([3, 1], gap="medium")
    with top_a:
        selected_label = st.selectbox(
            "Audit archive",
            options=list(label_to_meta.keys()),
            index=0,
            help="`Today (live)` reads the current audit file. Older entries "
                 "are dated archives produced at midnight rotation. "
                 "Add/remove diffs are reconstructed within a single archive "
                 "window only.",
        )
        selected = label_to_meta[selected_label]
    with top_b:
        st.markdown(
            '<div class="ms-label-spacer" aria-hidden="true">&nbsp;</div>',
            unsafe_allow_html=True,
        )
        if st.button(
            "🔄 Refresh", width="stretch", help="Re-read the selected file.",
            key="appchg_refresh_btn",
        ):
            st.rerun()

    # ── Filter panel ────────────────────────────────────────────────────
    with st.expander("🔍 Filters", expanded=False):
        with st.container(key="appchg_filterbar"):
            with st.form("app_changes_filters", clear_on_submit=False):
                row1_a, row1_b = st.columns([1, 1], gap="medium")
                with row1_a:
                    action_label = st.selectbox(
                        "Change type",
                        options=list(_ACTION_FILTER_LABELS.values()),
                        index=0,
                    )
                with row1_b:
                    max_lines = st.number_input(
                        "Max lines scanned",
                        min_value=100,
                        max_value=MAX_LINES_HARD_CAP,
                        value=5_000,
                        step=100,
                        help="Caps how much of the audit file is tailed.",
                    )

                row2_a, row2_b = st.columns([2, 1], gap="medium")
                with row2_a:
                    grep_q = st.text_input(
                        "Search text", value="",
                        placeholder="user id, rule name, threshold…",
                    )
                with row2_b:
                    mask_pii = st.checkbox(
                        "Mask PII (emails)", value=False,
                        help="Always-on: secrets/tokens are masked. Turn this "
                             "on to also mask email-shaped user IDs — useful "
                             "when screen-sharing.",
                    )

                submitted = st.form_submit_button(
                    "🔍 Apply filters", type="primary", width="stretch",
                )

    # ── Resolve filter values ───────────────────────────────────────────
    _label_to_action = {v: k for k, v in _ACTION_FILTER_LABELS.items()}
    action_filter = _label_to_action.get(action_label, "ALL")
    grep_clean = _sanitize_filter_term(grep_q)

    # ── Audit the search (only on form submit) ──────────────────────────
    if submitted:
        log_user_action(
            "app_changes_search",
            archive=selected.filename,
            change_type=action_filter,
            grep=grep_clean,
            mask_pii=str(mask_pii).lower(),
        )

    # ── Read + narrow to change events ──────────────────────────────────
    try:
        raw_lines = tail_lines(
            selected.filename,
            max_bytes=5 * 1024 * 1024,
            max_lines=int(max_lines),
            mask_pii=mask_pii,
        )
    except ValueError as e:
        logger.error('app_changes_read_rejected error="%s"', str(e)[:200])
        st.error(
            "Could not open that audit file. The selection is no longer valid."
        )
        return
    except OSError as e:
        logger.error('app_changes_read_failed error="%s"', str(e)[:200])
        st.error("Could not read the audit file. Check the log directory.")
        return

    try:
        # Narrow with a cheap substring grep BEFORE building the feed, so the
        # delta walk only sees lines that mention the change actions. The free
        # text search is applied to the friendly row below, not here, so a
        # user searching "Pinned" still matches synthesized summaries.
        records = list(filter_lines(
            raw_lines,
            grep="admin_defaults_",
            regex=False,
        ))
    except re.error as e:  # pragma: no cover — fixed literal grep
        st.error(f"Invalid filter: {e}")
        return

    feed = _build_change_feed(records, action_filter)

    # Free-text search applies to the friendly, synthesized fields so an admin
    # can find "Unpinned" or a rule name that never appears verbatim in the log.
    if grep_clean:
        needle = grep_clean.lower()
        feed = [
            r for r in feed
            if needle in r.summary.lower()
            or needle in r.detail.lower()
            or needle in r.user_id.lower()
            or needle in r.action.lower()
        ]

    # ── KPI row ─────────────────────────────────────────────────────────
    saves_n = sum(1 for r in feed if r.action == "admin_defaults_saved")
    resets_n = sum(
        1 for r in feed if r.action == "admin_defaults_reset_to_factory"
    )
    failures_n = sum(1 for r in feed if r.action.endswith("_failed"))
    last_change = feed[0].ts if feed else "—"

    with st.container(key="admin_kpi_row_app_changes"):
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Changes shown", f"{len(feed):,}")
        k2.metric("Saves", f"{saves_n:,}", delta_color="off")
        k3.metric("Factory resets", f"{resets_n:,}", delta_color="off")
        k4.metric(
            "Failures", f"{failures_n:,}",
            delta="!" if failures_n else "ok",
            delta_color="inverse" if failures_n else "off",
            help="Save/reset attempts that errored.",
        )
    st.caption(f"Most recent change in view: **{last_change or '—'}**")

    # ── Telescope master-detail: selectable grid → change-detail card ────
    if not feed:
        st.info("No admin changes match the current filter.")
    else:
        # Grid built positionally from ``feed`` so the selection index maps
        # straight back to ``feed[i]``. Full detail + raw line live in the card.
        grid_df = pd.DataFrame(
            [
                {
                    "Type": _TYPE_MAP.get(r.action, ("Change", "neutral"))[0],
                    "When": r.ts or "—",
                    "Who": r.user_id or "—",
                    "What changed": r.summary or "—",
                }
                for r in feed
            ]
        )

        theme = ui.get_theme()
        cell_style = _CHANGE_CELL_STYLE.get(theme, _CHANGE_CELL_STYLE["light"])
        default_cell = _CHANGE_CELL_DEFAULT.get(
            theme, _CHANGE_CELL_DEFAULT["light"]
        )

        def _type_cell_css(label: str) -> str:
            bg, fg = cell_style.get(label, default_cell)
            return f"background-color:{bg};color:{fg};font-weight:600"

        styled = grid_df.style.map(_type_cell_css, subset=["Type"])

        st.caption(
            f"Results · {len(feed):,} change(s) · click a row to inspect"
        )
        event = st.dataframe(
            styled,
            key="appchg_grid",
            on_select="rerun",
            selection_mode="single-row",
            hide_index=True,
            width="stretch",
            height=440,
            column_config={
                "Type": st.column_config.TextColumn("Type", width="small"),
                "When": st.column_config.TextColumn("When", width="small"),
                "Who": st.column_config.TextColumn("Who", width="medium"),
                "What changed": st.column_config.TextColumn(
                    "What changed", width="large",
                ),
            },
        )

        # Change-detail card for the selected row, full width below the grid.
        selected_rows = list(getattr(event.selection, "rows", []) or [])
        if selected_rows:
            r = feed[selected_rows[0]]
            label, tone = _TYPE_MAP.get(r.action, ("Change", "neutral"))
            ui.change_detail(
                ts=r.ts,
                user_id=r.user_id,
                action=r.action,
                summary=r.summary,
                detail=r.detail,
                raw=r.raw,
                tone=tone,
                label=label,
                extra_meta={"Archive": selected.filename},
            )
        else:
            st.caption("Select a row above to inspect the full change.")

    # ── Export ──────────────────────────────────────────────────────────
    if feed:
        user_id = st.session_state.get("user_id", "anonymous")
        safe_user_id = re.sub(r"[^A-Za-z0-9_.\-]", "_", user_id)[:40]
        ts_for_name = _dt.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        fname = (
            f"manning-app-changes_"
            f"{selected.date_label.replace(' ', '_')}_"
            f"{safe_user_id}_{ts_for_name}.tsv"
        )

        payload = _export_changes(feed)

        col_dl, _ = st.columns([1, 3])
        with col_dl:
            if st.download_button(
                "⬇️ Download change feed (TSV)",
                data=payload,
                file_name=fname,
                mime="text/tab-separated-values",
                width="stretch",
                type="secondary",
            ):
                log_user_action(
                    "app_changes_export",
                    archive=selected.filename,
                    rows=len(feed),
                    bytes=len(payload),
                    change_type=action_filter,
                    mask_pii=str(mask_pii).lower(),
                )
