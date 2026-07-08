"""
Manning Simulator — Streamlit Entrypoint (v1.9.1)
"""

from __future__ import annotations

import html
import uuid
import os
import pandas as pd
import streamlit as st
from datetime import date

from app.core.config import DAYS, DAYS_A, DAYS_B, EXTRA_COLS, SHIFT_TIMES, VALID_CODES
from app.core.rules import AVAILABLE_RULES, detect_matrix
from app.core.admin_defaults import load_admin_defaults
from app.core.logging import get_logger, log_startup_banner
from app.auth import (
    init_session_state,
    handle_auth,
    has_role,
    require_role,
    clear_schedule_data,
    get_rate_limiter,
    logout,
    maybe_show_debug_panel,
    render_idle_timeout_guard,
    PROTECTED_KEYS,
)
from app.core.roles import MANNING_USER, MANNING_SUPERADMIN
from app.core.checkpoint import save_checkpoint, restore_checkpoint
from app.utils import (
    validate, parse_bytes, create_excel_template,
    generate_styled_excel_export,
    log_user_action, inject_custom_css,
    fmt_day, fmt_week, week_dates,
)
from app import ui

logger = get_logger("forge.main")

_APP_VERSION = "v1.10.0"

# ── VIOLATION LOG PAGE SIZE ───────────────────────────────────────────────
# PERF [QA]: Rendering 700 rows inline causes DOM lag. Paginate instead.
# Increase if your typical dataset is larger and your browser can handle it.
_VIO_PAGE_SIZE = 50


# ── HELPERS ───────────────────────────────────────────────────────────────

def _derive_failed_weeks(details_str: str) -> str:

    lbl_a = st.session_state.get("week_a_label", "Week A")
    lbl_b = st.session_state.get("week_b_label", "Week B")
    has_a = "Wk A" in details_str
    has_b = "Wk B" in details_str
    if has_a and has_b:
        return f"{lbl_a} & {lbl_b}"
    if has_a:
        return lbl_a
    if has_b:
        return lbl_b
    # Fallback: violation detail didn't specify a week — assume both
    return f"{lbl_a} & {lbl_b}"


def _user_safe_error(trace_id: str, public_msg: str, exc: Exception = None) -> None:
    """Blackbox error: sanitised message to UI, full traceback to logs."""
    if exc:
        logger.exception(public_msg)
    else:
        logger.error(public_msg)
    st.error(
        f"🚨 {public_msg}\n\n"
        f"Contact IT support with **Trace ID: `{trace_id}`**."
    )


# ── ROW IDs ───────────────────────────────────────────────────────────────

def _ensure_row_ids(df: pd.DataFrame) -> pd.DataFrame:
    if "_row_id" not in df.columns:
        df = df.copy()
        df["_row_id"] = [str(uuid.uuid4()) for _ in range(len(df))]
    else:
        mask = df["_row_id"].isna() | (
            df["_row_id"].astype(str).str.strip() == "")
        if mask.any():
            df = df.copy()
            df.loc[mask, "_row_id"] = [str(uuid.uuid4())
                                       for _ in range(int(mask.sum()))]
    return df


# ── SIDEBAR ───────────────────────────────────────────────────────────────

def render_sidebar() -> None:
    from pathlib import Path

    # ── View-mode resolution ─────────────────────────────────────────────────
    # Two modes: "app" (default — simulator + operator widgets) and "admin"
    # (validation defaults + log viewer + admin chrome). Only superadmins can
    # enter admin mode; we force-revert if their role is revoked mid-session.
    _is_admin_capable = has_role(MANNING_SUPERADMIN)
    view_mode = st.session_state.get("view_mode", "app")
    if view_mode == "admin" and not _is_admin_capable:
        log_user_action(
            "view_mode_force_reset",
            from_="admin", to="app",
            reason="role_revoked_or_missing",
        )
        view_mode = "app"
        st.session_state.view_mode = "app"
    st.session_state.setdefault("view_mode", view_mode)

    # Inject admin chrome (sidebar accent ribbon, tinted main pane, deeper
    # accent on the active page) only when in admin mode. Keeping the style
    # block out of the global stylesheet means a misclick on the switcher
    # immediately reverts the visual treatment — no stale chrome.
    if view_mode == "admin":
        st.markdown(
            """
            <style>
            [data-testid="stSidebar"] {
                border-left: 3px solid var(--c-accent) !important;
                background: linear-gradient(180deg,
                    var(--c-bg-3) 0%, var(--c-surface) 320px) !important;
            }
            [data-testid="stAppViewContainer"] > .main,
            .block-container {
                background: var(--c-bg-3) !important;
            }
            [data-testid="stSidebarNav"] a[aria-current="page"],
            [data-testid="stSidebarNav"] a[aria-current="true"] {
                border-left-color: #cd3c10 !important;
                color: #cd3c10 !important;
                background: rgba(205, 60, 16, 0.10) !important;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

    # ── Logout-dialog dispatcher ─────────────────────────────────────────
    # When the popover's Sign out button is clicked WITH a schedule loaded,
    # it queues this flag and reruns. On the resulting rerun we render the
    # @st.dialog modal here, BEFORE the sidebar context — Streamlit overlays
    # it on the whole page regardless of where it's invoked. The flag is
    # pop()'d so it can't survive the rerun cycle.
    if st.session_state.pop("_show_logout_dialog", False):
        _open_logout_dialog()

    with st.sidebar:
        logo_path = Path(__file__).resolve().parent / "icon" / "Logo.png"
        if logo_path.exists():
            st.image(
                str(logo_path),
                caption=None,
                # Streamlit doesn't expose alt directly; the surrounding
                # ms-fallback-logo path covers screen readers when the
                # image is missing. For the present case we still want
                # discoverability — leave a sidebar caption disabled to
                # keep visual density. Screen-reader users get the
                # page title from <title>Manning Simulator</title>.
            )
        else:
            ui.fallback_logo()

        # ── User identity pill ────────────────────────────────────────────
        # Surfaces who's logged in (username, email, primary role) and the
        # build version. Email and roles come from the validated ID token
        # claims stashed in session_state at auth time. All values are
        # HTML-escaped — user_info originates from the IdP but is rendered
        # inside markdown(unsafe_allow_html=True), so escape is mandatory.
        user_id = st.session_state.get("user_id", "anonymous")
        user_info = st.session_state.get("user_info") or {}
        roles = (user_info.get("realm_access") or {}).get("roles") or []
        # Filter out Keycloak's noisy default roles so the badge stays readable.
        _NOISY_ROLES = {
            "offline_access", "uma_authorization", "default-roles-default",
        }
        primary_role = next(
            (r for r in roles if r not in _NOISY_ROLES),
            "",
        )
        # Prefer a human display name; fall back through the standard OIDC
        # claims before settling on the username.
        given = str(user_info.get("given_name") or "").strip()
        family = str(user_info.get("family_name") or "").strip()
        display_name = (
            str(user_info.get("name") or "").strip()
            or (f"{given} {family}".strip() if (given or family) else "")
            or str(user_id)
        )
        safe_role = html.escape(str(primary_role))
        # st.popover renders its label as Markdown — an IdP-supplied
        # display_name with brackets or HTML could inject links/markup
        # into the trusted UI chrome. Escape before interpolation.
        safe_display_name = html.escape(display_name)

        # ── User dropdown ────────────────────────────────────────────────
        # Single popover surface. Clicking Sign out either signs out
        # immediately (no schedule loaded) or queues a confirmation modal
        # via the ``_show_logout_dialog`` flag, which the dispatcher at
        # the top of render_sidebar drains on the next rerun.
        with st.popover(
            f"👤  {safe_display_name}",
            width="stretch",
            help="Account menu",
        ):
            if safe_role:
                # Role badge + right-aligned version number. Uses the
                # ms-chip / pure-flex layout from app/ui.py instead of
                # ad-hoc inline styles so theme changes propagate.
                st.markdown(
                    f'<div class="ms-user-meta" style="display:flex;'
                    f'align-items:center;justify-content:space-between;'
                    f'gap:var(--space-2);margin-bottom:var(--space-2);">'
                    f'{ui.badge(primary_role, tone="accent")}'
                    f'<span style="font-size:0.74rem;'
                    f'color:var(--c-text-muted);'
                    f'font-variant-numeric:tabular-nums;">'
                    f'{html.escape(_APP_VERSION)}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.caption(_APP_VERSION)

            # ── View switcher (superadmin only) ──────────────────────
            # Lives inside the user popover so the sidebar body stays
            # uncluttered. Renders nothing for regular users — they
            # never see "Admin" anywhere in the UI.
            if _is_admin_capable:
                st.divider()
                _current_mode = st.session_state.get("view_mode", "app")
                _target_mode = (
                    "app" if _current_mode == "admin" else "admin"
                )
                _btn_label = (
                    "🔀 Switch to App"
                    if _target_mode == "app"
                    else "🛡️ Switch to Admin"
                )
                _btn_help = (
                    "Return to the validation workflow."
                    if _target_mode == "app"
                    else "Configure org-wide defaults and view logs."
                )
                if st.button(
                    _btn_label,
                    width="stretch",
                    key="popover_view_switch",
                    help=_btn_help,
                ):
                    log_user_action(
                        "view_mode_changed",
                        from_=_current_mode, to=_target_mode,
                    )
                    st.session_state.view_mode = _target_mode
                    st.rerun()
                st.divider()

            if st.button(
                "🚪 Sign out",
                width="stretch",
                key="sidebar_logout_btn",
                help="End your session and return to the sign-in page.",
            ):
                # Smart confirm: skip the dialog when there's no loaded
                # data to lose. Otherwise queue the modal — it opens on
                # the rerun via the dispatcher at the top of this fn.
                _has_data = not st.session_state.get(
                    "schedule", pd.DataFrame(),
                ).empty
                if _has_data:
                    st.session_state._show_logout_dialog = True
                    st.rerun()
                else:
                    log_user_action("logout_clicked")
                    logout()
                    # logout() either reruns (dev) or redirects + stop()
                    # (prod). Control does not return here.

        # View switcher moved INTO the user popover (see the popover block
        # above). The sidebar body stays clean — no orphan widget between
        # the user pill and the Configuration accordions.

        # ── Admin-mode early-exit ────────────────────────────────────────
        # In admin mode the operator widgets (thresholds/rules/matrix
        # guide/shift codes/resources/clear-data) are hidden — they don't
        # apply when configuring the system. We still render a minimal
        # footer with About so superadmins always have a version/support
        # reference.
        if st.session_state.get("view_mode", "app") == "admin":
            st.divider()
            st.caption(
                "🛡️ Admin Console — operator widgets hidden in this mode."
            )
            with st.sidebar.expander("ℹ️ About"):
                st.markdown(
                    f"**Schedule Compliance App**  \n"
                    f"Version `{_APP_VERSION}`  \n\n"
                    f"14-day workforce schedule validator that flags rule "
                    f"violations and exports HR-ready reports.  \n\n"
                    f"**Support:** https://calpionsweb.automotive-wan.com:8091/"
                )
            return

        # ── Operator widgets (App mode only) ─────────────────────────────
        st.divider()

        st.header("⚙️ Configuration")

        # ── Admin-managed defaults ────────────────────────────────────────
        # SuperAdmin pins org-wide starting values via the "Admin: Validation
        # Defaults" page; users can still override per-session below. On a
        # missing/malformed config file, ``load_admin_defaults()`` returns
        # factory defaults and logs a warning — never raises.
        _admin_defaults = load_admin_defaults()
        _admin_thresholds = _admin_defaults["thresholds"]
        _admin_active_keys = _admin_defaults["active_rule_keys"]

        with st.expander("Active Rules", expanded=False):
            rule_options = {r.name: r.key for r in AVAILABLE_RULES}
            # If SuperAdmin has pinned an explicit active set, use it as the
            # default; otherwise fall back to each rule's hardcoded
            # ``default_active`` flag. Unknown keys (e.g. a rule that was
            # later removed from the codebase) are silently dropped via the
            # ``r.key in _admin_active_keys`` membership check.
            if _admin_active_keys is not None:
                default_names = [
                    r.name for r in AVAILABLE_RULES
                    if r.key in _admin_active_keys
                ]
            else:
                default_names = [
                    r.name for r in AVAILABLE_RULES if r.default_active]
            selected_names = st.multiselect(
                "Enforce rules:",
                options=list(rule_options.keys()),
                default=default_names,
                key="active_rule_names",
            )
            st.session_state.active_rule_keys = [
                rule_options[n] for n in selected_names]

            # Detect rule activation/deactivation across reruns.
            prev_rules = st.session_state.get("_prev_active_rule_names")
            curr_rules = sorted(selected_names)
            if prev_rules is not None and prev_rules != curr_rules:
                log_user_action(
                    "rules_changed",
                    active_rules=",".join(curr_rules),
                    count=len(curr_rules),
                )
            st.session_state._prev_active_rule_names = curr_rules

        with st.expander("Threshold Settings", expanded=False):
            prev_max = st.session_state.get("_prev_max_week_hrs")
            new_max = st.number_input(
                "Max Weekly Hours", min_value=40, max_value=84,
                value=st.session_state.get(
                    "max_week_hrs", _admin_thresholds["max_week_hrs"]),
                step=1,
                key="cfg_max_week_hrs",
                help=(
                    "Hard cap for weekly hours. Rows above this trigger a "
                    "Maximum Weekly Hours violation."
                ),
            )
            st.session_state.max_week_hrs = new_max
            if prev_max is not None and prev_max != new_max:
                log_user_action(
                    "threshold_changed",
                    setting="max_week_hrs", value=new_max,
                )
            st.session_state._prev_max_week_hrs = new_max

            prev_min = st.session_state.get("_prev_min_week_hrs")
            new_min = st.number_input(
                "Min Weekly Hours", min_value=0, max_value=60,
                value=st.session_state.get(
                    "min_week_hrs", _admin_thresholds["min_week_hrs"]),
                step=1,
                key="cfg_min_week_hrs",
                help=(
                    "Configurable floor for weekly hours (default 48). "
                    "Rows below this threshold trigger a Minimum Weekly "
                    "Hours violation. Leave days are credited at matrix "
                    "shift length (12h for 4-3, 8h for 6-1). For weeks "
                    "with paid plant-shutdown (NW) days, raise the NW "
                    "Credit Hours setting below instead of dropping the "
                    "floor. Set to 0 to disable the check entirely."
                ),
            )
            st.session_state.min_week_hrs = new_min
            if prev_min is not None and prev_min != new_min:
                log_user_action(
                    "threshold_changed",
                    setting="min_week_hrs", value=new_min,
                )
            st.session_state._prev_min_week_hrs = new_min

            prev_roll = st.session_state.get("_prev_max_rolling_7d_hrs")
            new_roll = st.number_input(
                "Max Rolling 7-Day Hours", min_value=40, max_value=84,
                value=st.session_state.get(
                    "max_rolling_7d_hrs",
                    _admin_thresholds["max_rolling_7d_hrs"]),
                step=1,
                key="cfg_max_rolling_7d_hrs",
                help=(
                    "Cap for any 7 consecutive days (rolling window). Catches "
                    "cross-week excess that per-week caps miss — e.g., 6×12h "
                    "spanning Friday Wk A through Wednesday Wk B = 72h."
                ),
            )
            st.session_state.max_rolling_7d_hrs = new_roll
            if prev_roll is not None and prev_roll != new_roll:
                log_user_action(
                    "threshold_changed",
                    setting="max_rolling_7d_hrs", value=new_roll,
                )
            st.session_state._prev_max_rolling_7d_hrs = new_roll

            prev_nw = st.session_state.get("_prev_nw_credit_hrs")
            new_nw = st.number_input(
                "NW Credit Hours (per shutdown day)",
                min_value=0, max_value=12,
                value=st.session_state.get(
                    "nw_credit_hrs", _admin_thresholds["nw_credit_hrs"]),
                step=1,
                key="cfg_nw_credit_hrs",
                help=(
                    "Credits NW (No-Work / plant shutdown) days at this "
                    "hour rate when computing weekly minimum hours. "
                    "Default 0 (unpaid shutdown — cost-driven closures). "
                    "Set to 8 (DOLE day) during paid holiday-closure "
                    "weeks per HR policy so those weeks stop "
                    "false-failing the weekly minimum."
                ),
            )
            st.session_state.nw_credit_hrs = new_nw
            if prev_nw is not None and prev_nw != new_nw:
                log_user_action(
                    "threshold_changed",
                    setting="nw_credit_hrs", value=new_nw,
                )
            st.session_state._prev_nw_credit_hrs = new_nw

            if st.session_state.get(
                "min_week_hrs", _admin_thresholds["min_week_hrs"]
            ) >= st.session_state.get(
                "max_week_hrs", _admin_thresholds["max_week_hrs"]
            ):
                st.warning("Min hours must be less than Max hours.")

        st.divider()
        ui.sidebar_section("Matrix Guide", icon="ℹ️")
        with st.expander("Auto-detection rules", expanded=False):
            # Matrix Guide redesigned from a dense markdown table into a
            # card-per-matrix grid. Each card lists trigger conditions on
            # the left and a short note on the right; the colored left
            # ribbon doubles as a quick-scan classifier (accent / success
            # / info). See app/ui.py:reference_card.
            ui.reference_card(
                "4-3 (Compressed Workweek)",
                rows=[
                    {"label": "Triggers",
                     "value": "Only AOT / BOT / COT shifts"},
                    {"label": "Or",
                     "value": "Mixed shifts, 12h-days outnumber 8h-days"},
                    {"label": "Or",
                     "value": "Mixed shifts with ≥4 literal RDs / 14d"},
                    {"label": "Rules",
                     "value": "Strict 12h · ≥3 RD/wk (≥2 with OT) · "
                              "consecutive RDs"},
                ],
                icon="🔁",
                accent_tone="accent",
            )
            ui.reference_card(
                "6-1 (Standard)",
                rows=[
                    {"label": "Triggers",
                     "value": "Only A / B / C / OS5 shifts"},
                    {"label": "Or",
                     "value": "Mixed shifts not matching 4-3 / 5-2"},
                    {"label": "Rules",
                     "value": "8–12h shifts · ≥1 RD/wk · OT extensions OK"},
                ],
                icon="📅",
                accent_tone="info",
            )
            ui.reference_card(
                "5-2 (Full Weekend Rest)",
                rows=[
                    {"label": "Triggers",
                     "value": "Only A / B / C / OS5 with weekend rest"},
                    {"label": "Rules",
                     "value": "9h Mon-Thu · 8h Fri · no weekday RD"},
                ],
                icon="🛌",
                accent_tone="success",
            )
            ui.reference_card(
                "Rest-Equivalent Fallback",
                rows=[
                    {"label": "Triggers",
                     "value": "No work shifts (full Leave / RD / NW)"},
                    {"label": "Rules",
                     "value": "Rest-equivalent count drives the matrix pick"},
                ],
                icon="⏸️",
                accent_tone="neutral",
                footnote=(
                    "Rest-equivalents counted: RD, LEAVE, RH, SPH, NW. "
                    "Mixed-branch detection uses literal RD or shift-count "
                    "majority — Leave/NW are treated as incidental absences, "
                    "not contract rest. The 4-3 RD minimum drops from 3 to "
                    "2/wk when OT extension is taken (one OT day "
                    "legitimately consumes one rest day; DOLE compliance "
                    "preserved by MaxWeeklyHours and ConsecutiveWorkDays)."
                ),
            )

        st.divider()
        ui.sidebar_section("Shift Codes", icon="🕒")
        with st.expander("View reference", expanded=False):
            # Shift codes rendered as a 2-col chip grid (narrows to 2-col
            # on small viewports automatically via the .ms-codegrid media
            # query). Each chip carries code · hours · time window with a
            # top-border tone for category-at-a-glance.
            ui.chip_grid(
                [
                    {"code": "A",   "hours": "8h", "window": "06–14",
                     "tone": "info"},
                    {"code": "B",   "hours": "8h", "window": "14–22",
                     "tone": "info"},
                    {"code": "C",   "hours": "8h", "window": "22–06",
                     "tone": "info"},
                    {"code": "AOT", "hours": "12h", "window": "06–18",
                     "tone": "accent"},
                    {"code": "BOT", "hours": "12h", "window": "10–22",
                     "tone": "accent"},
                    {"code": "COT", "hours": "12h", "window": "18–06",
                     "tone": "accent"},
                    {"code": "OS5", "hours": "9h", "window": "08–17",
                     "tone": "info"},
                    {"code": "RD",  "hours": "0h", "window": "Rest Day",
                     "tone": "success"},
                ],
                columns=2,
            )
            ui.chip_grid(
                [
                    {"code": "Leave", "hours": "0h",
                     "window": "VL / SL / PTO", "tone": "success"},
                    {"code": "AWOL",  "hours": "0h",
                     "window": "Not credited", "tone": "danger"},
                    {"code": "NW",    "hours": "0–8h",
                     "window": "Plant shutdown", "tone": "warn"},
                    {"code": "RH",    "hours": "0h · 200%",
                     "window": "Regular holiday", "tone": "warn"},
                    {"code": "SPH",   "hours": "0h · 130%",
                     "window": "Special holiday", "tone": "warn"},
                ],
                columns=2,
            )
            st.info(
                "If a holiday lands on a scheduled rest day, leave the "
                "cell as `RD` — the employee is already off, no premium "
                "is owed, and no shift-length credit applies. Enter "
                "`RH`/`SPH` only on slots that would otherwise have been "
                "worked.",
                icon="💡",
            )

        st.divider()
        st.header("📄 Resources")

        template_data = st.session_state.get("template_bytes", b"")
        if template_data:
            st.download_button(
                "⬇️ Download Blank Template",
                data=template_data,
                file_name="manning_template.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                on_click=lambda: log_user_action("download_template_clicked"),
                width="stretch",
                key="dl_template",
            )
        else:
            st.warning(
                "Template file missing.\nContact IT to restore `resource/manning_template.xlsx`.")

        st.divider()
        if not st.session_state.get("_confirm_clear", False):
            if st.button("🗑️ Clear Schedule Data", width="stretch", key="sidebar_clear_btn"):
                st.session_state._confirm_clear = True
                st.rerun()
        else:
            st.warning("Clear all loaded data? This cannot be undone.")
            _cc1, _cc2 = st.columns(2)
            with _cc1:
                if st.button("Yes, Clear", type="primary", width="stretch", key="sidebar_clear_confirm"):
                    st.session_state._confirm_clear = False
                    clear_schedule_data()
                    log_user_action("clear_data_clicked")
                    st.rerun()
            with _cc2:
                if st.button("Cancel", width="stretch", key="sidebar_clear_cancel"):
                    st.session_state._confirm_clear = False
                    log_user_action("clear_data_cancelled")
                    st.rerun()

        st.divider()

        # ── About ─────────────────────────────────────────────────────────
        # Shipping the version + support contact in-app cuts down on "what
        # build are we on?" support tickets. TODO: link an internal docs URL
        # here once the runbook lands in Confluence.
        with st.sidebar.expander("ℹ️ About"):
            st.markdown(
                f"**Schedule Compliance App**  \n"
                f"Version `{_APP_VERSION}`  \n\n"
                f"14-day workforce schedule validator that flags rule "
                f"violations and exports HR-ready reports.  \n\n"
                # PLACEHOLDER: replace with the real distribution-list / Teams
                # channel before the production cut.
                f"**Support:** https://calpionsweb.automotive-wan.com:8091/"
            )


# ── PARSING MODAL ─────────────────────────────────────────────────────────
# Centered popup that blocks the UI while parse_bytes() runs. We trigger it
# from the upload site; on completion it stashes the result in session_state
# and calls st.rerun() — Streamlit then closes the dialog and re-enters
# render_editor_tab where the result is drained at the top.

@st.dialog("Sign out?", width="small")
def _open_logout_dialog() -> None:
    """Confirmation modal shown when the user clicks Sign out with a
    schedule loaded. Two buttons: Cancel (rerun, closes the dialog) and
    Sign out (calls logout() which either reruns or redirects to KC).
    """
    schedule = st.session_state.get("schedule", pd.DataFrame())
    n = len(schedule) if hasattr(schedule, "__len__") else 0
    if n > 0:
        st.warning(
            f"You have **{n} employee{'s' if n != 1 else ''}** loaded. "
            f"Any unsaved edits will be lost.",
            icon="⚠️",
        )
    else:
        st.write(
            "You'll be returned to the sign-in page. Sign back in any "
            "time to continue."
        )

    col_cancel, col_signout = st.columns(2)
    with col_cancel:
        if st.button(
            "Cancel",
            width="stretch",
            key="logout_dialog_cancel",
        ):
            st.rerun()  # closes the dialog
    with col_signout:
        if st.button(
            "🚪 Sign out",
            type="primary",
            width="stretch",
            key="logout_dialog_confirm",
        ):
            log_user_action("logout_clicked")
            logout()  # either st.rerun() (dev) or redirect + st.stop()


@st.dialog("Parsing schedule", width="small")
def _open_parsing_dialog(filename: str, data: bytes) -> None:
    st.markdown(
        f"**Reading file** `{filename}`  \n"
        f"_This usually takes 2–5 seconds for a 14-day schedule._"
    )
    with st.spinner("Parsing…"):
        df_up, err = parse_bytes(filename, data)
    st.session_state._upload_result = {
        "df": df_up, "err": err, "name": filename,
    }
    st.rerun()


# ── EDITOR TAB ────────────────────────────────────────────────────────────

def render_editor_tab() -> None:
    trace_id = st.session_state.get("session_trace_id", "no-trace")
    rate_limiter = get_rate_limiter()

    # ── Pickup: drain any result the parsing modal staged on a prior rerun.
    _pending = st.session_state.pop("_upload_result", None)
    if _pending is not None:
        _df_up = _pending["df"]
        _err = _pending["err"]
        _filename = _pending["name"]
        if _err:
            log_user_action(
                "upload_failed", filename=_filename, reason=_err,
            )
            st.error(f"**Upload failed:** {_err}")
            st.toast("Upload failed", icon="❌")
        elif _df_up is not None:
            for _col in EXTRA_COLS:
                if _col not in _df_up.columns:
                    _df_up[_col] = "Unspecified"
            st.session_state.schedule = _ensure_row_ids(_df_up.astype(str))
            st.session_state.validation_results = None
            st.session_state.validation_results_records = None
            st.session_state.pop("master_schedule_editor", None)
            _n = len(_df_up)
            st.success(
                f"✅ Loaded **{_n} employee{'s' if _n != 1 else ''}** "
                f"from `{_filename}`"
            )
            st.toast(f"Loaded {_n} employee{'s' if _n != 1 else ''} ✓",
                     icon="✅")

    try:
        uploaded = st.file_uploader(
            "Upload schedule file (.xlsx, .xls, or .csv)",
            type=["xlsx", "xls", "csv"],
            key=st.session_state.uploader_key,
            help="Use the blank template from the sidebar to ensure correct headers.",
        )

        if uploaded is None:
            st.session_state.last_file_id = None
        else:
            current_file_id = getattr(uploaded, "file_id", None)
            if current_file_id != st.session_state.get("last_file_id"):
                log_user_action("upload_file_selected", filename=uploaded.name)

                allowed, wait_time = rate_limiter.check(
                    st.session_state.user_id)
                if not allowed:
                    log_user_action(
                        "upload_rate_limited",
                        filename=uploaded.name, wait_seconds=wait_time,
                    )
                    st.warning(
                        f"Upload limit reached — please wait **{wait_time}s** before uploading again."
                    )
                    st.session_state.last_file_id = current_file_id
                else:
                    try:
                        data = uploaded.getvalue()
                    except Exception:
                        data = uploaded.read()

                    if data:
                        # Stash file_id BEFORE the modal so the second rerun
                        # (triggered by the modal's st.rerun() on completion)
                        # doesn't see this branch as "new upload" and reopen
                        # the dialog. The result is picked up at the top of
                        # render_editor_tab via _upload_result drain.
                        st.session_state.last_file_id = current_file_id
                        _open_parsing_dialog(uploaded.name, data)
                    else:
                        log_user_action(
                            "upload_empty_file", filename=uploaded.name,
                        )
                        st.error("Could not read file. Try re-saving as CSV.")
                        st.session_state.last_file_id = current_file_id

        if st.session_state.get("schedule", pd.DataFrame()).empty:
            ui.empty_state(
                "📤",
                "No schedule loaded",
                "Upload an .xlsx, .xls, or .csv file above, or download "
                "the blank template from the sidebar. You can also add "
                "rows manually in the table below.",
                size="md",
            )

        st.divider()

        # ── Week reference settings ───────────────────────────────────────
        has_schedule = not st.session_state.get(
            "schedule", pd.DataFrame()).empty
        with st.expander(
            "📅 Week Reference Labels & Dates",
            expanded=not has_schedule,
        ):
            st.caption(
                "Set labels like 'Week X' / 'Week Y' for display and exports. "
                "Dates are reference-only — they do not affect validation logic."
            )
            wk_c1, wk_c2 = st.columns(2)
            with wk_c1:
                st.session_state.week_a_label = st.text_input(
                    "First week label",
                    value=st.session_state.get("week_a_label", "Week A"),
                    placeholder="e.g. Week 17",
                    key="inp_week_a_label",
                )
                st.session_state.week_a_start = st.date_input(
                    "First week start date (reference only)",
                    value=st.session_state.get("week_a_start"),
                    key="inp_week_a_date",
                    format="MM/DD/YYYY",
                )
                if st.session_state.week_a_start:
                    _wd_a = week_dates(st.session_state.week_a_start)
                    st.caption(
                        f"Week: **{_wd_a[0]:%a %m/%d}** → **{_wd_a[-1]:%a %m/%d}**"
                    )
            with wk_c2:
                st.session_state.week_b_label = st.text_input(
                    "Second week label",
                    value=st.session_state.get("week_b_label", "Week B"),
                    placeholder="e.g. Week 18",
                    key="inp_week_b_label",
                )
                st.session_state.week_b_start = st.date_input(
                    "Second week start date (reference only)",
                    value=st.session_state.get("week_b_start"),
                    key="inp_week_b_date",
                    format="MM/DD/YYYY",
                )
                if st.session_state.week_b_start:
                    _wd_b = week_dates(st.session_state.week_b_start)
                    st.caption(
                        f"Week: **{_wd_b[0]:%a %m/%d}** → **{_wd_b[-1]:%a %m/%d}**"
                    )

            # Detect week-label edits across reruns.
            prev_a = st.session_state.get("_prev_week_a_label")
            curr_a = st.session_state.get("week_a_label", "Week A")
            if prev_a is not None and prev_a != curr_a:
                log_user_action(
                    "week_label_changed", week="A",
                    old=prev_a, new=curr_a,
                )
            st.session_state._prev_week_a_label = curr_a

            prev_b = st.session_state.get("_prev_week_b_label")
            curr_b = st.session_state.get("week_b_label", "Week B")
            if prev_b is not None and prev_b != curr_b:
                log_user_action(
                    "week_label_changed", week="B",
                    old=prev_b, new=curr_b,
                )
            st.session_state._prev_week_b_label = curr_b

        col_search, col_view = st.columns([2, 3])
        with col_search:
            search_query = st.text_input(
                "Search", placeholder="Filter by name, ID, or station…",
                label_visibility="collapsed", key="editor_search",
            )
        with col_view:
            lbl_a = st.session_state.get("week_a_label", "Week A")
            lbl_b = st.session_state.get("week_b_label", "Week B")
            WK_A_OPT = f"{lbl_a} (Days 1–7)"
            WK_B_OPT = f"{lbl_b} (Days 8–14)"
            FULL_OPT = "Full 14-Day View"

            view_mode = st.radio(
                "View",
                [WK_A_OPT, WK_B_OPT, FULL_OPT],
                horizontal=True, label_visibility="collapsed",
                key="editor_view_mode",
            )

        for col in EXTRA_COLS:
            if col not in st.session_state.schedule.columns:
                st.session_state.schedule[col] = "Unspecified"
        for day in DAYS:
            if day not in st.session_state.schedule.columns:
                st.session_state.schedule[day] = ""

        display_df = st.session_state.schedule.copy()

        if search_query.strip() and not display_df.empty:
            search_cols = [c for c in ["Name", "ID No.", "Station", "EMP. STATUS"]
                           if c in display_df.columns]
            mask = display_df[search_cols].astype(str).apply(
                lambda col: col.str.contains(
                    search_query.strip(), case=False, na=False, regex=False)
            ).any(axis=1)
            display_df = display_df[mask]

        # Exact == comparison — safe regardless of label content
        display_days = (
            DAYS_A if view_mode == WK_A_OPT
            else DAYS_B if view_mode == WK_B_OPT
            else DAYS
        )

        col_config = {
            "Station":     st.column_config.TextColumn("Station", width="medium"),
            "EMP. STATUS": st.column_config.TextColumn("Status", width="small"),
            "ID No.":      st.column_config.TextColumn("ID No.", width="small"),
            "Name":        st.column_config.TextColumn("Name", width="medium"),
        }
        for d in DAYS:
            col_config[d] = st.column_config.SelectboxColumn(
                fmt_day(d),
                options=VALID_CODES, width="small",
            )

        total_c = len(st.session_state.schedule)
        shown_c = len(display_df)
        suffix = f" · filtered by `{search_query}`" if search_query.strip(
        ) else ""
        st.caption(f"Showing **{shown_c}** of **{total_c}** employees{suffix}")

        edited_df = st.data_editor(
            display_df,
            num_rows="dynamic", width="stretch",
            column_order=["Station", "EMP. STATUS",
                          "ID No.", "Name"] + display_days,
            column_config=col_config, hide_index=True,
            key="master_schedule_editor",
        )

        editor_state = st.session_state.get("master_schedule_editor", {})
        if (editor_state.get("edited_rows") or
                editor_state.get("added_rows") or
                editor_state.get("deleted_rows")):
            n_edited = len(editor_state.get("edited_rows") or {})
            n_added = len(editor_state.get("added_rows") or [])
            n_deleted = len(editor_state.get("deleted_rows") or [])
            # Only audit-log when the edit signature actually changes.
            # Streamlit's data_editor can preserve `edited_rows` across reruns,
            # which previously caused this event to fire on every rerun.
            edit_sig = (n_edited, n_added, n_deleted)
            if st.session_state.get("_prev_schedule_edit_sig") != edit_sig:
                log_user_action(
                    "schedule_edited",
                    edited=n_edited, added=n_added, deleted=n_deleted,
                )
                st.session_state._prev_schedule_edit_sig = edit_sig
            if search_query.strip():
                filtered_ids = set(display_df["_row_id"].astype(str))
                rest = st.session_state.schedule[
                    ~st.session_state.schedule["_row_id"].astype(
                        str).isin(filtered_ids)
                ]
                merged = pd.concat([rest, edited_df], ignore_index=True)
                st.session_state.schedule = _ensure_row_ids(merged)
            else:
                st.session_state.schedule = _ensure_row_ids(edited_df.copy())
            st.rerun()

        st.divider()
        st.caption(
            "💡 Tip: Press **Enter** or click outside a cell after typing a shift code.")

        btn_c1, btn_c2 = st.columns([3, 1])
        with btn_c1:
            validate_btn = st.button(
                "✅ Validate Manning Schedule", type="primary",
                width="stretch", key="editor_validate_btn",
            )
        with btn_c2:
            # Two-step confirm — mirrors the sidebar Clear Schedule Data
            # pattern (L298-315). Reset wipes uploaded rows + validation
            # results so an accidental click mid-edit is destructive.
            if not st.session_state.get("_confirm_editor_reset", False):
                if st.button("🔄 Reset", width="stretch", key="editor_reset_btn"):
                    st.session_state._confirm_editor_reset = True
                    st.rerun()
            else:
                st.warning("Reset all editor data? This cannot be undone.")
                _er1, _er2 = st.columns(2)
                with _er1:
                    if st.button(
                        "Yes, Reset", type="primary",
                        width="stretch", key="editor_reset_confirm",
                    ):
                        st.session_state._confirm_editor_reset = False
                        log_user_action("editor_reset_clicked")
                        clear_schedule_data()
                        st.rerun()
                with _er2:
                    if st.button(
                        "Cancel",
                        width="stretch", key="editor_reset_cancel",
                    ):
                        st.session_state._confirm_editor_reset = False
                        log_user_action("editor_reset_cancelled")
                        st.rerun()

        if validate_btn:
            log_user_action("validate_clicked")
            try:
                df = st.session_state.schedule.copy().drop(
                    columns=["_row_id"], errors="ignore")
                if df.empty or "Name" not in df.columns:
                    log_user_action("validate_empty_schedule")
                    st.warning(
                        "⚠️ No schedule data to validate. Upload a file first.")
                    return

                df = df.fillna("")
                initial = len(df)
                df = df[df["Name"].astype(str).str.strip() != ""]
                dropped = initial - len(df)
                if dropped > 0:
                    log_user_action("blank_rows_skipped", count=dropped)
                    st.toast(
                        f"⚠️ Skipped {dropped} row(s) with blank Name.", icon="⚠️")

                if not st.session_state.active_rule_keys:
                    log_user_action("validate_no_rules")
                    st.warning(
                        "⚠️ No rules selected. Enable rules in the sidebar.")
                    return

                config_payload = {
                    "max_week": st.session_state.max_week_hrs,
                    "min_week": st.session_state.min_week_hrs,
                    "max_rolling_7d": st.session_state.max_rolling_7d_hrs,
                    "nw_credit_hrs": st.session_state.nw_credit_hrs,
                }

                n_rules = len(st.session_state.active_rule_keys)
                with st.spinner(f"Validating {len(df)} employees across {n_rules} rules…"):
                    validated_df = validate(
                        df, config_payload, st.session_state.active_rule_keys)

                st.session_state.validation_results = validated_df
                st.session_state.validation_results_records = validated_df.to_dict(
                    "records")

                passing = int(validated_df["_pass"].sum())
                failing = len(validated_df) - passing
                log_user_action("validation_completed",
                                total=len(validated_df), valid=passing, invalid=failing)

                if failing == 0:
                    st.success(
                        "✅ All employees passed. Head to **Coverage Dashboard** to export and submit."
                    )
                else:
                    st.warning(
                        f"Complete — **{failing}/{len(validated_df)}** have violations. "
                        f"Review details in the **Validation Results** tab."
                    )
            except Exception as exc:
                _user_safe_error(
                    trace_id, "Validation failed due to an unexpected error.", exc)

    except Exception as exc:
        _user_safe_error(
            trace_id, "An unexpected error occurred in the schedule editor.", exc)


# ── RESULTS TAB ───────────────────────────────────────────────────────────

def render_results_tab() -> None:
    trace_id = st.session_state.get("session_trace_id", "no-trace")

    if st.session_state.get("validation_results_records") is None:
        ui.empty_state(
            "📋",
            "No results yet",
            "Upload a schedule and click Validate Manning Schedule "
            "in the first tab.",
            size="lg",
        )
        return

    try:
        results = pd.DataFrame(st.session_state.validation_results_records)
        total = len(results)
        passing = int(results["_pass"].sum())
        failing = total - passing
        rate = int(100 * passing / total) if total else 0

        st.subheader("🔍 Validation Results")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Headcount", total,
                  delta=f"{passing} valid · {failing} invalid",
                  delta_color="off")
        m2.metric("Valid Schedules ✅", passing,
                  delta=f"{rate}% compliance rate",
                  delta_color="normal" if rate >= 80 else "off")
        m3.metric("Invalid Schedules ❌", failing,
                  delta=f"{100 - rate}% gap" if failing > 0 else "None",
                  delta_color="inverse" if failing > 0 else "off")
        m4.metric("Overall Compliance", f"{rate}%",
                  "✓ Ready to submit" if rate == 100 else f"{100 - rate}% remaining",
                  delta_color="normal" if rate == 100 else "off")

        st.divider()

        # ── Filters ───────────────────────────────────────────────────────
        with st.expander("Filters", expanded=True):
            col_f1, col_f2, col_f3 = st.columns([1.5, 2.5, 1])
            with col_f1:
                srch = st.text_input("Search results", key="res_search",
                                     label_visibility="collapsed",
                                     placeholder="Filter by name, ID, station…")
            with col_f2:
                r_lbl_a = st.session_state.get("week_a_label", "Week A")
                r_lbl_b = st.session_state.get("week_b_label", "Week B")

                RES_WK_A_OPT = f"{r_lbl_a} (Days 1–7)"
                RES_WK_B_OPT = f"{r_lbl_b} (Days 8–14)"
                RES_FULL_OPT = "Full 14-Day View"

                res_view = st.radio(
                    "View",
                    [RES_WK_A_OPT, RES_WK_B_OPT, RES_FULL_OPT],
                    horizontal=True, label_visibility="collapsed",
                    key="results_view_mode",
                )
            with col_f3:
                show_invalid = st.toggle(
                    "Violations only", value=False, key="results_show_invalid")
                prev_filter = st.session_state.get("_prev_results_show_invalid")
                if prev_filter is not None and prev_filter != show_invalid:
                    log_user_action(
                        "results_filter_violations_only", enabled=show_invalid,
                    )
                st.session_state._prev_results_show_invalid = show_invalid

        # Only log when the totals change — prevents one debug line per rerun.
        _res_sig = (total, passing)
        if st.session_state.get("_prev_results_sig") != _res_sig:
            logger.debug(
                'results_rendered total=%d passing=%d', total, passing,
            )
            st.session_state._prev_results_sig = _res_sig

        filtered = results.copy()
        if srch.strip():
            try:
                mask = filtered.astype(str).apply(
                    lambda col: col.str.contains(
                        srch.strip(), case=False, na=False, regex=False)
                ).any(axis=1)
                filtered = filtered[mask]
            except Exception:
                pass

        if show_invalid:
            filtered = filtered[~filtered["_pass"]]

        # Exact == comparison — robust against any label value
        show_days = (
            DAYS_A if res_view == RES_WK_A_OPT
            else DAYS_B if res_view == RES_WK_B_OPT
            else DAYS
        )

        # OT columns scoped to current view — exact match
        ot_cols = (
            ["OT Hrs A"] if res_view == RES_WK_A_OPT
            else ["OT Hrs B"] if res_view == RES_WK_B_OPT
            else ["OT Hrs A", "OT Hrs B", "OT Hrs Total"]
        )

        ui_cols = ["Station", "EMP. STATUS", "ID No.",
                   "Name"] + show_days + ot_cols + ["Status"]
        for c in ui_cols:
            if c not in filtered.columns:
                filtered[c] = ""

        ui_display = filtered[ui_cols].copy().rename(
            columns={d: fmt_day(d) for d in DAYS}
        )

        # ── Per-Employee Status table ─────────────────────────────────────
        st.divider()
        st.subheader("👥 Per-Employee Status")

        total_emp = len(ui_display)
        emp_total_pages = max(1, (total_emp - 1) // _VIO_PAGE_SIZE + 1)

        # Reset to page 1 if filters shrink the dataset below the current page
        if "emp_page" not in st.session_state:
            st.session_state.emp_page = 1
        emp_page = max(1, min(st.session_state.emp_page, emp_total_pages))
        emp_start = (emp_page - 1) * _VIO_PAGE_SIZE
        emp_end = min(emp_start + _VIO_PAGE_SIZE, total_emp)
        emp_page_df = ui_display.iloc[emp_start:emp_end]

        # Theme-aware severity tones (valid/invalid) — readable in both light
        # and dark mode; the tone→colour pairs live in style.css.
        _emp_status = (
            emp_page_df["Status"].astype(str)
            if "Status" in emp_page_df.columns
            else [""] * len(emp_page_df)
        )
        _emp_row_tone = [
            "valid" if "Valid" in str(s) else "invalid" for s in _emp_status
        ]
        ui.data_table(
            emp_page_df,
            row_tone=_emp_row_tone,
            key="emp_status_table",
        )

        ui.pagination(
            page=emp_page,
            total_pages=emp_total_pages,
            total_items=total_emp,
            page_size=_VIO_PAGE_SIZE,
            state_key="emp_page",
            label="employees",
            on_change_audit="results_page_nav",
        )

        # ── Violation log ──────────────────────────────────────────────────
        if failing > 0 and not filtered[~filtered["_pass"]].empty:
            st.divider()
            st.subheader("⚠️ Violation Log")
            failed = filtered[~filtered["_pass"]]
            flat_records = []

            for _, row in failed.iterrows():
                rd_count = sum(1 for d in DAYS if str(
                    row.get(d, "")).strip().upper() == "RD")
                matrix = "4-3" if rd_count >= 6 else "6-1"
                base = {
                    "ID No.":  row.get("ID No.", ""),
                    "Name":    row.get("Name", ""),
                    "Station": row.get("Station", ""),
                    "Matrix":  matrix,
                }

                if isinstance(row.get("_dv"), list) and row["_dv"]:
                    flat_records.append({
                        **base, "Violation Type": "Daily Hours Check",
                        "Details": ", ".join(fmt_day(d) for d in row["_dv"]),
                    })

                if isinstance(row.get("_gv"), list) and row["_gv"]:
                    for v in row["_gv"]:
                        flat_records.append({
                            **base, "Violation Type": "Mandatory Shift Gap",
                            "Details": fmt_day(v),
                        })

                for rule in AVAILABLE_RULES:
                    if rule.key not in ("max_day", "shift_gap"):
                        msg = str(row.get(rule.name, ""))
                        if "❌" in msg:
                            flat_records.append({
                                **base, "Violation Type": rule.name,
                                "Details": fmt_day(msg.replace("❌ ", "")),
                            })

            if flat_records:
                per_type: dict[str, set] = {}
                for rec in flat_records:
                    per_type.setdefault(rec["Violation Type"], set()).add(
                        rec["ID No."] or rec["Name"]
                    )

                sorted_types = sorted(
                    per_type.items(), key=lambda x: -len(x[1]))
                # Fixed 4-column layout: top 4 violation categories,
                # mirroring the Dashboard's "Top Violation Categories" rhythm.
                top4 = sorted_types[:4]
                top_cols = st.columns(4)
                for i, col in enumerate(top_cols):
                    if i < len(top4):
                        vtype, emp_set = top4[i]
                        n = len(emp_set)
                        col.metric(
                            vtype,
                            f"{n} emp{'loyee' if n == 1 else 'loyees'}",
                        )
                    else:
                        # Empty placeholder keeps the 4-up grid stable
                        col.empty()

                st.write("")
                grouped: dict = {}
                for rec in flat_records:
                    key = (rec["ID No."], rec["Name"])
                    if key not in grouped:
                        grouped[key] = {**rec, "_vtypes": [], "_details": []}
                    entry = f"[{rec['Violation Type']}] {rec['Details']}"
                    if entry not in grouped[key]["_details"]:
                        grouped[key]["_vtypes"].append(rec["Violation Type"])
                        grouped[key]["_details"].append(entry)

                # Cards-per-employee, sorted by severity (count of broken
                # structural rules first, then total violation count).
                STRUCTURAL = {
                    "Maximum Weekly Hours", "Minimum Weekly Hours",
                    "Minimum Rest Days", "Consecutive Rest Days",
                    "Consecutive Work Days",
                }
                _VIO_CARD_PAGE_SIZE = 25

                summary_rows = []
                for d in grouped.values():
                    vtypes = list(dict.fromkeys(d["_vtypes"]))
                    items = []
                    for entry in d["_details"]:
                        # Each entry is "[Rule Name] detail string" — split
                        # back into structured fields for the card.
                        if entry.startswith("[") and "] " in entry:
                            close_idx = entry.index("] ")
                            v_type = entry[1:close_idx]
                            v_detail = entry[close_idx + 2:]
                        else:
                            v_type = "Violation"
                            v_detail = entry
                        items.append({"type": v_type, "detail": v_detail})

                    structural_count = sum(1 for t in vtypes if t in STRUCTURAL)
                    severity = "invalid" if structural_count > 0 else "warning"

                    all_details = "  |  ".join(d["_details"])
                    summary_rows.append({
                        "ID No.":         d["ID No."],
                        "Name":           d["Name"],
                        "Station":        d["Station"],
                        "Matrix":         d["Matrix"],
                        "Failed Week(s)": _derive_failed_weeks(all_details),
                        "# Violations":   len(vtypes),
                        "Violated Rules": ", ".join(vtypes),
                        "_structural":    structural_count,
                        "_items":         items,
                        "_severity":      severity,
                        "_search_blob":   " ".join([
                            str(d["ID No."]), str(d["Name"]),
                            str(d["Station"]), str(d["Matrix"]),
                            ", ".join(vtypes), all_details,
                        ]).lower(),
                    })

                summary_rows.sort(
                    key=lambda r: (-r["_structural"], -r["# Violations"]),
                )

                vio_search = st.text_input(
                    "Search violations",
                    placeholder="Filter by name, ID, station, or rule…",
                    label_visibility="collapsed",
                    key="vio_search",
                )
                if vio_search.strip():
                    needle = vio_search.strip().lower()
                    summary_rows = [
                        r for r in summary_rows if needle in r["_search_blob"]
                    ]
                    st.session_state.vio_page = 1

                total_vio = len(summary_rows)
                total_pages = max(
                    1, (total_vio - 1) // _VIO_CARD_PAGE_SIZE + 1
                )

                if "vio_page" not in st.session_state:
                    st.session_state.vio_page = 1
                vio_page = max(1, min(st.session_state.vio_page, total_pages))
                vio_start = (vio_page - 1) * _VIO_CARD_PAGE_SIZE
                vio_end = min(vio_start + _VIO_CARD_PAGE_SIZE, total_vio)
                page_rows = summary_rows[vio_start:vio_end]

                if total_vio == 0:
                    st.info("No violations match your search.")
                else:
                    for r in page_rows:
                        ui.violation_card(
                            name=str(r["Name"]),
                            emp_id=str(r["ID No."]),
                            station=str(r["Station"]),
                            matrix=str(r["Matrix"]),
                            failed_weeks=str(r["Failed Week(s)"]),
                            items=r["_items"],
                            severity=r["_severity"],
                        )

                ui.pagination(
                    page=vio_page,
                    total_pages=total_pages,
                    total_items=total_vio,
                    page_size=_VIO_CARD_PAGE_SIZE,
                    state_key="vio_page",
                    label="violations",
                    on_change_audit="violation_page_nav",
                )

        elif failing > 0:
            st.info("Violations exist but none match your current filters.")
        else:
            st.success("🎉 All employees passed — no violations found.")

    except Exception as exc:
        _user_safe_error(
            trace_id, "An error occurred while rendering results.", exc)
        if st.button("🔄 Reset Results View", key="reset_results_btn"):
            st.session_state.validation_results = None
            st.session_state.validation_results_records = None
            st.rerun()


# ── DASHBOARD TAB ─────────────────────────────────────────────────────────

def _resolve_dashboard_filter() -> tuple[list[str], list[str], tuple[date, date] | None]:
    """
    Render the unified Coverage-dashboard filter and return the active subsets.

    The filter is sourced from session state populated on the Import & Edit
    tab: ``week_a_label`` / ``week_b_label`` (display names) and
    ``week_a_start`` / ``week_b_start`` (Mon-anchored reference dates).

    Returns:
        A 3-tuple ``(active_weeks, active_days, date_window)`` where:

        - ``active_weeks`` — subset of ``["A", "B"]`` selected by the user.
        - ``active_days`` — subset of ``DAYS`` (e.g. ``Mon_A``, ``Tue_B``…)
          surviving both the week-label filter and the date-range filter.
        - ``date_window`` — ``(start, end)`` resolved date range, or ``None``
          when no week has a reference date (filter degrades to weeks-only).
    """
    from datetime import timedelta

    lbl_a = st.session_state.get("week_a_label", "Week A")
    lbl_b = st.session_state.get("week_b_label", "Week B")
    start_a = st.session_state.get("week_a_start")
    start_b = st.session_state.get("week_b_start")

    label_to_suffix = {lbl_a: "A", lbl_b: "B"}
    label_options = list(label_to_suffix.keys())

    with st.expander("🔎 Dashboard Filter", expanded=True):
        st.caption(
            "Single filter applied to every table on this dashboard. "
            "Week labels and reference dates come from the **Import & Edit** tab."
        )
        f_c1, f_c2 = st.columns([1, 2])

        with f_c1:
            selected_labels = st.multiselect(
                "Week Reference Labels",
                options=label_options,
                default=label_options,
                key="dash_filter_weeks",
                help=(
                    "Restrict every table on the dashboard to the selected "
                    "weeks. Edit the labels on the Import & Edit tab."
                ),
            )

        # ── Date range picker ─────────────────────────────────────────────
        # Range is anchored on whatever week-start dates the user set on
        # the editor tab. If neither is set, the picker is disabled (we have
        # no calendar truth to filter against — week labels still work).
        starts = [s for s in (start_a, start_b) if s]
        if starts:
            min_date = min(starts)
            max_date = max(s + timedelta(days=6) for s in starts)
            default_start = min_date
            default_end = max_date
        else:
            min_date = max_date = default_start = default_end = None

        with f_c2:
            if min_date is None:
                st.date_input(
                    "Date range",
                    value=(),
                    disabled=True,
                    key="dash_filter_dates_disabled",
                    help=(
                        "Set a Week start date on the Import & Edit tab to "
                        "enable date-range filtering."
                    ),
                )
                date_window: tuple[date, date] | None = None
            else:
                picked = st.date_input(
                    "Date range",
                    value=(default_start, default_end),
                    min_value=min_date,
                    max_value=max_date,
                    key="dash_filter_dates",
                    format="MM/DD/YYYY",
                    help=(
                        "Restrict every table to day columns whose mapped "
                        "calendar date falls inside this range."
                    ),
                )
                # st.date_input with a tuple value can return either a single
                # date (mid-edit) or a (start, end) tuple. Normalize both.
                if isinstance(picked, tuple) and len(picked) == 2:
                    date_window = (picked[0], picked[1])
                elif isinstance(picked, date):
                    date_window = (picked, picked)
                else:
                    date_window = (default_start, default_end)

    # Resolve active week suffixes from selected labels.
    active_weeks = [label_to_suffix[lbl]
                    for lbl in selected_labels if lbl in label_to_suffix]

    # Build per-day calendar map for the date filter.
    day_to_date: dict[str, date] = {}
    for suffix, start in (("A", start_a), ("B", start_b)):
        if not start:
            continue
        wk = [start + timedelta(days=i) for i in range(7)]
        prefixes = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        for prefix, d in zip(prefixes, wk):
            day_to_date[f"{prefix}_{suffix}"] = d

    base_days = (
        (DAYS_A if "A" in active_weeks else [])
        + (DAYS_B if "B" in active_weeks else [])
    )

    if date_window is not None:
        ds, de = date_window
        if ds > de:
            ds, de = de, ds
        active_days = [
            d for d in base_days
            if d not in day_to_date or ds <= day_to_date[d] <= de
        ]
    else:
        active_days = list(base_days)

    return active_weeks, active_days, date_window


def render_dashboard_tab() -> None:
    trace_id = st.session_state.get("session_trace_id", "no-trace")

    if not st.session_state.get("validation_results_records"):
        ui.empty_state(
            "📊",
            "No dashboard data",
            "Validate a schedule first to see operational coverage metrics.",
            size="lg",
        )
        return

    try:
        df_full = pd.DataFrame(st.session_state.validation_results_records)
        if df_full.empty:
            st.warning("No data available.")
            return

        st.subheader("📊 Operational Coverage Dashboard")

        # ── Unified filter (drives every table below) ────────────────────
        active_weeks, active_days, date_window = _resolve_dashboard_filter()

        # Audit: only log when the filter signature changes.
        _filter_sig = (
            tuple(active_weeks),
            tuple(active_days),
            (date_window[0].isoformat(), date_window[1].isoformat())
            if date_window else None,
        )
        if st.session_state.get("_prev_dash_filter_sig") != _filter_sig:
            log_user_action(
                "dashboard_filter_changed",
                weeks=",".join(active_weeks) or "none",
                days=len(active_days),
                date_range=(
                    f"{date_window[0]:%Y-%m-%d}..{date_window[1]:%Y-%m-%d}"
                    if date_window else "n/a"
                ),
            )
            st.session_state._prev_dash_filter_sig = _filter_sig

        # If the user has filtered out every week, short-circuit with a
        # friendly empty state rather than rendering blank tables.
        if not active_weeks:
            st.info(
                "No week selected. Pick at least one **Week Reference Label** "
                "in the filter above to see dashboard tables."
            )
            return

        # ── Filtered dataframe used by every table on this page ─────────
        # Employee metadata + validation status columns are kept full-truth
        # (per-employee `_pass` is computed across the entire 14-day matrix);
        # only the day-columns are narrowed by the filter so per-day tables
        # honor the user's selection.
        meta_cols = [c for c in df_full.columns if c not in DAYS]
        df = df_full[meta_cols + active_days].copy()

        total = len(df)
        valid_emp = int(df["_pass"].sum())
        invalid_emp = total - valid_emp
        rate = int(100 * valid_emp / total) if total else 0

        # ── Compliance metrics ───────────────────────────────────────────
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Headcount", total,
                  delta=f"{valid_emp} valid · {invalid_emp} invalid", delta_color="off")
        c2.metric("Valid Schedules ✅", valid_emp,
                  delta=f"{rate}% compliance rate",
                  delta_color="normal" if rate >= 80 else "off")
        c3.metric("Invalid Schedules ❌", invalid_emp,
                  delta=f"{100 - rate}% gap" if invalid_emp > 0 else "None",
                  delta_color="inverse" if invalid_emp > 0 else "off")
        c4.metric("Overall Compliance", f"{rate}%",
                  "✓ Ready to submit" if rate == 100 else f"{100 - rate}% remaining",
                  delta_color="normal" if rate == 100 else "off")

        # ── OT Summary metrics (filter-aware) ────────────────────────────
        st.divider()
        st.subheader("⏱️ Overtime Summary")
        ot_c1, ot_c2, ot_c3, ot_c4 = st.columns(4)

        # OT subtotals are baked into validation_results per-week; honor the
        # week filter by summing only the included weeks.
        ot_a = int(df_full["OT Hrs A"].sum()) if (
            "OT Hrs A" in df_full.columns and "A" in active_weeks
        ) else 0
        ot_b = int(df_full["OT Hrs B"].sum()) if (
            "OT Hrs B" in df_full.columns and "B" in active_weeks
        ) else 0
        total_ot = ot_a + ot_b
        avg_ot = round(total_ot / total, 1) if total else 0

        lbl_a = st.session_state.get("week_a_label", "Week A")
        lbl_b = st.session_state.get("week_b_label", "Week B")

        ot_c1.metric("Total OT Hours", f"{total_ot}h",
                     delta=f"Across {total} employees", delta_color="off")
        ot_c2.metric(f"{lbl_a} OT", f"{ot_a}h",
                     delta=(
                         f"Avg {round(ot_a/total, 1)}h/emp"
                         if total and "A" in active_weeks else "—"
                     ),
                     delta_color="off")
        ot_c3.metric(f"{lbl_b} OT", f"{ot_b}h",
                     delta=(
                         f"Avg {round(ot_b/total, 1)}h/emp"
                         if total and "B" in active_weeks else "—"
                     ),
                     delta_color="off")
        ot_c4.metric("Avg OT / Employee", f"{avg_ot}h",
                     delta="AOT / BOT / COT only", delta_color="off")

        # ── Per-Day Headcount with Shift Reference (filter-aware) ────────
        st.divider()
        st.subheader("👥 Per-Day Headcount by Shift")

        day_cols = [d for d in active_days if d in df.columns]
        if day_cols:
            ref_codes = ["A", "B", "C", "AOT", "BOT", "COT", "OS5"]
            ref_parts = []
            for c in ref_codes:
                t = SHIFT_TIMES.get(c, {})
                s, e = t.get("start"), t.get("end")
                if s is not None and e is not None:
                    ref_parts.append(
                        f"**{c}** {int(s):02d}:00–{int(e) % 24:02d}:00")
            if ref_parts:
                st.caption("Shift reference: " + " · ".join(ref_parts))

            day_codes = df[day_cols].astype(str).apply(
                lambda col: col.str.strip().str.upper())
            present = {v for col in day_codes.columns
                       for v in day_codes[col].unique() if v}
            work_order = ["A", "B", "C", "AOT", "BOT", "COT", "OS5"]
            rest_order = ["RD", "LEAVE", "RH", "SPH", "NW", "AWOL"]
            ordered = (
                [c for c in work_order if c in present]
                + [c for c in rest_order if c in present]
                + sorted(c for c in present
                         if c not in work_order and c not in rest_order)
            )
            rows = []
            for code in ordered:
                row = {"Shift": code}
                for d in day_cols:
                    row[fmt_day(d)] = int((day_codes[d] == code).sum())
                rows.append(row)
            if rows:
                total_row = {"Shift": "TOTAL"}
                for d in day_cols:
                    col = fmt_day(d)
                    total_row[col] = sum(r[col] for r in rows)
                rows.append(total_row)
                ui.data_table(pd.DataFrame(rows), key="tbl_perday_headcount")
        else:
            st.info(
                "No day columns match the current date range — widen the filter "
                "to see per-day headcount."
            )

        # ── Schedule Matrix Distribution ──────────────────────────────────
        # Matrix detection looks at the full 14-day pattern; when only one
        # week is selected we still classify by full-row matrix because
        # detection is row-level, not per-week. The per-week active_days
        # subset is used only for column-driven tables above.
        st.divider()
        st.subheader("🧩 Schedule Matrix Distribution")
        if len(active_weeks) < 2:
            st.caption(
                "Matrix classification reflects the full 14-day employee record "
                "(not split per week)."
            )
        matrices = df_full.apply(detect_matrix, axis=1)
        mat_df = (
            pd.DataFrame({"Matrix": matrices, "_pass": df_full["_pass"]})
            .groupby("Matrix")
            .agg(Headcount=("_pass", "count"), Valid=("_pass", "sum"))
            .assign(
                Invalid=lambda x: x["Headcount"] - x["Valid"],
                Compliance=lambda x: (
                    x["Valid"] / x["Headcount"] * 100).round(1).astype(str) + "%",
            )
            .reset_index()
            .sort_values("Headcount", ascending=False)
        )
        ui.data_table(mat_df, key="tbl_matrix_dist")

        # ── Coverage by Station ───────────────────────────────────────────
        if "Station" in df.columns:
            st.divider()
            st.subheader("🏭 Coverage by Station")
            by_station = (
                df.groupby("Station")
                .agg(Headcount=("_pass", "count"), Valid=("_pass", "sum"))
                .assign(
                    Invalid=lambda x: x["Headcount"] - x["Valid"],
                    Compliance=lambda x: (
                        x["Valid"] / x["Headcount"] * 100).round(1).astype(str) + "%",
                )
                .reset_index()
                .sort_values("Headcount", ascending=False)
            )
            ui.data_table(by_station, key="tbl_coverage_station")

        # ── Top Violation Categories ──────────────────────────────────────
        rule_cols = [r.name for r in AVAILABLE_RULES if r.name in df.columns]
        if rule_cols:
            st.divider()
            st.subheader("🚨 Top Violation Categories")
            failed = []
            for col in rule_cols:
                n = int(df[col].astype(str).str.startswith("❌").sum())
                if n > 0:
                    failed.append({"Rule": col, "Failed Employees": n})
            if failed:
                vio_df = pd.DataFrame(failed).sort_values(
                    "Failed Employees", ascending=False)
                ui.data_table(vio_df, key="tbl_top_violations")
            else:
                st.success("All employees pass every active rule.")

        st.divider()
        st.subheader("📤 Finalize & Export")

        # ── Compliance gate — visual progress + clear lock state ──────────
        # Progress bar gives HR/ops an immediate read on how close they are
        # to shippable. Export + Submit buttons are hard-gated at rate == 100.
        st.progress(
            rate / 100,
            text=f"Compliance: {rate}% — {valid_emp} of {total} schedules valid",
        )

        if rate < 100:
            # Only log on transition INTO blocked state, not every rerun.
            _prev_rate = st.session_state.get("_prev_export_block_rate")
            if _prev_rate != rate:
                logger.info(
                    'export_blocked compliance=%d%% invalid=%d', rate, invalid_emp,
                )
                st.session_state._prev_export_block_rate = rate
            # ── LOCKED state ─────────────────────────────────────────────
            st.error(
                f"🚫 **Export is locked until 100% compliance.**\n\n"
                f"**{invalid_emp} employee{'s' if invalid_emp != 1 else ''}** still "
                f"{'have' if invalid_emp != 1 else 'has'} violations. "
                f"Open the **🔍 Validation Results** tab to resolve them, "
                f"then return here."
            )

            # Show locked button (visual, non-interactive) so users see
            # what's waiting for them once they hit 100%.
            st.button("🔒 Export Excel", disabled=True,
                      width="stretch", key="locked_excel")

            st.caption(
                f"💡 Tip: The **🔍 Validation Results** tab shows exactly which "
                f"rules failed for each employee so you can fix them fast."
            )

        else:
            # Reset the block-transition tracker when we leave the locked
            # state, so re-entering blocked re-logs once.
            st.session_state.pop("_prev_export_block_rate", None)
            # ── UNLOCKED state ────────────────────────────────────────────
            st.success(
                "✅ **100% compliant.** The export uses the same layout as your "
                "upload template — HR can process it directly or re-upload for "
                "correction. Excel contains 3 sheets: Schedule, Validation Details, "
                "and Summary."
            )

            if st.button(
                "⚙️ Build Excel Report", width="stretch",
                key="dash_gen_excel_btn",
            ):
                log_user_action("excel_export_initiated", rows=total)
                with st.spinner("Building template-format Excel…"):
                    try:
                        xl_bytes = generate_styled_excel_export(df)
                        log_user_action("export_excel_dashboard", rows=total)
                        st.session_state["_excel_export_bytes"] = xl_bytes
                    except Exception as exc:
                        log_user_action("excel_export_failed")
                        _user_safe_error(trace_id, "Excel export failed.", exc)

            if st.session_state.get("_excel_export_bytes"):
                st.download_button(
                    "⬇️ Download Excel (.xlsx)",
                    data=st.session_state["_excel_export_bytes"],
                    file_name="manning_validated_schedule.xlsx",
                    mime=(
                        "application/vnd.openxmlformats-officedocument"
                        ".spreadsheetml.sheet"
                    ),
                    type="primary",
                    width="stretch",
                    key="dash_dl_excel_btn",
                )

    except Exception as exc:
        _user_safe_error(
            trace_id, "An error occurred while rendering the dashboard.", exc)


# ── MAIN ──────────────────────────────────────────────────────────────────

def manning_simulator_page() -> None:
    """Main 3-tab UI (Import & Edit · Validation Results · Coverage Dashboard).

    Visible to every authenticated user. Registered as the default page in
    ``st.navigation`` from ``main()``. Additional pages (e.g. SuperAdmin-only
    Validation Defaults manager) are appended to the navigation registry by
    ``main()`` based on the caller's roles.
    """
    trace_id = st.session_state.get("session_trace_id", "no-trace")

    # Skip-link landing target (a11y). Empty anchor — its only job is to
    # exist with id="main" so keyboard users can jump past the sidebar.
    st.markdown(
        '<a id="main" tabindex="-1" aria-hidden="true"></a>',
        unsafe_allow_html=True,
    )

    st.title("📋 Manning Simulator")
    st.caption(
        f"14-day workforce schedule validator · "
        f"Logged in as **{st.session_state.get('user_id', 'unknown')}** · "
        f"Session `{trace_id}`"
    )

    tab_editor, tab_results, tab_dash = st.tabs([
        "📝 1. Import & Edit",
        "🔍 2. Validation Results",
        "📊 3. Coverage Dashboard",
    ])

    with tab_editor:
        render_editor_tab()
    with tab_results:
        render_results_tab()
    with tab_dash:
        render_dashboard_tab()

    # Snapshot work-data after every authenticated render of the main page.
    # Cheap (in-memory dict, references — DataFrames are not copied) and
    # provides a fresh checkpoint for any subsequent WebSocket reset.
    try:
        save_checkpoint(st.session_state.get("user_id", "anonymous"))
    except Exception:
        logger.exception("checkpoint_save_failed")


def main() -> None:
    st.set_page_config(
        page_title="Manning Simulator",
        page_icon="📋",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    inject_custom_css()     # Step 1 — CSS (before any visible element)
    ui.skip_link("main")    # Step 1a — a11y: first focusable element on the page
    init_session_state()    # Step 2 — session state (before auth)

    # Emit a one-time startup banner per Streamlit process. Guarded against
    # rerun-spam via a session-state flag; the banner fires for the first
    # rerun in this browser session, which is sufficient for ops/correlation.
    if not st.session_state.get("_startup_banner_logged"):
        log_startup_banner(_APP_VERSION)
        st.session_state._startup_banner_logged = True

    if not handle_auth():   # Step 3 — auth (login() is first DOM element inside)
        return               # st.stop() already called inside

    # Step 3a — restore work-data checkpoint (once per Streamlit session).
    # If the user's previous WebSocket was reset (e.g. by an idle-timeout
    # "Continue" round-trip under IIS) the new session_state would otherwise
    # come up with empty defaults. The checkpoint, scoped per user_id and
    # held in @st.cache_resource, survives WS resets within the process and
    # rehydrates schedule/validation_results/edits on the new session.
    # Logout clears the checkpoint so a fresh sign-in starts clean.
    if not st.session_state.get("_checkpoint_restored"):
        try:
            restore_checkpoint(st.session_state.get("user_id", "anonymous"))
        except Exception:
            logger.exception("checkpoint_restore_failed")
        st.session_state._checkpoint_restored = True

    # Step 3b — idle-timeout watchdog. Must be mounted on every authenticated
    # rerun so its component iframe persists; if not re-rendered, Streamlit
    # would tear it down and the client-side timer would die. The component
    # itself is invisible (height=0, fixed-position modal) until it needs to
    # show the warning. May call logout() + st.stop() internally.
    render_idle_timeout_guard()

    # Step 4 — full app renders only after confirmed auth
    trace_id = st.session_state.get("session_trace_id", "no-trace")
    # Streamlit re-runs the script top-to-bottom on every interaction (button
    # click, input change, tab switch, even logout), so a bare logger.info()
    # here would flood app.log with one entry per interaction. Gate it with a
    # session_state flag so it fires exactly once per authenticated session
    # (i.e. the first rerun after handle_auth() returns True). The flag is
    # cleared by logout() via _LOGOUT_WIPE_KEYS rotation, so the next sign-in
    # produces a fresh marker.
    if not st.session_state.get("_app_render_logged"):
        logger.info('app_render_start user_id="%s"',
                    st.session_state.get("user_id", "anonymous"))
        st.session_state._app_render_logged = True
    try:
        # ── Baseline role gate ────────────────────────────────────────────
        # Authentication is necessary but not sufficient — every gated
        # capability on the main simulator page (upload, edit, run, reset,
        # export) requires the ``manning-user`` realm role per the role
        # hierarchy. A ``manning-superadmin`` user passes automatically
        # because Keycloak emits the composite role's parents in
        # ``realm_access.roles``. Denial is audited inside ``require_role``.
        require_role(MANNING_USER, audit_action="manning_user_gate_denied")

        render_sidebar()

        # ── Page registry (Streamlit multipage) ────────────────────────────
        # The main simulator page is visible to every ``manning-user``.
        # SuperAdmin-only pages are conditionally appended when the caller
        # has the ``manning-superadmin`` realm role. Each admin page
        # re-checks the role on render as defense-in-depth against direct
        # URL access if this filter is ever bypassed.
        # ── Page registry (mode-aware) ─────────────────────────────────────
        # App mode (and any non-superadmin) → simulator only, no admin
        # entries reachable. Admin mode (superadmin only) → admin pages
        # only, the simulator hidden so the surface feels distinct.
        # Defense-in-depth: each admin page calls require_role at the top,
        # so a bypass of this gate would still be blocked.
        _view_mode = st.session_state.get("view_mode", "app")
        pages: list[st.Page] = []
        if _view_mode == "admin" and has_role(MANNING_SUPERADMIN):
            pages.append(
                st.Page(
                    "pages/admin_console.py",
                    title="Admin Console",
                    icon="🛡️",
                    default=True,
                )
            )
        else:
            pages.append(
                st.Page(
                    manning_simulator_page,
                    title="Manning Simulator",
                    icon="📋",
                    default=True,
                )
            )
        nav_position = "hidden" if len(pages) == 1 else "sidebar"
        pg = st.navigation(pages, position=nav_position)
        pg.run()

        maybe_show_debug_panel()    # dev-only, invisible to normal users

    except Exception as exc:
        _user_safe_error(
            trace_id, "A fatal application error occurred. Please refresh.", exc)
        if st.button("🔄 Recover Application", key="fatal_recover_btn"):
            log_user_action("fatal_error_recovery")
            for k in list(st.session_state.keys()):
                if k not in PROTECTED_KEYS:
                    del st.session_state[k]
            st.rerun()


if __name__ == "__main__":
    main()
