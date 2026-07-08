"""
pages/admin_validation_defaults.py — SuperAdmin: Validation Defaults view.

Exposes a ``render()`` function consumed by ``pages/admin_console.py`` inside
a tab. The module is no longer a top-level Streamlit page; the console acts
as the single nav entry for everything admin-side. Defense-in-depth: the
role gate is the first line of ``render()`` so any direct call into this
module (script, repl, test) still trips the deny screen.
"""

from __future__ import annotations

import streamlit as st

from app.auth import has_role
from app.core.admin_defaults import (
    factory_defaults,
    load_admin_defaults,
    save_admin_defaults,
)
from app.core.logging import get_audit_logger, get_logger
from app.core.roles import MANNING_SUPERADMIN
from app.core.rules import AVAILABLE_RULES

logger = get_logger("forge.admin_page")
audit_logger = get_audit_logger()

_SUPERADMIN_ROLE = MANNING_SUPERADMIN


def _deny_and_stop() -> None:
    """Render an access-denied message and halt the page."""
    user_id = st.session_state.get("user_id", "anonymous")
    audit_logger.warning(
        'action="admin_page_access_denied" '
        'page="admin_validation_defaults" user_id="%s" required_role="%s"',
        user_id, _SUPERADMIN_ROLE,
    )
    st.error(
        "Access denied — this page is restricted to users with the "
        f"`{_SUPERADMIN_ROLE}` role."
    )
    st.stop()


def render() -> None:
    """Render the Validation Defaults view. Called from admin_console.py."""

    # ── Defense-in-depth ────────────────────────────────────────────────
    if not has_role(_SUPERADMIN_ROLE):
        _deny_and_stop()

    # ── Data load ───────────────────────────────────────────────────────
    user_id = st.session_state.get("user_id", "anonymous")
    current = load_admin_defaults()
    factory = factory_defaults()
    current_thresholds = current["thresholds"]
    current_active_keys = current["active_rule_keys"]
    rule_options = {r.key: r.name for r in AVAILABLE_RULES}

    # ── KPI row ─────────────────────────────────────────────────────────
    if current_active_keys is None:
        pinned_active_count = "—"
        pinned_active_help = "Falling back to each rule's code default"
    else:
        pinned_active_count = str(len(current_active_keys))
        pinned_active_help = f"out of {len(AVAILABLE_RULES)} available rules"

    with st.container(key="admin_kpi_row_defaults"):
        k1, k2, k3, k4 = st.columns(4)
        k1.metric(
            "Max weekly hrs",
            current_thresholds["max_week_hrs"],
            delta=f"factory {factory['thresholds']['max_week_hrs']}",
            delta_color="off",
        )
        k2.metric(
            "Min weekly hrs",
            current_thresholds["min_week_hrs"],
            delta=f"factory {factory['thresholds']['min_week_hrs']}",
            delta_color="off",
        )
        k3.metric(
            "Rolling 7-day cap",
            current_thresholds["max_rolling_7d_hrs"],
            delta=f"factory {factory['thresholds']['max_rolling_7d_hrs']}",
            delta_color="off",
        )
        k4.metric(
            "Pinned active rules",
            pinned_active_count,
            delta=pinned_active_help,
            delta_color="off",
        )

    # ── Editor sub-tabs ─────────────────────────────────────────────────
    tab_thresholds, tab_rules, tab_snapshot = st.tabs(
        ["📏 Thresholds", "✅ Active rules", "📋 Snapshot"]
    )

    # ── THRESHOLDS ──────────────────────────────────────────────────────
    with tab_thresholds:
        with st.form("admin_thresholds_form", clear_on_submit=False):
            st.caption("All values are integers · hours per cycle.")

            col1, col2 = st.columns(2, gap="large")
            with col1:
                with st.container(border=True):
                    st.markdown("##### Weekly hours")
                    new_max_week = st.number_input(
                        "Maximum",
                        min_value=40, max_value=84,
                        value=int(current_thresholds["max_week_hrs"]),
                        step=1, help="Hard cap for weekly hours.",
                    )
                    new_min_week = st.number_input(
                        "Minimum",
                        min_value=0, max_value=60,
                        value=int(current_thresholds["min_week_hrs"]),
                        step=1,
                        help="Floor for weekly hours. Set to 0 to disable.",
                    )

            with col2:
                with st.container(border=True):
                    st.markdown("##### Rolling & credits")
                    new_max_rolling = st.number_input(
                        "Max rolling 7-day hours",
                        min_value=40, max_value=84,
                        value=int(current_thresholds["max_rolling_7d_hrs"]),
                        step=1,
                        help="Cap for any 7 consecutive days (rolling window).",
                    )
                    new_nw_credit = st.number_input(
                        "NW credit hours per shutdown day",
                        min_value=0, max_value=12,
                        value=int(current_thresholds["nw_credit_hrs"]),
                        step=1,
                        help=(
                            "Credits NW (No-Work / plant shutdown) days at this "
                            "hour rate when computing weekly minimum hours."
                        ),
                    )

            if new_min_week >= new_max_week:
                st.warning(
                    "⚠️ Min weekly hours must be **less than** max weekly "
                    "hours before you can save."
                )

            st.markdown("")  # spacer
            col_save, _ = st.columns([1, 3])
            with col_save:
                save_thresholds_clicked = st.form_submit_button(
                    "💾 Save thresholds",
                    type="primary",
                    width="stretch",
                    disabled=new_min_week >= new_max_week,
                )

        if save_thresholds_clicked:
            new_thresholds = {
                "max_week_hrs": int(new_max_week),
                "min_week_hrs": int(new_min_week),
                "max_rolling_7d_hrs": int(new_max_rolling),
                "nw_credit_hrs": int(new_nw_credit),
            }
            try:
                save_admin_defaults(new_thresholds, current_active_keys)
            except (ValueError, OSError) as e:
                audit_logger.error(
                    'action="admin_defaults_save_failed" '
                    'user_id="%s" error="%s"',
                    user_id, str(e)[:200],
                )
                st.error(f"Save failed: {e}")
            else:
                audit_logger.info(
                    'action="admin_defaults_saved" user_id="%s" '
                    'thresholds=%s active_rule_keys=%s',
                    user_id, new_thresholds, current_active_keys,
                )
                st.toast("Thresholds saved ✓", icon="✅")
                st.rerun()

    # ── ACTIVE RULES ────────────────────────────────────────────────────
    with tab_rules:
        with st.form("admin_rules_form", clear_on_submit=False):
            if current_active_keys is None:
                preselected_keys = [
                    r.key for r in AVAILABLE_RULES if r.default_active
                ]
                source_label = (
                    "💡 not yet pinned — showing each rule's code default"
                )
            else:
                preselected_keys = [
                    k for k in current_active_keys if k in rule_options
                ]
                source_label = (
                    f"📌 pinned set — {len(preselected_keys)} rule(s) selected"
                )

            st.caption(source_label)

            use_factory_active = st.toggle(
                "Use each rule's built-in default (don't pin a set)",
                value=(current_active_keys is None),
                help=(
                    "When ON, saves `active_rule_keys: null` so the app falls "
                    "back to each rule's hardcoded `default_active` flag. "
                    "When OFF, the selection below is pinned."
                ),
            )

            if use_factory_active:
                st.info("Built-in defaults will be used for new sessions.")
                new_active_keys: list[str] | None = None
            else:
                selected_names = st.multiselect(
                    "Rules active by default:",
                    options=[rule_options[k] for k in rule_options],
                    default=[rule_options[k] for k in preselected_keys],
                    help="Users can still toggle individual rules per-session.",
                )
                _name_to_key = {v: k for k, v in rule_options.items()}
                new_active_keys = [_name_to_key[n] for n in selected_names]

            st.markdown("")  # spacer
            col_save_rules, _ = st.columns([1, 3])
            with col_save_rules:
                save_rules_clicked = st.form_submit_button(
                    "💾 Save active rules",
                    type="primary",
                    width="stretch",
                )

        if save_rules_clicked:
            try:
                save_admin_defaults(current_thresholds, new_active_keys)
            except (ValueError, OSError) as e:
                audit_logger.error(
                    'action="admin_defaults_save_failed" '
                    'user_id="%s" error="%s"',
                    user_id, str(e)[:200],
                )
                st.error(f"Save failed: {e}")
            else:
                audit_logger.info(
                    'action="admin_defaults_saved" user_id="%s" '
                    'thresholds=%s active_rule_keys=%s',
                    user_id, current_thresholds, new_active_keys,
                )
                st.toast("Active rules saved ✓", icon="✅")
                st.rerun()

    # ── SNAPSHOT ────────────────────────────────────────────────────────
    with tab_snapshot:
        col_a, col_b = st.columns(2, gap="large")
        with col_a:
            with st.container(border=True):
                st.markdown("##### Current (pinned)")
                st.json(current, expanded=True)
        with col_b:
            with st.container(border=True):
                st.markdown("##### Factory defaults")
                st.json(factory, expanded=True)

    # ── DANGER ZONE ─────────────────────────────────────────────────────
    with st.container(key="admin_danger_zone"):
        st.markdown("#### ⚠️ Danger zone")
        st.markdown(
            "Reset all pinned defaults to their hardcoded factory values. "
            "The active-rules set is reset to `null` (fall back to code "
            "defaults). This rewrites `config/admin_defaults.json` and "
            "cannot be undone."
        )

        if "_confirm_factory_reset" not in st.session_state:
            st.session_state._confirm_factory_reset = False

        if not st.session_state._confirm_factory_reset:
            if st.button(
                "🔄 Reset to factory defaults",
                key="reset_factory_btn",
                type="secondary",
            ):
                st.session_state._confirm_factory_reset = True
                st.rerun()
        else:
            st.warning(
                "Confirm: reset all validation defaults to factory values?"
            )
            col_y, col_n, _ = st.columns([1, 1, 3])
            with col_y:
                if st.button(
                    "Yes, reset",
                    type="primary",
                    width="stretch",
                    key="reset_factory_confirm",
                ):
                    try:
                        save_admin_defaults(
                            factory["thresholds"],
                            factory["active_rule_keys"],
                        )
                    except (ValueError, OSError) as e:
                        audit_logger.error(
                            'action="admin_defaults_reset_failed" '
                            'user_id="%s" error="%s"',
                            user_id, str(e)[:200],
                        )
                        st.error(f"Reset failed: {e}")
                    else:
                        audit_logger.info(
                            'action="admin_defaults_reset_to_factory" '
                            'user_id="%s"',
                            user_id,
                        )
                        st.session_state._confirm_factory_reset = False
                        st.toast("Defaults reset to factory ✓", icon="✅")
                        st.rerun()
            with col_n:
                if st.button(
                    "Cancel",
                    width="stretch",
                    key="reset_factory_cancel",
                ):
                    st.session_state._confirm_factory_reset = False
                    st.rerun()
