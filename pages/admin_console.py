"""
pages/admin_console.py — SuperAdmin: Admin Console (single entry, two tabs).

Replaces the two separate admin page entries (Validation Defaults + Log
Viewer) with one nav item. The two existing modules are now plain Python
modules that expose a ``render()`` function each; this console gates once
at the entry and composes both inside ``st.tabs(...)``.

Gating:
  * Conditionally registered by ``Main.py`` only when view_mode == "admin"
    AND has_role(MANNING_SUPERADMIN).
  * Defense-in-depth: first executable line calls ``require_role``; each
    inner render() also re-checks (so a direct module call still trips
    the deny screen).
"""

from __future__ import annotations

import streamlit as st

from app import ui
from app.auth import require_role
from app.core.logging import get_audit_logger, get_logger
from app.core.roles import MANNING_SUPERADMIN
from app.utils import log_user_action

logger = get_logger("forge.admin_console")
audit_logger = get_audit_logger()


# ── Defense-in-depth guard ────────────────────────────────────────────────
require_role(MANNING_SUPERADMIN, audit_action="admin_console_access_denied")


# ── First-render audit (once per session) ─────────────────────────────────
if not st.session_state.get("_admin_console_opened_logged"):
    log_user_action("admin_console_opened")
    st.session_state._admin_console_opened_logged = True


# ── Hero header ───────────────────────────────────────────────────────────
ui.hero(
    "Admin Console",
    "Validation defaults, change history, and log viewer for superadmins. "
    "All actions on this page are themselves audited.",
    icon="🛡️",
    chip="Admin Mode",
    chip_tone="accent",
    key="admin_hero",
)


# ── Tabs ──────────────────────────────────────────────────────────────────
# Import inside-tab so the per-view module's logger is only initialized
# when its tab is rendered for the first time in the session. Streamlit
# imports are cached, so this is free on subsequent reruns.
tab_defaults, tab_changes, tab_logs, tab_changelog = st.tabs(
    ["⚙️ Validation Defaults", "🛠️ Application Changes",
     "🪵 Log Viewer", "📝 Changelog"],
)

with tab_defaults:
    from pages.admin_validation_defaults import render as render_defaults
    render_defaults()

with tab_changes:
    from pages.admin_app_changes import render as render_app_changes
    render_app_changes()

with tab_logs:
    from pages.admin_log_viewer import render as render_logs
    render_logs()

with tab_changelog:
    from pages.admin_changelog import render as render_changelog
    render_changelog()
