"""
app/core/checkpoint.py — Per-user in-memory work-data checkpoint.

Defends against st.session_state loss caused by transient WebSocket resets
(observed under Streamlit 1.55 + IIS reverse proxy when the idle-timeout
"Continue session" path navigates the parent window). Without a checkpoint,
the new WebSocket session reinitialises every work-data key from scratch and
the user's uploaded schedule, edits, and validation results vanish.

The store is process-wide via ``@st.cache_resource`` keyed by ``user_id`` and
holds **plain Python objects** (DataFrames, dicts, lists). It survives:
  - WS reset / fresh Streamlit session within the same process
  - Idle "Continue session" round-trip
  - Tab refresh while authenticated

It does NOT survive a process / app-pool recycle. That is acceptable: a
recycle is a deploy event and users are expected to re-upload after a deploy.
If durable persistence is needed later, the public API
(``save_checkpoint`` / ``restore_checkpoint`` / ``clear_checkpoint``) is
stable — only ``_user_store`` body needs to change.

Security:
  - Anonymous user (no real identity) is a no-op. Otherwise a shared kiosk
    session could leak data between guests.
  - Auth tokens are NOT checkpointed — token refresh goes through Keycloak.
  - ``clear_checkpoint(user_id)`` is called on logout so a subsequent login
    on the same machine starts clean.
"""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from app.core.logging import get_logger, get_audit_logger

logger = get_logger("forge.checkpoint")
audit_logger = get_audit_logger()


# Keys that represent in-progress user work. Mirrors the work-data subset of
# _LOGOUT_WIPE_KEYS in app/auth.py — auth/identity keys are intentionally
# excluded (those flow through Keycloak token refresh, not this store).
_CHECKPOINT_KEYS: tuple[str, ...] = (
    "schedule",
    "validation_results",
    "validation_results_records",
    "active_rule_keys",
    "max_week_hrs",
    "min_week_hrs",
    "max_rolling_7d_hrs",
    "week_a_label",
    "week_b_label",
    "week_a_start",
    "week_b_start",
    "last_file_id",
    "emp_page",
    "vio_page",
)


@st.cache_resource(show_spinner=False)
def _user_store(user_id: str) -> dict[str, Any]:
    """Per-user in-memory dict, shared across WebSocket sessions for this
    Streamlit process. ``cache_resource`` returns the same object on repeat
    calls with the same key.
    """
    return {}


def _is_default(key: str, value: Any) -> bool:
    """Recognise the empty defaults set by ``init_session_state()``.

    Used by ``restore_checkpoint`` to avoid clobbering genuinely-cleared
    state with stale checkpoint data: only restore into keys that are still
    at their initial default.
    """
    if value is None:
        return True
    if isinstance(value, pd.DataFrame):
        return value.empty
    if isinstance(value, (list, dict, tuple, set, str)) and len(value) == 0:
        return True
    return False


def save_checkpoint(user_id: str) -> None:
    """Snapshot work-data keys from session_state into the per-user store.

    Cheap: shallow dict assignment, no I/O, no copies (DataFrames are
    references). Safe to call on every authenticated rerun.

    No-op for anonymous / unset users.
    """
    if not user_id or user_id == "anonymous":
        return
    store = _user_store(user_id)
    for k in _CHECKPOINT_KEYS:
        if k in st.session_state:
            store[k] = st.session_state[k]


def restore_checkpoint(user_id: str) -> bool:
    """Rehydrate session_state from the per-user store.

    Only writes into keys that are missing or at their default value, so a
    user who deliberately cleared their schedule does not get it back.

    Returns True if at least one key was restored, False otherwise.
    """
    if not user_id or user_id == "anonymous":
        return False
    store = _user_store(user_id)
    if not store:
        return False
    restored_any = False
    restored_keys: list[str] = []
    for k, v in store.items():
        if k not in _CHECKPOINT_KEYS:
            continue
        current = st.session_state.get(k, None)
        if k not in st.session_state or _is_default(k, current):
            st.session_state[k] = v
            restored_any = True
            restored_keys.append(k)
    if restored_any:
        audit_logger.info(
            'action="checkpoint_restored" user_id="%s" key_count=%d',
            user_id, len(restored_keys),
        )
        logger.info(
            'checkpoint_restored user_id="%s" keys=%s',
            user_id, ",".join(restored_keys),
        )
    return restored_any


def clear_checkpoint(user_id: str) -> None:
    """Drop the per-user store. Called on logout."""
    if not user_id or user_id == "anonymous":
        return
    store = _user_store(user_id)
    had_data = bool(store)
    store.clear()
    if had_data:
        audit_logger.info(
            'action="checkpoint_cleared" user_id="%s"', user_id,
        )
