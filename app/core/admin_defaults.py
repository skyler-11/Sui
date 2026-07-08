"""
app/core/admin_defaults.py — SuperAdmin-managed validation defaults.

Reads (and, in a follow-up step, writes) ``config/admin_defaults.json``,
which holds the org-wide starting values for the validation threshold
sliders and the default active-rules set. Users override these per-session
via the sidebar; the JSON is mutated only by the SuperAdmin
"Admin: Validation Defaults" page.

The file is intentionally tiny and human-editable as a fallback for ops.
Any load failure (missing file, malformed JSON, unexpected types) falls
back to factory defaults and emits a single warning log — the app never
refuses to render because of an admin-defaults file problem.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

logger = get_logger("forge.admin_defaults")

# Resolve ``config/admin_defaults.json`` relative to the repo root. The
# repo root is two directories above this module file (``app/core/``).
# Anchoring to ``__file__`` keeps the path stable regardless of cwd or
# launch method (``streamlit run`` from repo root vs IIS service account
# vs packaged binary).
_DEFAULTS_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "admin_defaults.json"
)

# Factory defaults — used when the JSON file is missing, malformed, or a
# key is absent. Mirrors the hardcoded values previously baked into the
# Main.py sliders and ``app/core/rules.py``.
_FACTORY: dict[str, Any] = {
    "thresholds": {
        "max_week_hrs": 60,
        "min_week_hrs": 48,
        "max_rolling_7d_hrs": 60,
        "nw_credit_hrs": 0,
    },
    # None ⇒ fall back to ``AVAILABLE_RULES`` items with ``default_active=True``.
    # A list ⇒ explicit set of rule keys the SuperAdmin has pinned as active
    # by default. Users can still override per-session via the sidebar.
    "active_rule_keys": None,
}


def load_admin_defaults() -> dict[str, Any]:
    """Return the current SuperAdmin defaults, merged with factory fallbacks.

    Always returns a well-formed dict with keys ``thresholds`` (dict of int
    threshold values) and ``active_rule_keys`` (``None`` or ``list[str]``).
    Callers can rely on the shape without further guarding.

    On any I/O or parse error, logs a warning and returns factory defaults
    so the app keeps rendering.
    """
    if not _DEFAULTS_PATH.exists():
        return _factory_copy()
    try:
        with _DEFAULTS_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(
            'admin_defaults_load_failed path="%s" error="%s" '
            '— falling back to factory defaults',
            _DEFAULTS_PATH, str(e)[:200],
        )
        return _factory_copy()

    # Merge — file may be partial, have unrelated keys, or carry malformed
    # values. Build the canonical shape from factory defaults and overwrite
    # only keys whose values pass type checks.
    merged = _factory_copy()
    thresholds = data.get("thresholds")
    if isinstance(thresholds, dict):
        for k in merged["thresholds"]:
            v = thresholds.get(k)
            if isinstance(v, (int, float)):
                merged["thresholds"][k] = int(v)
    if "active_rule_keys" in data:
        v = data["active_rule_keys"]
        if v is None or (isinstance(v, list) and all(isinstance(x, str) for x in v)):
            merged["active_rule_keys"] = v
    return merged


def get_default_threshold(name: str, fallback: int) -> int:
    """Return a single threshold default by name, falling back if absent.

    Convenience for sites that only need one value and don't want to read
    the whole dict. The full ``load_admin_defaults()`` is cheap (one small
    file read) but using this helper keeps call sites concise.
    """
    return int(load_admin_defaults()["thresholds"].get(name, fallback))


def factory_defaults() -> dict[str, Any]:
    """Return a fresh copy of the factory defaults dict.

    Exposed so the SuperAdmin admin page can implement a
    "Reset to factory defaults" action without re-importing the module
    internals.
    """
    return _factory_copy()


def save_admin_defaults(
    thresholds: dict[str, int],
    active_rule_keys: list[str] | None,
) -> None:
    """Atomically persist SuperAdmin-pinned defaults to disk.

    Validates inputs against the canonical shape, then writes to a temp
    file in the same directory and atomically renames it into place via
    ``os.replace`` (atomic on both POSIX and Windows). On any failure,
    raises ``ValueError`` (bad input) or the underlying ``OSError``
    (filesystem error). The caller is responsible for surfacing the error
    to the user and auditing the action.
    """
    # ── Validate ──────────────────────────────────────────────────────────
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be a dict")
    expected_keys = set(_FACTORY["thresholds"].keys())
    if set(thresholds.keys()) != expected_keys:
        raise ValueError(
            f"thresholds must contain exactly these keys: {sorted(expected_keys)}"
        )
    clean_thresholds: dict[str, int] = {}
    for k, v in thresholds.items():
        if not isinstance(v, (int, float)) or isinstance(v, bool):
            raise ValueError(f"thresholds[{k!r}] must be numeric, got {type(v).__name__}")
        clean_thresholds[k] = int(v)
    if active_rule_keys is not None:
        if not isinstance(active_rule_keys, list) or not all(
            isinstance(x, str) for x in active_rule_keys
        ):
            raise ValueError("active_rule_keys must be None or a list[str]")

    payload = {
        "_comment": (
            "Org-wide default values for validation thresholds and active "
            "rules. Edited via the 'Admin: Validation Defaults' page "
            "(SuperAdmin only). Users can still override per-session via "
            "the sidebar sliders."
        ),
        "_version": 1,
        "thresholds": clean_thresholds,
        "active_rule_keys": active_rule_keys,
    }

    # ── Atomic write ──────────────────────────────────────────────────────
    # Write to a temp file in the same directory so ``os.replace`` is an
    # atomic rename (cross-device renames would silently fall back to a
    # non-atomic copy). Ensure the target directory exists for clean
    # bootstrapping on fresh checkouts.
    _DEFAULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix=".admin_defaults_", suffix=".json.tmp",
        dir=str(_DEFAULTS_PATH.parent),
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp_path, _DEFAULTS_PATH)
    except Exception:
        # Best-effort cleanup of the temp file on any failure.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    logger.info(
        'admin_defaults_saved path="%s" thresholds=%s active_rule_keys=%s',
        _DEFAULTS_PATH, clean_thresholds, active_rule_keys,
    )


def _factory_copy() -> dict[str, Any]:
    """Return a copy of factory defaults with no shared mutables."""
    return {
        "thresholds": dict(_FACTORY["thresholds"]),
        "active_rule_keys": _FACTORY["active_rule_keys"],
    }
