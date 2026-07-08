"""
pages/admin_changelog.py — SuperAdmin: Changelog view.

Exposes a ``render()`` function consumed by ``pages/admin_console.py`` inside
a tab. Reads the repo's committed ``CHANGELOG.md`` (Keep a Changelog format)
and renders it as a modern vertical timeline of release cards instead of a
raw Markdown dump — see :func:`app.ui.changelog_timeline`.

The file is trusted (checked into the repo) but still parsed defensively: the
parser is pure-Python line scanning, and every interpolated value is escaped
in the UI helper before it reaches the DOM. A raw-Markdown fallback is offered
in an expander and used wholesale if parsing yields no releases.

Gating: the role gate is the first executable line of ``render()`` so any
direct call (script, repl, test) still trips the deny screen.

Audit instrumentation:
  * First open per session  → ``action="changelog_opened"``
  * Role denial             → ``action="changelog_access_denied"``
                              (emitted from ``require_role``)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import streamlit as st

from app import ui
from app.auth import require_role
from app.core.logging import get_audit_logger, get_logger
from app.core.roles import MANNING_SUPERADMIN
from app.utils import log_user_action

logger = get_logger("forge.changelog")
audit_logger = get_audit_logger()

# Repo-root CHANGELOG.md (pages/ -> repo root).
_CHANGELOG_PATH = Path(__file__).resolve().parent.parent / "CHANGELOG.md"

# ── Keep a Changelog grammar ──────────────────────────────────────────────
# Release header:  "## [v1.9.1] - 2026-06-01"  or  "## [v1.9.0]"
# Tolerates a bare "## v1.9.0" header (no brackets) as a fallback.
_RELEASE_RE = re.compile(
    r"^##\s+(?:\[(?P<ver_b>[^\]]+)\]|(?P<ver_p>\S+))"
    r"\s*(?:[-–—]\s*(?P<date>.+?))?\s*$"
)
# Category header: "### Added", "### Fixed", …
_SECTION_RE = re.compile(r"^###\s+(?P<cat>.+?)\s*$")
# Bullet item: "- text" / "* text".
_BULLET_RE = re.compile(r"^[-*]\s+(?P<text>.+?)\s*$")


@dataclass
class _Section:
    """One category block (e.g. ``Added``) within a release."""

    category: str
    items: list[str] = field(default_factory=list)


@dataclass
class _Release:
    """One release entry parsed from the changelog."""

    version: str
    date: str = ""
    sections: list[_Section] = field(default_factory=list)


def _parse_changelog(text: str) -> tuple[str, list[_Release]]:
    """Parse Keep a Changelog Markdown into ``(intro, releases)``.

    ``intro`` is the prose before the first release header (rendered as a
    caption). ``releases`` are newest-first in source order. Bullet
    continuation lines (indented under a bullet) are folded into the current
    item so multi-line entries survive intact.

    Args:
        text: raw contents of ``CHANGELOG.md``.

    Returns:
        A 2-tuple of the intro paragraph(s) and the ordered release list.
    """
    intro_lines: list[str] = []
    releases: list[_Release] = []
    current_rel: _Release | None = None
    current_sec: _Section | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()

        rel_match = _RELEASE_RE.match(line)
        if rel_match:
            version = rel_match.group("ver_b") or rel_match.group("ver_p") or ""
            current_rel = _Release(
                version=version.strip(),
                date=(rel_match.group("date") or "").strip(),
            )
            releases.append(current_rel)
            current_sec = None
            continue

        if current_rel is None:
            # Still in the preamble — skip the top-level "# Changelog" H1.
            if line and not line.startswith("# "):
                intro_lines.append(line)
            continue

        sec_match = _SECTION_RE.match(line)
        if sec_match:
            current_sec = _Section(category=sec_match.group("cat").strip())
            current_rel.sections.append(current_sec)
            continue

        bullet_match = _BULLET_RE.match(line)
        if bullet_match and current_sec is not None:
            current_sec.items.append(bullet_match.group("text").strip())
            continue

        # Indented continuation of the previous bullet.
        if (
            line.strip()
            and raw_line[:1].isspace()
            and current_sec is not None
            and current_sec.items
        ):
            current_sec.items[-1] += " " + line.strip()

    intro = " ".join(intro_lines).strip()
    return intro, releases


def render() -> None:
    """Render the Changelog view. Called from admin_console.py."""

    # ── Defense-in-depth ────────────────────────────────────────────────
    require_role(MANNING_SUPERADMIN, audit_action="changelog_access_denied")

    # ── First-render audit (once per session) ───────────────────────────
    if not st.session_state.get("_changelog_opened_logged"):
        log_user_action("changelog_opened")
        st.session_state._changelog_opened_logged = True

    # ── Load the committed changelog ────────────────────────────────────
    try:
        text = _CHANGELOG_PATH.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        logger.warning('changelog_read_failed path="%s" err="%s"',
                       _CHANGELOG_PATH, exc)
        ui.empty_state(
            "📝",
            "No changelog available",
            "CHANGELOG.md could not be found or read on the server.",
        )
        return

    # ── Parse → modern timeline ─────────────────────────────────────────
    intro, releases = _parse_changelog(text)

    if not releases:
        # Parsing produced nothing usable — fall back to trusted raw render
        # rather than showing an empty page.
        logger.info("changelog_parse_empty — falling back to raw markdown")
        st.markdown(text)
        return

    if intro:
        st.caption(intro)

    ui.changelog_timeline(releases_to_mapping(releases))

    # ── Raw source (opt-in) ─────────────────────────────────────────────
    with st.expander("📄 View raw CHANGELOG.md", expanded=False):
        st.code(text, language="markdown")


def releases_to_mapping(releases: list[_Release]) -> list[dict[str, object]]:
    """Adapt parsed dataclasses into the plain-mapping shape the UI helper
    expects (keeps :mod:`app.ui` free of this module's dataclasses)."""
    return [
        {
            "version": rel.version,
            "date": rel.date,
            "sections": [
                {"category": sec.category, "items": list(sec.items)}
                for sec in rel.sections
            ],
        }
        for rel in releases
    ]
