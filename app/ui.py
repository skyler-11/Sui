"""
app/ui.py — Reusable UI component module for Manning Simulator.

Centralizes every snippet of inline-styled HTML that used to live across
Main.py and pages/. Every helper builds HTML from a fixed template +
``html.escape()``-d dynamic fields; user-supplied strings never reach the
DOM raw.

Two responsibilities:

1.  Stylesheet + theme injection — :func:`inject_theme` loads
    ``assets/style.css`` once and stamps ``data-theme="light|dark"`` on
    ``<html>`` so the dual-mode token set in the stylesheet resolves.
2.  Component helpers — small render functions for heroes, KPI rows,
    empty states, badges, pagination, violation cards, reference cards,
    skip-link, fallback logo.

All helpers are pure: they call ``st.markdown(..., unsafe_allow_html=True)``
internally so the call-sites stay declarative. Read the source of any
helper before introducing new dynamic fields — every interpolated value
MUST be escaped first.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import streamlit as st

from app.core.logging import get_logger

logger = get_logger("forge.ui")


# ── Constants ─────────────────────────────────────────────────────────────

_THEME_KEY = "theme"
_VALID_THEMES = ("light", "dark")
# The app is light-only — a runtime light/dark toggle can't theme Streamlit's
# canvas data-grid (its native theme is static), so the toggle was removed and the
# theme is pinned to light to match Streamlit's native theme (config.toml /
# run_streamlit.bat STREAMLIT_THEME_BASE=light). The dark token set in
# assets/style.css is dormant (data-theme="dark" is never stamped). get_theme()
# always returns "light", which the histogram / log-grid callers rely on.
_DEFAULT_THEME = "light"

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CSS_PATH = _REPO_ROOT / "assets" / "style.css"


# ── Raw-HTML helper ───────────────────────────────────────────────────────

def _collapse_html(markup: str) -> str:
    """Flatten a multi-line HTML template into a single line.

    Streamlit renders ``unsafe_allow_html`` markup through a Markdown
    processor, and a *blank line* inside the markup ends the raw-HTML block.
    When an optional interpolation (e.g. a footnote) is empty, the line it
    sat on collapses to whitespace — that blank line terminates the block and
    Streamlit renders the trailing close tag (``</article>``) as literal text.

    Stripping each line and dropping the empties, then joining with no
    separator, removes that failure mode. The rendered DOM is unchanged:
    these templates never split a text node across lines, so inter-tag
    whitespace here is not significant.
    """
    return "".join(
        line.strip() for line in markup.splitlines() if line.strip()
    )


# ── Theme + stylesheet injection ──────────────────────────────────────────

def get_theme() -> str:
    """Return the active theme name from session state.

    Defaults to ``"light"`` on first call. Validated against the allow-list
    so a corrupted session value can't break the data-theme selector chain.
    """
    value = st.session_state.get(_THEME_KEY, _DEFAULT_THEME)
    if value not in _VALID_THEMES:
        value = _DEFAULT_THEME
        st.session_state[_THEME_KEY] = value
    return value


def set_theme(mode: str) -> None:
    """Persist the chosen theme to session state.

    Raises:
        ValueError: if ``mode`` is not one of ``"light"`` or ``"dark"``.
    """
    if mode not in _VALID_THEMES:
        raise ValueError(
            f"Unknown theme {mode!r}; expected one of {_VALID_THEMES}."
        )
    st.session_state[_THEME_KEY] = mode


def _load_css() -> str:
    """Read the global stylesheet from disk, returning ``""`` on failure.

    Failure is logged but never raised — an unstyled page is preferable to
    a hard crash during chrome injection.
    """
    if not _CSS_PATH.exists():
        logger.error("CSS not found at %s — app will render unstyled.",
                     _CSS_PATH)
        return ""
    try:
        return _CSS_PATH.read_text(encoding="utf-8")
    except OSError:
        logger.exception("Failed to read CSS file.")
        return ""


def inject_theme(mode: str | None = None) -> None:
    """Inject the global stylesheet and stamp ``data-theme`` on ``<html>``.

    Must be called once per render, before any visible widget. The CSS
    file contains both ``:root[data-theme="light"]`` and
    ``:root[data-theme="dark"]`` token blocks — only the matching one
    resolves.

    Implementation split:

    *   ``<style>`` block via :func:`st.markdown` — Streamlit allows raw
        markup but **strips ``<script>`` tags** from markdown, so the
        stylesheet alone goes here.
    *   ``<script>`` for ``data-theme`` stamping + aria-live wiring goes
        through :func:`st.components.v1.html` (iframe) at height=0; from
        the iframe ``window.parent.document`` reaches the host app DOM.

    Args:
        mode: explicit theme override (``"light"`` / ``"dark"``). When
            ``None`` (the default) the value from session state wins.
    """
    if mode is None:
        mode = get_theme()
    elif mode in _VALID_THEMES:
        st.session_state[_THEME_KEY] = mode
    else:
        mode = get_theme()

    css = _load_css()
    safe_mode = html.escape(mode)

    # Stylesheet first — runs in the host document.
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

    # Script runs from an iframe (height=0) and reaches the host DOM via
    # window.parent.document. Same pattern as the idle-watchdog component
    # in app/auth.py — known-working under Streamlit's strict mode.
    theme_color = "#0b1220" if mode == "dark" else "#F24713"
    st.components.v1.html(
        f"""
        <script>
        (function() {{
            try {{
                var doc = window.parent.document;
                if (!doc) return;
                var root = doc.documentElement;
                var body = doc.body;
                root.setAttribute('data-theme', '{safe_mode}');
                if (body) {{
                    body.classList.remove('theme-light', 'theme-dark');
                    body.classList.add('theme-{safe_mode}');
                }}
                var meta = doc.querySelector('meta[name="theme-color"]');
                if (!meta) {{
                    meta = doc.createElement('meta');
                    meta.setAttribute('name', 'theme-color');
                    doc.head.appendChild(meta);
                }}
                meta.setAttribute('content', '{theme_color}');
                var attachLive = function() {{
                    var t = doc.querySelector(
                        '[data-testid="stToastContainer"]'
                    );
                    if (t && !t.getAttribute('aria-live')) {{
                        t.setAttribute('role', 'status');
                        t.setAttribute('aria-live', 'polite');
                    }}
                }};
                attachLive();
                setTimeout(attachLive, 500);
                setTimeout(attachLive, 1500);
            }} catch (e) {{ /* same-origin guard; non-fatal */ }}
        }})();
        </script>
        """,
        height=0,
    )


def inject_custom_css() -> None:
    """Back-compat shim — delegates to :func:`inject_theme`.

    Older call-sites (``Main.py``, tests) import ``inject_custom_css`` from
    ``app.utils``; that function now forwards here so we keep one canonical
    injector.
    """
    inject_theme()


# ── Skip link (a11y — first focusable element on the page) ────────────────

def skip_link(target_id: str = "main") -> None:
    """Render a visually hidden 'Skip to main content' link.

    The link becomes visible on keyboard focus. Place it as the very first
    element after :func:`inject_theme` so screen-reader and keyboard users
    can bypass the sidebar.
    """
    safe_id = html.escape(target_id)
    st.markdown(
        f'<a class="ms-skip-link" href="#{safe_id}">Skip to main content</a>',
        unsafe_allow_html=True,
    )


# ── Hero ──────────────────────────────────────────────────────────────────

def hero(
    title: str,
    subtitle: str = "",
    *,
    icon: str = "",
    chip: str | None = None,
    chip_tone: str = "accent",
    key: str = "admin_hero",
) -> None:
    """Render a page-hero card.

    Use at the top of admin pages instead of plain ``st.title``. The card
    styling (gradient bg, border, shadow) comes from the
    ``.st-key-admin_hero`` rule in the stylesheet — this helper only
    handles the internal flexbox layout and the optional right-pinned chip.

    Args:
        title: heading text. Rendered as ``<h2>``.
        subtitle: body copy under the heading.
        icon: optional leading emoji or short symbol (rendered as-is —
            keep it to single grapheme to avoid breaking the flex layout).
        chip: optional pill text pinned to the right (e.g. "ADMIN MODE").
        chip_tone: one of ``"accent" | "success" | "warn" | "danger" |
            "neutral"``.
        key: container key — keep unique per page to satisfy Streamlit's
            no-duplicate-keys rule.
    """
    safe_title = html.escape(title)
    safe_subtitle = html.escape(subtitle) if subtitle else ""
    safe_icon = html.escape(icon) if icon else ""

    chip_html = ""
    if chip:
        safe_chip = html.escape(chip)
        safe_tone = _safe_tone(chip_tone)
        chip_html = (
            f'<span class="ms-chip ms-chip--{safe_tone}" '
            f'aria-label="{safe_chip}">{safe_chip}</span>'
        )

    icon_html = (
        f'<span class="ms-hero__icon" aria-hidden="true">{safe_icon}</span>'
        if safe_icon else ""
    )
    subtitle_html = (
        f'<p class="ms-hero__subtitle">{safe_subtitle}</p>'
        if safe_subtitle else ""
    )

    with st.container(key=key):
        st.markdown(
            _collapse_html(
                f"""
                <div class="ms-hero">
                    <div class="ms-hero__body">
                        <h2 class="ms-hero__title">{icon_html}{safe_title}</h2>
                        {subtitle_html}
                    </div>
                    <div class="ms-hero__chip-wrap">{chip_html}</div>
                </div>
                """
            ),
            unsafe_allow_html=True,
        )


# ── KPI row ───────────────────────────────────────────────────────────────

def kpi_row(
    items: Sequence[Mapping[str, object]],
    *,
    key: str = "kpi_row",
) -> None:
    """Render a row of styled KPI tiles via ``st.metric``.

    Each item is a mapping with the keys ``label``, ``value`` and the
    optional ``delta``, ``delta_color``, ``help``. The container key gets
    a ``ms-kpi-row__*`` prefix so the CSS rule set picks up the tiles
    regardless of which page renders them.

    Args:
        items: 1–6 KPI definitions. Rendered side-by-side via
            ``st.columns(len(items))``.
        key: unique-per-page container key.

    Example:
        >>> kpi_row(
        ...     [
        ...         {"label": "Total", "value": 42},
        ...         {"label": "Valid", "value": 40, "delta": "+2"},
        ...     ],
        ...     key="kpi_results",
        ... )
    """
    n = len(items)
    if n == 0:
        return
    safe_key = key if key.startswith("admin_kpi_row") else f"admin_kpi_row_{key}"
    with st.container(key=safe_key):
        cols = st.columns(n)
        for col, item in zip(cols, items):
            label = str(item.get("label", ""))
            value = item.get("value", "")
            delta = item.get("delta", None)
            delta_color = str(item.get("delta_color", "normal"))
            help_text = item.get("help", None)
            col.metric(
                label,
                value,
                delta=delta,
                delta_color=delta_color,  # type: ignore[arg-type]
                help=help_text,  # type: ignore[arg-type]
            )


# ── Empty state ───────────────────────────────────────────────────────────

def empty_state(
    icon: str,
    title: str,
    body: str = "",
    *,
    size: str = "md",
) -> None:
    """Render a centered empty-state placeholder.

    Replaces the half-dozen hand-rolled "dashed border" boxes that used to
    live in ``Main.py``. Token-driven, theme-aware, and respects reduced
    motion.

    Args:
        icon: leading emoji (e.g. ``"📤"``, ``"📋"``).
        title: short headline.
        body: optional supporting copy. Wraps at ~400px.
        size: ``"sm"``, ``"md"`` (default), or ``"lg"`` — controls
            internal padding and icon size only, not width.
    """
    safe_icon = html.escape(icon)
    safe_title = html.escape(title)
    safe_body = html.escape(body) if body else ""
    sz = size if size in ("sm", "md", "lg") else "md"

    body_html = (
        f'<div class="ms-empty__body">{safe_body}</div>'
        if safe_body else ""
    )
    st.markdown(
        _collapse_html(
            f"""
            <div class="ms-empty ms-empty--{sz}" role="status">
                <div class="ms-empty__icon" aria-hidden="true">{safe_icon}</div>
                <div class="ms-empty__title">{safe_title}</div>
                {body_html}
            </div>
            """
        ),
        unsafe_allow_html=True,
    )


# ── Badge / chip ──────────────────────────────────────────────────────────

_VALID_TONES = ("accent", "success", "warn", "danger", "neutral", "info")


def _safe_tone(tone: str) -> str:
    """Validate badge tone against the allow-list; fall back to neutral."""
    return tone if tone in _VALID_TONES else "neutral"


def badge(text: str, *, tone: str = "neutral") -> str:
    """Return a single-line HTML chip; caller renders via ``st.markdown``.

    Use this when composing inline content (e.g. inside a sentence). For
    standalone block placement, prefer :func:`render_badge` which writes
    to the page directly.
    """
    safe_text = html.escape(text)
    safe_tone = _safe_tone(tone)
    return (
        f'<span class="ms-chip ms-chip--{safe_tone}">{safe_text}</span>'
    )


def render_badge(text: str, *, tone: str = "neutral") -> None:
    """Render a single chip as its own block."""
    st.markdown(badge(text, tone=tone), unsafe_allow_html=True)


# ── Pagination control ───────────────────────────────────────────────────

def pagination(
    page: int,
    total_pages: int,
    *,
    total_items: int,
    page_size: int,
    state_key: str,
    label: str = "items",
    on_change_audit: str | None = None,
) -> int:
    """Render a Prev / counter / Next pagination strip.

    The page number lives in ``st.session_state[state_key]`` — clicking
    Prev/Next mutates it and reruns. Returns the clamped page number for
    the current render (so the caller can slice its dataframe with confidence).

    Args:
        page: current page (1-indexed).
        total_pages: total pages available.
        total_items: total row count (for the counter copy).
        page_size: rows per page (for the counter copy).
        state_key: session state key holding the page number.
        label: noun for the counter ("items", "violations", "employees").
        on_change_audit: optional audit action name; when set, the helper
            calls ``app.utils.log_user_action(<name>, direction=..., page=...)``
            on click. Lazy-imported to avoid a circular dependency.
    """
    if total_pages <= 1:
        st.caption(
            f"{total_items} {label}"
            if total_items != 1
            else f"1 {label.rstrip('s')}"
        )
        return max(1, page)

    page = max(1, min(page, total_pages))
    start = (page - 1) * page_size + 1
    end = min(start + page_size - 1, total_items)

    def _audit(direction: str, new_page: int) -> None:
        if not on_change_audit:
            return
        try:
            from app.utils import log_user_action
            log_user_action(
                on_change_audit, direction=direction, page=new_page,
            )
        except Exception:
            # Audit failure must never block UI rerun.
            logger.debug("pagination audit failed", exc_info=True)

    c1, c2, c3 = st.columns([1, 2, 1])
    with c1:
        if st.button(
            "← Prev",
            disabled=page <= 1,
            key=f"{state_key}__prev",
            width="stretch",
            help="Previous page",
        ):
            st.session_state[state_key] = page - 1
            _audit("prev", page - 1)
            st.rerun()
    with c2:
        safe_label = html.escape(label)
        st.markdown(
            f'<div class="ms-pager__counter" role="status" '
            f'aria-live="polite">'
            f'Page <b>{page}</b> of <b>{total_pages}</b> · '
            f'rows {start}–{end} of {total_items} {safe_label}'
            f'</div>',
            unsafe_allow_html=True,
        )
    with c3:
        if st.button(
            "Next →",
            disabled=page >= total_pages,
            key=f"{state_key}__next",
            width="stretch",
            help="Next page",
        ):
            st.session_state[state_key] = page + 1
            _audit("next", page + 1)
            st.rerun()
    return page


# ── Fallback logo (when icon/Logo.png is missing) ─────────────────────────

def fallback_logo(product_name: str = "MANNING",
                  tagline: str = "Workforce Validator") -> None:
    """Render a typographic logo block when the image asset is unavailable.

    Same visual footprint as ``st.image(Logo.png)`` so the sidebar layout
    doesn't jump if the file is missing.
    """
    safe_name = html.escape(product_name)
    safe_tagline = html.escape(tagline)
    st.markdown(
        f"""
        <div class="ms-fallback-logo" role="img"
             aria-label="{safe_name} — {safe_tagline}">
            <span class="ms-fallback-logo__icon" aria-hidden="true">📋</span>
            <span class="ms-fallback-logo__name">{safe_name}</span>
            <span class="ms-fallback-logo__tagline">{safe_tagline}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ── Reference card (Matrix Guide / Shift Codes redesign) ─────────────────

def reference_card(
    title: str,
    rows: Iterable[Mapping[str, str]],
    *,
    icon: str = "",
    accent_tone: str = "accent",
    footnote: str = "",
) -> None:
    """Render a single info card with a title, optional icon, and bullet rows.

    Each row is a mapping with ``label`` (left, bold) and ``value`` (right,
    secondary). ``hint`` is optional and renders as a small caption row.
    """
    safe_title = html.escape(title)
    safe_icon = html.escape(icon) if icon else ""
    safe_tone = _safe_tone(accent_tone)
    safe_footnote = html.escape(footnote) if footnote else ""

    icon_html = (
        f'<span class="ms-refcard__icon" aria-hidden="true">{safe_icon}</span>'
        if safe_icon else ""
    )

    row_lines = []
    for row in rows:
        safe_label = html.escape(str(row.get("label", "")))
        safe_value = html.escape(str(row.get("value", "")))
        hint = row.get("hint", "")
        hint_html = (
            f'<div class="ms-refcard__hint">{html.escape(hint)}</div>'
            if hint else ""
        )
        row_lines.append(
            f'<li class="ms-refcard__row">'
            f'<span class="ms-refcard__label">{safe_label}</span>'
            f'<span class="ms-refcard__value">{safe_value}</span>'
            f'{hint_html}'
            f'</li>'
        )
    rows_html = "\n".join(row_lines)
    footnote_html = (
        f'<div class="ms-refcard__footnote">{safe_footnote}</div>'
        if safe_footnote else ""
    )

    st.markdown(
        _collapse_html(
            f"""
            <article class="ms-refcard ms-refcard--{safe_tone}">
                <header class="ms-refcard__header">
                    {icon_html}
                    <h4 class="ms-refcard__title">{safe_title}</h4>
                </header>
                <ul class="ms-refcard__rows">{rows_html}</ul>
                {footnote_html}
            </article>
            """
        ),
        unsafe_allow_html=True,
    )


def chip_grid(
    chips: Iterable[Mapping[str, str]],
    *,
    columns: int = 4,
) -> None:
    """Render a grid of small reference chips (e.g. shift codes).

    Each chip carries ``code``, ``hours`` and ``window`` (optional).
    """
    chip_html_parts: list[str] = []
    for c in chips:
        safe_code = html.escape(str(c.get("code", "")))
        safe_hours = html.escape(str(c.get("hours", "")))
        safe_window = html.escape(str(c.get("window", "")))
        safe_tone = _safe_tone(str(c.get("tone", "neutral")))
        window_html = (
            f'<div class="ms-codechip__window">{safe_window}</div>'
            if safe_window else ""
        )
        chip_html_parts.append(
            f'<div class="ms-codechip ms-codechip--{safe_tone}">'
            f'<div class="ms-codechip__code">{safe_code}</div>'
            f'<div class="ms-codechip__hours">{safe_hours}</div>'
            f'{window_html}'
            f'</div>'
        )
    safe_cols = max(1, min(int(columns), 6))
    st.markdown(
        f'<div class="ms-codegrid" style="--ms-codegrid-cols:{safe_cols}">'
        + "".join(chip_html_parts)
        + '</div>',
        unsafe_allow_html=True,
    )


# ── Changelog timeline (Keep a Changelog renderer) ────────────────────────

# Category → chip tone. Lower-cased lookup; unknown categories fall back to
# neutral so a future heading (e.g. "Performance") still renders cleanly.
_CHANGELOG_TONES: Mapping[str, str] = {
    "added":      "success",
    "fixed":      "info",
    "changed":    "accent",
    "removed":    "danger",
    "security":   "warn",
    "deprecated": "warn",
}

_MD_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_MD_CODE_RE = re.compile(r"`([^`]+?)`")


def _inline_md(text: str) -> str:
    """Escape ``text`` then honor a tiny, safe subset of inline Markdown.

    Only ``**bold**`` and ``` `code` ``` are converted, and only *after*
    :func:`html.escape` has run — so no raw markup from the source file can
    reach the DOM. The regexes wrap already-escaped text in our own fixed
    tags, which keeps this XSS-safe even though the changelog is a trusted
    repo file.
    """
    safe = html.escape(text)
    safe = _MD_BOLD_RE.sub(r"<strong>\1</strong>", safe)
    safe = _MD_CODE_RE.sub(r"<code>\1</code>", safe)
    return safe


def changelog_timeline(
    releases: Sequence[Mapping[str, object]],
    *,
    key: str = "admin_changelog",
) -> None:
    """Render parsed changelog releases as a modern vertical timeline.

    Each release renders as a card hung off a rail with a status dot; the
    first release is treated as the latest (accent dot + "Latest" chip).
    Change groups are labelled with a tone-coded chip (Added=green,
    Fixed=blue, Changed=accent, Removed=red, Security/Deprecated=amber).

    Args:
        releases: ordered newest-first. Each mapping carries:
            ``version`` (str), ``date`` (str, optional), and ``sections``
            — a sequence of ``{"category": str, "items": Sequence[str]}``.
            The ``items`` strings may use ``**bold**`` / ``` `code` ```.
        key: unique-per-page container key.
    """
    if not releases:
        return

    release_html_parts: list[str] = []
    for idx, rel in enumerate(releases):
        is_latest = idx == 0
        safe_version = html.escape(str(rel.get("version", "")))
        date_val = str(rel.get("date", "") or "")
        date_html = (
            f'<span class="ms-changelog__date">{html.escape(date_val)}</span>'
            if date_val else ""
        )
        latest_chip = (
            '<span class="ms-chip ms-chip--accent">Latest</span>'
            if is_latest else ""
        )

        sections = rel.get("sections", []) or []
        group_html_parts: list[str] = []
        for section in sections:  # type: ignore[assignment]
            category = str(section.get("category", "")).strip()  # type: ignore[union-attr]
            tone = _safe_tone(_CHANGELOG_TONES.get(category.lower(), "neutral"))
            items = section.get("items", []) or []  # type: ignore[union-attr]
            item_html = "".join(
                f"<li>{_inline_md(str(it))}</li>" for it in items
            )
            group_html_parts.append(
                f'<section class="ms-changelog__group">'
                f'<span class="ms-chip ms-chip--{tone}">'
                f'{html.escape(category)}</span>'
                f'<ul class="ms-changelog__items">{item_html}</ul>'
                f'</section>'
            )

        latest_mod = " ms-changelog__release--latest" if is_latest else ""
        release_html_parts.append(
            f'<article class="ms-changelog__release{latest_mod}">'
            f'<div class="ms-changelog__rail" aria-hidden="true">'
            f'<span class="ms-changelog__dot"></span></div>'
            f'<div class="ms-changelog__card">'
            f'<header class="ms-changelog__head">'
            f'<span class="ms-changelog__version">{safe_version}</span>'
            f'{latest_chip}{date_html}'
            f'</header>'
            f'<div class="ms-changelog__sections">'
            f'{"".join(group_html_parts)}</div>'
            f'</div>'
            f'</article>'
        )

    with st.container(key=key):
        st.markdown(
            f'<div class="ms-changelog">{"".join(release_html_parts)}</div>',
            unsafe_allow_html=True,
        )


# ── Data table (themed HTML alternative to st.dataframe) ──────────────────

# Accept only literal CSS colours we control (hex / rgb[a]); anything else is
# dropped so a stray value can't inject style/markup. Row colours come from our
# own constants, but this keeps the boundary explicit.
_CSS_COLOR_RE = re.compile(
    r"^#[0-9A-Fa-f]{3,8}$|^rgba?\([0-9.,%\s]+\)$"
)


def _safe_css_color(value: object) -> str | None:
    """Return ``value`` if it is a safe CSS colour literal, else ``None``."""
    if not value:
        return None
    text = str(value).strip()
    return text if _CSS_COLOR_RE.match(text) else None


# Severity row tones → CSS classes. These resolve to theme-aware token pairs
# (bg + text) defined in style.css, so a toned row stays AA-legible in BOTH
# light and dark mode — unlike a hardcoded pastel fill.
_ROW_TONES = {"valid", "invalid", "warn", "neutral"}


def _cell_text(value: object) -> str:
    """Coerce a cell value to a single-line, HTML-escaped string.

    Newlines/tabs are flattened to spaces so a multi-line value (e.g. a log
    message) can't break the single-line raw-HTML block, and every value is
    escaped so user/log data never reaches the DOM as markup.
    """
    if value is None or (isinstance(value, float) and value != value):  # NaN
        return ""
    text = re.sub(r"[\r\n\t]+", " ", str(value))
    return html.escape(text)


def data_table(
    df: "object",
    *,
    columns: Sequence[Mapping[str, object]] | None = None,
    row_tone: Sequence[object] | None = None,
    row_bg: Sequence[object] | None = None,
    row_fg: object | Sequence[object] | None = None,
    max_height: int | None = None,
    sticky_first: bool = False,
    key: str = "ms_table",
    empty: str = "No rows to display.",
) -> None:
    """Render a pandas DataFrame as a theme-aware HTML ``<table>``.

    A CSS-styled, read-only alternative to ``st.dataframe``. The glide grid
    paints to a ``<canvas>`` themed only at page load, so it can't follow the
    ``data-theme`` toggle; this table can. Every cell is HTML-escaped.

    Args:
        df: a pandas DataFrame (read-only; iterated via ``to_dict``).
        columns: optional ordered column specs — each a mapping with ``key``
            (must match a df column), ``label``, and optional ``width``
            (CSS length), ``align`` (``"left"``/``"right"``/``"center"``),
            ``sticky`` (pin this column left), ``help`` (header tooltip).
            Defaults to every df column, left-aligned (numeric → right).
        row_tone: optional per-row severity tone (``"valid"`` / ``"invalid"`` /
            ``"warn"`` / ``"neutral"``); renders a theme-aware row fill+text that
            stays legible in both light and dark mode. Preferred over raw
            ``row_bg``/``row_fg`` for severity colouring.
        row_bg: optional per-row background colour (len == row count); each
            passes through :func:`_safe_css_color`.
        row_fg: optional text colour — a single colour for all coloured rows
            or a per-row sequence.
        max_height: optional px height → vertical scroll container.
        sticky_first: pin the first column to the left edge on horizontal
            scroll (equivalent to ``column_config(pinned=True)``).
        key: unique-per-page container key.
        empty: message shown via :func:`empty_state` when ``df`` has no rows.
    """
    if df is None or len(df.index) == 0:  # type: ignore[attr-defined]
        empty_state("📋", empty)
        return

    df_cols = list(df.columns)  # type: ignore[attr-defined]
    if columns:
        col_specs = [c for c in columns if c.get("key") in df_cols]
    else:
        col_specs = [{"key": c, "label": str(c)} for c in df_cols]
    if not col_specs:
        empty_state("📋", empty)
        return

    def _is_num(col_key: object) -> bool:
        try:
            return df[col_key].dtype.kind in "iuf"  # type: ignore[index]
        except Exception:
            return False

    def _classes(spec: Mapping[str, object], index: int) -> str:
        align = spec.get("align") or ("right" if _is_num(spec["key"]) else "left")
        cls: list[str] = []
        if align == "right":
            cls.append("ms-num")
        elif align == "center":
            cls.append("ms-center")
        if spec.get("sticky") or (sticky_first and index == 0):
            cls.append("ms-table__sticky")
        return f' class="{" ".join(cls)}"' if cls else ""

    # Header
    head_cells: list[str] = []
    for i, spec in enumerate(col_specs):
        label = html.escape(str(spec.get("label", spec["key"])))
        width = spec.get("width")
        style = f' style="width:{html.escape(str(width))}"' if width else ""
        title = spec.get("help")
        title_attr = f' title="{html.escape(str(title))}"' if title else ""
        head_cells.append(
            f"<th{_classes(spec, i)}{style}{title_attr}>{label}</th>"
        )
    thead = f"<thead><tr>{''.join(head_cells)}</tr></thead>"

    # Body
    records = df.to_dict("records")  # type: ignore[attr-defined]
    body_rows: list[str] = []
    for r_idx, rec in enumerate(records):
        styles: list[str] = []
        if row_bg is not None and r_idx < len(row_bg):
            bg = _safe_css_color(row_bg[r_idx])
            if bg:
                styles.append(f"background-color:{bg}")
        if row_fg is not None:
            fg_val = (
                row_fg[r_idx] if isinstance(row_fg, (list, tuple)) else row_fg
            )
            fg = _safe_css_color(fg_val)
            if fg:
                styles.append(f"color:{fg}")
        row_style = f' style="{";".join(styles)}"' if styles else ""

        row_class = ""
        if row_tone is not None and r_idx < len(row_tone):
            tone = str(row_tone[r_idx]).strip().lower()
            if tone in _ROW_TONES:
                row_class = f' class="ms-row--{tone}"'

        cells = [
            f"<td{_classes(spec, i)}>{_cell_text(rec.get(spec['key'], ''))}</td>"
            for i, spec in enumerate(col_specs)
        ]
        body_rows.append(f"<tr{row_class}{row_style}>{''.join(cells)}</tr>")
    tbody = f"<tbody>{''.join(body_rows)}</tbody>"

    wrap_style = (
        f' style="max-height:{int(max_height)}px"' if max_height else ""
    )
    with st.container(key=key):
        st.markdown(
            f'<div class="ms-table-wrap"{wrap_style}>'
            f'<table class="ms-table">{thead}{tbody}</table></div>',
            unsafe_allow_html=True,
        )


# ── Log detail pane (telescope master-detail view) ────────────────────────

_LEVEL_TONE = {
    "CRITICAL": "danger",
    "ERROR":    "danger",
    "WARNING":  "warn",
    "INFO":     "info",
    "DEBUG":    "neutral",
}


def log_detail(
    *,
    ts: str,
    level: str,
    logger_name: str,
    trace_id: str,
    message: str,
    key: str = "ms_logdetail",
    extra_meta: Mapping[str, str] | None = None,
) -> None:
    """Render the Telescope-style detail pane for a single log entry.

    The right-hand pane of the Log Viewer's master-detail layout, modelled on
    Laravel Telescope's entry view:

    *   a tag-coded header — a tone pill with the level word, the logger name,
        and the timestamp pinned right;
    *   a two-column metadata grid (Timestamp / Level / Logger / Trace ID plus
        any ``extra_meta`` rows);
    *   a payload block with its own caption bar and the full message in a
        selectable monospace ``<pre>``.

    Every interpolated value is ``html.escape()``-d before it reaches the DOM;
    user/log strings never render as raw markup (XSS boundary).

    Args:
        ts: timestamp substring as parsed from the line.
        level: severity word; drives the header tone (danger/warn/info/neutral).
        logger_name: logger/source name shown in the header and metadata grid.
        trace_id: correlation id; shown in the metadata grid.
        message: full message body, rendered verbatim (newlines preserved).
        key: unique-per-page container key.
        extra_meta: optional ordered extra key/value rows appended to the grid
            (e.g. ``{"Archive": "app.log"}``). Keys and values are escaped.
    """
    tone = _safe_tone(_LEVEL_TONE.get((level or "").upper(), "neutral"))
    safe_level = html.escape((level or "—").upper())
    safe_logger = html.escape(logger_name or "—")
    safe_ts = html.escape(ts or "—")

    # Level is intentionally omitted here — the header pill already states it,
    # so repeating it in the grid is noise.
    rows: list[tuple[str, str]] = [
        ("Timestamp", ts or "—"),
        ("Logger", logger_name or "—"),
        ("Trace ID", trace_id or "—"),
    ]
    if extra_meta:
        rows.extend((str(k), str(v)) for k, v in extra_meta.items())

    meta = "".join(
        f'<div class="ms-logdetail__row">'
        f'<span class="ms-logdetail__k">{html.escape(k)}</span>'
        f'<span class="ms-logdetail__v">{html.escape(str(v))}</span>'
        f'</div>'
        for k, v in rows
    )

    with st.container(key=key):
        st.markdown(
            _collapse_html(
                f'<article class="ms-logdetail ms-logdetail--{tone}">'
                f'<header class="ms-logdetail__head">'
                f'<span class="ms-chip ms-chip--{tone} ms-logdetail__level">'
                f'{safe_level}</span>'
                f'<span class="ms-logdetail__logger" '
                f'title="{safe_logger}">{safe_logger}</span>'
                f'<span class="ms-logdetail__ts">{safe_ts}</span>'
                f'</header>'
                f'<div class="ms-logdetail__meta">{meta}</div>'
                f'<div class="ms-logdetail__msgbar">'
                f'<span class="ms-logdetail__msglabel">Message</span>'
                f'</div>'
                f'</article>'
            ),
            unsafe_allow_html=True,
        )
        # Full message via st.code: robust multi-line rendering, theme-aware
        # monospace, and a built-in copy-to-clipboard button on hover. Passing
        # plain text (never raw HTML) keeps the XSS boundary — Streamlit emits
        # it as text, not markup — and preserves newlines that ``_collapse_html``
        # would otherwise flatten in a hand-rolled ``<pre>``.
        st.code(message or "—", language=None)


# ── Change detail pane (Application Changes master-detail view) ───────────

def change_detail(
    *,
    ts: str,
    user_id: str,
    action: str,
    summary: str,
    detail: str,
    raw: str,
    tone: str = "info",
    label: str = "CHANGE",
    key: str = "ms_changedetail",
    extra_meta: Mapping[str, str] | None = None,
) -> None:
    """Render the Telescope-style detail pane for a single admin-change row.

    The right-hand pane of the Application Changes master-detail layout — a
    sibling of :func:`log_detail` that reuses the same ``.ms-logdetail*`` CSS so
    the two admin tabs read as one family. Layout:

    *   a tag-coded header — a tone pill stating the change ``label`` (SAVE /
        RESET / FAILED), the acting ``user_id``, and the timestamp pinned right;
    *   a two-column metadata grid (Event / Summary / Detail plus any
        ``extra_meta`` rows);
    *   a payload block with the full **post-redaction** audit line in a
        selectable monospace ``st.code`` block.

    Every interpolated value is ``html.escape()``-d before it reaches the DOM;
    the ``raw`` audit string is already redacted upstream and is emitted via
    ``st.code`` (text, not markup) — so log data never renders as raw HTML.

    Args:
        ts: timestamp substring lifted from the audit line.
        user_id: who performed the change; shown in the header and grid.
        action: raw audit action string (e.g. ``admin_defaults_saved``).
        summary: friendly one-line description of what changed.
        detail: secondary context — threshold values, added/removed rule names,
            or error text. May be empty (rendered as "—").
        raw: the original post-redaction audit message, shown verbatim.
        tone: header pill tone (``info`` / ``success`` / ``warn`` / ``danger`` /
            ``neutral`` / ``accent``); validated against the allow-list.
        label: short header pill text (e.g. ``"SAVE"``).
        key: unique-per-page container key. Must differ from
            :func:`log_detail`'s ``ms_logdetail`` — both render in the same
            Streamlit run under ``st.tabs``.
        extra_meta: optional ordered extra key/value rows appended to the grid
            (e.g. ``{"Archive": "audit.log"}``). Keys and values are escaped.
    """
    safe_tone = _safe_tone(tone)
    safe_label = html.escape((label or "CHANGE").upper())
    safe_user = html.escape(user_id or "—")
    safe_ts = html.escape(ts or "—")

    rows: list[tuple[str, str]] = [
        ("Event", action or "—"),
        ("Summary", summary or "—"),
        ("Detail", detail or "—"),
    ]
    if extra_meta:
        rows.extend((str(k), str(v)) for k, v in extra_meta.items())

    meta = "".join(
        f'<div class="ms-logdetail__row">'
        f'<span class="ms-logdetail__k">{html.escape(k)}</span>'
        f'<span class="ms-logdetail__v">{html.escape(str(v))}</span>'
        f'</div>'
        for k, v in rows
    )

    with st.container(key=key):
        st.markdown(
            _collapse_html(
                f'<article class="ms-logdetail ms-logdetail--{safe_tone}">'
                f'<header class="ms-logdetail__head">'
                f'<span class="ms-chip ms-chip--{safe_tone} ms-logdetail__level">'
                f'{safe_label}</span>'
                f'<span class="ms-logdetail__logger" '
                f'title="{safe_user}">{safe_user}</span>'
                f'<span class="ms-logdetail__ts">{safe_ts}</span>'
                f'</header>'
                f'<div class="ms-logdetail__meta">{meta}</div>'
                f'<div class="ms-logdetail__msgbar">'
                f'<span class="ms-logdetail__msglabel">Raw audit line</span>'
                f'</div>'
                f'</article>'
            ),
            unsafe_allow_html=True,
        )
        # Full raw line via st.code: theme-aware monospace + copy button, and
        # Streamlit emits it as text (never markup), preserving the XSS boundary.
        st.code(raw or "—", language=None)


# ── Severity histogram (Telescope time-distribution chart) ────────────────

# Level → fixed severity hex, per theme. Altair can't read CSS custom
# properties, so the chart carries its own palette; these mirror the
# ``--c-*-strong`` tokens in style.css and are AA-legible on each theme's
# surface. DEBUG/unknown fall back to a muted slate.
_HIST_COLORS: Mapping[str, Mapping[str, str]] = {
    "light": {
        "CRITICAL": "#b91c1c",
        "ERROR":    "#b91c1c",
        "WARNING":  "#b45309",
        "INFO":     "#1d4ed8",
        "DEBUG":    "#64748b",
    },
    "dark": {
        "CRITICAL": "#f87171",
        "ERROR":    "#f87171",
        "WARNING":  "#fbbf24",
        "INFO":     "#60a5fa",
        "DEBUG":    "#94a3b8",
    },
}

# Stacking / legend order — most severe at the bottom of each bar.
_HIST_LEVEL_ORDER = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")


def severity_histogram(
    df: "object",
    *,
    theme: str = "light",
    key: str = "logv_hist",
) -> None:
    """Render a Telescope-style time-distribution histogram of log events.

    Stacked bars of event counts over time, coloured by severity. The chart
    bins the timestamps adaptively (``maxbins``) so the bar count stays
    readable regardless of the selected window. Colours are pulled from
    :data:`_HIST_COLORS` for the active ``theme`` so the chart matches the
    in-app light/dark mode (Altair can't follow the CSS ``data-theme`` toggle
    on its own).

    Args:
        df: a pandas DataFrame with a ``ts`` column (``datetime64``) and a
            ``level`` column (severity word). Rows are pre-filtered by the
            caller; an empty/all-unparsed frame renders nothing.
        theme: ``"light"`` or ``"dark"`` — selects the severity palette and
            the axis/grid ink colour.
        key: unique-per-page container key.
    """
    # Lazy import: altair is only needed on this view, and keeping it out of
    # module import time avoids paying for it on every page.
    import altair as alt

    if df is None or len(df.index) == 0:  # type: ignore[attr-defined]
        return

    mode = theme if theme in ("light", "dark") else "light"
    palette = _HIST_COLORS[mode]
    # Restrict the colour scale to the levels actually present so the legend
    # doesn't advertise empty series; preserve severity order.
    present = [lv for lv in _HIST_LEVEL_ORDER
               if lv in set(df["level"].tolist())]  # type: ignore[index]
    if not present:
        return
    domain = present
    color_range = [palette.get(lv, palette["DEBUG"]) for lv in present]

    ink = "#94a3b8" if mode == "dark" else "#64748b"
    grid = "#25304a" if mode == "dark" else "#e8ddd9"

    chart = (
        alt.Chart(df)
        .mark_bar(stroke=None)
        .encode(
            x=alt.X(
                "ts:T",
                bin=alt.Bin(maxbins=60),
                title=None,
                axis=alt.Axis(
                    format="%H:%M", labelColor=ink, tickColor=grid,
                    domainColor=grid, gridColor=grid, labelFontSize=10,
                ),
            ),
            y=alt.Y(
                "count():Q",
                title=None,
                axis=alt.Axis(
                    labelColor=ink, tickColor=grid, domainColor=grid,
                    gridColor=grid, labelFontSize=10, tickMinStep=1,
                ),
            ),
            color=alt.Color(
                "level:N",
                scale=alt.Scale(domain=domain, range=color_range),
                legend=alt.Legend(
                    title=None, orient="top", labelColor=ink,
                    symbolType="square", labelFontSize=11,
                ),
                sort=list(_HIST_LEVEL_ORDER),
            ),
            tooltip=[
                alt.Tooltip("ts:T", title="Bucket", format="%Y-%m-%d %H:%M"),
                alt.Tooltip("level:N", title="Level"),
                alt.Tooltip("count():Q", title="Events"),
            ],
        )
        .properties(height=120)
        .configure_view(strokeWidth=0, fill=None)
        .configure(background="transparent")
    )

    with st.container(key=key):
        st.altair_chart(chart, width="stretch")


# ── Violation card (replaces pipe-separated dataframe row) ────────────────

def violation_card(
    *,
    name: str,
    emp_id: str,
    station: str,
    matrix: str,
    failed_weeks: str,
    items: Sequence[Mapping[str, str]],
    severity: str = "warning",
) -> None:
    """Render a single employee's violation set as a card.

    Args:
        name, emp_id, station: identifying fields (escaped before render).
        matrix: detected rest matrix ("4-3" / "6-1" / "5-2").
        failed_weeks: pre-formatted string like "A, B" or "A".
        items: each item has ``type`` (rule name) and ``detail`` (day/cell
            context). Optional ``hint`` collapses into a ``<details>``.
        severity: ``"invalid"`` (structural rule broken) or ``"warning"``
            (non-structural). Drives the left ribbon color.
    """
    sev = "invalid" if severity == "invalid" else "warning"
    safe_name = html.escape(name)
    safe_id = html.escape(emp_id)
    safe_station = html.escape(station)
    safe_matrix = html.escape(matrix)
    safe_weeks = html.escape(failed_weeks)

    item_html_parts = []
    for it in items:
        safe_type = html.escape(str(it.get("type", "")))
        safe_detail = html.escape(str(it.get("detail", "")))
        hint = it.get("hint", "")
        hint_html = ""
        if hint:
            safe_hint = html.escape(hint)
            hint_html = (
                f'<details class="ms-violcard__why">'
                f'<summary>Why</summary>'
                f'<div>{safe_hint}</div>'
                f'</details>'
            )
        item_html_parts.append(
            f'<li class="ms-violcard__item">'
            f'<span class="ms-violcard__type">{safe_type}</span>'
            f'<span class="ms-violcard__detail">{safe_detail}</span>'
            f'{hint_html}'
            f'</li>'
        )

    st.markdown(
        _collapse_html(
            f"""
            <article class="ms-violcard ms-violcard--{sev}"
                     aria-label="Violation set for {safe_name}">
                <div class="ms-violcard__ribbon" aria-hidden="true"></div>
                <header class="ms-violcard__header">
                    <div class="ms-violcard__who">
                        <span class="ms-violcard__name">{safe_name}</span>
                        <span class="ms-violcard__id">ID&nbsp;{safe_id}</span>
                        <span class="ms-violcard__sep">·</span>
                        <span class="ms-violcard__station">{safe_station}</span>
                    </div>
                    <div class="ms-violcard__meta">
                        {badge(f"Matrix {matrix}", tone="neutral")}
                        {badge(
                            f"Week {failed_weeks}" if failed_weeks else "Week —",
                            tone="warn" if sev == "warning" else "danger",
                        )}
                    </div>
                </header>
                <ul class="ms-violcard__items">{''.join(item_html_parts)}</ul>
            </article>
            """
        ),
        unsafe_allow_html=True,
    )


# ── Danger zone container ─────────────────────────────────────────────────

def danger_zone(
    title: str = "⚠️ Danger zone",
    body: str = "",
    *,
    key: str = "ms_danger_zone",
):
    """Open a styled "destructive actions" container.

    Use as a context manager so call-sites can add their own buttons inside:

        with danger_zone("Clear all data", "Cannot be undone."):
            if st.button("Clear", type="primary"):
                ...

    The container key uses the existing ``.st-key-admin_danger_zone`` CSS
    rule (red-tinted bg + left border).
    """
    container = st.container(key=key if key.startswith("admin_danger_zone")
                             else f"admin_danger_zone_{key}")
    with container:
        safe_title = html.escape(title)
        st.markdown(
            f'<h4 class="ms-danger__title">{safe_title}</h4>',
            unsafe_allow_html=True,
        )
        if body:
            st.markdown(
                f'<p class="ms-danger__body">{html.escape(body)}</p>',
                unsafe_allow_html=True,
            )
    return container


# ── Sidebar section label (replaces small-caps sidebar headers) ───────────

def sidebar_section(label: str, *, icon: str = "") -> None:
    """Render a sidebar section label.

    More legible than the previous all-caps ``st.header`` overrides: same
    weight, lighter tracking, optional leading icon.
    """
    safe_label = html.escape(label)
    safe_icon = html.escape(icon) if icon else ""
    icon_html = (
        f'<span class="ms-sidesection__icon" aria-hidden="true">'
        f'{safe_icon}</span>'
        if safe_icon else ""
    )
    st.markdown(
        f'<div class="ms-sidesection">{icon_html}'
        f'<span class="ms-sidesection__label">{safe_label}</span></div>',
        unsafe_allow_html=True,
    )
