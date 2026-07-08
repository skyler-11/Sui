"""
app/auth.py — Authentication & Session Bootstrap
"""

from __future__ import annotations

import base64
import hashlib
import html
import os
import secrets
import threading
import time
import uuid
from typing import Any
from urllib.parse import urlencode, urlparse

import pandas as pd
import requests
import streamlit as st

from app.core.logging import (
    get_logger, get_audit_logger, set_trace_id,
)
from app.core.config import DEFAULT_NW_CREDIT_HRS
from app.core.rules import AVAILABLE_RULES
from app.core.checkpoint import clear_checkpoint
from app.utils import get_user_context, create_excel_template

logger = get_logger("forge.auth")
audit_logger = get_audit_logger()

PROTECTED_KEYS: frozenset[str] = frozenset({
    "user_id", "user_ctx", "session_trace_id",
    "template_bytes", "_auth_confirmed", "_auth_timestamp",
})


# ── RATE LIMITER ──────────────────────────────────────────────────────────────

class _RateLimiter:
    def __init__(self, limit: int = 5, window_seconds: int = 60) -> None:
        self._limit = limit
        self._window = window_seconds
        self._store: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, user_id: str) -> tuple[bool, int]:
        now = time.time()
        with self._lock:
            window_times = [t for t in self._store.get(user_id, []) if now - t < self._window]
            if len(window_times) >= self._limit:
                logger.warning(
                    'rate_limit_hit user_id="%s" window_count=%d limit=%d',
                    user_id, len(window_times), self._limit,
                )
                return False, max(int(self._window - (now - window_times[0])), 1)
            window_times.append(now)
            self._store[user_id] = window_times
            return True, 0


@st.cache_resource
def get_rate_limiter() -> _RateLimiter:
    return _RateLimiter(limit=5, window_seconds=60)


@st.cache_resource
def get_login_rate_limiter() -> _RateLimiter:
    """Pre-auth rate limiter keyed by client IP.

    SEC [CWE-307]: Caps token-exchange attempts per remote IP per window so
    a brute-forced state guess, replay storm, or credential-stuffing botnet
    cannot exhaust Keycloak/JWKS or trigger account-lockout DoS on the IdP
    side. Limits are deliberately looser than the upload limiter because a
    legitimate user with a transient IdP error can legitimately retry a
    handful of times. Tune via MANNING_LOGIN_RATE_LIMIT / _WINDOW env vars
    without code changes.
    """
    try:
        limit = max(1, int(os.getenv("MANNING_LOGIN_RATE_LIMIT", "10")))
    except ValueError:
        limit = 10
    try:
        window = max(1, int(os.getenv("MANNING_LOGIN_RATE_WINDOW_SEC", "60")))
    except ValueError:
        window = 60
    return _RateLimiter(limit=limit, window_seconds=window)


# ── SESSION STATE ─────────────────────────────────────────────────────────────

def init_session_state() -> None:
    defaults: dict = {
        "schedule":                   pd.DataFrame([]),
        "session_trace_id":           f"sesh-{uuid.uuid4().hex[:10]}",
        "validation_results":         None,
        "validation_results_records": None,
        "last_file_id":               None,
        "uploader_key":               str(uuid.uuid4()),
        "active_rule_keys":           [r.key for r in AVAILABLE_RULES if r.default_active],
        "max_week_hrs":               60,
        "min_week_hrs":               48,
        "max_rolling_7d_hrs":         60,
        "nw_credit_hrs":              DEFAULT_NW_CREDIT_HRS,
        "user_id":                    "anonymous",
        "user_ctx":                   {"ip": "unknown", "user_agent": "unknown"},
        "_auth_confirmed":            False,
        "_auth_timestamp":            0.0,
        "week_a_label":               "Week A",
        "week_b_label":               "Week B",
        "week_a_start":               None,
        "week_b_start":               None,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val

    if "template_bytes" not in st.session_state:
        st.session_state.template_bytes = create_excel_template()

    # Propagate the per-session trace_id onto the contextvar so all log
    # records emitted in this Streamlit re-run carry it automatically.
    trace_id = st.session_state["session_trace_id"]
    set_trace_id(trace_id)
    logger.debug('session_initialized')


# ── OIDC: PENDING-LOGIN STORE ─────────────────────────────────────────────────
# A short-lived, process-wide map of `state -> {code_verifier, created_at}`.
# Required because the OAuth round-trip is a full browser navigation, which
# wipes Streamlit's per-session state. The state parameter sent to Keycloak
# is the only thing we control on the way back, so we use it as the key.
#
# Entries auto-expire after 5 minutes. The store is bounded — anything older
# is pruned on every read/write to prevent unbounded growth.

_PENDING_TTL_SEC = 300
_pending_lock = threading.Lock()
_pending_logins: dict[str, dict[str, Any]] = {}


def _pending_put(state: str, code_verifier: str) -> None:
    now = time.time()
    with _pending_lock:
        # Prune expired entries
        for k in [k for k, v in _pending_logins.items()
                  if now - v["created_at"] > _PENDING_TTL_SEC]:
            _pending_logins.pop(k, None)
        _pending_logins[state] = {"code_verifier": code_verifier, "created_at": now}


def _pending_pop(state: str) -> str | None:
    now = time.time()
    with _pending_lock:
        entry = _pending_logins.pop(state, None)
        # Prune stale siblings while we hold the lock
        for k in [k for k, v in _pending_logins.items()
                  if now - v["created_at"] > _PENDING_TTL_SEC]:
            _pending_logins.pop(k, None)
    if entry is None:
        return None
    if now - entry["created_at"] > _PENDING_TTL_SEC:
        return None
    return entry["code_verifier"]


# ── OIDC: PKCE / STATE HELPERS ────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _new_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) per RFC 7636 (S256)."""
    verifier = _b64url(secrets.token_bytes(64))           # 86 chars
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _new_state() -> str:
    return _b64url(secrets.token_bytes(24))


# ── SSL VERIFICATION ──────────────────────────────────────────────────────────
# Set KEYCLOAK_SSL_VERIFY in the environment:
#   (unset / "true" / "1")  → verify with default CA bundle (default)
#   "/path/to/ca-bundle.crt" → verify with a custom corporate CA certificate
#   "false" / "0"            → INSECURE — disabled (DEV ONLY, refused in prod/test)
#
# SEC [CWE-295]: Disabling certificate validation is only permitted when
# MANNING_ENV=development. In test or production, KEYCLOAK_SSL_VERIFY=false
# is rejected at startup. The corporate CA bundle path is the supported
# integration point for internal-CA-signed Keycloak certificates.

_SSL_WARNING_LOGGED = False


def _ssl_verify() -> bool | str:
    global _SSL_WARNING_LOGGED
    raw = os.getenv("KEYCLOAK_SSL_VERIFY", "true").strip()
    manning_env = os.getenv("MANNING_ENV", "").strip().lower()

    if raw.lower() in ("false", "0", "no"):
        # SEC [CWE-295]: Hard-refuse verify=False outside of dev mode.
        if manning_env != "development":
            raise RuntimeError(
                "KEYCLOAK_SSL_VERIFY=false is forbidden when MANNING_ENV != "
                "'development'. Provide the corporate CA bundle as a PEM "
                "file path instead (e.g. KEYCLOAK_SSL_VERIFY=C:\\certs\\"
                "corporate-ca.crt). Export the issuing CA from certmgr.msc "
                "(Trusted Root CAs > Export > Base-64 .CER)."
            )
        if not _SSL_WARNING_LOGGED:
            logger.warning(
                'ssl_verify_disabled MANNING_ENV="development" '
                '— certificate validation is OFF. NEVER USE THIS IN PRODUCTION.'
            )
            _SSL_WARNING_LOGGED = True
        return False
    if raw.lower() not in ("true", "1", "yes", ""):
        return raw   # treat as a path to a CA bundle / cert file
    return True


# ── OIDC: KEYCLOAK ENDPOINT DISCOVERY + JWKS ──────────────────────────────────

@st.cache_resource(show_spinner=False)
def _kc_discovery(url: str, realm: str) -> dict[str, Any]:
    """Fetch the OIDC discovery document (.well-known) once per process.

    SSL note: in corporate environments Keycloak is typically fronted by an
    internal CA-signed certificate. If `KEYCLOAK_SSL_VERIFY` is left at the
    default ("true"), `requests` will fall back to certifi's public-trust
    bundle, which does NOT contain the corporate Root CA — that surfaces as
    `ssl.SSLCertVerificationError ... unable to get local issuer certificate
    (_ssl.c:NNNN)` and is logged below with the exception type so ops can
    distinguish a TLS trust problem from a network / DNS problem.
    """
    import ssl as _ssl_mod
    base = url.rstrip("/")
    discovery_url = f"{base}/realms/{realm}/.well-known/openid-configuration"
    verify_setting = _ssl_verify()
    try:
        resp = requests.get(discovery_url, timeout=10, verify=verify_setting)
    except requests.exceptions.SSLError as ssl_exc:
        # Surface the real cause to the operator. The user-facing message in
        # handle_auth() stays generic; this log line is the actionable one.
        logger.error(
            'kc_discovery_ssl_failure url="%s" verify_setting=%r exc_type=%s msg="%s" '
            '| Hint: KEYCLOAK_SSL_VERIFY should point at the corporate CA bundle '
            '(PEM). Export the issuing CA from the Windows cert store '
            '(certmgr.msc -> Trusted Root CAs -> Export -> Base-64 .CER) and '
            'set KEYCLOAK_SSL_VERIFY=C:\\certs\\corporate-ca.crt.',
            discovery_url, verify_setting, type(ssl_exc).__name__, str(ssl_exc)[:500],
        )
        raise
    except requests.exceptions.ConnectionError as conn_exc:
        logger.error(
            'kc_discovery_connection_failure url="%s" exc_type=%s msg="%s"',
            discovery_url, type(conn_exc).__name__, str(conn_exc)[:500],
        )
        raise
    except requests.exceptions.Timeout as to_exc:
        logger.error(
            'kc_discovery_timeout url="%s" exc_type=%s msg="%s"',
            discovery_url, type(to_exc).__name__, str(to_exc)[:500],
        )
        raise
    resp.raise_for_status()
    return resp.json()


@st.cache_resource(show_spinner=False)
def _kc_jwk_client(jwks_uri: str):
    """Cached PyJWKClient — fetches and caches signing keys per process."""
    import ssl
    from jwt import PyJWKClient
    ssl_verify = _ssl_verify()
    if ssl_verify is False:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        return PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600, ssl_context=ssl_ctx)
    if isinstance(ssl_verify, str):
        ssl_ctx = ssl.create_default_context(cafile=ssl_verify)
        return PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600, ssl_context=ssl_ctx)
    return PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600)


# ── OIDC: TOKEN EXCHANGE + VALIDATION ─────────────────────────────────────────

def _exchange_code_for_tokens(
    discovery: dict[str, Any],
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str | None,
) -> dict[str, Any]:
    """POST /token to swap the auth code for access/id/refresh tokens."""
    token_endpoint = discovery["token_endpoint"]
    data: dict[str, str] = {
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  redirect_uri,
        "client_id":     client_id,
        "code_verifier": code_verifier,
    }
    if client_secret:
        data["client_secret"] = client_secret

    resp = requests.post(
        token_endpoint, data=data, timeout=15,
        headers={"Accept": "application/json"},
        verify=_ssl_verify(),
    )
    if resp.status_code != 200:
        # Log the error body but do NOT surface it to the UI — it can echo
        # client config back to the user, which is a leak.
        logger.error(
            'token_exchange_failed status=%s body=%s',
            resp.status_code, resp.text[:500],
        )
        resp.raise_for_status()
    return resp.json()


def _validate_id_token(
    id_token: str,
    discovery: dict[str, Any],
    *,
    client_id: str,
    issuer: str,
) -> dict[str, Any]:
    """Validate the ID token signature and standard claims."""
    import jwt as _jwt
    jwk_client = _kc_jwk_client(discovery["jwks_uri"])
    signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    return _jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
        audience=client_id,
        issuer=issuer,
        options={
            "require": ["exp", "iat", "iss", "aud", "sub"],
            "verify_signature": True,
            "verify_exp":       True,
            "verify_iat":       True,
            "verify_iss":       True,
            "verify_aud":       True,
        },
        leeway=30,
    )


def _read_token_exp(access_token: str) -> int | None:
    """Read the `exp` claim from a previously-validated access token.

    SEC NOTE: This is a POST-VALIDATION read. The access token in
    session_state was issued by Keycloak in response to a successful
    authorization-code exchange and the paired ID token was signature-
    validated in `_validate_id_token` before we ever stashed these tokens.
    We therefore decode without re-verifying the signature here — we are
    *reading a claim*, not making a trust decision off the signature.

    Returns the Unix-epoch `exp` integer, or None if the token is malformed
    or the claim is missing/non-numeric.
    """
    import jwt as _jwt
    try:
        claims = _jwt.decode(access_token, options={"verify_signature": False})
    except Exception:
        return None
    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        return int(exp)
    return None


def _should_refresh_token(access_token: str, leeway_sec: int = 60) -> bool:
    """Return True when the access token is within `leeway_sec` of expiry.

    Returning True for an unreadable / missing exp is the safe default — we'd
    rather attempt a refresh than carry forward a token we cannot reason about.
    """
    exp = _read_token_exp(access_token)
    if exp is None:
        return True
    return time.time() >= (exp - leeway_sec)


def _refresh_access_token(refresh_token: str) -> bool:
    """Exchange a refresh_token for a fresh access/id/refresh triple.

    Returns True on success (session_state updated in place), False on any
    failure. Caller is expected to call logout() + st.stop() on False.

    We deliberately do NOT raise — refresh failures are an expected, routine
    part of session lifecycle (refresh token expired, revoked, network blip).
    They should be handled by `_check_session_expiry()` triggering a clean
    logout, not by a traceback bubbling to the user.
    """
    KC_URL = os.getenv("KEYCLOAK_URL", "").strip()
    if not KC_URL:
        return False
    realm         = os.getenv("KEYCLOAK_REALM", "default")
    client_id     = os.getenv("KEYCLOAK_CLIENT_ID", "").strip()
    client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET", "").strip() or None
    if not client_id:
        logger.warning('refresh_failed reason="client_id_missing"')
        return False

    try:
        discovery = _kc_discovery(KC_URL, realm)
    except Exception:
        logger.warning('refresh_failed reason="discovery_unavailable"')
        return False

    token_endpoint = discovery.get("token_endpoint")
    if not token_endpoint:
        logger.warning('refresh_failed reason="no_token_endpoint"')
        return False

    data: dict[str, str] = {
        "grant_type":    "refresh_token",
        "refresh_token": refresh_token,
        "client_id":     client_id,
    }
    if client_secret:
        data["client_secret"] = client_secret

    try:
        resp = requests.post(
            token_endpoint, data=data, timeout=15,
            headers={"Accept": "application/json"},
            verify=_ssl_verify(),
        )
    except Exception as exc:
        logger.warning(
            'refresh_failed reason="network" exc_type=%s',
            type(exc).__name__,
        )
        return False

    if resp.status_code != 200:
        # 400 invalid_grant = refresh token expired or revoked. Routine.
        # We log at info to keep ops noise down.
        logger.info(
            'refresh_rejected status=%s body=%s',
            resp.status_code, resp.text[:200],
        )
        return False

    try:
        tokens = resp.json()
    except Exception:
        logger.warning('refresh_failed reason="non_json_response"')
        return False

    new_access  = tokens.get("access_token")
    new_id      = tokens.get("id_token")
    new_refresh = tokens.get("refresh_token")
    if not new_access:
        logger.warning('refresh_failed reason="no_access_token_in_response"')
        return False

    st.session_state.access_token = new_access
    if new_id:
        st.session_state.id_token = new_id
    if new_refresh:
        # Keycloak rotates refresh tokens by default. Persist the new one;
        # the old one may be invalidated server-side immediately.
        st.session_state.refresh_token = new_refresh
    st.session_state._auth_timestamp = time.time()

    audit_logger.info(
        'action="auth_token_refreshed" user_id="%s"',
        st.session_state.get("user_id", "anonymous"),
    )
    logger.debug('token_refreshed user_id="%s"',
                 st.session_state.get("user_id", "anonymous"))
    return True


def _check_session_expiry() -> None:
    """Enforce idle timeout + token TTL. Called from handle_auth() after auth.

    Three distinct expiry conditions, in evaluation order:

      1. Idle timeout — `time.time() - _auth_timestamp > KEYCLOAK_SESSION_MAX_IDLE_SEC`.
         This is the "user walked away from their desk" guard; it fires even
         when tokens are still valid. Default 1800s (30 min).
      2. Access token within leeway of `exp`, but refresh succeeds — silent
         refresh, no UX disruption, `_auth_timestamp` updated.
      3. Access token within leeway of `exp` AND refresh fails (token expired,
         revoked, network) — show "session expired" and force logout.

    Dev-bypass mode (MANNING_ENV=development, no KEYCLOAK_URL) is exempt: there
    is no real token lifecycle to enforce, and forcing logouts in local dev
    creates noise without security benefit.
    """
    KC_URL = os.getenv("KEYCLOAK_URL", "").strip()
    MANNING_ENV = os.getenv("MANNING_ENV", "").strip().lower()
    if MANNING_ENV == "development" and not KC_URL:
        return  # dev bypass — no-op

    if not st.session_state.get("_auth_confirmed"):
        return

    # ── Compute idle threshold (also used by the continue grace check) ────
    # Enforce the TIGHTER of:
    #   - KEYCLOAK_SESSION_MAX_IDLE_SEC (server-only backstop, default 1800s)
    #   - IDLE_TIMEOUT_SECONDS (also drives the JS watchdog modal,
    #     default 300s) — covers frozen-tab / JS-suspended cases where
    #     the client watchdog never fires and the only safety net is the
    #     next rerun the user happens to trigger.
    try:
        max_idle_kc = int(os.getenv("KEYCLOAK_SESSION_MAX_IDLE_SEC", "1800"))
    except ValueError:
        max_idle_kc = 1800
    try:
        max_idle_js = int(os.getenv("IDLE_TIMEOUT_SECONDS", "300"))
    except ValueError:
        max_idle_js = 300
    max_idle = min(max_idle_kc, max_idle_js)
    last_activity = float(st.session_state.get("_auth_timestamp") or 0.0)

    # ── (0a) Same-WS continue: handled by on_click callback ───────────────
    # The hidden Streamlit button registered by _render_idle_continue_button
    # uses an `on_click` callback that refreshes _auth_timestamp BEFORE this
    # function runs (Streamlit guarantees on_click fires before script body).
    # If the user just clicked Continue, last_activity has already been
    # bumped to time.time() by the callback — re-read it here.
    last_activity = float(st.session_state.get("_auth_timestamp") or 0.0)

    # ── (0b) Honour pending `idle_event=continue` BEFORE expiry check ──────
    # The continue event is processed in render_idle_timeout_guard(), which
    # runs AFTER handle_auth() → _check_session_expiry(). Without this short-
    # circuit, a user who clicks "Continue session" close to the timeout sees
    # _check_session_expiry() observe the stale _auth_timestamp first and
    # force a logout — wiping their schedule edits before the continue ever
    # lands.
    #
    # SEC [CWE-613]: The continue param is set client-side and must not be
    # able to revive an arbitrarily-stale session. Only honour it when the
    # existing timestamp is within a small grace window past max_idle —
    # i.e. the warning modal could plausibly still be open. A long-stale
    # URL replay (e.g. an attacker sharing the link hours later) will fall
    # through to the normal idle-timeout branch and force a logout.
    #
    # 120s accommodates real-world latency: IIS reverse-proxy round-trips
    # can add several seconds on busy workers, and a backgrounded browser
    # tab may have its JS watchdog suspended so the modal pops on the next
    # foreground rerun (sometimes a minute or more after the actual idle
    # threshold passed). 30s was too tight and false-rejected legitimate
    # continues. The replay defense remains — past 120s the URL is rejected.
    _CONTINUE_GRACE_SEC = 120
    try:
        _pending_event = st.query_params.get("idle_event")
    except Exception:
        _pending_event = None
    if _pending_event == "continue":
        idle_for = time.time() - last_activity if last_activity > 0 else 0
        if last_activity > 0 and idle_for <= (max_idle + _CONTINUE_GRACE_SEC):
            st.session_state._auth_timestamp = time.time()
            last_activity = st.session_state._auth_timestamp
        else:
            audit_logger.warning(
                'action="session_continue_rejected_stale" user_id="%s" idle_sec=%d limit_sec=%d',
                st.session_state.get("user_id", "anonymous"),
                int(idle_for), max_idle + _CONTINUE_GRACE_SEC,
            )

    # ── (1) Idle timeout ──────────────────────────────────────────────────
    if last_activity > 0 and (time.time() - last_activity) > max_idle:
        # Diagnostic: did this fire despite a recent continue intent? If
        # `recent_continue_seen=true` shows up in audit logs alongside an
        # idle_timeout firing, the on_click callback is not refreshing
        # _auth_timestamp before this check — log so the next user report
        # has actionable trace data.
        recent_continue_seen = (
            bool(st.session_state.get("_just_continued"))
            or _pending_event == "continue"
        )
        audit_logger.info(
            'action="session_idle_timeout" user_id="%s" idle_sec=%d '
            'limit_sec=%d recent_continue_seen=%s',
            st.session_state.get("user_id", "anonymous"),
            int(time.time() - last_activity),
            max_idle,
            str(recent_continue_seen).lower(),
        )
        st.warning(
            "Session expired due to inactivity — please sign in again."
        )
        logout()
        st.stop()
        return

    # ── (2) / (3) Access token TTL with refresh attempt ───────────────────
    access_token = st.session_state.get("access_token", "")
    refresh_token = st.session_state.get("refresh_token", "")
    if not access_token:
        return  # nothing to evaluate (e.g. partial state)

    if _should_refresh_token(access_token, leeway_sec=60):
        if not refresh_token or not _refresh_access_token(refresh_token):
            # Soft path when the user just signaled continuation: hard-
            # logging-out immediately after the user clicked "Continue
            # session" is the worst possible UX. Show an inline re-auth
            # prompt instead — the checkpoint at Main.py:1615-1620 will
            # restore their schedule edits after re-authentication.
            just_continued = bool(
                st.session_state.pop("_just_continued", False)
                or (_pending_event == "continue")
            )
            audit_logger.info(
                'action="session_token_expired" user_id="%s" just_continued=%s',
                st.session_state.get("user_id", "anonymous"),
                str(just_continued).lower(),
            )
            if just_continued:
                st.warning(
                    "Your session token expired. Click below to sign in "
                    "again — your work will be preserved."
                )
                if st.button("Sign in again", key="__post_continue_reauth"):
                    logout()
                st.stop()
                return
            st.warning("Session expired — please sign in again.")
            logout()
            st.stop()
            return


def has_role(role: str) -> bool:
    """Return True if the currently authenticated user has the given Keycloak realm role.

    Reads from ``st.session_state.user_ctx['roles']``, populated at login by
    ``handle_auth()``. Safe to call before auth completes — returns False if the
    session has no role data yet. Intended for page-level and widget-level
    authorization checks; never re-decodes tokens.
    """
    ctx = st.session_state.get("user_ctx") or {}
    roles = ctx.get("roles") or []
    return role in roles


def require_role(role: str, *, audit_action: str = "access_denied") -> None:
    """Enforce that the current user has ``role`` or render a deny screen and stop.

    Behavior on missing role:
      1. Emits a single audit_logger entry of the form
         ``action="<audit_action>" user_id="..." ip="..." required_role="<role>"``
         so superadmin denials, log-viewer denials, and gate-block denials are
         distinguishable in SIEM. Uses ``log_user_action`` so the line shape
         matches every other audit event.
      2. Renders a minimal "No access" screen — no app data leaks into the DOM.
      3. Calls ``st.stop()`` so no downstream widget code runs.

    Composite roles in Keycloak: a user with ``manning-superadmin`` also carries
    ``manning-user`` in ``realm_access.roles``, so they pass the user gate
    automatically — no special-casing here.
    """
    if has_role(role):
        return

    # Late import: app.utils imports from app.auth indirectly via get_user_context,
    # so a top-level import would create a cycle at module load.
    from app.utils import log_user_action
    log_user_action(audit_action, required_role=role)

    st.error("**No access** — your account is not authorized for this area.")
    st.caption(
        f"Required role: `{role}`. Contact your administrator if you believe "
        "this is a mistake."
    )
    st.stop()


def _extract_realm_roles(access_token: str, decoded_id: dict[str, Any]) -> list[str]:
    """Best-effort role extraction from the access token (realm and client roles).

    Sources are **merged**, not fallback-chained, because Keycloak almost
    always emits a non-empty ``realm_access.roles`` containing the default
    realm roles (``default-roles-<realm>``, ``offline_access``,
    ``uma_authorization``). A naïve fallback chain would stop at the first
    non-empty source and never see the Manning client roles sitting in
    ``resource_access.<client>.roles``.

    Sources considered (results unioned, order-preserved, deduped):

      1. ``access_token.realm_access.roles``
      2. ``id_token.realm_access.roles``
      3. ``access_token.resource_access.<KEYCLOAK_CLIENT_ID>.roles``
      4. ``id_token.resource_access.<KEYCLOAK_CLIENT_ID>.roles``

    The access_token signature is validated by Keycloak when it issued it; we
    decode it without re-verifying because we just received it directly from
    the token endpoint over TLS and the corresponding ID token was already
    verified above.

    All sources flow into the same flat ``roles`` list — ``has_role`` and
    ``require_role`` do not distinguish realm vs client origin. The gate
    logic in ``handle_auth`` filters this list against
    ``KEYCLOAK_ALLOWED_ROLES`` so Keycloak's default roles never grant
    access by themselves.
    """
    import jwt as _jwt
    found: list[str] = []
    at_claims: dict = {}
    at_decode_failed = False

    def _add(items: object) -> None:
        if not items:
            return
        for item in items:
            if isinstance(item, str) and item and item not in found:
                found.append(item)

    # Decode the access token once — we mine it twice (realm_access then
    # resource_access) and there's no point doing it twice.
    try:
        at_claims = _jwt.decode(access_token, options={"verify_signature": False})
    except Exception as e:
        at_decode_failed = True
        logger.warning(
            'realm_role_decode_failed source="access_token" error="%s"',
            str(e)[:200],
        )

    # 1 & 2. realm_access on both tokens
    _add((at_claims.get("realm_access") or {}).get("roles"))
    _add((decoded_id.get("realm_access") or {}).get("roles"))

    # 3 & 4. client roles via resource_access.<client_id>.roles
    client_id = os.environ.get("KEYCLOAK_CLIENT_ID", "").strip()
    if client_id:
        for source_name, claims in (
            ("access_token", at_claims),
            ("id_token", decoded_id),
        ):
            ra_clients = claims.get("resource_access") or {}
            client_entry = ra_clients.get(client_id) or {}
            client_roles = client_entry.get("roles") or []
            if client_roles:
                logger.info(
                    'roles_from_client_scope source="%s" client_id="%s" count=%d',
                    source_name, client_id, len(client_roles),
                )
                _add(client_roles)
                break  # AT wins over ID for the client-roles source

    # Telltale: a non-empty access_token yielded no roles via any path.
    # Likely causes: realm-roles mapper stripped AND client roles unassigned,
    # OR KEYCLOAK_CLIENT_ID does not match the client name Keycloak emitted.
    if not found and access_token and not at_decode_failed:
        logger.warning(
            'realm_roles_empty_after_decode '
            'hint="checked realm_access and resource_access.<KEYCLOAK_CLIENT_ID> '
            'on both AT and ID token — verify mapper config and client_id match"',
        )
    return found


# ── REDIRECT TRIGGER ──────────────────────────────────────────────────────────

def _redirect_browser(url: str) -> None:
    """Issue a hard, full-page redirect from inside Streamlit.

    We use a meta-refresh tag plus a JS fallback. This must run before the
    rest of the app is rendered or the user will briefly see the login UI.

    SEC [CWE-79/CWE-116]: The URL is built internally from the cached
    Keycloak discovery document, so it should already be trustworthy. As
    defense-in-depth we still:
      - HTML-escape the value used in the meta-refresh attribute and the
        <a href="...">  fallback (handles ", <, >, &, ').
      - JSON-encode the value used inside the inline <script> string so a
        rogue character cannot break out of the JS string literal.
    """
    import json as _json
    html_safe_url = html.escape(url, quote=True)
    js_safe_url = _json.dumps(url)  # produces a quoted, fully-escaped JS string
    st.markdown(
        f'<meta http-equiv="refresh" content="0; url={html_safe_url}">'
        f'<script>window.location.replace({js_safe_url});</script>'
        f'<noscript>'
        f'<a href="{html_safe_url}">Click here to sign in</a>'
        f'</noscript>',
        unsafe_allow_html=True,
    )
    st.info("Redirecting to single sign-on…")
    st.stop()


# ── AUTH ──────────────────────────────────────────────────────────────────────

def _render_retry_button(key: str) -> None:
    """Render a "Retry sign-in" button that fully resets OAuth state.

    Use this immediately before any `st.stop()` in an auth error path so the
    user has a way out of a stuck round-trip without restarting the browser
    (e.g. stale `?code=` in the URL, expired pending-login entry, transient
    IdP failure). Clearing query_params + session_state ensures the next
    rerun starts the flow from a clean slate.
    """
    if st.button("🔁 Retry sign-in", key=key):
        st.query_params.clear()
        st.session_state.clear()
        st.rerun()


def handle_auth() -> bool:
    trace_id = st.session_state.get("session_trace_id", "no-trace")
    KC_URL = os.getenv("KEYCLOAK_URL", "").strip()
    MANNING_ENV = os.getenv("MANNING_ENV", "").strip().lower()

    # ── Dev bypass ────────────────────────────────────────────────────────
    # SEC [CWE-287/CWE-306]: The bypass MUST be gated on an explicit positive
    # MANNING_ENV=development assertion. Falling back when KC_URL is merely
    # missing (e.g. due to a typo'd MANNING_ENV value or a forgotten
    # environment variable in production) would silently grant unauthenticated
    # access. We therefore require BOTH:
    #   1. MANNING_ENV == "development", AND
    #   2. KEYCLOAK_URL is unset.
    # Any other combination is treated as a misconfiguration and refuses to
    # serve the app.
    if MANNING_ENV == "development":
        if KC_URL:
            logger.error(
                'auth_misconfigured reason="dev_mode_with_kc_url_set" '
                'kc_url="%s" — refusing to start',
                KC_URL,
            )
            st.error(
                "Configuration error: MANNING_ENV=development is incompatible "
                "with KEYCLOAK_URL being set. Unset one of them and restart. "
                f"(Trace: `{trace_id}`)"
            )
            _render_retry_button("retry_dev_misconfig")
            st.stop()
            return False
        if not st.session_state.get("_auth_confirmed"):
            local_user = os.getenv("MANNING_LOCAL_USER", "local_dev")
            st.session_state._auth_confirmed = True
            st.session_state._auth_timestamp = time.time()
            st.session_state.user_id = local_user
            st.session_state.user_ctx = get_user_context()
            ctx = st.session_state.user_ctx
            # Dev-only: allow faking Keycloak roles via MANNING_LOCAL_ROLES
            # (comma-separated). Used to exercise role-gated pages without a
            # live Keycloak. Empty list when unset.
            local_roles_csv = os.getenv("MANNING_LOCAL_ROLES", "").strip()
            ctx["roles"] = [
                r.strip() for r in local_roles_csv.split(",") if r.strip()
            ] if local_roles_csv else []
            logger.warning(
                'sso_bypass_dev_mode user_id="%s" ip="%s" roles=%s '
                '(MANNING_ENV=development — DO NOT USE IN PRODUCTION)',
                local_user, ctx.get("ip", "unknown"), ctx["roles"],
            )
        return True

    # SEC [CWE-287/CWE-306]: From here on, SSO is mandatory. Refuse to start
    # if KEYCLOAK_URL is missing — never silently fall through to a bypass.
    if not KC_URL:
        logger.error(
            'auth_misconfigured reason="kc_url_missing" manning_env="%s" — refusing to start',
            MANNING_ENV or "<unset>",
        )
        st.error(
            "Configuration error: KEYCLOAK_URL is not set and MANNING_ENV is "
            "not 'development'. The application will not start without a "
            "configured identity provider. Contact IT support. "
            f"(Trace: `{trace_id}`)"
        )
        _render_retry_button("retry_kc_url_missing")
        st.stop()
        return False

    # ── Fast path — already authenticated this session ────────────────────
    if st.session_state.get("_auth_confirmed"):
        # Idle timeout + silent token refresh. May call logout() + st.stop()
        # internally if expiry/refresh fails — control will not return.
        _check_session_expiry()
        return True

    # ── OIDC config ───────────────────────────────────────────────────────
    realm         = os.getenv("KEYCLOAK_REALM", "default")
    client_id     = os.getenv("KEYCLOAK_CLIENT_ID", "").strip()
    client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET", "").strip() or None
    redirect_uri  = os.getenv("KEYCLOAK_REDIRECT_URI", "").strip()
    # SEC [CWE-1188]: refuse to start with default/empty client identity.
    # Previously defaulted to "reactjs" (a Keycloak demo-client name); if the
    # env var was accidentally unset in prod, the app would authenticate as
    # the wrong client. Fail loudly instead.
    if not client_id:
        logger.error(
            'auth_misconfigured reason="client_id_missing" '
            '— refusing to start auth flow'
        )
        st.error(
            "Configuration error: KEYCLOAK_CLIENT_ID is not set. Configure it "
            "in run_streamlit.bat to the Client ID registered on the Keycloak "
            "client for this app."
        )
        _render_retry_button("retry_client_id_missing")
        st.stop()
        return False
    if not redirect_uri:
        st.error(
            "KEYCLOAK_REDIRECT_URI is not set. Configure it in run_streamlit.bat "
            "to the public URL of this app (must be registered as a Valid Redirect "
            "URI on the Keycloak client)."
        )
        _render_retry_button("retry_redirect_uri_missing")
        st.stop()
        return False
    # SEC [CWE-601]: validate redirect URI format defensively. Keycloak
    # server-side will reject unregistered URIs, but we want to fail fast
    # with a clear operator-facing message on typos. Require a well-formed
    # absolute URL; require https outside dev mode.
    _parsed_redirect = urlparse(redirect_uri)
    _is_dev = os.getenv("MANNING_ENV", "").strip().lower() == "development"
    _allowed_schemes = {"http", "https"} if _is_dev else {"https"}
    if (
        not _parsed_redirect.scheme
        or not _parsed_redirect.netloc
        or _parsed_redirect.scheme not in _allowed_schemes
    ):
        logger.error(
            'auth_misconfigured reason="redirect_uri_invalid" '
            'redirect_uri="%s" scheme="%s" netloc="%s" dev=%s',
            redirect_uri, _parsed_redirect.scheme,
            _parsed_redirect.netloc, _is_dev,
        )
        st.error(
            "Configuration error: KEYCLOAK_REDIRECT_URI is not a valid URL. "
            f"Expected an absolute {'http(s)' if _is_dev else 'https'} URL "
            "(e.g. https://your-app.example.com/). Check run_streamlit.bat."
        )
        _render_retry_button("retry_redirect_uri_invalid")
        st.stop()
        return False

    # ── Discovery (cached) ────────────────────────────────────────────────
    try:
        discovery = _kc_discovery(KC_URL, realm)
    except Exception as exc:
        # `logger.exception` already includes the traceback; we add the
        # exception class name and a short reason on the headline so SREs
        # scanning logs can immediately tell SSL trust failures apart from
        # connectivity/DNS/timeouts. The user-facing message stays generic
        # to avoid leaking infrastructure details.
        logger.exception(
            'kc_discovery_failed exc_type=%s reason="%s" kc_url="%s" realm="%s" ssl_verify=%r',
            type(exc).__name__, str(exc)[:300], KC_URL, realm, _ssl_verify(),
        )
        st.error(
            "Unable to reach the identity provider. Please retry in a moment "
            f"or contact IT support. (Trace: `{trace_id}`)"
        )
        _render_retry_button("retry_kc_discovery")
        st.stop()
        return False

    # ── Step B: handle the redirect-back from Keycloak ────────────────────
    qp = st.query_params
    err_code = qp.get("error")
    if err_code:
        err_desc = qp.get("error_description", "")
        audit_logger.warning(
            'action="auth_idp_error" error="%s" desc="%s"',
            err_code, err_desc,
        )
        st.query_params.clear()
        # SEC [CWE-79]: err_code comes from a URL parameter the IdP set on
        # redirect-back. Never echo it raw — strip everything that isn't a
        # safe identifier-like character before placing it in the markdown.
        safe_err = "".join(
            ch for ch in str(err_code)[:64]
            if ch.isalnum() or ch in ("_", "-", ".")
        ) or "unspecified"
        st.error(
            f"Single sign-on failed: `{safe_err}`. "
            f"Please try again or contact IT. (Trace: `{trace_id}`)"
        )
        _render_retry_button("retry_idp_error")
        st.stop()
        return False

    incoming_code  = qp.get("code")
    incoming_state = qp.get("state")
    if incoming_code and incoming_state:
        # SEC [CWE-307]: per-IP rate limit on pre-auth token-exchange. Keyed
        # on the resolved client IP (which itself respects the trusted-proxy
        # allowlist in app/utils.get_user_context). Anyone hammering the
        # callback with random state/code values to probe for replays or
        # exhaust the IdP gets a 429-equivalent here BEFORE we hit Keycloak.
        _client_ip = (get_user_context() or {}).get("ip", "unknown")
        _login_rl = get_login_rate_limiter()
        _rl_allowed, _retry_after = _login_rl.check(f"login:{_client_ip}")
        if not _rl_allowed:
            audit_logger.warning(
                'action="auth_rate_limited" ip="%s" retry_after_sec=%d',
                _client_ip, _retry_after,
            )
            st.query_params.clear()
            st.error(
                "Too many sign-in attempts. Please wait "
                f"{_retry_after}s and retry. (Trace: `{trace_id}`)"
            )
            _render_retry_button("retry_rate_limited")
            st.stop()
            return False

        verifier = _pending_pop(incoming_state)
        if verifier is None:
            audit_logger.warning('action="auth_state_mismatch"')
            st.query_params.clear()
            st.error(
                "Login session expired or invalid. Please refresh the page "
                f"and try again. (Trace: `{trace_id}`)"
            )
            _render_retry_button("retry_state_mismatch")
            st.stop()
            return False

        try:
            tokens = _exchange_code_for_tokens(
                discovery,
                code=incoming_code,
                code_verifier=verifier,
                redirect_uri=redirect_uri,
                client_id=client_id,
                client_secret=client_secret,
            )
            logger.debug('token_exchange_ok client_id="%s"', client_id)
        except Exception as exc:
            # SEC: never log the request payload — it contains client_secret.
            # Log only the exception type and a truncated message so SREs can
            # distinguish network blips, Keycloak 4xx responses, and parse
            # errors during root-cause analysis.
            logger.error(
                'token_exchange_failed exc_type=%s reason="%s" client_id="%s"',
                type(exc).__name__, str(exc)[:200], client_id,
            )
            st.query_params.clear()
            st.error(
                "Could not complete sign-in. Please try again. "
                f"(Trace: `{trace_id}`)"
            )
            _render_retry_button("retry_token_exchange")
            st.stop()
            return False

        id_token     = tokens.get("id_token", "")
        access_token = tokens.get("access_token", "")
        if not id_token or not access_token:
            logger.error('token_exchange_incomplete reason="missing_id_or_access_token"')
            st.query_params.clear()
            st.error(f"Sign-in response was incomplete. (Trace: `{trace_id}`)")
            _render_retry_button("retry_token_incomplete")
            st.stop()
            return False

        try:
            id_claims = _validate_id_token(
                id_token, discovery,
                client_id=client_id,
                issuer=discovery["issuer"],
            )
        except Exception as exc:
            logger.exception('id_token_validation_failed')
            st.query_params.clear()
            st.error(f"Sign-in could not be verified. (Trace: `{trace_id}`)")
            _render_retry_button("retry_id_token_invalid")
            st.stop()
            return False

        username = (
            id_claims.get("preferred_username")
            or id_claims.get("email")
            or id_claims.get("name")
            or id_claims.get("sub")
            or "authenticated_user"
        )

        # ── Role extraction & guard ────────────────────────────────────────
        # Always extract roles so downstream code (has_role(), admin pages) can
        # authorize without re-decoding tokens. Roles are persisted into
        # st.session_state.user_ctx["roles"] further down regardless of whether
        # an allowed-set guard is configured.
        user_roles = _extract_realm_roles(access_token, id_claims)

        # Build the allowed-set: prefer KEYCLOAK_ALLOWED_ROLES (comma-separated
        # list of any-of), fall back to legacy KEYCLOAK_REQUIRED_ROLE (single
        # required role) for backwards-compat with existing deployments. If
        # neither is set, no role gating is enforced at login — any
        # authenticated user is admitted.
        allowed_csv = os.getenv("KEYCLOAK_ALLOWED_ROLES", "").strip()
        allowed_set: set[str] = set()
        if allowed_csv:
            allowed_set = {r.strip() for r in allowed_csv.split(",") if r.strip()}
        else:
            legacy = os.getenv("KEYCLOAK_REQUIRED_ROLE", "").strip()
            if legacy:
                allowed_set = {legacy}

        if allowed_set and not (set(user_roles) & allowed_set):
            audit_logger.warning(
                'action="auth_denied_missing_role" user_id="%s" allowed="%s" has="%s"',
                username, sorted(allowed_set), user_roles,
            )
            st.query_params.clear()
            st.error(
                f"Access denied — missing one of the required roles: "
                f"`{', '.join(sorted(allowed_set))}`. (Trace: `{trace_id}`)"
            )
            _render_retry_button("retry_missing_role")
            st.stop()
            return False

        # ── Persist tokens & identity ──────────────────────────────────────
        # We keep tokens in session_state for downstream API calls; Streamlit's
        # session_state is per-browser-session and held server-side only — it
        # is not exposed to the client beyond the session cookie.
        # SEC [CWE-384]: rotate the Streamlit session state at the
        # boundary between unauthenticated and authenticated. A pre-auth
        # attacker who tricks a victim into adopting an attacker-known
        # session_trace_id (or any other pre-login state) must not have
        # that handle survive the privilege transition. We clear every
        # key EXCEPT the OIDC ones we just consumed (already popped via
        # _pending_pop) and the new identity we're about to write. The
        # session_trace_id is re-minted so audit-correlation pre-auth
        # cannot be linked to post-auth activity through a leaked id.
        _preserve_post_auth = {"template_bytes"}
        for _k in [k for k in list(st.session_state.keys())
                   if k not in _preserve_post_auth]:
            try:
                del st.session_state[_k]
            except Exception:
                pass
        st.session_state.session_trace_id = f"sesh-{uuid.uuid4().hex[:10]}"
        set_trace_id(st.session_state.session_trace_id)

        st.session_state.access_token  = access_token
        st.session_state.id_token      = id_token
        st.session_state.refresh_token = tokens.get("refresh_token", "")
        st.session_state.user_info     = id_claims
        st.session_state._auth_confirmed = True
        st.session_state._auth_timestamp = time.time()
        st.session_state.user_id         = username
        st.session_state.user_ctx        = get_user_context()
        # SEC [CWE-352]: per-session CSRF token used by the idle-watchdog
        # endpoint (?idle_event=...&idle_csrf=...) so third-party origins
        # cannot trigger forced session-extend / forced-logout on a victim
        # who happens to be authenticated. The token is minted once at
        # login and lives for the lifetime of the session.
        import secrets as _secrets
        st.session_state._idle_csrf_token = _secrets.token_urlsafe(32)
        # Persist ONLY the intersection with the configured allowlist when one
        # is set. The gate at line 1070 admits users who carry *any* allowed
        # role, but if we stored the full IdP role list here, downstream
        # has_role() / RBAC checks could match an unintended high-privilege
        # role smuggled in alongside the allowed one (CWE-285). When no
        # allowlist is configured, persist the full set (legacy behavior).
        if allowed_set:
            st.session_state.user_ctx["roles"] = sorted(
                set(user_roles) & allowed_set
            )
        else:
            st.session_state.user_ctx["roles"] = user_roles

        audit_logger.info(
            'action="auth_success" user_id="%s" ip="%s" sub="%s" exp=%s',
            username,
            st.session_state.user_ctx.get("ip", "unknown"),
            id_claims.get("sub", ""),
            id_claims.get("exp", ""),
        )
        logger.info(
            'session_authenticated user_id="%s" ip="%s"',
            username,
            st.session_state.user_ctx.get("ip", "unknown"),
        )

        # Clear the ?code=&state= from the URL so a refresh doesn't try to
        # reuse a one-time code.
        st.query_params.clear()
        st.rerun()
        return False  # unreachable; rerun raises

    # ── Step A: kick off the redirect to Keycloak ─────────────────────────
    # Detect post-logout return. Two signals can mark this:
    #
    #   (a) `?signed_out=1` — set by logout() on the post_logout_redirect_uri
    #       when the server-side logout flow ran cleanly.
    #   (b) `?idle_event=logout` — set by the JS watchdog. This one matters
    #       because window.location.replace() from the iframe tears down the
    #       Streamlit session: on the rerun, _auth_confirmed is already False
    #       so handle_auth's fast path is skipped, _check_session_expiry()
    #       never fires, logout() is never called — the URL carries
    #       idle_event=logout straight into Step A. Without honoring it here,
    #       we'd just silent-SSO the user right back into the app.
    #
    # When either is present we add `prompt=login` + `max_age=0` to the next
    # /authorize so Keycloak forces a credential prompt instead of reusing
    # the realm SSO cookie. (`qp.get` may return None, a str, or a list — be
    # defensive so the detection doesn't silently miss the flag.)
    def _qp_str(key: str) -> str:
        raw = qp.get(key)
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        return str(raw or "")

    raw_signed_out = _qp_str("signed_out")
    raw_idle_event = _qp_str("idle_event")
    just_signed_out = (raw_signed_out == "1") or (raw_idle_event == "logout")

    # Diagnostic: pair this with auth_redirect_initiated + the next
    # auth_success to trace the round-trip end-to-end.
    logger.info(
        'signed_out_detect signed_out=%r idle_event=%r matched=%s qp_keys=%s',
        raw_signed_out, raw_idle_event, just_signed_out,
        sorted(list(qp.keys())),
    )

    if just_signed_out:
        st.info("You have been signed out. Redirecting to sign-in…")

    code_verifier, code_challenge = _new_pkce_pair()
    state = _new_state()
    _pending_put(state, code_verifier)

    auth_params: dict[str, str] = {
        "client_id":             client_id,
        "redirect_uri":          redirect_uri,
        "response_type":         "code",
        "scope":                 "openid profile email",
        "state":                 state,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
    }
    if just_signed_out:
        # Two redundant force-reauth signals — KC honors either, but some
        # versions / realm configs respect one but not the other:
        #   prompt=login : OIDC core. Forces KC to render the login form.
        #   max_age=0    : OIDC core. Says "auth_time must be ≤0 sec ago",
        #                  which any cached SSO necessarily fails, forcing
        #                  fresh credentials.
        auth_params["prompt"] = "login"
        auth_params["max_age"] = "0"
    auth_url = f"{discovery['authorization_endpoint']}?{urlencode(auth_params)}"

    audit_logger.info(
        'action="auth_redirect_initiated" client_id="%s" prompt_login=%s',
        client_id, just_signed_out,
    )
    # Truncated state prefix only — full state is a CSRF secret, never log it.
    logger.debug('pkce_state="%s..."', state[:8])
    _redirect_browser(auth_url)
    return False  # unreachable; _redirect_browser calls st.stop()


# ── SCHEDULE DATA RESET ───────────────────────────────────────────────────────

def clear_schedule_data() -> None:
    for k in [
        "schedule", "validation_results", "validation_results_records",
        "last_file_id", "master_schedule_editor",
        "_excel_export_bytes",
    ]:
        st.session_state.pop(k, None)
    st.session_state.uploader_key = str(uuid.uuid4())
    audit_logger.info(
        'action="schedule_data_cleared" user_id="%s"',
        st.session_state.get("user_id", "anonymous"),
    )


# ── LOGOUT ────────────────────────────────────────────────────────────────────
# Public: invoked from the sidebar logout button in Main.py.
#
# Two regimes:
#   1. Dev bypass (MANNING_ENV=development, KEYCLOAK_URL unset) — no IdP session
#      to terminate; just wipe session_state and rerun. The next handle_auth()
#      pass will re-mint a local_dev identity, which is the correct behaviour
#      for local development.
#   2. Production / test (Keycloak-backed) — clear local session_state AND
#      redirect the browser to Keycloak's RP-initiated logout endpoint
#      (`end_session_endpoint` from the cached discovery doc) with
#      `id_token_hint` so Keycloak can identify and terminate the SSO session,
#      then send the user back to KEYCLOAK_REDIRECT_URI for a fresh login.
#
# We do NOT touch token validation, SSL settings, or any of the security
# decisions made elsewhere in this module — this is a pure session-lifecycle
# helper.

# Keys to wipe on logout. We intentionally do NOT wipe `template_bytes` (cached
# blank-template bytes — expensive to rebuild and not user-specific) or
# `session_trace_id` (kept so the logout itself is traceable in logs).
_LOGOUT_WIPE_KEYS: tuple[str, ...] = (
    "_auth_confirmed", "_auth_timestamp",
    "access_token", "id_token", "refresh_token", "user_info",
    "user_id", "user_ctx",
    "schedule", "validation_results", "validation_results_records",
    "last_file_id", "master_schedule_editor",
    "_excel_export_bytes",
    "active_rule_names", "_prev_active_rule_names",
    "emp_page", "vio_page",
    "_checkpoint_restored",
    # View-mode and per-session "opened" flags so the next sign-in always
    # lands in App mode and audit events fire once per fresh session.
    "view_mode", "_log_viewer_opened_logged", "_app_render_logged",
    "_admin_console_opened_logged",
    "_confirm_factory_reset", "_confirm_logout", "_confirm_clear",
    # Pending upload result staged by the parsing modal; if a user signs
    # out mid-parse we don't want a stale result to surface on next login.
    "_upload_result",
    # Logout-dialog trigger flag (defensive — pop()'d on every rerun, but
    # keep it here so a half-rendered prior session can't reopen the modal
    # on the next sign-in).
    "_show_logout_dialog",
)


def logout() -> None:
    """Terminate the user's session and (in production) the Keycloak SSO session.

    Behaviour:
      - Always wipes auth + working-data keys from session_state.
      - In Keycloak-backed mode, redirects the browser to the IdP's
        end_session_endpoint with id_token_hint and post_logout_redirect_uri,
        which kills the SSO cookie at Keycloak and sends the user back to the
        login URL. The browser-side redirect is delegated to _redirect_browser()
        and ends in st.stop().
      - In dev bypass mode, just calls st.rerun() — handle_auth() will then
        re-mint a local_dev identity on the next pass.
    """
    user_id_at_logout = st.session_state.get("user_id", "anonymous")
    id_token_hint = st.session_state.get("id_token", "")

    KC_URL = os.getenv("KEYCLOAK_URL", "").strip()
    MANNING_ENV = os.getenv("MANNING_ENV", "").strip().lower()
    realm = os.getenv("KEYCLOAK_REALM", "default")
    redirect_uri = os.getenv("KEYCLOAK_REDIRECT_URI", "").strip()
    client_id = os.getenv("KEYCLOAK_CLIENT_ID", "").strip()
    if not client_id and KC_URL:
        # Logout still proceeds (local session wipe must always happen); we
        # just can't build a Keycloak end-session URL without the client_id.
        logger.warning(
            'logout_partial reason="client_id_missing" '
            'note="local session wiped; IdP end-session redirect skipped"'
        )

    # Drop any cross-session work-data checkpoint for this user. Logout must
    # clear it so a subsequent sign-in on the same machine (or a different
    # user reusing the device) starts with a clean slate.
    clear_checkpoint(user_id_at_logout)

    # Wipe local session state first — even if the IdP redirect fails for some
    # reason, we want this app's authenticated session to be gone.
    for k in _LOGOUT_WIPE_KEYS:
        st.session_state.pop(k, None)

    audit_logger.info(
        'action="logout" user_id="%s"', user_id_at_logout,
    )
    logger.info('session_logout user_id="%s"', user_id_at_logout)

    # Dev bypass: no IdP session exists. Just rerun — handle_auth() will
    # remint the local identity.
    if MANNING_ENV == "development" and not KC_URL:
        st.rerun()
        return  # unreachable; rerun raises

    # Production / test: redirect to Keycloak end-session endpoint. We use the
    # cached discovery doc — if it's not reachable, fall back to a hand-built
    # URL (the standard Keycloak path) so the user is not stranded.
    end_session_url: str | None = None
    if KC_URL:
        try:
            discovery = _kc_discovery(KC_URL, realm)
            end_session_url = discovery.get("end_session_endpoint")
        except Exception:
            logger.warning(
                'logout_discovery_unavailable — falling back to hand-built end_session URL'
            )

        if not end_session_url:
            end_session_url = (
                f"{KC_URL.rstrip('/')}/realms/{realm}"
                f"/protocol/openid-connect/logout"
            )

        params: dict[str, str] = {}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        # Belt-and-braces: include `client_id` too. Newer Keycloak versions
        # require it for confirmation-less logout when the id_token_hint has
        # expired (which is exactly what happens after a 5-min idle: access &
        # ID tokens are likely past their TTL, so KC may otherwise show a
        # logout-confirm prompt OR silently leave the realm SSO cookie alive).
        params["client_id"] = client_id
        if redirect_uri:
            # post_logout_redirect_uri must be registered as a Valid Post Logout
            # Redirect URI on the Keycloak client. Reusing KEYCLOAK_REDIRECT_URI
            # is the simplest path that works without a second config knob.
            #
            # The `?signed_out=1` flag survives KC's redirect back into the app
            # and signals handle_auth() to add `prompt=login` to the next
            # /authorize request. Without it, KC's still-alive realm SSO cookie
            # silently re-auths the same user and lands them right back on the
            # main page — defeating both idle-logout and the manual Sign-Out
            # button. (KC's end_session_endpoint terminates the *client*
            # session, but the realm SSO cookie can persist depending on the
            # realm's SSO Session Idle / Max settings.)
            sep = "&" if "?" in redirect_uri else "?"
            params["post_logout_redirect_uri"] = f"{redirect_uri}{sep}signed_out=1"
        if params:
            end_session_url = f"{end_session_url}?{urlencode(params)}"

        _redirect_browser(end_session_url)
        return  # unreachable; _redirect_browser calls st.stop()

    # No KC_URL and not dev mode — should be unreachable because handle_auth()
    # refuses to start in this state, but be defensive.
    st.rerun()


def maybe_show_debug_panel(kc_obj=None) -> None:
    pass


# ── IDLE-TIMEOUT WATCHDOG ─────────────────────────────────────────────────────
# Two-layer scheme:
#
#   Layer 1 (client-side, fires reliably even without reruns):
#     A small HTML/JS bundle embedded via streamlit.components.v1.html
#     (height=0). The iframe JS injects its warning modal into the *parent*
#     document (window.parent.document.body) so position:fixed is clipped to
#     the parent viewport rather than the 0-px iframe. It listens for
#     mousemove/keydown/click/scroll/touchstart on the parent document,
#     maintains its own `lastActivity` timestamp, and on every 1s tick:
#       (a) opens the warning modal with a live countdown when
#           idle ≥ (IDLE_TIMEOUT_SECONDS − WARNING_LEAD_SECONDS), OR
#       (b) navigates the parent to ?idle_event=logout when idle ≥
#           IDLE_TIMEOUT_SECONDS (or the user clicks "Sign out now").
#     Continue button navigates to ?idle_event=continue.
#
#     The round-trip is via window.parent.location query string — a full
#     Streamlit rerun with the param set — because components.html iframes
#     cannot use Streamlit.setComponentValue (that protocol is reserved for
#     declared components with a frontend bundle).
#
#   Layer 2 (server-side backstop):
#     `_check_session_expiry()` enforces `_auth_timestamp` against the
#     tighter of IDLE_TIMEOUT_SECONDS and KEYCLOAK_SESSION_MAX_IDLE_SEC on
#     every rerun. If the JS layer is suspended (frozen background tab, JS
#     disabled, cross-origin parent), the next rerun the user triggers when
#     they return will catch the staleness and force a logout.
#
# SEC: This component does NOT send tokens, identity, or any secret to the
# client. It only reads activity events and writes back a small status enum
# via the URL query string. All authoritative session decisions remain
# server-side.

# Configurable via env vars; sensible defaults for a 5-min idle cycle.
def _idle_config() -> dict[str, int]:
    """Return the idle-timeout configuration, parsed from env with safe defaults.

    Env:
        IDLE_TIMEOUT_SECONDS: total seconds of inactivity before forced logout.
            Default: 300 (5 min).
        WARNING_LEAD_SECONDS: seconds before logout that the warning modal
            appears. Default: 60 (1 min).

    Returns:
        dict with keys: idle_timeout, warning_lead.
    """
    def _int_env(name: str, default: int, minimum: int) -> int:
        raw = os.getenv(name, "").strip()
        if not raw:
            return default
        try:
            val = int(raw)
        except ValueError:
            logger.warning(
                'idle_config_invalid env="%s" raw="%s" using_default=%d',
                name, raw, default,
            )
            return default
        return max(val, minimum)

    idle_timeout = _int_env("IDLE_TIMEOUT_SECONDS", 300, 30)
    warning_lead = _int_env("WARNING_LEAD_SECONDS", 60, 5)

    # Guard: warning_lead must be < idle_timeout, else the modal would never
    # appear before the auto-logout fires.
    if warning_lead >= idle_timeout:
        warning_lead = max(idle_timeout // 5, 5)

    return {
        "idle_timeout":  idle_timeout,
        "warning_lead":  warning_lead,
    }


def _render_idle_watchdog_component() -> None:
    """Render the client-side idle watchdog.

    Mounts a 0-height iframe whose script injects the warning modal into the
    *parent* document and round-trips Continue / Logout decisions via the
    parent's URL query string (`?idle_event=continue|logout`). The server
    reads that param in `render_idle_timeout_guard()`.

    Returns None — no back-channel; events arrive as a normal Streamlit
    rerun with the query param set.

    SEC: cross-origin parents (e.g. component sandboxed by a host that
    isolates iframes) will throw on `window.parent.document` access. We
    catch and degrade silently; the server backstop in
    `_check_session_expiry()` (now bounded by IDLE_TIMEOUT_SECONDS) still
    enforces logout on the next rerun.
    """
    import streamlit.components.v1 as components

    cfg = _idle_config()
    idle_total = cfg["idle_timeout"]
    warn_lead = cfg["warning_lead"]

    # The component HTML is fully self-contained. We pass config through
    # JS template literals — values are integers from env parsing, not user
    # input, so no XSS risk; nonetheless we json.dumps them.
    import json as _json
    idle_total_js = _json.dumps(idle_total)
    warn_lead_js = _json.dumps(warn_lead)
    # SEC [CWE-352]: bind the per-session CSRF token into the JS so the
    # watchdog can attach it to the GET it issues when the user clicks
    # Continue / Sign-out-now. The token is server-minted at login.
    _csrf_tok = st.session_state.get("_idle_csrf_token", "")
    csrf_js = _json.dumps(_csrf_tok)

    html_payload = f"""
<!doctype html>
<html><head><meta charset="utf-8"></head><body style="margin:0;padding:0;background:transparent;">
<script>
(function() {{
  const IDLE_TOTAL_SEC   = {idle_total_js};
  const WARNING_LEAD_SEC = {warn_lead_js};
  const MODAL_ID         = 'idle-watchdog-modal';
  const STYLE_ID         = 'idle-watchdog-style';

  // ── Cross-origin guard ────────────────────────────────────────────────
  // If the parent is sandboxed/cross-origin, accessing parent.document
  // throws SecurityError. We degrade silently and let the server-side
  // backstop in _check_session_expiry() handle the timeout.
  let parentDoc = null;
  let parentWin = null;
  try {{
    parentWin = window.parent;
    parentDoc = parentWin && parentWin.document;
    // Force-touch a property to confirm same-origin access actually works.
    void parentDoc.body;
  }} catch (e) {{
    try {{ console.warn('idle-watchdog: parent doc inaccessible, server backstop only', e); }} catch(_) {{}}
    return;
  }}
  if (!parentDoc || !parentDoc.body) return;

  // ── Inject parent-realm navigation function (once per parent doc) ─────
  // The iframe runs with sandbox="allow-scripts" (set by Streamlit's
  // components.html), so direct calls to parentWin.location.replace from
  // iframe-realm code are blocked by the browser's sandbox check (the
  // initiator's realm is the iframe, not the parent). Workaround: inject
  // a <script> element into parentDoc.head whose body defines a function
  // on the parent window. Parser-inserted scripts execute in their host
  // document's realm, so this function is NOT subject to the sandbox flag
  // — when called via parentWin.__idleWatchdogNav(...), the navigation
  // proceeds normally.
  const NAV_SCRIPT_ID = 'idle-watchdog-nav-script';
  if (!parentDoc.getElementById(NAV_SCRIPT_ID)) {{
    try {{
      const navScript = parentDoc.createElement('script');
      navScript.id = NAV_SCRIPT_ID;
      // BUG FIX: previously this used window.location.replace(url), which is
      // a HARD navigation. Under Streamlit 1.55 + IIS reverse proxy, that
      // reload sometimes establishes a fresh session — wiping st.session_state
      // (schedule edits, validation results, etc.) and forcing a re-auth that
      // looked to the user like progress was lost on Continue.
      //
      // For "continue": update the URL via history.replaceState (no reload)
      // and dispatch a popstate event so Streamlit's frontend re-reads query
      // params and triggers a script rerun. The server-side handler then sees
      // ?idle_event=continue, refreshes _auth_timestamp, and clears the param
      // — all without ever losing the WebSocket / session.
      //
      // For "logout": keep the hard navigation. Logout intentionally tears
      // down the session and redirects to Keycloak's end-session endpoint,
      // so a full reload is the correct behavior.
      navScript.textContent = [
        'window.__idleWatchdogNav = function(eventName) {{',
        '  try {{',
        '    var csrf = ' + {csrf_js} + ';',
        '    var url = window.location.pathname + "?idle_event=" + encodeURIComponent(eventName) + "&idle_csrf=" + encodeURIComponent(csrf);',
        '    if (eventName === "continue" && window.history && window.history.replaceState) {{',
        '      window.history.replaceState(null, "", url);',
        '      try {{ window.dispatchEvent(new PopStateEvent("popstate")); }} catch (_) {{',
        '        try {{ window.dispatchEvent(new Event("popstate")); }} catch (_) {{}}',
        '      }}',
        '      return;',
        '    }}',
        '    window.location.replace(url);',
        '  }} catch (e) {{',
        '    try {{ console.warn("idle-watchdog parent-nav failed", e); }} catch(_) {{}}',
        '  }}',
        '}};'
      ].join('\\n');
      parentDoc.head.appendChild(navScript);
    }} catch (e) {{
      try {{ console.warn('idle-watchdog: nav script injection failed', e); }} catch(_) {{}}
    }}
  }}

  // ── Idempotency: if we already injected on a prior rerun, replace the
  // node so handlers re-bind cleanly without stacking listeners. ────────
  const existing = parentDoc.getElementById(MODAL_ID);
  if (existing && existing.parentNode) {{
    existing.parentNode.removeChild(existing);
  }}

  // ── Inject styles (once) ──────────────────────────────────────────────
  if (!parentDoc.getElementById(STYLE_ID)) {{
    const style = parentDoc.createElement('style');
    style.id = STYLE_ID;
    style.textContent = [
      '#' + MODAL_ID + ' {{ display:none; }}',
      '#' + MODAL_ID + '.idle-open {{ display:flex; }}',
      '#' + MODAL_ID + ' .idle-overlay {{',
      '  position: fixed; inset: 0;',
      '  background: rgba(15, 23, 42, 0.55);',
      '  z-index: 2147483647;',
      '  display: flex; align-items: center; justify-content: center;',
      '  backdrop-filter: blur(2px);',
      '  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;',
      '}}',
      '#' + MODAL_ID + ' .idle-modal {{',
      '  background:#fff; border-radius:12px;',
      '  box-shadow: 0 25px 60px -10px rgba(0,0,0,0.45);',
      '  padding:1.6rem 1.8rem; max-width:440px; width:calc(100% - 2rem);',
      '  border-top:4px solid #f24713;',
      '}}',
      '#' + MODAL_ID + ' h2 {{ margin:0 0 .6rem 0; font-size:1.15rem; font-weight:700; color:#1f2937; }}',
      '#' + MODAL_ID + ' p  {{ margin:0 0 1.0rem 0; font-size:.92rem; color:#475569; line-height:1.45; }}',
      '#' + MODAL_ID + ' .idle-countdown {{ font-variant-numeric:tabular-nums; font-weight:700; color:#f24713; font-size:1.05rem; }}',
      '#' + MODAL_ID + ' .idle-actions {{ display:flex; gap:.6rem; justify-content:flex-end; }}',
      '#' + MODAL_ID + ' .idle-btn {{ padding:.5rem 1.1rem; border-radius:6px; cursor:pointer; font-size:.88rem; font-weight:600; border:1px solid transparent; transition:background .15s ease; }}',
      '#' + MODAL_ID + ' .idle-btn-primary {{ background:#f24713; color:#fff; }}',
      '#' + MODAL_ID + ' .idle-btn-primary:hover {{ background:#d63d0e; }}',
      '#' + MODAL_ID + ' .idle-btn-secondary {{ background:#f1f5f9; color:#334155; border-color:#cbd5e1; }}',
      '#' + MODAL_ID + ' .idle-btn-secondary:hover {{ background:#e2e8f0; }}',
      ''
    ].join('\\n');
    parentDoc.head.appendChild(style);
  }}

  // ── Build the modal in the parent DOM ─────────────────────────────────
  const wrap = parentDoc.createElement('div');
  wrap.id = MODAL_ID;
  wrap.innerHTML = [
    '<div class="idle-overlay" role="dialog" aria-modal="true"',
    '     aria-labelledby="idle-watchdog-title" aria-describedby="idle-watchdog-desc">',
    '  <div class="idle-modal">',
    '    <h2 id="idle-watchdog-title">Are you still there?</h2>',
    '    <p id="idle-watchdog-desc">',
    '      For your security, you will be signed out in',
    '      <span class="idle-countdown" id="idle-watchdog-seconds">--</span>',
    '      seconds due to inactivity.',
    '    </p>',
    '    <div class="idle-actions">',
    '      <button class="idle-btn idle-btn-secondary" id="idle-watchdog-logout-now" type="button">Sign out now</button>',
    '      <button class="idle-btn idle-btn-primary" id="idle-watchdog-continue" type="button" autofocus>Continue session</button>',
    '    </div>',
    '  </div>',
    '</div>'
  ].join('');
  parentDoc.body.appendChild(wrap);

  const secondsEl   = parentDoc.getElementById('idle-watchdog-seconds');
  const continueBtn = parentDoc.getElementById('idle-watchdog-continue');
  const logoutBtn   = parentDoc.getElementById('idle-watchdog-logout-now');

  let lastActivity = Date.now();
  let modalOpen    = false;
  let fired        = false;

  // Same-WS continue path: find the hidden Streamlit button rendered by
  // `_render_idle_continue_button()` and dispatch a real click. Streamlit
  // delivers the click over the existing WebSocket and reruns the script
  // on the SAME session, so nothing in st.session_state is lost.
  //
  // The button is inside a st.container(key="idle_continue_container"),
  // which Streamlit renders as <div class="st-key-idle_continue_container">.
  // CSS in assets/style.css hides that class on first paint; .click() still
  // fires on display:none elements via React's delegated event handler.
  function findContinueButton() {{
    try {{
      var container = parentDoc.querySelector('.st-key-idle_continue_container');
      if (container) {{
        return container.querySelector('button');
      }}
    }} catch (e) {{}}
    return null;
  }}

  function tryClickContinueButton() {{
    var btn = findContinueButton();
    if (btn) {{
      try {{
        btn.click();
        return true;
      }} catch (e) {{
        try {{ console.warn('idle-watchdog: button click failed', e); }} catch(_) {{}}
      }}
    }}
    return false;
  }}

  function navParent(eventName) {{
    if (fired) return;
    fired = true;

    // PRIMARY (continue only): same-WebSocket button click. No navigation
    // means no IIS reverse-proxy session reset means session_state stays
    // alive — the user's uploaded schedule, edits, and validation
    // results all survive.
    if (eventName === 'continue') {{
      if (tryClickContinueButton()) {{
        return;
      }}
    }}

    // FALLBACK: URL navigation. For "continue" this is reached only if
    // the hidden button is not in the DOM (mid-page-load); for "logout"
    // this is the intended path because we want a hard tear-down.
    try {{
      if (typeof parentWin.__idleWatchdogNav === 'function') {{
        parentWin.__idleWatchdogNav(eventName);
      }} else {{
        // Defensive: parent-realm script injection failed earlier. This
        // direct call WILL be sandbox-blocked in srcdoc iframes, but try
        // anyway so we leave breadcrumbs in the console for diagnosis.
        parentWin.location.replace(
          parentWin.location.pathname + '?idle_event=' + encodeURIComponent(eventName) +
          '&idle_csrf=' + encodeURIComponent({csrf_js})
        );
      }}
    }} catch (e) {{
      try {{ console.warn('idle-watchdog: parent nav failed', e); }} catch(_) {{}}
      // NOTE: do NOT reset `fired`. Letting tick() retry every second
      // produces a console-error storm. The server-side backstop in
      // _check_session_expiry() will catch the user on their next
      // interaction and force the logout.
    }}
  }}

  function showModal() {{
    if (modalOpen) return;
    modalOpen = true;
    wrap.classList.add('idle-open');
    try {{ continueBtn.focus(); }} catch (e) {{}}
  }}
  function hideModal() {{
    modalOpen = false;
    wrap.classList.remove('idle-open');
  }}

  function onActivity() {{
    // Ignore activity while the modal is up — the user must explicitly
    // click Continue. An accidental mouse twitch should not defeat the
    // security control.
    if (modalOpen) return;
    lastActivity = Date.now();
  }}

  ['mousemove','mousedown','keydown','scroll','touchstart','click'].forEach(
    function(evt) {{
      try {{ parentDoc.addEventListener(evt, onActivity, {{passive:true, capture:true}}); }}
      catch (e) {{}}
    }}
  );

  continueBtn.addEventListener('click', function() {{
    lastActivity = Date.now();
    hideModal();
    navParent('continue');
  }});
  logoutBtn.addEventListener('click', function() {{
    hideModal();
    navParent('logout');
  }});

  function tick() {{
    if (fired) return;
    const idleSec = (Date.now() - lastActivity) / 1000;
    if (idleSec >= IDLE_TOTAL_SEC) {{
      hideModal();
      navParent('logout');
      return;
    }}
    if (idleSec >= IDLE_TOTAL_SEC - WARNING_LEAD_SEC) {{
      showModal();
      const remaining = Math.max(0, Math.ceil(IDLE_TOTAL_SEC - idleSec));
      secondsEl.textContent = String(remaining);
    }} else {{
      // user came back to life before countdown — reset modal if open
      if (modalOpen) hideModal();
    }}
  }}

  setInterval(tick, 1000);
  tick();
}})();
</script>
</body></html>
"""

    # height=0 — the modal is rendered into the PARENT document; this iframe
    # only hosts the script and takes no layout space. The keyed wrapper lets
    # a `display:none` CSS rule (assets/style.css: .st-key-idle_watchdog_container)
    # collapse the otherwise-empty element row + vertical-block gap that the
    # height-0 component still reserves at the top of `.block-container`. The
    # iframe script keeps running while display:none — same semantics that let
    # the hidden `idle_continue_container` button receive synthetic clicks.
    with st.container(key="idle_watchdog_container"):
        components.html(html_payload, height=0)


_IDLE_CONTINUE_CONTAINER_KEY = "idle_continue_container"


def _render_idle_continue_button() -> None:
    """Render a hidden Streamlit button that the iframe JS can click to
    extend the session **without leaving the current WebSocket**.

    Why this exists:
      The original design routed "Continue session" through a parent-window
      navigation (?idle_event=continue). Under Streamlit 1.55 + IIS reverse
      proxy that navigation sometimes severs the WebSocket and the user
      lands on a fresh session_state with empty defaults — every uploaded
      schedule, edit, and validation result wiped.

      A real Streamlit button click is delivered over the existing
      WebSocket, triggers a normal script rerun on the same session, and
      keeps every key in st.session_state alive.

    Hiding strategy:
      The button is wrapped in `st.container(key=...)`, which Streamlit
      renders as a <div class="st-key-idle_continue_container">. A CSS
      rule in assets/style.css hides that class with display:none on
      first paint — no flicker, no marker-text leak through the layout.

      `display:none` does not block synthetic .click() dispatch: the
      browser still fires the click event, React's delegated listener
      still receives it, and Streamlit reruns the script on the live
      WebSocket as if the user clicked normally.
    """
    def _on_continue_click() -> None:
        """Pre-script-body callback: refresh _auth_timestamp BEFORE handle_auth's
        idle check runs.

        Streamlit guarantees on_click callbacks run before the rerun's script
        body. This is the load-bearing semantics — relying on widget-state
        propagation through session_state is unreliable for st.button (its
        True value is observable at the widget call site, not pre-render).

        Also sets `_just_continued` so the post-continue token-refresh branch
        in _check_session_expiry can show a soft re-auth prompt instead of a
        hard logout if the token can't be refreshed.
        """
        st.session_state._auth_timestamp = time.time()
        st.session_state._just_continued = True
        audit_logger.info(
            'action="session_continued_after_warning" user_id="%s" path="same_ws_callback"',
            st.session_state.get("user_id", "anonymous"),
        )
        logger.info(
            'session_extended user_id="%s" path="same_ws_callback"',
            st.session_state.get("user_id", "anonymous"),
        )

    with st.container(key=_IDLE_CONTINUE_CONTAINER_KEY):
        if st.button(
            "Continue session",
            key="__idle_continue_btn",
            on_click=_on_continue_click,
            help="hidden — used by idle watchdog",
        ):
            # Body runs after on_click; timestamp already refreshed there.
            # Explicit rerun keeps the modal-dismiss UX clean.
            st.rerun()


def render_idle_timeout_guard() -> None:
    """Mount the idle-timeout watchdog and react to its events.

    Call once per rerun, AFTER `handle_auth()` has confirmed authentication.
    Has no effect for unauthenticated sessions or in dev-bypass mode (where
    there is no real session lifecycle to enforce — rerunning into a fresh
    local_dev identity on every idle event would only create test friction).

    Two continue paths exist:

        Same-WS (preferred): the iframe JS clicks a hidden Streamlit button
            (rendered by `_render_idle_continue_button()`). Streamlit reruns
            on the live socket — no navigation, no IIS WebSocket reset, no
            risk of wiping the user's in-progress work.

        URL fallback (`idle_event=continue`): used only if the iframe JS
            cannot locate the hidden button (e.g. mid-page-load). Triggers
            a real navigation and may invalidate the WebSocket under IIS;
            the per-user checkpoint in `app/core/checkpoint.py` rehydrates
            session_state on the new session so progress is still preserved.

    Logout always uses the URL path — a hard navigation is exactly what
    logout wants.
    """
    if not st.session_state.get("_auth_confirmed"):
        return

    KC_URL = os.getenv("KEYCLOAK_URL", "").strip()
    MANNING_ENV = os.getenv("MANNING_ENV", "").strip().lower()
    # Dev bypass: no IdP session, no point in forcing logouts during local
    # development. The watchdog would just bounce the developer back to a
    # newly-minted local_dev identity, which is noise without a security win.
    if MANNING_ENV == "development" and not KC_URL:
        return

    # Hidden button that the iframe JS clicks for the same-WS continue path.
    # Must be rendered BEFORE the watchdog component so it exists in the DOM
    # when the iframe script runs.
    _render_idle_continue_button()

    # Process any pending idle event BEFORE re-mounting the watchdog so the
    # post-event rerun lands on a clean URL.
    try:
        event = st.query_params.get("idle_event")
    except Exception:
        event = None
    try:
        idle_csrf = st.query_params.get("idle_csrf")
    except Exception:
        idle_csrf = None

    if event:
        user_id = st.session_state.get("user_id", "anonymous")

        # SEC [CWE-352]: validate the per-session CSRF token before honouring
        # *any* idle_event side-effect. A third-party origin can race the
        # user into ?idle_event=logout via a stray <img> or window.open, but
        # cannot read this session-bound token. Reject mismatches loudly and
        # strip the params so a refresh does not replay.
        import hmac as _hmac
        expected = st.session_state.get("_idle_csrf_token", "")
        if not (expected and idle_csrf and
                _hmac.compare_digest(str(idle_csrf), str(expected))):
            audit_logger.warning(
                'action="idle_event_csrf_rejected" user_id="%s" event="%s"',
                user_id, event,
            )
            try:
                del st.query_params["idle_event"]
            except Exception:
                pass
            try:
                del st.query_params["idle_csrf"]
            except Exception:
                pass
            # Re-mount watchdog so the session keeps functioning normally.
            _render_idle_watchdog_component()
            return

        if event == "continue":
            st.session_state._auth_timestamp = time.time()
            audit_logger.info(
                'action="session_continued_after_warning" user_id="%s" path="url_fallback"',
                user_id,
            )
            logger.info('session_extended user_id="%s" path="url_fallback"', user_id)
            # Clear the params so a manual refresh does not re-fire it,
            # and the CSRF token does not stay visible in the address bar.
            try:
                del st.query_params["idle_event"]
            except Exception:
                try:
                    st.query_params.clear()
                except Exception:
                    pass
            try:
                del st.query_params["idle_csrf"]
            except Exception:
                pass
            st.rerun()
            return

        if event == "logout":
            audit_logger.info(
                'action="session_idle_auto_logout" user_id="%s" trigger="client_watchdog"',
                user_id,
            )
            logger.info('idle_auto_logout user_id="%s"', user_id)
            st.warning("Signed out due to inactivity. Please sign in to continue.")
            logout()
            # logout() redirects to Keycloak end-session and wipes state;
            # no need to clear the param.
            return

        # Unknown idle_event value — clear and continue.
        logger.debug('idle_unknown_event event="%s"', event)
        try:
            del st.query_params["idle_event"]
        except Exception:
            pass
        try:
            del st.query_params["idle_csrf"]
        except Exception:
            pass

    _render_idle_watchdog_component()
