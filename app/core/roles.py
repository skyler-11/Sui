"""Realm role identifiers for the Manning Validation System.

These constants are the single source of truth for role-gate checks. Keycloak
emits these strings in `access_token.realm_access.roles`; `app.auth.has_role`
and `app.auth.require_role` compare against them.
"""

MANNING_USER = "manning-user"
MANNING_SUPERADMIN = "manning-superadmin"
