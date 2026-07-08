"""
patch_keycloak_bundle.py
Run this once on each machine / Python environment that hosts the test or
production server.  It auto-locates the streamlit_keycloak package, applies
all required bundle.js patches, and creates the missing bootstrap.min.css.map
stub so Streamlit stops logging FileNotFoundError on every page load.

Usage (run as the user that owns the Python environment):
    python patch_keycloak_bundle.py
"""

import importlib.util
import os
import re
import sys


# ── Locate the package ────────────────────────────────────────────────────────

spec = importlib.util.find_spec("streamlit_keycloak")
if spec is None:
    sys.exit("ERROR: streamlit_keycloak is not installed in this Python environment.")

pkg_root = os.path.dirname(spec.origin)
public_dir = os.path.join(pkg_root, "frontend", "public")
bundle_path = os.path.join(public_dir, "build", "bundle.js")

print(f"Python       : {sys.executable}")
print(f"Package root : {pkg_root}")
print(f"bundle.js    : {bundle_path}")

if not os.path.isfile(bundle_path):
    sys.exit(f"ERROR: bundle.js not found at {bundle_path}")


# ── Read bundle ───────────────────────────────────────────────────────────────

with open(bundle_path, "r", encoding="utf-8") as fh:
    original = fh.read()

print(f"Bundle size  : {len(original):,} chars\n")
patched = original

_applied = []
_warned  = []


def _show_context(src: str, term: str, chars: int = 120) -> None:
    """Print surrounding context when a patch anchor isn't found."""
    # Try to find something nearby as a hint
    idx = src.find(term[:20]) if len(term) >= 20 else -1
    if idx >= 0:
        start = max(0, idx - chars)
        end   = min(len(src), idx + chars)
        print(f"  Context around '{term[:20]}...':")
        print(f"  ...{src[start:end]}...")
    else:
        print(f"  '{term[:40]}' not found anywhere in the bundle.")


# ── Patch 1: silence loadUserInfo() CORS / network rejection ─────────────────
# Without this, a rejected promise propagates and blocks setComponentValue().

P1_OLD = "await h.loadUserInfo(),"
P1_NEW = "await h.loadUserInfo().catch(()=>{}),"

# Fallback: some minifiers drop the trailing comma
P1_OLD_ALT = "await h.loadUserInfo()"
P1_NEW_ALT = "await h.loadUserInfo().catch(()=>{})"

if P1_NEW in patched or P1_NEW_ALT in patched:
    print("PATCH 1 already present — skipping")
elif P1_OLD in patched:
    patched = patched.replace(P1_OLD, P1_NEW, 1)
    print("PATCH 1 applied : loadUserInfo().catch(()=>{})")
    _applied.append(1)
elif P1_OLD_ALT in patched:
    patched = patched.replace(P1_OLD_ALT, P1_NEW_ALT, 1)
    print("PATCH 1 applied (alt) : loadUserInfo().catch(()=>{})")
    _applied.append(1)
else:
    print("WARN  PATCH 1 : anchor not found — bundle may have changed")
    _show_context(original, "loadUserInfo")
    _warned.append(1)


# ── Patch 2: null-guard Svelte catch block reading t[18].error ───────────────
# Flexible regex handles slight minification differences across versions.

P2_PATTERN = re.compile(r'\bt\[18\]\.error\b')
P2_OLD_STR = "c=t[18].error+"
P2_NEW_STR = 'c=((t[18]&&t[18].error)||"Auth error")+'
P2_NEW_MARKER = "(t[18]&&t[18].error)||"

if P2_NEW_MARKER in patched:
    print("PATCH 2 already present — skipping")
elif P2_OLD_STR in patched:
    patched = patched.replace(P2_OLD_STR, P2_NEW_STR, 1)
    print("PATCH 2 applied : t[18] null-guard (exact)")
    _applied.append(2)
elif P2_PATTERN.search(patched):
    # Replace any bare t[18].error reference in an assignment context
    patched = P2_PATTERN.sub('((t[18]&&t[18].error)||"Auth error")', patched, count=1)
    print("PATCH 2 applied : t[18] null-guard (regex fallback)")
    _applied.append(2)
else:
    print("WARN  PATCH 2 : t[18].error not found")
    _show_context(original, "t[18]")
    _warned.append(2)


# ── Patch 3: null-guard Svelte catch block reading t[10].message ─────────────

P3_PATTERN = re.compile(r'\bt\[10\]\.message\b')
P3_OLD_STR = "i=t[10].message+"
P3_NEW_STR = 'i=((t[10]&&t[10].message)||"Auth error")+'
P3_NEW_MARKER = "(t[10]&&t[10].message)||"

if P3_NEW_MARKER in patched:
    print("PATCH 3 already present — skipping")
elif P3_OLD_STR in patched:
    patched = patched.replace(P3_OLD_STR, P3_NEW_STR, 1)
    print("PATCH 3 applied : t[10] null-guard (exact)")
    _applied.append(3)
elif P3_PATTERN.search(patched):
    patched = P3_PATTERN.sub('((t[10]&&t[10].message)||"Auth error")', patched, count=1)
    print("PATCH 3 applied : t[10] null-guard (regex fallback)")
    _applied.append(3)
else:
    print("WARN  PATCH 3 : t[10].message not found")
    _show_context(original, "t[10]")
    _warned.append(3)


# ── Patch 4: remove hardcoded onLoad:"check-sso" + silentCheckSsoRedirectUri ─
# The component overrides our init_options with check-sso which triggers a
# hidden iframe.  Keycloak's CSP sends frame-ancestors:'self' so the iframe
# is blocked in the browser → white screen / KC:Svelte:98 crash.
# Strategy: try progressively looser regexes, then fall back to stripping the
# two offending properties individually — works regardless of minification.

# Level 1 — exact variable name "a", comma-separated
CHECKSSO_RE = re.compile(
    r'h\.init\(\{\.\.\.a,\s*onLoad\s*:\s*"check-sso",\s*silentCheckSsoRedirectUri\s*:[^}]+\}\)'
)
# Level 2 — variable "a" or "r", single/double quotes
CHECKSSO_RE2 = re.compile(
    r'h\.init\(\{\.\.\.(?:a|r),\s*onLoad\s*:\s*["\']check-sso["\'],\s*silentCheckSsoRedirectUri\s*:[^}]+\}\)'
)
# Level 3 — any variable, any property order
CHECKSSO_LOOSE = re.compile(r'h\.init\(\{[^}]*["\']check-sso["\'][^}]*\}\)')

# Level 4 — strip the two properties individually wherever they appear
P4_ONLOAD_RE = re.compile(r',?\s*onLoad\s*:\s*["\']check-sso["\']')
P4_SILENT_RE = re.compile(r',?\s*silentCheckSsoRedirectUri\s*:[^,}]+')

P4_DONE = "h.init({...a,})"

if P4_DONE in patched:
    print("PATCH 4 already present — skipping")
elif CHECKSSO_RE.search(patched):
    patched = CHECKSSO_RE.sub(P4_DONE, patched)
    print("PATCH 4 applied : removed check-sso iframe init (level 1)")
    _applied.append(4)
elif CHECKSSO_RE2.search(patched):
    patched = CHECKSSO_RE2.sub(P4_DONE, patched)
    print("PATCH 4 applied : removed check-sso iframe init (level 2)")
    _applied.append(4)
elif CHECKSSO_LOOSE.search(patched):
    patched = CHECKSSO_LOOSE.sub(P4_DONE, patched)
    print("PATCH 4 applied : removed check-sso iframe init (level 3)")
    _applied.append(4)
elif P4_ONLOAD_RE.search(patched) or P4_SILENT_RE.search(patched):
    # Strip the two properties individually — handles any surrounding structure
    before = patched
    patched = P4_ONLOAD_RE.sub("", patched)
    patched = P4_SILENT_RE.sub("", patched)
    if patched != before:
        print("PATCH 4 applied : stripped check-sso properties (level 4 fallback)")
        _applied.append(4)
    else:
        print("WARN  PATCH 4 : property strip matched but produced no change")
        _warned.append(4)
else:
    print("WARN  PATCH 4 : no check-sso pattern found in bundle")
    _show_context(original, "check-sso")
    print()
    print("  >>> This means the Keycloak iframe block is STILL ACTIVE on HTTPS. <<<")
    print("  >>> Set PYTHON_EXE in run_streamlit.bat to the full Python path.   <<<")
    _warned.append(4)


# ── Patch 5: force checkLoginIframe=false in the Keycloak adapter defaults ───
# Even when checkLoginIframe:false is passed through init_options, the adapter
# may reset it to true via its internal default object before init() runs.
# This patch overwrites every occurrence of the hardcoded true so the adapter
# never creates the login-status-iframe that Keycloak's frame-ancestors blocks.

P5_PAIRS = [
    ("checkLoginIframe:!0",    "checkLoginIframe:!1"),    # minified  true / false
    ("checkLoginIframe: !0",   "checkLoginIframe: !1"),
    ("checkLoginIframe:true",  "checkLoginIframe:false"),
    ("checkLoginIframe: true", "checkLoginIframe: false"),
]
P5_MARKER = "checkLoginIframe:!1"   # proof the patch already landed

p5_hits = sum(1 for old, _ in P5_PAIRS if old in patched)
p5_already = P5_MARKER in patched or "checkLoginIframe:false" in patched

if p5_already and p5_hits == 0:
    print("PATCH 5 already present — skipping")
elif p5_hits:
    for old, new in P5_PAIRS:
        patched = patched.replace(old, new)
    print(f"PATCH 5 applied : checkLoginIframe forced false ({p5_hits} occurrence(s))")
    _applied.append(5)
else:
    print("WARN  PATCH 5 : checkLoginIframe:true not found (may already be false in this build)")
    _show_context(original, "checkLoginIframe")


# ── Patch 6: no-op the createLoginIframe / setupCheckLoginIframe function ─────
# Belt-and-suspenders: even if the flag slips through, make the iframe-creation
# function itself a no-op so no iframe is ever appended to the DOM.

P6_PATTERNS = [
    # Common minified patterns for the function body that appends the iframe
    re.compile(r'function\s+\w+\(\)\s*\{[^}]*login-status-iframe[^}]*\}'),
    re.compile(r'setupCheckLoginIframe\s*=\s*function[^;]+;'),
    re.compile(r'createLoginIframe\s*=\s*function[^;]+;'),
]
P6_MARKER = "/*kc-iframe-disabled*/"

if P6_MARKER in patched:
    print("PATCH 6 already present — skipping")
else:
    p6_applied = False
    for pat in P6_PATTERNS:
        m = pat.search(patched)
        if m:
            patched = patched[:m.start()] + P6_MARKER + "function(){};" + patched[m.end():]
            print("PATCH 6 applied : createLoginIframe no-op'd")
            _applied.append(6)
            p6_applied = True
            break
    if not p6_applied:
        print("INFO  PATCH 6 : createLoginIframe function not isolated (Patch 5 flag should suffice)")


# ── Write bundle if changed ───────────────────────────────────────────────────

print()
if patched != original:
    backup_path = bundle_path + ".orig"
    if not os.path.isfile(backup_path):
        with open(backup_path, "w", encoding="utf-8") as fh:
            fh.write(original)
        print(f"Backup saved  : {backup_path}")
    with open(bundle_path, "w", encoding="utf-8") as fh:
        fh.write(patched)
    print(f"bundle.js written — {len(_applied)} patch(es) applied.")
else:
    print("bundle.js unchanged — all patches were already present.")


# ── Fix: create missing bootstrap.min.css.map stub ───────────────────────────
# Streamlit's ComponentRequestHandler tries to serve every file referenced by
# a sourceMappingURL comment.  bootstrap.min.css ends with:
#   /*# sourceMappingURL=bootstrap.min.css.map */
# If the .map file is absent the server logs a FileNotFoundError on every load.

map_path = os.path.join(public_dir, "bootstrap.min.css.map")
STUB = '{"version":3,"sources":[],"names":[],"mappings":""}\n'

if not os.path.isfile(map_path):
    with open(map_path, "w", encoding="utf-8") as fh:
        fh.write(STUB)
    print(f"Created stub  : {map_path}")
else:
    print(f"Map file OK   : {map_path}")


# ── Summary ───────────────────────────────────────────────────────────────────

print()
if _warned:
    print(f"WARNING: {len(_warned)} patch(es) could not be applied: {_warned}")
    print("The bundle on this Python version may differ.")
    print("Share the output above with the developer to create updated patterns.")
else:
    print("All patches OK. Restart the Streamlit server for changes to take effect.")
