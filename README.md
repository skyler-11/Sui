# Sui

> A 14-day workforce schedule **validation and compliance engine** built with Streamlit.

[![Version](https://img.shields.io/badge/version-v1.10.0-F24713)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-≥3.10-blue)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/streamlit-1.55-FF4B4B)](https://streamlit.io/)
[![Auth](https://img.shields.io/badge/auth-Keycloak%20OIDC%20%2B%20PKCE-success)](https://www.keycloak.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

---

Sui ingests Excel/CSV staffing schedules, automatically detects the shift-matrix
pattern (6-1, 5-2, or 4-3), enforces **10 labour-compliance rules**, computes
overtime per matrix semantics, and produces a **3-sheet Excel compliance report** —
all behind Keycloak SSO with role-based access control.

## ✨ Features

| Category | Detail |
|----------|--------|
| **Schedule ingestion** | Drag-and-drop upload of `.xlsx`, `.xls`, and `.csv` with security-hardened parsing |
| **Matrix auto-detection** | Classifies each employee row as 6-1, 5-2, or 4-3 from shift codes alone |
| **10 compliance rules** | Enforced per-matrix — see [Validation Rules](#-validation-rules) |
| **Overtime computation** | Matrix-aware OT calculation (standard vs compressed shift semantics) |
| **3-sheet Excel export** | Gated on 100 % compliance — schedule, violations, and OT summary |
| **Keycloak SSO** | OIDC + PKCE (S256) with realm-role-based access control |
| **Role-based access** | Standard User · SuperAdmin |
| **Admin Console** | Configurable validation thresholds, audit-log viewer, in-app changelog (SuperAdmin) |
| **Audit trail** | Full logging of user actions with reverse-proxy-aware client IP resolution |
| **Idle-timeout watchdog** | Client-side modal + server-side backstop; preserves in-progress work on "continue" |
| **Session checkpoint** | Survives WebSocket resets — uploaded data persists across tab refreshes |

## 📏 Validation Rules

| # | Rule | Description |
|---|------|-------------|
| 1 | `max_day` | Maximum hours per day |
| 2 | `max_week` | Maximum hours per week |
| 3 | `max_rolling_7d` | Maximum hours in any rolling 7-day window |
| 4 | `min_week` | Minimum hours per week |
| 5 | `max_consecutive` | Maximum consecutive working days |
| 6 | `valid_codes` | Only approved shift codes allowed |
| 7 | `min_rd` | Minimum rest days per period |
| 8 | `broken_rd` | Rest-day fragmentation detection |
| 9 | `shift_gap` | Minimum gap between shifts |
| 10 | `holiday_pay` | Holiday compensation enforcement |

> The rule engine in `app/core/rules.py` is the compliance source of truth.
> Thresholds are configurable at runtime by SuperAdmins via the Admin Console.

## 🏗️ Tech Stack

| Layer | Technology |
|-------|------------|
| UI | [Streamlit](https://streamlit.io/) 1.55 · Python ≥ 3.10 |
| Auth | Keycloak OIDC + PKCE S256 ([`streamlit-keycloak`](https://pypi.org/project/streamlit-keycloak/)) |
| Data processing | pandas · openpyxl · xlrd |
| Export | openpyxl (3-sheet workbook) |
| Reverse proxy | IIS + ARR on Windows Server |
| Process model | Blue / green deployment slots (loopback only) |
| Testing | pytest |
| Linting | ruff |

## 📂 Project Structure

```
.
├── Main.py                     # Streamlit entrypoint
├── app/
│   ├── auth.py                 # Keycloak OIDC + PKCE session lifecycle
│   ├── ui.py                   # Reusable UI components & theme injection
│   ├── utils.py                # Parsing, validation orchestration, exports
│   └── core/
│       ├── rules.py            # 10 validation rules (compliance source of truth)
│       ├── config.py           # Shift codes, hours, matrix constants
│       ├── roles.py            # Realm role identifiers
│       ├── admin_defaults.py   # SuperAdmin-managed validation defaults
│       ├── checkpoint.py       # Per-user in-memory work-data checkpoint
│       ├── log_reader.py       # Secure log reader with redaction (CWE-22/200/400)
│       └── logging.py          # Structured app + audit logging with rotation
├── pages/                      # Streamlit multipage views
│   ├── admin_console.py        # SuperAdmin dashboard
│   ├── admin_validation_defaults.py
│   ├── admin_log_viewer.py
│   ├── admin_changelog.py
│   └── admin_app_changes.py
├── config/
│   └── admin_defaults.json     # Org-wide validation thresholds (no secrets)
├── assets/
│   └── style.css               # Design-system theme
├── resource/
│   └── manning_template.xlsx   # Schedule upload template
├── scripts/
│   └── patch_keycloak_bundle.py
├── .streamlit/
│   └── config.toml             # Streamlit server settings
├── web.config                  # IIS / ARR reverse proxy + security headers
├── setup_venv.bat              # Per-slot virtualenv bootstrap
├── deploy.bat                  # Mirror to IIS site folder
├── requirements.txt            # Pinned production dependencies
└── pyproject.toml              # Project metadata + dev tooling config
```

## 🚀 Getting Started

> Requires **Python ≥ 3.10**.

```bash
# 1  Create an isolated virtualenv
setup_venv.bat

# 2  Launch the app (binds to 127.0.0.1:4444, headless)
#    To bypass Keycloak SSO locally, set MANNING_ENV=development
#    inside your own copy of run_streamlit.bat.
run_streamlit.bat
```

### Environment Modes

The app behaviour is driven by a single `MANNING_ENV` variable:

| Mode | Server | XSRF | Keycloak SSO |
|------|--------|------|--------------|
| `production` | HTTPS (via IIS) | ✅ Enabled | ✅ Enforced |
| `test` | HTTP | ❌ Disabled | ✅ Enforced |
| `development` | HTTP (local) | ❌ Disabled | ⛔ Bypassed |

## 🔒 Security Highlights

- **OIDC + PKCE S256** — no client secret in the browser; authorization code
  flow with code verifier.
- **Rate-limited auth** — prevents brute-force / JWKS-exhaustion attacks.
- **XSRF protection** — enabled in production via Streamlit's built-in guard.
- **IIS security headers** — CSP, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, HSTS, `SameSite=Lax` cookie stamping.
- **Log redaction** — Bearer tokens, JWTs, passwords, API keys, and secrets
  are masked before any log line leaves the reader module.
- **Path traversal defence** — log viewer enforces an allow-set rooted at the
  log directory; symlinks, `..`, and absolute paths from callers are rejected.
- **Hardened file parsing** — uploaded files are validated for type, size, and
  structure before any data processing.

## 🚢 Deployment (IIS + Blue/Green)

The app runs as a loopback Streamlit process behind **IIS + ARR**, which
terminates TLS and applies security headers from `web.config`.

Two slots — **Blue (`4444`)** and **Green (`4445`)** — enable zero-downtime
cut-over:

1. Stand up the idle slot on the alternate port and smoke-test.
2. Flip the `web.config` ARR rewrite rule to the new port.
3. Mirror code to the IIS site folder:

   ```bash
   deploy.bat "D:\inetpub\manning"
   ```

## 🧪 Testing & Linting

```bash
# Lint
ruff check .

# Test
pytest
```

Dev dependencies (pytest, playwright, ruff) are installed via:

```bash
pip install -e ".[dev]"
```

## ⚙️ Configuration

| What | Where |
|------|-------|
| Streamlit server settings | `.streamlit/config.toml` (committed) |
| Streamlit secrets | `.streamlit/secrets.toml` (git-ignored) |
| Keycloak + runtime env vars | `run_streamlit.bat` (git-ignored) |
| Validation thresholds | `config/admin_defaults.json` (or Admin Console UI) |
| TLS certificate | `certs/` (git-ignored) |

> Secrets, certificates, internal URLs, and logs are **never** committed —
> see [`.gitignore`](.gitignore).

## 📝 Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for the full release history.
Current release: **v1.10.0**.

## 📄 License

MIT — see [LICENSE](LICENSE) for details.
