# Changelog

All notable changes to the Manning Simulator are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow semantic-ish versioning per release tag. The
top entry should match `_APP_VERSION` in `Main.py`.

## [v1.10.0] - 2026-06-08
### Changed
- Refreshed the light theme toward a warmer, Clay-inspired visual direction:
  cream-tinted canvas and surfaces, larger corner radii (new `--radius-xl`),
  softer warm-toned shadows, and a rounded **Baloo 2** display typeface at lighter
  weight with tighter letter-spacing. AUMOVIO orange branding, all severity colours,
  and the dark theme are unchanged.

## [v1.9.2] - 2026-06-02
### Removed
- Orphaned PDF export code path (`generate_pdf_export`) and the `reportlab`
  dependency. The product ships the 3-sheet Excel export only.

## [v1.9.1] - 2026-06-01
### Fixed
- Vulnerability fixes and security hardening.
- Removed the empty placeholder box above the page title (idle-watchdog
  component is now fully collapsed).
### Added
- In-app **Changelog** tab in the Admin Console (superadmin-only).

## [v1.9.0]
### Added
- Week reference labels feature trial (display-only labels and reference dates
  for the two-week schedule view).

## [v1.8.1]
### Fixed
- Session-handling fix for authenticated reruns.

## [v1.8.0]
### Changed
- Stabilized end-to-end working system across upload, validation, and export.

## [v1.7.x]
### Added
- Keycloak (KCL) integration and OIDC session lifecycle.
### Fixed
- Compliance progress text and related KC fixes/enhancements.

## [v1.6.x]
### Fixed
- Log Viewer pagination and filtering bugs.
- OIDC issuer treated as identity (not endpoint) — fixes login `InvalidIssuerError`.

## [v1.5.0-RC]
### Added
- Role-Based Access Control (RBAC).
- Admin Log Viewer.
### Fixed
- CWE and CVE remediations.
