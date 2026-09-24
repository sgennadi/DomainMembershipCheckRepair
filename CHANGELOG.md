# Changelog

## 1.3.0

- Changed the application manifest from always-admin to least-privilege `asInvoker` startup.
- Added on-demand self-elevation through the standard Windows `runas` broker so CyberArk EPM can approve the executable without making the user a permanent local administrator.
- GUI diagnostics, trust checks, domain detection, AD account lookup, and diagnostic export remain available to standard users.
- Repair Trust, Join/Rejoin, rename/join recovery, destructive conflict recovery, and Restart request administrator elevation only when needed.
- Added safe GUI resume after elevation while deliberately never transferring the domain password between processes.
- Added CLI self-elevation for mutating actions and a one-shot `--action restart`.
- Added elevation loop protection and exit code 13 when elevation is cancelled, blocked, or returns without an administrator token.
- Added Standard/Elevated privilege status to the GUI footer, About dialog, and CLI header.
- Added Windows shield indicators to GUI buttons that require elevation.

## 1.2.1

- Added a compact color-coded GUI status footer for Domain, Trust, DC, and AD computer-account state.
- Added a main-window **Copy Diagnostics** action for quick clipboard troubleshooting.
- Added architecture/version/process information to the GUI footer and expanded the About dialog.
- Added a Windows shield application/window icon generated from the built-in Windows system icon during compilation.
- Preserved optional file logging as OFF by default and kept the read-only AD account check behavior unchanged.

## 1.2.0

- Added shared Core services for validation, diagnostics, and Active Directory computer-account operations.
- Added CLI `--dry-run` for mutating repair/join/rename/restart workflows.
- Added CLI `--json` for read-only and reporting actions.
- Added optional `--dc` preferred directory server for LDAP lookup/deletion.
- Added CLI and GUI diagnostic ZIP export.
- Added diagnostics JSON alongside the human-readable report.
- Added unit tests for computer-name validation, domain-user formats, domain hints, LDAP escaping, suggested names, and DC normalization.
- Added MIT license and security policy.
- Added Dependabot for GitHub Actions.
- Added CodeQL workflow.
- Pinned GitHub Actions to immutable commit SHAs.
- Standardized GitHub Actions on Node.js 24.
- Added release build provenance attestations.
- Integrated the existing SignPath release-signing pipeline, pinned its Node.js 24 action, and preserved unsigned fallback behavior until onboarding is enabled.
- Centralized the application version in `VersionInfo.cs`; release tags are validated against it.
- Added GUI Preferred DC field, Export Diagnostics button, and About dialog.
- File logging remains disabled by default and is never persisted.

## 1.1.0

- Added x64 build target.
- Added ARM64 build target using .NET Framework 4.8.1.
- Added multi-architecture GitHub Actions build and release workflows.
- Added read-only AD computer-account check in GUI and CLI.
- Added CLI `--action ad-check` and `--computer`.
- Added GUI/CLI diagnostics report.
- Added architecture/runtime information to diagnostics.
- Added AD account metadata display (DN, DNS host name, enabled state, OS, description, GUID, timestamps).
- Added pending-rename safety guard before Join/Rejoin.
- Added retry/backoff after destructive AD computer-object deletion to allow replication time.
- Added copyable GUI report dialog.
- Added assembly version metadata and high-DPI manifest settings.
- File logging remains disabled by default and is not persisted.
