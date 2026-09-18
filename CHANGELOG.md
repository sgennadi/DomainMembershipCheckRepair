# Changelog

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
