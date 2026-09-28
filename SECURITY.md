# Security Policy

## Supported versions

The maintained development line is `1.6.x`. Until the signed `v1.6.0` release is published, the latest public release remains `v1.2.1`; historical `v1.1.x`/`v1.2.x` binaries were published before SignPath onboarding and should be treated as legacy unsigned builds. Security fixes are applied to the current maintained line and then shipped in the next signed release.

## Reporting a vulnerability

Please use GitHub's private security advisory feature for this repository rather than opening a public issue with exploit details.

When reporting a problem, include:

- the affected release and architecture;
- Windows version;
- the operation involved (trust repair, join/rejoin, AD lookup, rename, or deletion);
- steps to reproduce;
- whether the issue could expose credentials, delete the wrong AD object, or modify domain membership unexpectedly.

Do not include real passwords, recovery keys, or other secrets in a report.

## Credential handling

DomainMembershipCheckRepair intentionally does not persist entered domain usernames or passwords. Passwords are not accepted as CLI arguments. File logging is disabled by default.

## Destructive AD operations

Deleting an Active Directory computer object is destructive and always requires explicit confirmation. The program re-reads the object and verifies its class, sAMAccountName, and object GUID immediately before deletion.


## Validation infrastructure

The protected `main` branch requires Build and CodeQL. Build runs unit tests, x86/x64 GUI/DPI smoke tests, all three architecture builds, compiles the native C# repository/lab tools, runs a lab-artifact redaction regression test, and enforces repository supply-chain policy. The release pipeline is tag-only and additionally verifies that the tagged commit is already contained in protected `main` and that the exact SHA has successful `build` and `Analyze C#` checks from protected-`main` push workflow runs before any SignPath request is submitted. Feature-branch or scheduled runs on the same SHA are not eligible. The policy rejects `.ps1` files entirely and rejects PowerShell shells/`powershell.exe` in GitHub Actions workflow orchestration. All remote GitHub Actions are pinned to immutable 40-character commit SHAs, checkout credentials are not persisted after source retrieval, and workflows declare explicit top-level token permissions.

Manual live-domain workflows are intentionally separated from normal CI:

- the read-only AD Integration Lab performs live diagnostic validation;
- the Disposable AD Destructive Lab is disabled by default and requires a dedicated self-hosted lab runner plus an explicit confirmation gate;
- the CyberArk EPM Integration Lab validates the standard-user-to-elevated broker path using a non-destructive elevation probe.

Self-hosted live-lab evidence remains on the runner by default. Optional GitHub artifact upload requires `LAB_UPLOAD_SANITIZED_ARTIFACTS=true`; only the fail-closed sanitized copy is uploaded, with a 7-day retention period. Raw and sanitized working directories are removed from the runner after each workflow.

Do not point destructive lab workflows at production Active Directory.
