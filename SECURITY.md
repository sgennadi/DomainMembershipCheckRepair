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

DomainMembershipCheckRepair intentionally does not persist entered domain usernames or passwords. Passwords are not accepted as CLI arguments. File logging is disabled by default. Arguments passed to Windows helper executables are constructed with a shared Windows argv-compatible builder. Dynamic arguments for `nltest`, `klist`, `repadmin`, `w32tm`, `sc`, `net`, and `djoin` are passed as individual tokens before canonical quoting; Offline Domain Join and Safe Recovery additionally reject unsafe domain tokens before an external process is started. Post-reboot `RunOnce` registration uses the same canonical argument builder, validates the optional domain token, requires an absolute executable path, and fails closed unless an interactive-user SID is positively identified. It never falls back to the current/elevated process identity when interactive-user detection or hive access fails.

## Destructive AD operations

Deleting an Active Directory computer object is destructive and always requires explicit confirmation. The program re-reads the object and verifies its class, sAMAccountName, object GUID, and leaf/child-object state immediately before deletion. The final LDAP delete is deliberately non-recursive; if a child object appears after the safety check, Active Directory must reject the delete rather than recursively removing the subtree. The mandatory pre-delete recovery metadata package is written only after its ProgramData storage ACL is hardened and re-verified; if broad users retain write-capable access or ACL verification fails, package creation fails and destructive deletion remains blocked.
Recovery-package and transaction-journal trust checks share one write-capability policy based on primitive write, delete, and ACL/ownership-change rights; broad read-only access is not treated as writable.

Active Directory Recycle Bin queries and restore operations use LDAP 389 with Windows Negotiate plus explicit signing and sealing. Immediately before restore, the exact deleted object is re-read and its sAMAccountName, object GUID, deleted/recycled state, lastKnownParent and msDS-LastKnownRDN are revalidated; restore fails closed if that identity or restore location changed.


## Validation infrastructure

The protected `main` branch requires Build and CodeQL. Build runs unit tests, x86/x64 GUI/DPI smoke tests, all three architecture builds, compiles the native C# repository/lab tools, runs a lab-artifact redaction regression test, and enforces repository supply-chain policy. The release pipeline is tag-only and additionally verifies that the tagged commit is already contained in protected `main` and that the exact SHA has successful `build` and `Analyze C#` checks from protected-`main` push workflow runs before any SignPath request is submitted. Feature-branch or scheduled runs on the same SHA are not eligible. The policy rejects `.ps1` files entirely and rejects PowerShell shells/`powershell.exe` in GitHub Actions workflow orchestration. All remote GitHub Actions are pinned to immutable 40-character commit SHAs, checkout credentials are not persisted after source retrieval, and workflows declare explicit top-level token permissions.

Manual live-domain workflows are intentionally separated from normal CI:

- the read-only AD Integration Lab performs live diagnostic validation;
- the Disposable AD Destructive Lab is disabled by default and requires a dedicated self-hosted lab runner plus an explicit confirmation gate;
- the CyberArk EPM Integration Lab validates the standard-user-to-elevated broker path using a non-destructive elevation probe.

Self-hosted live-lab evidence remains on the runner by default. Optional GitHub artifact upload requires `LAB_UPLOAD_SANITIZED_ARTIFACTS=true`; only the fail-closed sanitized copy is uploaded, with a 7-day retention period. Raw and sanitized working directories are removed from the runner after each workflow.

Do not point destructive lab workflows at production Active Directory.
