# Changelog

## 1.6.0

- Added AD replication metadata analyzer with `repadmin /replsummary`, `/showobjmeta` and `/showattr` support when RSAT AD DS tools are installed.
- Added SPN collision analyzer for HOST, RestrictedKrbHost, TERMSRV and explicit CIFS registrations.
- Added SMB/Kerberos analyzer with explicit CIFS ticket acquisition, SMB access testing and NTLM/signing policy context.
- Integrated replication/SPN/SMB analyzers into Advanced Diagnostics, Support Bundle, CLI and the Advanced GUI tab.
- Fed replication/SPN/SMB evidence into prioritized root-cause findings and the ordered Recovery Plan.
- Hardened replication diagnostics so `repadmin` Access Denied / 8453 is reported as insufficient diagnostic permission instead of a false HIGH replication-health failure.
- Prevented SMB/Kerberos fallback warnings when Kerberos was not actually tested.
- Added explicit Preferred-DC precedence so a manually selected DC wins over DC Locator discovery.
- Added standalone/workgroup support for replication/SPN/SMB CLI diagnostics with `--dc` even when domain discovery is unavailable.
- Targeted `repadmin /replsummary` at the selected Preferred DC instead of relying only on local domain context.
- Extended Self Test with DN-to-DNS conversion validation and optional `repadmin.exe` availability reporting.
- Added regression tests for replication access-denied classification, targeted replication summary arguments, CIFS SPN generation/deduplication, SMB/Kerberos mismatch classification and Preferred-DC selection precedence.
- Fixed Advanced GUI busy-state handling so all diagnostic buttons are disabled during an active operation.
- Added structured JSON output for all read-only/reporting CLI actions, with machine-readable action/result envelopes.
- Added normalized diagnostic exit codes: 20 finding detected, 21 not tested/capability unavailable, 22 diagnostic access denied and 23 partial result.
- Added network-only credential execution for Kerberos, SMB, RPC and repadmin diagnostics using Windows `LOGON_NETCREDENTIALS_ONLY`; entered passwords are never added to command lines or logs.
- Read-only AD computer-account and permission analysis now tries the current Windows security context when explicit credentials are not supplied.
- Added LDAP/ADSI replication metadata fallback so useful replication/object metadata remains available without RSAT/repadmin.
- Expanded DC Matrix with per-DC SPN visibility/collision state and cross-DC computer/SPN consistency detection.
- Moved Advanced GUI diagnostics to background execution with live step status and cooperative Cancel support, including cancellation-aware external command runners.
- Added `advanced-diagnostics.json` to Advanced Support Bundles and regression tests for JSON, diagnostic exit codes, net-only credential parsing and SPN state fingerprints.
- Advanced Support Bundles are now sanitized before ZIP packaging: detected secrets are removed and environment identifiers are replaced with per-bundle opaque tokens.
- Support Bundle sanitization is fail-closed per file, with a redaction summary and regression coverage for secrets, UPNs, domain accounts, IP/MAC addresses, SIDs, GUIDs and DNs.
- Standard Export Diagnostics now uses the same fail-closed redaction pipeline before ZIP creation, including copied NetSetup/application logs and a redaction summary.
- Removed computer names from default diagnostic ZIP and pre-change Safety Bundle filenames.
- Added an end-to-end ZIP regression test that reopens a generated archive and verifies that representative secrets and environment identifiers are absent.
- Updated release provenance attestation to `actions/attest-build-provenance` v4.2.2 and documented the recommended protected-`main` ruleset.
- Added protected-build WinForms GUI/DPI smoke automation for x86/x64 across 100-250% synthetic scaling profiles, plus a manual native ARM64 UI lab workflow.
- Added a non-destructive `elevation-probe` action and manual CyberArk EPM integration workflow to validate the real Windows `runas` broker path from a standard-user session.
- Hardened elevation semantics: recovery snapshots are now limited to actual recovery mutations, so `elevation-probe` and plain Restart no longer create persistent snapshot files.
- Hardened `--password-stdin` across privilege boundaries: administrative redirected-password automation must already be elevated instead of attempting to carry redirected stdin through Windows `runas`/CyberArk EPM.
- Added `--password-stdin` for controlled automation so lab credentials can be supplied through redirected standard input without placing passwords on command lines.
- Added a separately gated Disposable AD Destructive Lab with preflight, Safe Fixes, repair-if-broken, MII disable/rollback, and disposable Recycle Bin restore scenarios.
- Hardened the disposable Recycle Bin lab to require RSAT, resolve the created/restored computer strictly by exact sAMAccountName, and require exactly one match before GUID verification.
- Hardened `--password-stdin` so automation must supply `--user`, preventing redirected password input from being misinterpreted as an interactive username.
- Hardened signed release validation with timestamp, ProductVersion, PE architecture, signer-subject pinning support, x86/x64 GUI/DPI smoke execution, and SHA-256 self-verification before publication.
- Replaced repository/lab PowerShell helpers with a compiled C#/.NET Framework `Tools/` project and added a policy gate that rejects `.ps1` files entirely.
- Made GitHub Actions orchestration PowerShell-free: workflows use `cmd` plus compiled native tools, and CI rejects `shell: pwsh`, `shell: powershell`, or `powershell.exe` in workflow files.
- Moved release tag/version checks, unsigned staging, signed-PE validation, timestamp/version/architecture checks, final assembly, SHA-256 verification and release smoke tests into the compiled C# release orchestrator.
- Added protected-Build coverage for the native release prepare/finalize/smoke path so release orchestration is exercised before a SignPath-enabled tag is ever created.
- Added a tag-only release origin gate: the tagged SHA must already be contained in protected `main`, and the exact commit must have successful GitHub Actions `build` and `Analyze C#` checks before any SignPath request can be submitted.
- Hardened the release gate against same-SHA feature-branch noise: required checks are now correlated to eligible GitHub Actions `push` workflow runs on `main`, so branch-copy/scheduled checks cannot override a valid protected-main result.
- Repository policy now requires both `checks: read` and `actions: read` for release-origin validation and workflow-run correlation.
- Added CI policy enforcement and a synthetic parser self-test so manual release dispatch, missing origin validation, missing `checks: read`, or stale/failed duplicate required checks cannot silently weaken the release gate.
- Added repository policy validation for immutable remote GitHub Action SHAs, explicit workflow permissions, rejection of `pull_request_target`, `persist-credentials: false` on checkout, and protected-`main` restriction for self-hosted workflows.
- Rebuilt the Disposable AD Destructive Lab as a compiled C# harness so manual lab code is type-checked on every protected build instead of being skipped when lab runners are offline.
- Hardened self-hosted AD/EPM lab privacy: removed internal identity/domain details from public workflow logs, serialized live lab runs, made artifact upload opt-in, added fail-closed text redaction with per-run opaque HMAC identifiers, shortened optional artifact retention to 7 days, and clean raw evidence from runner workspaces after each run.
- Added a GitHub-hosted regression test that verifies representative lab passwords/tokens, host/domain identifiers, UPNs, IPs, SIDs, GUIDs, MACs, DNs and UNC paths do not survive artifact sanitization.
- Added Kerberos Deep Analyzer for TGT/HOST/LDAP/CIFS tickets, KDC bindings, ticket encryption, flags, lifetime and time-skew evidence.
- Added real LDAP compatibility tests for signed LDAP 389, LDAPS authenticated bind and TLS certificate/hostname validation.
- Added native RPC Endpoint Mapper enumeration and concrete dynamic RPC TCP reachability tests without requiring PortQry.
- Added parsed cross-DC replication timeline analysis for pwdLastSet, servicePrincipalName, dNSHostName and userAccountControl metadata versions.
- Added computer identity consistency analysis for duplicate/stale SAM, DNS host-name and HOST/CIFS SPN identity keys.
- Added Smart Next Safe Action and integrated the new deep evidence into Root Cause analysis and Recovery Plan.
- Added local transaction journals for Safe Fixes, MII and rename/join audit evidence plus explicit Rollback Local for reversible local changes.
- Hardened transaction rollback with protected ProgramData ACLs and a fixed allowlist limited to MII DWORDs and Netlogon service state.
- Added individual GUI/CLI actions and Support Bundle reports for Kerberos Deep, LDAP Compatibility, RPC Endpoints, Replication Timeline, Identity Consistency, Next Safe Action and Transactions.
- Added regression tests for Kerberos parsing, LDAP failure classification, RPC endpoint parsing, identity LDAP filters, GUI/CLI rollback elevation and transaction rollback allowlists.
- Added LDAP 389 StartTLS + Negotiate compatibility testing to exercise the TLS-protected Windows SSPI path used by CBT-capable LDAP clients.
- Added known RPC interface mapping plus functional Netlogon, LSA Policy, SAMR and DRSUAPI probes on top of Endpoint Mapper/dynamic-port testing.
- Expanded Self Test with Kerberos TGT, signed LDAP/StartTLS/LDAPS, RPC interface, replication-metadata and transaction-storage ACL checks.
- Reorganized the Advanced GUI into workflow groups while preserving DPI-aware sizing, scrolling and background cancellation.
- Added a manual self-hosted AD Integration Lab GitHub Actions workflow for live-domain read-only smoke/healthy validation without storing domain credentials; the harness now runs through the compiled C#/.NET Framework `Tools/` project.
- Added regression tests for the known Netlogon/LSA/SAMR/DRSUAPI interface UUID mappings.
- Added Active Directory Recycle Bin readiness detection and read-only deleted-computer-object discovery.
- Added a fail-closed pre-delete AD recovery metadata package under ProgramData; Delete + Recreate is blocked if the package cannot be written.
- Added guarded deleted-object restore with elevation, explicit confirmation, Recycle Bin enforcement, unambiguous-match checks, original-parent validation and target-DN conflict protection.
- Added GUI actions for AD Recovery and Restore Deleted AD plus CLI actions `ad-recycle-bin`, `ad-deleted` and `ad-restore`.
- Expanded the live AD Integration Lab with read-only Recycle Bin/deleted-object readiness checks.
- Added regression tests for Recycle Bin feature GUID, deleted-object LDAP filters, restore-DN construction/escaping and AD restore elevation/resume behavior.
- Hardened mandatory pre-delete AD recovery-package storage so ACL application and verification are fail-closed; destructive deletion cannot proceed when broad-user write access remains or storage security cannot be inspected.
- Added regression coverage for recovery-package ACL policy, including Builtin Users, Authenticated Users, Everyone, Administrators and deny-rule handling.
- Centralized protected-storage ACL classification for recovery packages and transaction journals; write detection now uses primitive write/delete/ACL-change rights so broad read-only grants are accepted while Modify/FullControl remain blocked through their write-capable bits.
- Fixed transaction-journal security validation so the intended Builtin Users read-only ACL no longer creates a false untrusted-storage result that can block Rollback Local.
- Hardened final destructive AD deletion against TOCTOU/subtree races: the exact computer GUID/class/sAMAccountName and leaf state are revalidated immediately before deletion, and deletion is now non-recursive so Active Directory rejects a newly non-leaf object instead of recursively deleting its subtree.
- Added regression coverage for final AD delete identity/leaf validation, including changed GUID, changed sAMAccountName, wrong object class and newly appeared child objects.

- Hardened post-reboot resume target selection so `RunOnce` registration requires a positively identified interactive-user SID and never falls back to the current/elevated process identity after runas/CyberArk elevation.
- Added regression coverage proving that an absent interactive SID fails closed even when a current elevated-process SID is available.

- Hardened Active Directory Recycle Bin/recovery LDAP sessions with explicit Negotiate signing and sealing on port 389.
- Hardened deleted-object restore against TOCTOU/state races by requiring an immutable object GUID and re-reading the exact deleted object immediately before restore; sAMAccountName, GUID, deleted/recycled state, lastKnownParent and last-known RDN must still match.
- Added regression coverage for final AD restore identity/state validation, including changed GUID/SAM, recycled/restored state and changed restore location.

- Hardened transaction-journal creation so ProgramData ACL application and verification are fail-closed instead of best-effort; recovery mutations do not proceed with a newly created untrusted rollback journal.
- Made transaction-journal updates atomic with same-directory temporary files plus replace/move semantics, preserving the previous complete JSON if an update is interrupted before replacement.
- Added regression coverage for initial and replacement atomic journal writes and temporary-file cleanup.
- Hardened protected ProgramData storage against NTFS reparse-point/junction/symlink redirection: every existing directory component is verified before ACL hardening and before trust is accepted.
- Applied the reparse-point guard to both transaction journals and mandatory pre-delete AD recovery packages, failing closed if protected storage resolves through a reparse point.
- Added regression coverage for reparse-point attribute classification.
- Updated account-reuse diagnostics to the current KB5020276 model: `0xAAC` guidance now points to computer-object ownership, the DC-side `ComputerAccountReuseAllowList` trusted-owner policy, and authenticated SAMRPC access, and explicitly avoids the removed `NetJoinLegacyAccountReuse` workaround.
- Expanded Windows event timeline classification for Netjoin 4100/4101 and Directory-Services-SAM 16995-16998 account-reuse/allow-list events plus SAM_DOMAIN_JOIN_POLICY evidence.
- Clarified that `ComputerAccountReuseAllowList` registry evidence is DC-side; absence of the local value on a member workstation does not prove target DCs are unconfigured.
- Added regression coverage for modern domain-join account-reuse event classification and guidance.
- Hardened Build workflow concurrency to include the exact commit SHA, so a newer push on the same branch cannot cancel the required `build` check attached to an older commit that another PR or release gate may still need.
- Repository policy now enforces SHA-scoped Build concurrency while retaining duplicate-run cancellation for the same ref/SHA.
- Added explicit NetSetup.log detection for the documented `SAM_DOMAIN_JOIN_POLICY_LEVEL_V2` / `c0000022` / `NetStatus:0x5` failure pattern, identifying authenticated SAMRPC validation denied by the target DC.
- Added focused remediation guidance for the DC `RestrictRemoteSam` policy (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictRemoteSam`) and promoted this evidence to a dedicated high-priority Domain-join SAMRPC root-cause category.
- Added regression coverage that distinguishes SAMRPC domain-join policy denial from unrelated access-denied text.
- Moved recovery snapshots out of Windows Logs/%TEMP% fallback into protected `%ProgramData%\DomainMembershipCheckRepair\Snapshots` storage with ACL and reparse-point verification.
- Made the BEFORE recovery snapshot a required atomic write before guarded mutation proceeds; AFTER/comparison writes remain best-effort so they cannot mask a mutation that already completed.
- Removed the computer name from recovery snapshot filenames and added Self Test coverage for snapshot-storage trust.
- Added explicit CLI/GUI fail-closed handling for required BEFORE snapshot creation so storage failures block the operation with a clear error instead of surfacing as an unhandled exception.
- Aligned GUI `Restore Deleted AD` and `Rollback Local` with CLI recovery semantics by requiring the same protected BEFORE/AFTER snapshot scope around those mutations.
- Made mandatory pre-delete AD recovery-package JSON writes atomic with same-directory temporary files plus replace/move semantics, and re-verify protected storage trust immediately before persistence.
- Added regression coverage for initial/replacement AD recovery-package atomic writes and temporary-file cleanup.

## 1.5.0

- Added Per-Monitor V2 DPI configuration and high-DPI automatic WinForms resizing.
- Reworked the main GUI into responsive Basic/Advanced tabs with scroll-safe, resizable layout for small displays and 100-200%+ DPI scaling.
- Reworked all custom dialogs to use DPI scaling, TableLayout/FlowLayout, minimum sizes and resizable report/conflict views instead of fixed pixel coordinates.
- Added screen-aware sizing that clamps top-level windows to the active monitor working area and re-evaluates layout after per-monitor DPI changes.
- Updated GitHub artifacts, signed release packaging, local builds and checksums so every architecture ships with the matching `.exe.config` required for PerMonitorV2 DPI behavior.
- Added AD Site/Subnet diagnostics using client site detection, DC site data and AD Sites and Services subnet matching.
- Added protocol-level checks for DNS UDP SRV queries, LDAP/LDAPS authenticated bind, Kerberos ticket requests, RPC service-control reachability and SMB.
- Fixed remote RPC/SMB command targeting to use proper UNC server syntax and added regression tests.
- Added LDAP signing/channel-binding, Netlogon/NTLM and Kerberos encryption hardening diagnostics.
- Added decoding of computer-account Kerberos encryption flags and warnings for DES/RC4-only configurations.
- Added Domain Join Permissions Analyzer for MachineAccountQuota, operator SID/token groups, OU/computer ACL evidence, ownership and account-reuse rights.
- Added Hybrid Microsoft Entra diagnostics from dsregcmd /status.
- Added Policy Source Analyzer for GPO/runtime/MDM evidence around MII, Credential Guard, LDAP, Kerberos and Netlogon settings.
- Added application Self Test in GUI and CLI.
- Added automatic BEFORE/AFTER recovery snapshots for mutating workflows without storing passwords.
- Added pre-change support bundles before MII disable, Offline Domain Join, Rename+Join and Delete+Recreate.
- Added a destructive AD Delete Safety Gate that blocks deletion when GUID/owner verification is missing, child objects exist, the object changed too recently, RODC/writable-DC validation fails, or cross-DC replication state is inconsistent.
- Extended prioritized root-cause analysis and Recovery Plan with site/subnet, protocol, hardening, permissions, policy-source and Hybrid Entra evidence.
- Added CLI actions: site-subnet, protocols, hardening, join-permissions, hybrid-entra, policy-source and self-test.
- Added individual Advanced GUI actions for Site/Subnet, Protocol Tests, Hardening, Join Permissions, Hybrid Entra and Policy Sources.
- Added optional internal code-signing documentation and helper scripts for AD CS or managed-endpoint self-signed trust while SignPath onboarding is pending.
- Public GitHub releases remain SignPath signing-required; internal signing does not weaken that release policy.
- Modernized local Test/Build BAT scripts to use the current MSBuild project instead of an obsolete partial-source CSC build.

## 1.4.0

- Added prioritized evidence-based root-cause findings to Advanced Diagnostics and Support Bundle.
- Hardened all external command execution with bounded timeouts and asynchronous stdout/stderr draining.
- Improved post-reboot resume to target the interactive user's RunOnce hive instead of relying on an administrator logon.
- Upgraded operational Event Log collection to EventLogReader for Device Guard, Kerberos and DNS channels.
- Expanded DC Matrix with AD site, writable/RODC state, synchronization and Global Catalog readiness.
- Expanded DNS diagnostics with active adapter details, DNS suffixes, gateways, local FQDN forward/reverse consistency, stale/duplicate record hints and multi-NIC/VPN hints.
- Added Safe Fixes + Retry Same Name as the preferred non-destructive computer-account conflict recovery option.
- Conflict recovery now displays owner, pwdLastSet, GUID, SPN count and child-object count before destructive choices.
- Recovery Plan numbering is now dynamic and includes Safe Fixes and DC writability/replication checks.
- Added a 120-second timeout to Offline Domain Join execution.


- Added NetSetup.log analysis with common domain-join error classification.
- Added recent Windows event timeline collection for Netlogon, Kerberos, LSA, DNS, Time Service, and Device Guard-related failures.
- Added DNS/DC Locator diagnostics for LDAP and Kerberos SRV records.
- Added Domain Controller Matrix with per-DC TCP reachability, LDAP RootDSE, time-skew checks, and optional cross-DC computer-account comparison.
- Expanded AD computer-account analysis with owner, pwdLastSet, lastLogonTimestamp, canonical name, SPNs, child-object count, UAC, and supported encryption types.
- Added ordered Recovery Plan generation that keeps destructive account deletion as a last resort.
- Added Advanced Diagnostics and Advanced Support Bundle export.
- Added CyberArk/EPM local health discovery and current Standard/Elevated state reporting.
- Added Offline Domain Join blob apply and provisioning support through djoin.exe.
- Hardened Offline Domain Join command construction with canonical Windows argv quoting, computer-name/domain validation, and regression coverage for option-injection/trailing-backslash edge cases.
- Security-hardening: standardized dynamic external-tool invocation through the shared canonical Windows argv builder for `nltest`, `klist`, `repadmin`, `w32tm`, `sc`, `net`, and `djoin`; removed remaining ad-hoc quoting from network-credential and replication paths and added regression coverage for multi-token/DN arguments.
- Hardened post-reboot `RunOnce` resume registration to use the same canonical Windows argv builder, reject unsafe domain tokens and relative/untrusted executable paths, and avoid ad-hoc command-line quoting.
- Post-reboot resume now fails closed when an interactive user's RunOnce hive is known but cannot be written, instead of silently redirecting registration to the elevated/current account.
- Added safe post-reboot recovery resume without storing usernames or passwords.
- MII disable and Offline Domain Join now register a post-reboot validation flow.
- Added GUI actions for Advanced Diagnostics, Recovery Plan, DC Matrix, Support Bundle, CyberArk Health, and Offline Join.
- Added CLI actions: advanced, netsetup, dc-matrix, recovery-plan, support-bundle, cyberark, odj-apply, and odj-provision.
- Added machine-password consistency analysis using AD pwdLastSet and recent local Netlogon event 5823 when available.
- Added non-destructive Safe Fixes: DNS cache flush, Windows Time resync, Netlogon restart, and forced DC rediscovery.
- Added regression tests for ODJ/Safe Fixes elevation, post-reboot resume parsing, and NetSetup error mapping.

## 1.3.1

- Added Machine Identity Isolation diagnostics from both LSA and policy registry locations.
- Added Credential Guard/VBS state detection.
- Added domain functional level detection through RootDSE and compatibility warning for MII enforcement below Windows Server 2025 functional level.
- Added Netlogon, Windows Time, and DNS Client service checks.
- Added active-interface DNS server reporting.
- Added DC clock-skew diagnostics and warnings at five minutes or more.
- Added quick TCP reachability checks for DNS 53, Kerberos 88, RPC endpoint mapper 135, LDAP 389, and SMB 445.
- Added root-cause hints for DC discovery failure, MII, time skew, service failures, network/firewall issues, pending rename, machine-password mismatch, AD computer-account state, account-reuse hardening, replication, and permissions.
- Added GUI MII Enforcement preflight before trust repair with an explicit Disable MII / continue / cancel choice.
- Added CLI `--action mii-disable`, protected by the same on-demand elevation/CyberArk EPM flow.
- MII changes are local-only and warn when Group Policy or Intune may reapply the setting.

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
