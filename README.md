# DomainMembershipCheckRepair

Windows GUI + CLI utility for diagnosing and repairing a workstation's Active Directory domain membership.

The project is domain-neutral. It contains no hard-coded organization, domain, domain controller, OU, or administrator names.

## Current version

`1.6.0`

The release version has one source of truth: `VersionInfo.cs`. Assembly metadata and the UI read that value, and the release workflow refuses to publish a tag that does not match it.

## Main features

- Automatic target-domain detection with a manual override.
- Secure-channel / trust verification.
- Native secure-channel repair without PowerShell.
- Join/Rejoin with the current computer name.
- Rename + Join recovery workflow.
- Existing AD computer-account conflict detection.
- Explicit, safety-checked deletion of the exact conflicting AD computer object.
- Replication-aware Join/Rejoin retry after deletion.
- Read-only AD computer-account lookup.
- Optional preferred DC for LDAP lookup/deletion.
- Pending-rename safety guard.
- GUI and CLI diagnostics.
- Diagnostic ZIP export with text + JSON diagnostics and optional logs.
- CLI JSON output for automation.
- CLI dry-run for mutating operations.
- Optional application file logging, disabled by default and never remembered.
- No password command-line argument and no credential persistence.
- Least-privilege startup: read-only diagnostics run as a standard user and mutating recovery actions request elevation only when needed.
- Windows `runas` self-elevation is compatible with endpoint privilege brokers such as CyberArk EPM.
- x86, x64 and ARM64 builds.
- Per-Monitor V2 high-DPI UI with resizable/scroll-safe layouts for small displays and 100-200%+ scaling.
- AD Site/Subnet diagnostics.
- Protocol-level DNS/LDAP/LDAPS/Kerberos/RPC/SMB diagnostics.
- LDAP/Kerberos/Netlogon hardening analysis.
- Domain Join Permissions Analyzer and policy-source analysis.
- AD replication metadata diagnostics using `repadmin` when RSAT AD DS tools are available.
- SPN collision detection for HOST/RestrictedKrbHost/TERMSRV registrations.
- SMB/Kerberos authentication analysis with explicit CIFS ticket testing and NTLM/signing policy context.
- Kerberos Deep Analyzer for TGT/HOST/LDAP/CIFS tickets, encryption, flags, ticket lifetime, KDC binding and time-skew evidence.
- Real LDAP compatibility tests: signed SASL LDAP, LDAP StartTLS + Negotiate, authenticated LDAPS and TLS certificate/hostname validation. StartTLS exercises the Windows SSPI TLS-protected path used by CBT-capable LDAP clients without claiming that server-side CBT enforcement is proven from the client alone.
- Native RPC Endpoint Mapper enumeration with dynamic RPC TCP endpoint reachability tests plus known-interface mapping and functional probes for Netlogon, LSA Policy, SAMR and DRSUAPI.
- Parsed per-DC replication timeline for pwdLastSet, servicePrincipalName, dNSHostName and userAccountControl.
- Computer identity consistency search across sAMAccountName, dNSHostName and expected HOST/CIFS SPNs.
- Smart Next Safe Action that highlights one immediate non-destructive next step and can block destructive recovery when evidence is unsafe.
- Local transaction journal with allowlisted rollback for reversible MII/Netlogon changes.
- Active Directory Recycle Bin readiness/search/restore workflow with a mandatory pre-delete recovery metadata package.
- Per-user Advanced Diagnostics history with DC/Kerberos/SPN/replication/root-cause Compare Runs.
- Hybrid Microsoft Entra diagnostics.
- Automatic pre/post recovery snapshots and pre-change safety bundles.
- Destructive AD Delete Safety Gate with cross-DC/RODC/child-object/recent-change checks.
- Application Self Test for deployment validation.
- NetSetup.log analyzer and Windows event timeline, including operational Event Log channels.
- DNS/DC Locator, active-adapter, local FQDN, forward/reverse record and multi-NIC diagnostics.
- AD computer-account owner/pwdLastSet/SPN/child-object analysis.
- Ordered recovery plan with destructive deletion kept as a last resort.
- Advanced support bundle export.
- CyberArk/EPM local health discovery.
- Offline Domain Join apply/provision workflows.
- Safe post-reboot recovery resume without storing credentials.
- Unit tests, CodeQL, Dependabot, SHA-256 checksums and release build provenance.

## Architectures

GitHub Actions builds:

- `DomainMembershipCheckRepair-x86.exe` + `DomainMembershipCheckRepair-x86.exe.config` — .NET Framework 4.8
- `DomainMembershipCheckRepair-x64.exe` + `DomainMembershipCheckRepair-x64.exe.config` — .NET Framework 4.8
- `DomainMembershipCheckRepair-arm64.exe` + `DomainMembershipCheckRepair-arm64.exe.config` — .NET Framework 4.8.1

ARM64 is intended for Windows 11 on Arm.

**Keep the matching `.exe.config` file next to the EXE.** The config contains the WinForms `PerMonitorV2` and high-DPI auto-resizing settings. Renaming or distributing an EXE without the correspondingly renamed `.exe.config` falls back to less reliable DPI behavior.

## GUI

Run the executable without `--cli`.

The GUI provides:

- Detect Domain
- Check Trust
- Diagnostics
- Copy Diagnostics
- Export Diagnostics
- Repair Trust
- Join / Rejoin Domain
- Check AD Account
- Restart Windows
- Advanced Diagnostics
- Recovery Plan
- DC Matrix (site, writable/RODC, synchronization, ports, time and optional cross-DC account comparison)
- Support Bundle
- CyberArk Health
- Offline Join
- Safe Fixes
- Self Test
- Replication Metadata
- SPN Collisions
- SMB / Kerberos
- Kerberos Deep
- LDAP Compatibility
- RPC Endpoints
- Replication Timeline
- Identity Consistency
- AD Recovery
- Restore Deleted AD
- Next Safe Action
- History
- Compare Runs
- Transactions
- Rollback Local
- About

The **Preferred DC** field is optional. It pins Active Directory LDAP lookup/deletion to that directory server. Windows still chooses the domain controller used by the native domain-join operation.

The bottom status footer shows color-coded **Domain**, **Trust**, **DC**, and **AD** state plus the current application version/architecture. **Copy Diagnostics** places the current human-readable diagnostic report on the clipboard without including the entered domain username or password.

The application uses the built-in Windows shield icon for the window and compiled EXE resource.

The **Write application log to file** checkbox is OFF by default and is not saved anywhere.

Application log path when enabled:

```text
C:\Windows\Logs\DomainMembershipRepair.log
```

## Privilege and CyberArk EPM model

The executable starts with the Windows manifest level `asInvoker`; simply opening the GUI no longer requires an administrator token.

Read-only operations remain available to a standard user: Detect Domain, Check Trust/status, Diagnostics, Copy/Export Diagnostics, and Check AD Account.

Operations that change Windows or domain state request elevation only when selected: Repair Trust, Join/Rejoin Domain, Rename + Join recovery, conflict deletion/retry, and Restart Windows.

Elevation is requested through the standard Windows `runas` verb. This intentionally avoids a CyberArk-specific API: an installed CyberArk EPM agent can intercept and approve the normal Windows elevation request according to the organization's policy.

The domain password is never placed in the elevation command line and is never transferred from the standard process to the elevated process. In GUI mode, after elevation for Join/Rejoin, enter the password in the elevated window and click Join / Rejoin again. In CLI mode, the elevated child process prompts for the password interactively.

If elevation is cancelled, blocked, or returns without an administrator token, mutating actions stop safely while read-only functions remain available. CLI returns exit code `13`.

For an EPM application rule, prefer matching the trusted installed executable using multiple attributes, such as trusted path plus product/signature metadata, instead of granting elevation to every binary signed by a shared publisher.

## CLI

Interactive mode:

```text
DomainMembershipCheckRepair.exe --cli
```

One-shot actions:

```text
DomainMembershipCheckRepair.exe --cli --action status
DomainMembershipCheckRepair.exe --cli --action check
DomainMembershipCheckRepair.exe --cli --action repair
DomainMembershipCheckRepair.exe --cli --action join
DomainMembershipCheckRepair.exe --cli --action rename
DomainMembershipCheckRepair.exe --cli --action restart
DomainMembershipCheckRepair.exe --cli --action mii-disable
DomainMembershipCheckRepair.exe --cli --action detect
DomainMembershipCheckRepair.exe --cli --action ad-check
DomainMembershipCheckRepair.exe --cli --action ad-recycle-bin
DomainMembershipCheckRepair.exe --cli --action ad-deleted --computer PC-042
DomainMembershipCheckRepair.exe --cli --action ad-restore --computer PC-042
DomainMembershipCheckRepair.exe --cli --action diagnose
DomainMembershipCheckRepair.exe --cli --action export-diagnostics
DomainMembershipCheckRepair.exe --cli --action advanced
DomainMembershipCheckRepair.exe --cli --action netsetup
DomainMembershipCheckRepair.exe --cli --action dc-matrix
DomainMembershipCheckRepair.exe --cli --action site-subnet
DomainMembershipCheckRepair.exe --cli --action protocols
DomainMembershipCheckRepair.exe --cli --action hardening
DomainMembershipCheckRepair.exe --cli --action join-permissions
DomainMembershipCheckRepair.exe --cli --action hybrid-entra
DomainMembershipCheckRepair.exe --cli --action policy-source
DomainMembershipCheckRepair.exe --cli --action replication-metadata
DomainMembershipCheckRepair.exe --cli --action spn-collisions
DomainMembershipCheckRepair.exe --cli --action smb-kerberos
DomainMembershipCheckRepair.exe --cli --action kerberos-deep
DomainMembershipCheckRepair.exe --cli --action ldap-compatibility
DomainMembershipCheckRepair.exe --cli --action rpc-endpoints
DomainMembershipCheckRepair.exe --cli --action replication-timeline
DomainMembershipCheckRepair.exe --cli --action identity-consistency
DomainMembershipCheckRepair.exe --cli --action next-action
DomainMembershipCheckRepair.exe --cli --action history
DomainMembershipCheckRepair.exe --cli --action history-compare
DomainMembershipCheckRepair.exe --cli --action transactions
DomainMembershipCheckRepair.exe --cli --action rollback-local
DomainMembershipCheckRepair.exe --cli --action self-test
DomainMembershipCheckRepair.exe --cli --action recovery-plan
DomainMembershipCheckRepair.exe --cli --action support-bundle
DomainMembershipCheckRepair.exe --cli --action cyberark
DomainMembershipCheckRepair.exe --cli --action safe-fixes
DomainMembershipCheckRepair.exe --cli --action odj-apply --blob C:\Temp\odj.txt
DomainMembershipCheckRepair.exe --cli --action odj-provision --domain example.com --computer PC-042 --output C:\Temp\PC-042-odj.txt
```

Options:

```text
--domain example.com
--user DOMAIN\username
--user username@example.com
--new-name PC-NEW-NAME
--computer PC-NAME
--dc dc01.example.com
--json
--dry-run
--output C:\Temp\domain-diagnostics.zip
--blob C:\Temp\odj.txt
--reuse
--include-app-log
--log
--no-log
--restart
--no-restart
```

Passwords are never accepted as a command-line argument. When credentials are needed, the CLI asks for the password interactively without echoing it. In `--json` mode password prompts are written to stderr so stdout remains a single machine-readable JSON document.

### Dry-run

Dry-run is intended for operations that would modify Windows or domain state:

```text
DomainMembershipCheckRepair.exe --cli --action repair --dry-run
DomainMembershipCheckRepair.exe --cli --action join --domain example.com --dry-run
DomainMembershipCheckRepair.exe --cli --action rename --domain example.com --new-name PC-042 --dry-run
```

Dry-run does not repair trust, rename the computer, join the domain, delete an AD object, or restart Windows.

### JSON output

JSON is available for all read-only/reporting actions, including the enterprise analyzers:

```text
DomainMembershipCheckRepair.exe --cli --action diagnose --json
DomainMembershipCheckRepair.exe --cli --action advanced --json
DomainMembershipCheckRepair.exe --cli --action dc-matrix --json
DomainMembershipCheckRepair.exe --cli --action protocols --json
DomainMembershipCheckRepair.exe --cli --action hardening --json
DomainMembershipCheckRepair.exe --cli --action join-permissions --json
DomainMembershipCheckRepair.exe --cli --action replication-metadata --json
DomainMembershipCheckRepair.exe --cli --action spn-collisions --json
DomainMembershipCheckRepair.exe --cli --action smb-kerberos --json
DomainMembershipCheckRepair.exe --cli --action kerberos-deep --json
DomainMembershipCheckRepair.exe --cli --action ldap-compatibility --json
DomainMembershipCheckRepair.exe --cli --action rpc-endpoints --json
DomainMembershipCheckRepair.exe --cli --action replication-timeline --json
DomainMembershipCheckRepair.exe --cli --action identity-consistency --json
DomainMembershipCheckRepair.exe --cli --action next-action --json
DomainMembershipCheckRepair.exe --cli --action transactions --json
DomainMembershipCheckRepair.exe --cli --action recovery-plan --json
DomainMembershipCheckRepair.exe --cli --action self-test --json
DomainMembershipCheckRepair.exe --cli --action ad-check --domain example.com --user EXAMPLE\admin --computer PC-042 --json
```

The 1.6 enterprise actions use a common envelope containing `action`, `exitCode`, `exitMeaning` and `result`. This makes the utility easier to consume from RMM, SCCM, PDQ, Intune scripts and other automation. Mutating actions such as Repair, Join/Rejoin, MII disable, Safe Fixes, Rollback Local and Offline Domain Join intentionally reject `--json`.

### Preferred DC

```text
DomainMembershipCheckRepair.exe --cli --action ad-check --domain example.com --dc dc01.example.com --user EXAMPLE\admin --computer PC-042
```

`--dc` pins read-only LDAP, replication, SPN and SMB/Kerberos diagnostics to the selected DC when those diagnostics accept a DC target. It does not force the native Windows domain-join API to use that DC.

For read-only troubleshooting on a standalone/workgroup computer, `replication-metadata`, `spn-collisions`, and `smb-kerberos` can use `--dc` directly even when DC Locator cannot determine a domain. Advanced Diagnostics also falls back to the entered Preferred DC when automatic DC discovery is unavailable.

### Export diagnostics

```text
DomainMembershipCheckRepair.exe --cli --action export-diagnostics --output C:\Temp\domain-diagnostics.zip
```

The ZIP can contain:

- `diagnostics.txt`
- `diagnostics.json`
- `NetSetup.log`, when present
- `DomainMembershipRepair.log`, only when explicitly requested with `--include-app-log`
- a small README explaining the package

The diagnostic report intentionally does not contain the entered domain username or password. Windows and third-party logs can still contain environment-specific information, so review exported logs before sharing them.

## Root-cause diagnostics

The diagnostics view and exported report now check more than the secure channel itself.

It reports:

- Machine Identity Isolation from both the local LSA and policy registry paths
- Credential Guard and VBS state
- Windows version/build
- domain functional level when a DC is available
- Netlogon, Windows Time, and DNS Client service state
- DNS servers on active adapters
- DC time skew
- quick TCP checks to the discovered DC on 53, 88, 135, 389, and 445
- pending computer rename
- DC discovery and secure-channel state

The report also produces root-cause hints. These are diagnostic leads, not proof of a single cause. In particular, do not exclude:

- Machine Identity Isolation / Credential Guard interaction
- DNS/DC Locator problems or non-AD DNS servers
- client/DC clock skew and Kerberos failures
- Netlogon or Windows Time service problems
- firewall, VPN, routing, RPC, LDAP, SMB, or Kerberos reachability
- stale, disabled, duplicate, or wrong-OU computer objects
- machine-account password mismatch / broken secure-channel secret
- KB5020276 account-reuse hardening and insufficient ownership/permissions
- AD replication latency or inconsistent DC state
- pending computer rename / reboot requirement
- wrong credentials, UPN/NetBIOS mismatch, or insufficient join/delete rights
- GPO/Intune security policy reapplying a setting after local repair
- endpoint security/EDR/EPM products blocking process, registry, LSASS, Netlogon, LDAP, or RPC activity

### Machine Identity Isolation repair

When Repair Trust is selected and MII is detected in Enforcement mode, the GUI offers:

1. disable MII locally and restart;
2. keep MII enabled and continue repair;
3. cancel.

CLI:

```text
DomainMembershipCheckRepair.exe --cli --action mii-disable
```

The MII action uses the same on-demand elevation flow as other mutating operations. It changes only values that already exist locally. If Group Policy or Intune manages MII, change the central policy too; otherwise the setting can return after policy refresh.

## Advanced recovery and troubleshooting

Version 1.4.0 introduced the higher-level troubleshooting engine. Version 1.5.0 extended it with enterprise policy, protocol, permissions, site/subnet, Hybrid Entra and deployment self-test analysis. Version 1.6.0 adds deeper AD replication, SPN and SMB/Kerberos diagnostics plus explicit Preferred-DC handling for broken-trust and standalone troubleshooting.

### Enterprise diagnostics in 1.5.0

Advanced Diagnostics includes:

- client AD site, selected DC site and AD subnet matching;
- protocol-level DNS UDP, LDAP/LDAPS bind, Kerberos ticket, RPC and SMB checks;
- LDAP signing/channel binding, Netlogon/NTLM and Kerberos encryption policy;
- computer-account Kerberos encryption decoding;
- MachineAccountQuota and conservative join-permission ACL evidence;
- Microsoft Entra hybrid-join/device-auth state from `dsregcmd /status`;
- GPO/runtime/MDM policy-source evidence;
- application Self Test.

These 1.5 checks feed the prioritized root-cause engine and Recovery Plan rather than appearing only as raw diagnostic output. The Advanced GUI exposes Site/Subnet, Protocol Tests, Hardening, Join Permissions, Hybrid Entra and Policy Sources as individual reports.

### AD replication and Kerberos diagnostics in 1.6.0

Version 1.6.0 additionally includes:

- AD replication metadata from `repadmin /replsummary`, `/showobjmeta` and `/showattr` when RSAT AD DS tools are installed;
- LDAP/ADSI fallback for RootDSE and computer-object replication metadata when `repadmin.exe` is not installed;
- SPN collision checks for HOST, RestrictedKrbHost, TERMSRV and explicit CIFS registrations;
- per-DC SPN visibility/collision fingerprints in DC Matrix, with cross-DC SPN inconsistency detection;
- explicit CIFS Kerberos ticket acquisition compared with SMB access and local SMB NTLM/signing policy context;
- optional network-only credentials for Kerberos/SMB/RPC/repadmin checks using Windows `LOGON_NETCREDENTIALS_ONLY`, without putting passwords in command lines or logs;
- read-only AD lookup and join-permission analysis under the current Windows security context when explicit credentials are not supplied;
- Preferred DC precedence: a manually entered DC is used before an automatically discovered DC;
- standalone/workgroup execution of the replication, SPN and SMB/Kerberos CLI analyzers when `--dc` is supplied;
- replication Access Denied / 8453 classification as insufficient diagnostic permission instead of a false replication-health failure;
- structured JSON for all read-only/reporting CLI actions and dedicated diagnostic exit codes;
- background execution for Advanced GUI reports with live step status and cooperative Cancel support;
- Kerberos Deep Analyzer for the current TGT plus HOST/LDAP/CIFS service tickets, including encryption type, ticket flags, lifetime, KDC binding and reported time skew;
- real LDAP compatibility testing with signed SASL LDAP 389, LDAP StartTLS + Negotiate, LDAPS 636 authenticated bind, and an SslStream TLS handshake that validates both the certificate chain and DC hostname;
- native RPC Endpoint Mapper enumeration through Rpcrt4.dll followed by concrete dynamic TCP endpoint reachability checks and functional Netlogon/LSA/SAMR/DRSUAPI probes;
- parsed `msDS-ReplAttributeMetaData` timeline across reachable DCs for `pwdLastSet`, `servicePrincipalName`, `dNSHostName` and `userAccountControl`;
- computer identity consistency analysis for duplicate/stale `sAMAccountName`, `dNSHostName`, HOST and CIFS identity keys;
- Smart Next Safe Action that selects one immediate safe technical step and marks when destructive recovery should be deferred;
- expanded Self Test coverage for Kerberos TGT, LDAP StartTLS/LDAPS, RPC interface probes, AD replication metadata and transaction ACL security;
- grouped Advanced GUI sections for easier operation at high DPI and on smaller displays;
- a manual self-hosted AD Integration Lab workflow for live-domain smoke/healthy JSON validation without storing a domain password;
- local transaction journals under `%ProgramData%\DomainMembershipCheckRepair\Transactions` for reversible local recovery changes;
- explicit Rollback Local support restricted to an allowlist of Machine Identity Isolation DWORDs and the Netlogon service; domain join, rename, AD deletion, DNS flush and time resync are never automatically reversed;
- transaction folder ACL hardening for SYSTEM/Administrators with read access for Users, plus a second hard-coded rollback target allowlist to resist journal tampering;
- Active Directory Recycle Bin status detection through forest optional-feature state, read-only deleted-computer search, and guarded deleted-object restore;
- a mandatory pre-delete AD recovery package under `%ProgramData%\DomainMembershipCheckRepair\RecoveryPackages`; Delete + Recreate fails closed if the package cannot be created;
- deleted-object restore safety that requires Recycle Bin enabled, exactly one matching deleted object, a non-recycled/restorable state, the original parent to exist, and the original target DN to be free;
- per-user Advanced Diagnostics history under `%LocalAppData%\DomainMembershipCheckRepair\History`, keeping a compact credential-free history of DC Matrix, Kerberos, SPN, replication, root-cause and Next Safe Action state;
- History and Compare Runs reports that highlight tracked changes between the two latest records for the same computer;
- integration of deep Kerberos/LDAP/RPC/identity/replication findings into Root Cause analysis, Recovery Plan and the Advanced Support Bundle.

The Advanced GUI exposes the deep analyzers as individual reports. Actions are grouped into **Overview & Reports**, **Identity & Active Directory**, **Network & Protocols**, **Security & Hybrid**, and **Recovery & Operations**. Long-running read-only diagnostics run off the UI thread; Cancel interrupts cancellation-aware external commands immediately and stops other analyzers after the current Windows/LDAP API call returns.

### DPI and display scaling

The WinForms application is configured for `PerMonitorV2` DPI awareness on .NET Framework 4.8/4.8.1 with high-DPI automatic resizing enabled.

The main window and custom dialogs use responsive TableLayout/FlowLayout containers, wrapping action areas and scroll-safe layouts. A screen-aware sizing helper clamps windows to the current monitor working area after DPI changes, so high scaling does not force a form larger than the available desktop. The UI is intended to remain usable across common laptop/desktop resolutions and Windows display scaling including 100%, 125%, 150%, 175%, 200% and higher.

### Recovery snapshots and safety bundles

Mutating workflows capture compact BEFORE/AFTER state snapshots without storing domain passwords. Riskier operations also create a pre-change support bundle where possible.

The destructive AD Delete path has an additional safety gate. Deletion is blocked when identity/ownership cannot be verified, child objects exist, the object changed too recently, a writable/synchronized DC cannot be verified, the preferred DC is an RODC, or DC Matrix evidence indicates replication inconsistency.

### NetSetup.log analyzer

The tool reads the recent part of `C:\Windows\Debug\NetSetup.log`, extracts relevant join/rejoin lines, remembers the most recent DC/error code, and maps common codes such as account-reuse hardening, Access Denied, RPC failures, bad credentials, no-such-domain, and no-logon-servers.

### Domain Controller Matrix

The tool discovers DCs through `_ldap._tcp.dc._msdcs.<domain>` SRV records and checks each discovered DC for:

- DNS/Kerberos/RPC/LDAP/SMB TCP reachability
- time-skew information
- LDAP RootDSE access
- AD site
- writable vs RODC status when exposed by LDAP
- synchronization and Global Catalog readiness
- computer-account comparison using explicit credentials when supplied, otherwise the current Windows security context
- expected HOST/RestrictedKrbHost/TERMSRV/CIFS SPN visibility and collision state per DC

When the same computer account is present on some DCs but missing/different on others, or expected SPN visibility differs between DCs, the matrix flags likely AD replication inconsistency/stale state.

### Account Reuse Analyzer

Read-only AD account inspection now includes:

- object owner
- `pwdLastSet`
- `lastLogonTimestamp`
- object GUID
- canonical name
- userAccountControl
- supported Kerberos encryption types
- SPN list/count
- child-object count

These values are shown before destructive deletion so an existing object is not deleted merely because Join/Rejoin failed.

### Prioritized root-cause analysis and Recovery Plan

Advanced Diagnostics generates evidence-based prioritized root-cause findings. These are troubleshooting priorities, not probability estimates. Recovery Plan then orders corrective actions so prerequisites are handled first: pending reboot, MII compatibility, DNS/DC Locator, time/Kerberos, Netlogon, DC writability/replication, Safe Fixes, secure-channel repair, account reuse/ownership, Join/Rejoin, Rename+Join, and only then Delete+Recreate.

### Post-reboot resume

MII disable and Offline Domain Join can register a one-time RunOnce entry in the interactive user's loaded registry hive. This avoids depending on an administrator logging on after reboot. The command contains only the executable path, target domain and resume action; no username or password is stored.

### Advanced Support Bundle

The bundle can include:

- advanced diagnostics report
- structured advanced diagnostics JSON
- Kerberos Deep report
- LDAP Compatibility report
- RPC Endpoint Mapper report
- Replication Timeline report
- Identity Consistency report
- Next Safe Action report
- latest transaction journal when present
- latest diagnostic history record when present
- latest pre-delete AD recovery package when present
- diagnostics JSON
- NetSetup.log analysis and original NetSetup.log
- Windows event timeline
- DNS diagnostics
- DC Matrix
- AD Site/Subnet report
- protocol-level diagnostics
- LDAP/Kerberos/Netlogon hardening report
- Join Permissions report
- Hybrid Microsoft Entra report
- policy-source report
- AD replication metadata report
- SPN collision report
- SMB/Kerberos authentication report
- application self-test
- Recovery Plan
- CyberArk/EPM health
- `ipconfig /all`
- route table
- Windows Time status/source
- `nltest /dsgetdc`, `/dclist`, and `/sc_query`
- optional application log

Review the bundle before sharing because Windows logs and command output can contain environment-specific metadata.

### Machine-password consistency

Advanced Diagnostics compares the AD computer object's `pwdLastSet` with a recent local Netlogon event 5823 when both are available. The result is treated as a diagnostic clue, not proof of a password mismatch, because event retention and AD replication can differ between machines and DCs.

### Safe Fixes

Safe Fixes is a non-destructive elevated workflow that:

- flushes the Windows DNS resolver cache
- requests an immediate Windows Time resynchronization
- restarts the Netlogon service
- forces DC Locator rediscovery

It does not delete or modify the AD computer object, rename the workstation, or perform Join/Rejoin.

CLI:

```text
DomainMembershipCheckRepair.exe --cli --action safe-fixes
```

### Offline Domain Join

Apply an existing provisioning blob from the GUI or CLI:

```text
DomainMembershipCheckRepair.exe --cli --action odj-apply --blob C:\Temp\odj.txt
```

Provision a blob on a machine/account that has the required Active Directory permissions:

```text
DomainMembershipCheckRepair.exe --cli --action odj-provision --domain example.com --computer PC-042 --output C:\Temp\PC-042-odj.txt
```

Optional reuse of an existing computer account:

```text
--reuse
```

The tool calls the built-in Windows `djoin.exe`; it does not store domain credentials.

## Read-only AD account check

When an account exists, the utility can display:

- distinguished name
- DNS host name
- enabled/disabled state
- operating system
- description
- object GUID
- created/changed timestamps

The check itself never modifies AD.

## Existing AD computer object handling

If Join/Rejoin fails with an account reuse/name conflict, or Access Denied plus an LDAP lookup confirms the same computer account exists, the tool shows owner, pwdLastSet, GUID, SPN count and child-object count before recovery choices.

Recommended order:

1. run non-destructive Safe Fixes and retry the same name;
2. use a new computer name if safe reuse is not possible;
3. delete the exact existing AD computer object and retry the same name only as a last resort;
4. cancel.

Deletion is never silent.

GUI mode requires an explicit confirmation. CLI mode requires typing `DELETE` exactly.

Immediately before deletion, the shared AD service re-reads the LDAP object and verifies:

- object class is `computer`
- `sAMAccountName` still matches `COMPUTERNAME$`
- object GUID still matches the object found earlier

If any safety check fails, deletion is cancelled.

Deleting an AD computer object is destructive. Environment-specific child/recovery data can also be deleted, including LAPS or BitLocker recovery information.

## Pending rename safety

If Windows already has a pending computer rename, Join/Rejoin is blocked until the machine is restarted.

## Domain detection

Automatic detection uses, where applicable:

1. explicit `--domain` or the GUI Target domain field;
2. current Windows domain membership;
3. physical DNS suffix validated by DC discovery;
4. `USERDNSDOMAIN` validated by DC discovery;
5. domain portion of entered credentials when credentials are required.

### Transaction journal and Rollback Local

Local mutating recovery actions create a transaction journal when there is something useful to record. The journal is intended for **local configuration rollback**, not for reversing Active Directory history.

Currently reversible targets are deliberately restricted to:

- `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\MachineIdentityIsolation`;
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MachineIdentityIsolation`;
- the previous Running/Stopped state of the `Netlogon` service.

Other actions such as DNS cache flush, time resync, DC rediscovery, computer rename, domain join/rejoin and AD computer-object deletion may be recorded as audit notes but are **never automatically rolled back**.

GUI: use **Transactions** to inspect the latest journal and **Rollback Local** to restore the most recent journal that contains an allowlisted reversible change.

CLI:

```text
DomainMembershipCheckRepair.exe --cli --action transactions --json
DomainMembershipCheckRepair.exe --cli --action rollback-local
```

`rollback-local` requires administrator elevation. The transaction directory is ACL-hardened, and the elevated rollback path independently enforces a fixed allowlist so editing a journal cannot request an arbitrary registry or service change.

### AD Recycle Bin recovery and Diagnostic History

Before **Delete + Recreate** can delete an Active Directory computer object, the tool must successfully write a pre-delete recovery metadata package to:

```text
%ProgramData%\DomainMembershipCheckRepair\RecoveryPackages
```

The package contains identity/recovery metadata such as the original DN, object GUID, SAM name, DNS host name, owner, timestamps, SPNs, UAC and encryption flags. It never contains the entered domain password. If this package cannot be created, deletion is blocked.

**AD Recovery** is read-only. It reports forest Recycle Bin readiness, searches for a matching deleted computer object, shows the original parent/RDN and proposed restore DN, and displays the latest recovery-package path.

**Restore Deleted AD** is a mutating action. It requires administrator elevation, domain credentials, and explicit confirmation. The password is not transferred across elevation. Restore is allowed only when Recycle Bin is verified enabled, exactly one matching deleted object exists, the object is not already recycled, the original parent still exists, and the target DN is not occupied. If Recycle Bin is disabled, the pre-delete package remains useful for investigation/manual reconstruction, but the tool deliberately does not attempt incomplete tombstone reanimation.

CLI:

```text
DomainMembershipCheckRepair.exe --cli --action ad-recycle-bin --domain example.com --json
DomainMembershipCheckRepair.exe --cli --action ad-deleted --domain example.com --computer PC-042 --json
DomainMembershipCheckRepair.exe --cli --action ad-restore --domain example.com --computer PC-042
```

Advanced Diagnostics saves a compact record to:

```text
%LocalAppData%\DomainMembershipCheckRepair\History
```

The history record intentionally excludes credentials and raw command output. It tracks secure-channel state, computer GUID/pwdLastSet, DC Matrix state, Kerberos ticket state, SPN ownership, replication timeline, root causes and Next Safe Action. **Compare Runs** compares the newest record with the previous record for the same computer. The history store keeps the most recent 60 records.

CLI:

```text
DomainMembershipCheckRepair.exe --cli --action history --json
DomainMembershipCheckRepair.exe --cli --action history-compare --json
```

## Credentials and privacy

Accepted user formats:

```text
DOMAIN\username
username@example.com
```

A short username by itself is intentionally rejected.

The program does not save usernames or passwords to Registry/config files. The optional application log does not record the entered username or password. When explicit credentials are supplied for read-only Kerberos/SMB/RPC/repadmin tests, Windows starts the diagnostic command with `LOGON_NETCREDENTIALS_ONLY`: the password remains in process memory for the API call and is not included in the child command line.

## CLI exit codes

```text
0   Success / trust healthy
1   General operation failure
2   Trust is broken
3   Invalid argument or input
4   Computer is not a domain member
5   Trust repair failed
6   Domain join/rejoin failed
7   Operation cancelled
8   Rename/join failed
9   AD computer account deletion failed
10  AD computer account not found
11  AD lookup failed
12  Restart required because a rename is pending
13  Administrator elevation was cancelled, blocked, or ineffective
14  Deleted AD computer object restore failed

20  Diagnostic finding detected (read-only/reporting actions)
21  Diagnostic was not tested / required capability unavailable
22  Diagnostic access denied
23  Partial diagnostic result
```

Codes 20-23 are used by the new read-only/reporting analyzers so automation can distinguish a detected problem from an unavailable test or insufficient diagnostic permissions. Existing operational codes 0-13 remain unchanged for domain membership, repair, join and elevation workflows. Code 14 is reserved for a failed or unavailable deleted-object restore.

## Local builds

Run validation tests:

```text
Test.bat
```

Build one architecture:

```text
Build-x86.bat
Build-x64.bat
Build-arm64.bat
```

Run tests and build all architectures:

```text
Build-All.bat
```

ARM64 local compilation requires Visual Studio 2022/Build Tools, MSBuild, .NET desktop tooling, and the .NET Framework 4.8.1 targeting pack.

## GitHub Actions and supply-chain security

The repository uses Node.js 24-compatible GitHub Actions. Actions are pinned to immutable commit SHAs.

`build.yml`:

- runs unit tests
- builds x86, x64 and ARM64
- packages each EXE with its matching `.exe.config`
- creates SHA-256 checksums for executable and config files
- uploads the build artifact

`codeql.yml` performs scheduled and push/PR C# analysis.

`release.yml`:

- verifies that the Git tag matches `VersionInfo.cs`
- runs tests
- builds all architectures
- signs the EXE files through SignPath
- includes the matching DPI `.exe.config` files unchanged
- generates `SHA256SUMS.txt` for all final files
- creates GitHub build-provenance attestations
- publishes the GitHub Release

Dependabot checks GitHub Actions updates weekly.

`ad-integration.yml` is a manual, opt-in workflow for a dedicated self-hosted Windows runner in a test AD domain. It is gated by `AD_LAB_ENABLED=true`, uses the runner's domain security context rather than a stored password, executes the deep read-only CLI analyzers, validates their JSON envelopes/diagnostic exit codes, and uploads the resulting integration diagnostics. See [Tests/Integration/README.md](Tests/Integration/README.md).

## Release process

Update `VersionInfo.cs` and `CHANGELOG.md`, merge the change, then tag the same version:

```text
git tag v1.6.0
git push origin v1.6.0
```

The release workflow will reject a mismatched tag.

## Internal signing fallback

While SignPath Foundation onboarding is pending, managed organizational endpoints can use an internal AD CS or self-signed/GPO trust path without changing the public signed-only release policy. See [INTERNAL_SIGNING.md](INTERNAL_SIGNING.md).

## Code signing policy


Free code signing is provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

Future releases are configured as **signed-only**: the release workflow will not publish unsigned binaries. SignPath Foundation onboarding is the remaining external prerequisite. See [SIGNING.md](SIGNING.md) and the prepared [application worksheet](SIGNPATH_APPLICATION.md).

- Committer and reviewer: [@sgennadi](https://github.com/sgennadi)
- Approver: [@sgennadi](https://github.com/sgennadi)
- Release binaries are built only from this repository by GitHub Actions on GitHub-hosted runners.
- Every SignPath release signing request requires manual approval.
- x86, x64 and ARM64 release executables are signed together.
- SHA-256 checksums are generated from the final release files after signing.
- The SignPath GitHub Action is pinned to an immutable Node.js 24-compatible commit.
- Full policy and verification details: [SIGNING.md](SIGNING.md)

Privacy statement: **This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.** See the full [Privacy Policy](PRIVACY.md).

Release `v1.1.0` predates SignPath Foundation onboarding and is unsigned. New tagged releases are signing-required: `SIGNPATH_ORGANIZATION_ID` and `SIGNPATH_API_TOKEN` must be configured before the release workflow can publish binaries. The workflow intentionally fails rather than publishing an unsigned release.

## Privacy

See [PRIVACY.md](PRIVACY.md) for the full project privacy policy.

## License

MIT. See `LICENSE`.

## Security

See `SECURITY.md` for vulnerability reporting guidance.
