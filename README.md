# DomainMembershipCheckRepair

Windows GUI + CLI utility for diagnosing and repairing a workstation's Active Directory domain membership.

The project is domain-neutral. It contains no hard-coded organization, domain, domain controller, OU, or administrator names.

## Current version

`1.4.0`

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
- NetSetup.log analyzer and Windows event timeline.
- DNS/DC Locator diagnostics and multi-DC consistency matrix.
- AD computer-account owner/pwdLastSet/SPN/child-object analysis.
- Ordered recovery plan with destructive deletion kept as a last resort.
- Advanced support bundle export.
- CyberArk/EPM local health discovery.
- Offline Domain Join apply/provision workflows.
- Safe post-reboot recovery resume without storing credentials.
- Unit tests, CodeQL, Dependabot, SHA-256 checksums and release build provenance.

## Architectures

GitHub Actions builds:

- `DomainMembershipCheckRepair-x86.exe` — .NET Framework 4.8
- `DomainMembershipCheckRepair-x64.exe` — .NET Framework 4.8
- `DomainMembershipCheckRepair-arm64.exe` — .NET Framework 4.8.1

ARM64 is intended for Windows 11 on Arm.

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
- DC Matrix
- Support Bundle
- CyberArk Health
- Offline Join
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
DomainMembershipCheckRepair.exe --cli --action diagnose
DomainMembershipCheckRepair.exe --cli --action export-diagnostics
DomainMembershipCheckRepair.exe --cli --action advanced
DomainMembershipCheckRepair.exe --cli --action netsetup
DomainMembershipCheckRepair.exe --cli --action dc-matrix
DomainMembershipCheckRepair.exe --cli --action recovery-plan
DomainMembershipCheckRepair.exe --cli --action support-bundle
DomainMembershipCheckRepair.exe --cli --action cyberark
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

Passwords are never accepted as a command-line argument. When credentials are needed, the CLI asks for the password interactively without echoing it.

### Dry-run

Dry-run is intended for operations that would modify Windows or domain state:

```text
DomainMembershipCheckRepair.exe --cli --action repair --dry-run
DomainMembershipCheckRepair.exe --cli --action join --domain example.com --dry-run
DomainMembershipCheckRepair.exe --cli --action rename --domain example.com --new-name PC-042 --dry-run
```

Dry-run does not repair trust, rename the computer, join the domain, delete an AD object, or restart Windows.

### JSON output

JSON is available for read-only/reporting actions:

```text
DomainMembershipCheckRepair.exe --cli --action diagnose --json
DomainMembershipCheckRepair.exe --cli --action status --json
DomainMembershipCheckRepair.exe --cli --action check --json
DomainMembershipCheckRepair.exe --cli --action detect --json
DomainMembershipCheckRepair.exe --cli --action ad-check --domain example.com --user EXAMPLE\admin --computer PC-042 --json
```

This makes the utility easier to consume from RMM, SCCM, PDQ, Intune scripts and other automation.

### Preferred DC

```text
DomainMembershipCheckRepair.exe --cli --action ad-check --domain example.com --dc dc01.example.com --user EXAMPLE\admin --computer PC-042
```

`--dc` affects LDAP lookup/deletion. It does not force the native Windows domain-join API to use that DC.

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

Version 1.4.0 adds a higher-level troubleshooting engine around the existing repair operations.

### NetSetup.log analyzer

The tool reads the recent part of `C:\Windows\Debug\NetSetup.log`, extracts relevant join/rejoin lines, remembers the most recent DC/error code, and maps common codes such as account-reuse hardening, Access Denied, RPC failures, bad credentials, no-such-domain, and no-logon-servers.

### Domain Controller Matrix

The tool discovers DCs through `_ldap._tcp.dc._msdcs.<domain>` SRV records and checks each discovered DC for:

- DNS/Kerberos/RPC/LDAP/SMB TCP reachability
- time-skew information
- LDAP RootDSE access
- optional computer-account comparison when valid domain credentials are already supplied

When the same computer account is present on some DCs but missing/different on others, the matrix flags likely AD replication inconsistency.

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

### Recovery Plan

Recovery Plan orders corrective actions so prerequisites are handled first: pending reboot, MII compatibility, DNS/DC Locator, time/Kerberos, Netlogon, replication, secure-channel repair, account reuse/ownership, Join/Rejoin, Rename+Join, and only then Delete+Recreate.

### Post-reboot resume

MII disable and Offline Domain Join can register a one-time HKLM RunOnce entry that launches the tool after reboot with only the target domain and resume action. No username or password is stored.

### Advanced Support Bundle

The bundle can include:

- advanced diagnostics report
- diagnostics JSON
- NetSetup.log analysis and original NetSetup.log
- Windows event timeline
- DNS diagnostics
- DC Matrix
- Recovery Plan
- CyberArk/EPM health
- `ipconfig /all`
- route table
- Windows Time status/source
- `nltest /dsgetdc`, `/dclist`, and `/sc_query`
- optional application log

Review the bundle before sharing because Windows logs and command output can contain environment-specific metadata.

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

If Join/Rejoin fails with an account reuse/name conflict, or Access Denied plus an LDAP lookup confirms the same computer account exists, the tool can:

1. delete the exact existing AD computer object and retry the same name;
2. use a new computer name;
3. cancel.

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

## Credentials and privacy

Accepted user formats:

```text
DOMAIN\username
username@example.com
```

A short username by itself is intentionally rejected.

The program does not save usernames or passwords to Registry/config files. The optional application log does not record the entered username or password.

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
```

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
- creates SHA-256 checksums
- uploads the build artifact

`codeql.yml` performs scheduled and push/PR C# analysis.

`release.yml`:

- verifies that the Git tag matches `VersionInfo.cs`
- runs tests
- builds all architectures
- generates `SHA256SUMS.txt`
- creates GitHub build-provenance attestations
- publishes the GitHub Release

Dependabot checks GitHub Actions updates weekly.

## Release process

Update `VersionInfo.cs` and `CHANGELOG.md`, merge the change, then tag the same version:

```text
git tag v1.4.0
git push origin v1.4.0
```

The release workflow will reject a mismatched tag.

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

Release `v1.1.0` predates SignPath Foundation onboarding and is unsigned. When `SIGNPATH_ENABLED=true` and the required repository variable/secret are configured, tagged releases use the SignPath pipeline automatically. If signing is not enabled, the release workflow clearly marks the binaries as unsigned.

## Privacy

See [PRIVACY.md](PRIVACY.md) for the full project privacy policy.

## License

MIT. See `LICENSE`.

## Security

See `SECURITY.md` for vulnerability reporting guidance.
