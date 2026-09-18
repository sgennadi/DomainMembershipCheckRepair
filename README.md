# DomainMembershipCheckRepair

Windows GUI + CLI utility for diagnosing and repairing a workstation's Active Directory domain membership.

The project is domain-neutral. It contains no hard-coded organization, domain, domain controller, OU, or administrator names.

## Current version

`1.2.1`

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
- x86, x64 and ARM64 builds.
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
- About

The **Preferred DC** field is optional. It pins Active Directory LDAP lookup/deletion to that directory server. Windows still chooses the domain controller used by the native domain-join operation.

The bottom status footer shows color-coded **Domain**, **Trust**, **DC**, and **AD** state plus the current application version/architecture. **Copy Diagnostics** places the current human-readable diagnostic report on the clipboard without including the entered domain username or password.

The application uses the built-in Windows shield icon for the window and compiled EXE resource.

The **Write application log to file** checkbox is OFF by default and is not saved anywhere.

Application log path when enabled:

```text
C:\Windows\Logs\DomainMembershipRepair.log
```

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
DomainMembershipCheckRepair.exe --cli --action detect
DomainMembershipCheckRepair.exe --cli --action ad-check
DomainMembershipCheckRepair.exe --cli --action diagnose
DomainMembershipCheckRepair.exe --cli --action export-diagnostics
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
git tag v1.2.0
git push origin v1.2.0
```

The release workflow will reject a mismatched tag.

## Code signing policy

Free code signing is provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

- Committer and reviewer: [@sgennadi](https://github.com/sgennadi)
- Approver: [@sgennadi](https://github.com/sgennadi)
- Release binaries are built only from this repository by GitHub Actions on GitHub-hosted runners.
- Every SignPath release signing request requires manual approval.
- x86, x64 and ARM64 release executables are signed together.
- SHA-256 checksums are generated from the final release files after signing.
- The SignPath GitHub Action is pinned to an immutable Node.js 24-compatible commit.
- Full policy and verification details: [SIGNING.md](SIGNING.md)

Privacy statement: **This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.**

Release `v1.1.0` predates SignPath Foundation onboarding and is unsigned. When `SIGNPATH_ENABLED=true` and the required repository variable/secret are configured, tagged releases use the SignPath pipeline automatically. If signing is not enabled, the release workflow clearly marks the binaries as unsigned.

## License

MIT. See `LICENSE`.

## Security

See `SECURITY.md` for vulnerability reporting guidance.
