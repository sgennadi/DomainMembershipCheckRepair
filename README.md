# Domain Membership Check & Repair

A Windows WinForms + CLI utility for diagnosing and repairing a workstation's Active Directory domain membership.

The project is domain-neutral: there are no hard-coded organization, domain, DC, OU, or administrator names.

## Main features

- Automatically detects the current/target domain when possible.
- Editable target domain for unjoined systems or domain changes.
- Checks the Netlogon secure channel.
- Attempts native secure-channel repair without PowerShell.
- Join/Rejoin with the current computer name.
- Rename + Join in one recovery workflow.
- Detects existing AD computer-account conflicts instead of assuming every join failure is a name conflict.
- Can delete the exact conflicting AD computer object and retry the same name after explicit destructive confirmation.
- Uses replication-aware retry/backoff after AD object deletion.
- Read-only **Check AD Account** lookup in both GUI and CLI.
- **Diagnostics** report in both GUI and CLI.
- Blocks Join/Rejoin when a computer rename is already pending and requires a reboot first.
- Optional application file logging; disabled by default and never remembered.
- Does not store entered domain usernames or passwords.
- No PowerShell dependency at runtime.

## Architectures

GitHub Actions builds three executables:

- `DomainMembershipCheckRepair-x86.exe` - .NET Framework 4.8
- `DomainMembershipCheckRepair-x64.exe` - .NET Framework 4.8
- `DomainMembershipCheckRepair-arm64.exe` - native managed ARM64 target, .NET Framework 4.8.1

ARM64 is intended for Windows 11 on Arm. The x86/x64 builds retain .NET Framework 4.8 compatibility.

## GUI

Run the executable without `--cli`.

The GUI provides:

- Detect Domain
- Check Trust
- Diagnostics
- Repair Trust
- Join / Rejoin Domain
- Check AD Account (read-only; lets you enter a computer name)
- Restart Windows

The **Write application log to file** checkbox is off by default and is not saved anywhere.

## CLI

Interactive mode:

```text
DomainMembershipCheckRepair.exe --cli
```

Menu:

```text
1. Show status / check trust
2. Repair trust
3. Join / rejoin domain with current computer name
4. Rename computer + join domain
5. Detect target domain
6. Check AD computer account (read-only)
7. Diagnostics
8. Restart Windows
0. Exit
```

### One-shot actions

```text
DomainMembershipCheckRepair.exe --cli --action status
DomainMembershipCheckRepair.exe --cli --action check
DomainMembershipCheckRepair.exe --cli --action repair
DomainMembershipCheckRepair.exe --cli --action join
DomainMembershipCheckRepair.exe --cli --action rename
DomainMembershipCheckRepair.exe --cli --action detect
DomainMembershipCheckRepair.exe --cli --action ad-check
DomainMembershipCheckRepair.exe --cli --action diagnose
```

Options:

```text
--domain example.com
--user DOMAIN\username
--user username@example.com
--new-name PC-NEW-NAME
--computer PC-NAME
--log
--no-log
--restart
--no-restart
```

`--computer` is used by `ad-check`; if omitted, the current computer name is checked.

The password is never accepted as a command-line argument. When needed, the CLI reads it interactively without echoing it.

Examples:

```text
DomainMembershipCheckRepair.exe --cli --action check --no-log
DomainMembershipCheckRepair.exe --cli --action diagnose --no-log
DomainMembershipCheckRepair.exe --cli --action ad-check --domain example.com --user EXAMPLE\administrator --computer PC-042
DomainMembershipCheckRepair.exe --cli --action join --domain example.com --user administrator@example.com --no-restart
DomainMembershipCheckRepair.exe --cli --action rename --domain example.com --user EXAMPLE\administrator --new-name PC-043
```

## Read-only AD account check

The AD check returns useful object information when available:

- Distinguished name
- DNS host name
- Enabled/disabled state
- Operating system
- Description
- Object GUID
- Created/changed timestamps

The check itself never modifies AD.

CLI exit codes specific to `ad-check`:

```text
0   Account found / query succeeded
10  Account not found
11  AD lookup failed
```

## Diagnostics

Diagnostics reports:

- Computer name
- Build/process/OS architecture
- CLR version
- Physical DNS suffix
- Pending computer rename
- Domain membership
- Secure-channel state
- Trusted DC, when returned by Netlogon
- Target-domain discovery
- Domain controller and forest
- Whether `C:\Windows\Debug\NetSetup.log` exists and when it was last modified

No credentials are required for the basic diagnostics action.

## Existing AD computer object handling

If Join/Rejoin fails with an error indicating account reuse/name conflict, or Access Denied plus an LDAP lookup confirms the same computer account exists, the tool offers:

1. Delete the exact existing AD computer object and retry the same name.
2. Use a new computer name.
3. Cancel.

Deletion is intentionally not a silent operation. GUI mode requires a confirmation dialog. CLI mode requires typing `DELETE` exactly. Immediately before deletion, the tool re-reads the LDAP object and verifies its object class, `sAMAccountName`, and object GUID so a stale lookup cannot silently delete a different object.

After deletion the tool waits and retries Join/Rejoin with increasing delays to reduce failures caused by AD replication latency.

### Deletion warning

Deleting a computer object is destructive. Data stored on or below that object may also be deleted, including environment-specific recovery data such as LAPS or BitLocker recovery child objects.

## Pending rename safety

If Windows already has a pending computer rename, Join/Rejoin is blocked until the machine is restarted. This avoids joining AD with a name that does not match the name that will become active after reboot.

## Domain detection

Automatic detection uses, in order where applicable:

1. Explicit `--domain` or GUI Target domain field.
2. Current Windows domain membership.
3. Physical DNS suffix, validated by DC discovery.
4. `USERDNSDOMAIN`, validated by DC discovery.
5. Domain portion of the entered credential when an operation requires credentials.

The final target domain remains editable in GUI mode.

## Credentials and privacy

Accepted user formats:

```text
DOMAIN\username
```

or:

```text
username@example.com
```

A short username by itself is intentionally rejected.

The program does **not** save usernames or passwords to Registry/config files. The optional application log does not record the entered username or password.

## Logging

Optional application log:

```text
C:\Windows\Logs\DomainMembershipRepair.log
```

File logging is disabled by default in both GUI and CLI.

Enable only for the current run:

```text
DomainMembershipCheckRepair.exe --log
DomainMembershipCheckRepair.exe --cli --log
```

Windows also maintains its own domain-join troubleshooting log:

```text
C:\Windows\Debug\NetSetup.log
```

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

## Requirements

- Windows 10/11 workstation for x86/x64 builds.
- .NET Framework 4.8 for x86/x64.
- Windows 11 on Arm with .NET Framework 4.8.1 for ARM64.
- Local administrator rights (requested by the application manifest).
- Network/DNS connectivity to the target domain.
- Appropriate AD permissions for Join/Rejoin, rename, or computer-object deletion.

## Local builds

### x86

```text
Build-x86.bat
```

Output:

```text
dist\x86\DomainMembershipCheckRepair-x86.exe
```

### x64

```text
Build-x64.bat
```

Output:

```text
dist\x64\DomainMembershipCheckRepair-x64.exe
```

### ARM64

```text
Build-arm64.bat
```

ARM64 local compilation requires Visual Studio 2022/Build Tools, MSBuild, the .NET desktop tooling, and the .NET Framework 4.8.1 targeting pack.

Output:

```text
dist\ARM64\DomainMembershipCheckRepair-arm64.exe
```

### All architectures

```text
Build-All.bat
```

## Code signing policy

Free code signing is provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

- Committer and reviewer: [@sgennadi](https://github.com/sgennadi)
- Approver: [@sgennadi](https://github.com/sgennadi)
- Release binaries are built only from this repository by GitHub Actions on GitHub-hosted runners.
- Every SignPath release signing request requires manual approval.
- The three release executables (x86, x64, ARM64) are signed together and SHA-256 checksums are generated only after signing.
- Full policy and verification details: [SIGNING.md](SIGNING.md)

Privacy statement: **This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.**

Release `v1.1.0` predates SignPath Foundation onboarding and is unsigned. Once the SignPath Foundation application is approved and the repository variables/secrets are enabled, future tagged releases are configured to use the signing pipeline automatically.

## License

DomainMembershipCheckRepair is released under the [MIT License](LICENSE).

## GitHub Actions

`.github/workflows/build.yml` automatically builds x86, x64, and ARM64 on push, pull request, or manual dispatch. It uploads all three executables plus `SHA256SUMS.txt` as one workflow artifact.

`.github/workflows/release.yml` performs the same three builds for a `v*` tag. Before SignPath onboarding is enabled it publishes the unsigned executables as before. After `SIGNPATH_ENABLED=true` is configured, it submits the GitHub-hosted build artifact to SignPath, waits for manual approval, validates the returned Authenticode signatures, generates checksums from the signed files, and then publishes the GitHub Release.

Example:

```text
git tag v1.1.0
git push origin v1.1.0
```
