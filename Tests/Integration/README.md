# Active Directory integration-test harness

This directory contains the live-domain integration harness for DomainMembershipCheckRepair.

The normal GitHub-hosted Build workflow remains deterministic and does not require Active Directory. The AD Integration Lab workflow is intentionally manual and runs only when the repository variable AD_LAB_ENABLED is set to true.

## Runner requirements

Use a disposable or dedicated Windows self-hosted GitHub Actions runner with the custom label:

~~~text
domain-lab
~~~

The runner must:

- be joined to the test Active Directory domain;
- run under a domain identity suitable for read-only diagnostics;
- have Visual Studio Build Tools/MSBuild and the .NET Framework 4.8 targeting pack;
- have normal network access to the test DCs;
- not store a domain password in the repository or workflow.

The harness deliberately uses the runner's Windows security context. It does not pass a password on the command line or through GitHub Actions secrets.

## Repository variables

Set:

~~~text
AD_LAB_ENABLED=true
AD_LAB_DOMAIN=example.com
AD_LAB_DC=dc01.example.com
AD_LAB_COMPUTER=LAB-PC01
~~~

AD_LAB_DC and AD_LAB_COMPUTER are optional. If the computer variable is empty, the runner's own computer name is used.

## Profiles

smoke verifies that each deep diagnostic action executes, returns valid JSON, uses an expected diagnostic exit code, and keeps the process exit code consistent with the JSON envelope.

healthy performs the same checks and additionally fails when a diagnostic action returns exit code 20 (finding detected).

The workflow is read-only. It does not invoke Repair Trust, Join/Rejoin, AD deletion, MII changes, Safe Fixes, Offline Domain Join, or Rollback Local.

## Actions exercised

- self-test
- dc-matrix
- ldap-compatibility
- rpc-endpoints
- kerberos-deep
- identity-consistency
- replication-timeline
- spn-collisions
- smb-kerberos
- ad-recycle-bin
- ad-deleted
- next-action
- advanced

Each action's JSON and stderr are retained as a workflow artifact for troubleshooting and validation.


## Disposable destructive AD lab

The separate `Disposable AD Destructive Lab` workflow is manual-only and is intended for a dedicated, disposable Windows runner with the custom label:

~~~text
domain-destructive-lab
~~~

It is gated by:

~~~text
AD_DESTRUCTIVE_LAB_ENABLED=true
~~~

Mutating scenarios additionally require the exact workflow confirmation text:

~~~text
DESTROY_DISPOSABLE_LAB
~~~

The runner must be domain joined, elevated, isolated from production, and dedicated to this repository. The `recycle-bin-restore` scenario additionally requires RSAT / the ActiveDirectory PowerShell module. Recommended repository configuration:

~~~text
AD_LAB_DOMAIN=example.com
AD_LAB_DC=dc01.example.com
AD_LAB_COMPUTER=LAB-PC01
AD_LAB_TEST_OU_DN=OU=DMCR-Lab,DC=example,DC=com
AD_LAB_USER=EXAMPLE\lab-admin
~~~

Store the password only as the repository secret `AD_LAB_PASSWORD`. The application receives that password through redirected standard input using `--password-stdin`; it is never placed on the command line or written to the workflow artifacts.

Available scenarios:

- `preflight` - read-only self-test and AD Recycle Bin readiness.
- `safe-fixes` - runs the real Safe Fixes workflow on the disposable runner.
- `repair-if-broken` - repairs the secure channel only when the runner is already in a broken-trust state, then verifies it.
- `mii-disable-rollback` - when MII is enabled, disables the local setting without reboot and immediately exercises Rollback Local.
- `recycle-bin-restore` - creates a uniquely named disposable computer object inside `AD_LAB_TEST_OU_DN`, deletes it, verifies deleted-object discovery, restores it through DomainMembershipCheckRepair, verifies the original ObjectGUID, and removes the restored lab object.

The recycle/restore scenario refuses to touch a pre-existing object with the generated lab name. It does not use the runner's own computer account.

## CyberArk EPM live lab

The `CyberArk EPM Integration Lab` workflow is also manual-only and uses a self-hosted Windows runner with:

~~~text
epm-lab
~~~

Enable it with:

~~~text
EPM_LAB_ENABLED=true
~~~

For the strongest validation, run the GitHub runner interactively under a standard-user token. The harness first runs the read-only CyberArk/EPM discovery action, then invokes the non-destructive `elevation-probe` action. The probe requests elevation through the normal Windows `runas` broker and succeeds only when the child process is actually elevated. This validates the same elevation path used by Repair, Join, Safe Fixes, Rollback Local, and other administrative actions without changing Windows or Active Directory.

## GUI / DPI smoke automation

The normal protected Build workflow now instantiates the real WinForms UI without live domain diagnostics and exercises synthetic layouts for:

- 1366x768 at 100% and 125%
- 1920x1080 at 150% and 175%
- 2560x1440 at 200%
- 3840x2160 at 250%

Both x86 and x64 builds run this test on GitHub-hosted Windows runners. A separate manual `ARM64 GUI Smoke Lab` workflow can execute the same test on a native self-hosted Windows ARM64 runner labeled `ui-lab` when `ARM64_UI_LAB_ENABLED=true`.
