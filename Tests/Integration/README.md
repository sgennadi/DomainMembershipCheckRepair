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
- history
- history-compare

Each action's JSON and stderr are retained as a workflow artifact for later comparison.
