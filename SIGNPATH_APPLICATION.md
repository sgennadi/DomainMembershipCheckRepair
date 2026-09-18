# SignPath Foundation application worksheet

This file contains the public project information needed for the SignPath Foundation OSS application.

## Project

- Project name: DomainMembershipCheckRepair
- Repository: https://github.com/sgennadi/DomainMembershipCheckRepair
- Current release: https://github.com/sgennadi/DomainMembershipCheckRepair/releases/tag/v1.2.1
- License: MIT
- Privacy policy: https://github.com/sgennadi/DomainMembershipCheckRepair/blob/main/PRIVACY.md
- Maintainer / repository owner: sgennadi
- Platforms: Windows x86, x64, ARM64
- Build system: GitHub Actions on GitHub-hosted Windows runners
- Signing format: Microsoft Authenticode, SHA-256
- Proposed SignPath project slug: `DomainMembershipCheckRepair`
- Proposed signing policy slug: `release-signing`

## Project description

DomainMembershipCheckRepair is an open-source Windows GUI and CLI utility for diagnosing and repairing Active Directory domain membership. It can inspect domain membership and secure-channel state, perform native trust repair, join or rejoin a workstation to a domain, perform rename-and-join recovery, inspect an AD computer account, and optionally delete an exact conflicting AD computer object after explicit confirmation and safety checks.

The project contains no hard-coded organization, domain, domain-controller, OU, administrator, username, or password values.

## Release artifacts to sign

- `DomainMembershipCheckRepair-x86.exe`
- `DomainMembershipCheckRepair-x64.exe`
- `DomainMembershipCheckRepair-arm64.exe`

Only executables built by the tagged GitHub Actions release workflow from this repository are eligible for signing.

## Installation / uninstallation

The application is portable. It does not require installation and does not create an installed application entry. To remove it, delete the executable and any diagnostic files intentionally exported by the operator. The optional application log exists only when the operator explicitly enables file logging.

## Network and privacy statement

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

The application communicates with Active Directory/domain infrastructure only for actions explicitly initiated by the operator. It does not send telemetry or analytics to the project maintainer and does not persist entered domain passwords.

## System changes

Read-only diagnostics do not change the workstation or Active Directory.

Mutating operations are explicitly initiated by the operator. Destructive AD computer-object deletion requires explicit confirmation and verifies the exact object again immediately before deletion. Operations that require a reboot inform the operator.

## Team roles

- Committer / author: https://github.com/sgennadi
- Reviewer: https://github.com/sgennadi
- Signing approver: https://github.com/sgennadi

Every release signing request is intended to require manual approval.

## Repository signing policy

https://github.com/sgennadi/DomainMembershipCheckRepair/blob/main/SIGNING.md

The repository already contains:

- `.signpath/artifact-configuration.xml`
- `.signpath/pipeline-policy.yml`
- a GitHub Actions release workflow using the official SignPath GitHub action
- SHA-256 verification
- Authenticode verification
- GitHub build-provenance attestations
- immutable action SHAs
- Node.js 24-compatible GitHub Actions

## Items that require the maintainer / SignPath web UI

- Confirm GitHub MFA is enabled.
- Submit the application at https://signpath.org/apply.
- Accept the SignPath terms.
- Complete SignPath Foundation review/onboarding.
- Install/authorize the SignPath GitHub App.
- Create/link the SignPath organization/project/trusted build system/signing policy.
- Create the API token.
- Store `SIGNPATH_ORGANIZATION_ID` as a GitHub repository variable.
- Store `SIGNPATH_API_TOKEN` as a GitHub repository secret.

Do not commit the API token to this repository.
