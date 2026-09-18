# Code signing policy

Free code signing is provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

## Project

- Repository: https://github.com/sgennadi/DomainMembershipCheckRepair
- License: MIT
- Signed artifacts: `DomainMembershipCheckRepair-x86.exe`, `DomainMembershipCheckRepair-x64.exe`, and `DomainMembershipCheckRepair-arm64.exe`
- Signing format: Microsoft Authenticode with SHA-256
- Source/build system: GitHub Actions on GitHub-hosted Windows runners

## Team roles

- Committer: [@sgennadi](https://github.com/sgennadi)
- Reviewer: [@sgennadi](https://github.com/sgennadi)
- Approver: [@sgennadi](https://github.com/sgennadi)

Changes proposed by contributors who do not have commit access must be reviewed before merge. Signing requests for releases require manual approval.

## Build and signing process

1. GitHub Actions checks out the tagged source revision.
2. The workflow builds x86, x64, and ARM64 from source on a GitHub-hosted Windows runner.
3. The three unsigned executables are uploaded as a GitHub Actions artifact.
4. The workflow submits that GitHub artifact to SignPath using the SignPath GitHub connector and origin verification.
5. A release signing request is manually approved in SignPath.
6. SignPath Authenticode-signs the three executables and returns the signed artifact.
7. The workflow verifies each Authenticode signature with `Get-AuthenticodeSignature`.
8. SHA-256 checksums are generated from the signed executables.
9. Only then are the executables and `SHA256SUMS.txt` published to the GitHub Release.

The SignPath artifact configuration is stored in `.signpath/artifact-configuration.xml`. The repository also contains `.signpath/pipeline-policy.yml`, which requires GitHub-hosted runners.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

DomainMembershipCheckRepair communicates with Active Directory/domain infrastructure only as part of actions explicitly initiated by the operator, such as domain discovery, trust checks, account lookup, repair, join/rejoin, rename/join, or deletion of a confirmed conflicting computer object.

The application does not transmit telemetry or analytics to the project maintainer and does not store entered domain passwords.

## System changes

Operations that modify the workstation or Active Directory are initiated explicitly by the operator. Destructive AD computer-object deletion requires explicit confirmation. Actions that require a reboot report that requirement to the operator.

## Historical releases

Release `v1.1.0` was published before SignPath Foundation onboarding and is unsigned. Future releases will use the SignPath pipeline after the Foundation application is approved and the required GitHub repository secret/variables are enabled.
