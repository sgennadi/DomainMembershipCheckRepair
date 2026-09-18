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
8. SHA-256 checksums are generated from the final executables.
9. GitHub build-provenance attestations are generated for the final release executables.
10. Only then are the executables and `SHA256SUMS.txt` published to the GitHub Release.

The SignPath artifact configuration is stored in `.signpath/artifact-configuration.xml`. The repository also contains `.signpath/pipeline-policy.yml`, which requires GitHub-hosted runners. GitHub Actions used by the release workflow are pinned to immutable commits and use Node.js 24-compatible runtimes.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

DomainMembershipCheckRepair communicates with Active Directory/domain infrastructure only as part of actions explicitly initiated by the operator, such as domain discovery, trust checks, account lookup, repair, join/rejoin, rename/join, or deletion of a confirmed conflicting computer object.

The application does not transmit telemetry or analytics to the project maintainer and does not store entered domain passwords.

## System changes

Operations that modify the workstation or Active Directory are initiated explicitly by the operator. Destructive AD computer-object deletion requires explicit confirmation. Actions that require a reboot report that requirement to the operator.

## Signing status

The repository is now **fail-closed for releases**: the release workflow requires SignPath configuration, requires a successful SignPath signing request, verifies every returned Authenticode signature, and only then publishes release binaries. There is no unsigned fallback in the release workflow.

The external SignPath Foundation onboarding is still required before the first signed release can be produced. Until that approval and repository configuration are completed, the release workflow will fail before publishing assets.

Historical releases `v1.1.0`, `v1.2.0`, and `v1.2.1` were published before SignPath Foundation onboarding and are unsigned.

## One-time SignPath onboarding

1. Apply for the free OSS subscription at https://signpath.org/apply.
2. Enable multi-factor authentication for both GitHub and SignPath.
3. After approval, install/authorize the SignPath GitHub App for this repository.
4. In SignPath, create/link the project with slug `DomainMembershipCheckRepair`.
5. Configure the repository's `.signpath/artifact-configuration.xml` as the artifact configuration (or reproduce it exactly in SignPath and make it the project default).
6. Create a signing policy with slug `release-signing`, require origin verification, and require manual approval.
7. Link the SignPath `GitHub.com` trusted build system to the project.
8. Create a SignPath API token for a user allowed to submit signing requests.
9. Add GitHub repository variable `SIGNPATH_ORGANIZATION_ID`.
10. Add GitHub repository secret `SIGNPATH_API_TOKEN`.

After those one-time steps, create the next version tag. The release workflow will submit the three EXEs to SignPath, wait for manual approval, verify `Get-AuthenticodeSignature` returns `Valid`, regenerate SHA-256 checksums from the signed binaries, create provenance attestations, and publish the release.
