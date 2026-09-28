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

1. A `v*` tag starts the release workflow; there is no manual release-dispatch path.
2. The workflow checks out the tagged source revision and validates that the tag exactly matches `VersionInfo.cs`.
3. The compiled release validator confirms that the tagged SHA is already contained in protected `main`.
4. The validator queries GitHub Actions workflow runs and accepts required checks only when they belong to `push` runs whose `head_branch` is `main` and whose `head_sha` is the tagged commit. Feature-branch/scheduled runs on the same SHA are ignored.
5. The exact tagged SHA must have successful `build` and `Analyze C#` checks from those eligible protected-main runs.
6. The workflow builds x86, x64, and ARM64 from source on a GitHub-hosted Windows runner.
7. The three unsigned executables are uploaded as a GitHub Actions artifact.
8. The workflow submits that artifact to SignPath using the SignPath GitHub connector and origin verification.
9. A release signing request is manually approved in SignPath.
10. SignPath Authenticode-signs the three executables and returns the signed artifact.
11. The compiled C# release validator invokes Windows SDK `signtool verify /pa /v`, requires trusted-timestamp evidence, reads the signer certificate, and validates ProductVersion plus PE architecture.
12. SHA-256 checksums are generated and re-verified, x86/x64 GUI/DPI smoke tests run on the final files, and GitHub build-provenance attestations are generated.
13. Only then are the executables and `SHA256SUMS.txt` published to the GitHub Release.

The SignPath artifact configuration is stored in `.signpath/artifact-configuration.xml`. The repository also contains `.signpath/pipeline-policy.yml`, which requires GitHub-hosted runners. GitHub Actions used by the release workflow are pinned to immutable commits and use Node.js 24-compatible runtimes. Release orchestration itself uses `cmd` plus the compiled C#/.NET Framework `Tools/` executable; repository policy rejects PowerShell workflow shells.

## Privacy policy

The full project privacy policy is published at:

https://github.com/sgennadi/DomainMembershipCheckRepair/blob/main/PRIVACY.md

In summary, the application does not transmit telemetry or analytics to the project maintainer, does not persist entered domain passwords, and communicates with Active Directory/domain infrastructure only for operations explicitly initiated by the operator.

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

After those one-time steps, create the next version tag. The release workflow will submit the three EXEs to SignPath, wait for manual approval, validate the returned signatures with the compiled C# release orchestrator and Windows SDK `signtool`, regenerate and re-verify SHA-256 checksums, run final x86/x64 GUI/DPI smoke tests, create provenance attestations, and publish the release.
