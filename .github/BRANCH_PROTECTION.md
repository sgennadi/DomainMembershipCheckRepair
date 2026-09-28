# Recommended protection for `main`

DomainMembershipCheckRepair uses GitHub Actions for deterministic builds, CodeQL analysis, provenance attestations, and SignPath release signing. The default branch should be protected before signed releases are enabled.

The connected GitHub application used by ChatGPT does not have repository-administration write permission, so this ruleset must be enabled once in the GitHub web UI by a repository administrator.

## GitHub ruleset

Open:

`Settings -> Rules -> Rulesets -> New ruleset -> New branch ruleset`

Use:

- Ruleset name: `Protect main`
- Enforcement status: `Active`
- Target branches: include default branch / `main`
- Bypass list: leave empty unless an emergency administrator bypass is intentionally required

Enable these rules:

- Restrict deletions
- Block force pushes
- Require a pull request before merging
- Require conversation resolution before merging
- Require status checks to pass
- Require branches to be up to date before merging

Required status checks:

- `build`
- `Analyze C#`

For this single-maintainer repository, do not require another approving reviewer unless a second independent maintainer is added; GitHub does not allow an author to approve their own pull request. PR-only merging still preserves reviewable history and ensures required CI checks run before changes enter `main`.

Do not allow direct pushes to `main` after the ruleset is active.

## Release tags

The release workflow validates that a tag such as `v1.6.0` exactly matches `VersionInfo.ProductVersion`. Public release binaries are signing-required and the workflow fails before publication if SignPath configuration is missing.

Do not create a release tag until:

1. `main` Build is green.
2. `main` CodeQL is green.
3. SignPath Foundation onboarding is complete.
4. `SIGNPATH_ORGANIZATION_ID` is configured as a repository variable.
5. `SIGNPATH_API_TOKEN` is configured as a repository secret.
6. The SignPath project, trusted build system, artifact configuration, and `release-signing` policy are active.
