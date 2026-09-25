# Internal code signing fallback

This is an optional signing path for managed Windows endpoints while public SignPath Foundation onboarding is pending.

It does **not** replace public Authenticode trust for GitHub users. Internal certificates are trusted only on endpoints where the organization deploys the corresponding trust chain.

## Preferred option: Active Directory Certificate Services

If the organization has an Enterprise CA:

1. Create or duplicate a certificate template intended for **Code Signing**.
2. Limit enrollment to the release/build administrators or signing service account.
3. Prefer non-exportable private keys when PFX transport is not required.
4. Deploy the issuing CA chain through Group Policy.
5. Deploy publisher trust as required by the organization's application-control/EPM policy.
6. Sign only release binaries after tests succeed.
7. Verify every binary with `signtool verify /pa /v`.

For CyberArk EPM, prefer an application definition that combines publisher/signature information with product metadata and a protected install path. Do not grant elevation to every executable signed by a broad/shared publisher.

## Free fallback: self-signed organizational certificate

For managed endpoints only, `tools/New-InternalCodeSigningCertificate.ps1` can create a self-signed Code Signing certificate.

The public certificate/chain must then be deployed to managed endpoints through Group Policy or another device-management system. A self-signed certificate generally needs trust in:

- Trusted Root Certification Authorities
- Trusted Publishers

Do not publish the generated PFX or its password in GitHub, source control, release artifacts, tickets, logs, or chat.

Example:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\New-InternalCodeSigningCertificate.ps1
```

The script prompts securely for the PFX password.

## Sign a local release

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Sign-InternalRelease.ps1 -PfxPath C:\Secure\InternalCodeSigning.pfx -Files .\DomainMembershipCheckRepair-x86.exe,.\DomainMembershipCheckRepair-x64.exe,.\DomainMembershipCheckRepair-arm64.exe
```

The signing helper prompts securely for the PFX password. It can also sign by certificate thumbprint from the LocalMachine certificate store.

## Trust deployment

Recommended Group Policy paths are under:

```text
Computer Configuration
  Policies
    Windows Settings
      Security Settings
        Public Key Policies
```

Deploy only the public certificate/CA chain. Never deploy the private key/PFX to workstations.

## Separation from public releases

The GitHub Release workflow remains **SignPath signing-required**. The internal workflow is intentionally manual/offline and does not weaken the public release policy.

Internal builds may be signed for managed endpoints while the public release remains blocked until SignPath Foundation is configured.
