# Internal code signing fallback

This is an optional signing path for managed Windows endpoints while public SignPath Foundation onboarding is pending.

It does **not** replace public Authenticode trust for GitHub users. Internal certificates are trusted only on endpoints where the organization deploys the corresponding trust chain.

The repository does not use PowerShell helper scripts. Internal signing support is implemented in the native .NET Framework tools project under `Tools/`.

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

## Free fallback: local self-signed organizational certificate

Build the native repository tools first:

~~~text
msbuild Tools\DomainMembershipCheckRepair.Tools.csproj /m /t:Rebuild /p:Configuration=Release /p:Platform=AnyCPU
~~~

From an elevated command prompt, create a local Code Signing certificate:

~~~text
Tools\bin\Release\DomainMembershipCheckRepair.Tools.exe internal-cert
~~~

The helper uses the Windows `certreq.exe` API path to create a 3072-bit RSA/SHA-256 Code Signing certificate in `LocalMachine\My`. The private key is non-exportable. A public `InternalCodeSigning.cer` is written to the `internal-signing` directory for controlled trust deployment.

Optional parameters:

~~~text
--subject "CN=DomainMembershipCheckRepair Internal Code Signing"
--friendly-name "DomainMembershipCheckRepair Internal Code Signing"
--valid-years 2
--output C:\Secure\InternalSigning
~~~

Deploy only the public certificate/CA chain to managed endpoints. Never publish a private signing key.

## Sign a local release

Sign by certificate thumbprint from the LocalMachine certificate store:

~~~text
Tools\bin\Release\DomainMembershipCheckRepair.Tools.exe internal-sign --thumbprint THUMBPRINT --machine-store true --file DomainMembershipCheckRepair-x86.exe --file DomainMembershipCheckRepair-x64.exe --file DomainMembershipCheckRepair-arm64.exe
~~~

An existing PFX is also supported:

~~~text
Tools\bin\Release\DomainMembershipCheckRepair.Tools.exe internal-sign --pfx C:\Secure\CodeSigning.pfx --file DomainMembershipCheckRepair-x64.exe
~~~

When a PFX is used, the helper asks for the password without echoing it. The password is used only to import the certificate temporarily into the current user's certificate store; the password is **not** passed to `signtool.exe` on its command line. The temporary imported certificate is removed after signing.

Optional RFC3161 timestamping:

~~~text
--timestamp-url https://timestamp.example.invalid
~~~

Every file is verified with `signtool verify /pa /v` after signing.

## Trust deployment

Recommended Group Policy paths are under:

~~~text
Computer Configuration
  Policies
    Windows Settings
      Security Settings
        Public Key Policies
~~~

Deploy only the public certificate/CA chain. Never deploy signing private keys to workstations.

## Separation from public releases

The GitHub Release workflow remains **SignPath signing-required**. The internal workflow is intentionally local and does not weaken the public release policy.

Internal builds may be signed for managed endpoints while the public release remains blocked until SignPath Foundation is configured.
