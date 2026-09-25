[CmdletBinding()]
param(
    [Parameter()]
    [string]$Subject = "CN=DomainMembershipCheckRepair Internal Code Signing",

    [Parameter()]
    [string]$FriendlyName = "DomainMembershipCheckRepair Internal Code Signing",

    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "internal-signing"),

    [Parameter()]
    [int]$ValidYears = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell session. It creates the certificate in LocalMachine\My."
}

if ($ValidYears -lt 1 -or $ValidYears -gt 10) {
    throw "ValidYears must be between 1 and 10."
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path $OutputDirectory).Path

Write-Host "Creating a self-signed Code Signing certificate..."
$certificate = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -FriendlyName $FriendlyName `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears($ValidYears)

$password = Read-Host "Enter a strong password for the exported PFX" -AsSecureString

$cerPath = Join-Path $OutputDirectory "InternalCodeSigning.cer"
$pfxPath = Join-Path $OutputDirectory "InternalCodeSigning.pfx"

Export-Certificate -Cert $certificate -FilePath $cerPath -Force | Out-Null
Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $password -CryptoAlgorithmOption AES256_SHA256 -Force | Out-Null

Write-Host ""
Write-Host "Certificate created:"
Write-Host "  Subject:    $($certificate.Subject)"
Write-Host "  Thumbprint: $($certificate.Thumbprint)"
Write-Host "  Expires:    $($certificate.NotAfter)"
Write-Host "  CER:        $cerPath"
Write-Host "  PFX:        $pfxPath"
Write-Host ""
Write-Warning "Keep the PFX and password private. Never commit them to source control."
Write-Warning "Deploy only the public certificate/CA trust to managed endpoints."
