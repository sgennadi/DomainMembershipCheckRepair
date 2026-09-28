param()

$ErrorActionPreference = "Stop"

$root = Join-Path ([System.IO.Path]::GetTempPath()) ("dmcr-lab-redaction-" + [Guid]::NewGuid().ToString("N"))
$input = Join-Path $root "raw"
$output = Join-Path $root "sanitized"

New-Item -ItemType Directory -Force -Path $input | Out-Null

$oldValues = @{}
$names = @(
    "AD_LAB_DOMAIN",
    "AD_LAB_DC",
    "AD_LAB_COMPUTER",
    "AD_LAB_TEST_OU_DN",
    "AD_LAB_USER",
    "AD_LAB_PASSWORD"
)

foreach ($name in $names) {
    $oldValues[$name] = [Environment]::GetEnvironmentVariable($name)
}

try {
    [Environment]::SetEnvironmentVariable("AD_LAB_DOMAIN", "example.test")
    [Environment]::SetEnvironmentVariable("AD_LAB_DC", "dc01.example.test")
    [Environment]::SetEnvironmentVariable("AD_LAB_COMPUTER", "LAB-PC01")
    [Environment]::SetEnvironmentVariable("AD_LAB_TEST_OU_DN", "OU=DMCR-Lab,DC=example,DC=test")
    [Environment]::SetEnvironmentVariable("AD_LAB_USER", "EXAMPLE\lab-admin")
    [Environment]::SetEnvironmentVariable("AD_LAB_PASSWORD", "SuperSecret-123!")

    @"
Computer=LAB-PC01
Domain=example.test
DC=dc01.example.test
User=EXAMPLE\lab-admin
UPN=admin@example.test
IPv4=10.20.30.40
IPv6=2001:db8::1234
SID=S-1-5-21-111111111-222222222-333333333-1001
GUID=12345678-1234-1234-1234-123456789abc
MAC=00-11-22-33-44-55
DN=CN=LAB-PC01,OU=DMCR-Lab,DC=example,DC=test
Share=\\dc01.example.test\share
password=SuperSecret-123!
Authorization: Bearer abc.def.ghi
"@ | Set-Content -LiteralPath (Join-Path $input "sample.txt") -Encoding UTF8

    & (Join-Path $PSScriptRoot "Sanitize-LabArtifacts.ps1") -InputDirectory $input -OutputDirectory $output

    $combined = (Get-ChildItem -LiteralPath $output -Recurse -File |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join [Environment]::NewLine

    $forbidden = @(
        "LAB-PC01",
        "example.test",
        "dc01.example.test",
        "EXAMPLE\lab-admin",
        "admin@example.test",
        "10.20.30.40",
        "2001:db8::1234",
        "S-1-5-21-111111111-222222222-333333333-1001",
        "12345678-1234-1234-1234-123456789abc",
        "00-11-22-33-44-55",
        "OU=DMCR-Lab",
        "\\dc01.example.test\share",
        "SuperSecret-123!",
        "abc.def.ghi"
    )

    foreach ($value in $forbidden) {
        if ($combined.IndexOf($value, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "Sanitizer regression: a sensitive test value remains in output."
        }
    }

    if ($combined -notmatch '\[REDACTED\]') {
        throw "Sanitizer regression: secret marker was not emitted."
    }

    if ($combined -notmatch '<(?:ENV|SID|GUID|MAC|IPV4|IPV6|UPN|DOMAIN_ACCOUNT|DN|UNC|FQDN):[0-9a-f]{12}>') {
        throw "Sanitizer regression: opaque identifier token was not emitted."
    }

    Write-Host "Lab artifact sanitizer regression test passed."
}
finally {
    foreach ($name in $names) {
        [Environment]::SetEnvironmentVariable($name, $oldValues[$name])
    }

    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
