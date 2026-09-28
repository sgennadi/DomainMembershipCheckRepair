param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,
    [string]$OutputDirectory = "",
    [bool]$RequireStandardUser = $true,
    [bool]$RequireCyberArkDetection = $true
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot "epm-artifacts"
}

$ExePath = [System.IO.Path]::GetFullPath($ExePath)
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

if (-not (Test-Path $ExePath)) {
    throw "Executable not found: $ExePath"
}

New-Item -ItemType Directory -Force $OutputDirectory | Out-Null

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

$environment = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    Identity = $identity.Name
    IsAdministrator = [bool]$isAdmin
    UserInteractive = [Environment]::UserInteractive
    RequireStandardUser = [bool]$RequireStandardUser
    RequireCyberArkDetection = [bool]$RequireCyberArkDetection
    TimestampUtc = [DateTime]::UtcNow.ToString("o")
}

$environment | ConvertTo-Json -Depth 4 |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "environment.json")

if (-not [Environment]::UserInteractive) {
    throw "The EPM lab runner must run in an interactive Windows session so the elevation broker can operate."
}

if ($RequireStandardUser -and $isAdmin) {
    throw "The EPM lab must start from a standard-user token. The current runner identity is already elevated."
}

Write-Host "Collecting CyberArk/EPM diagnostics..."
$cyberArkOutput = & $ExePath --cli --action cyberark --json 2>&1 | Out-String
$cyberArkExitCode = $LASTEXITCODE
$cyberArkOutput | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "cyberark.json")

if (@(0, 20, 21, 22, 23) -notcontains $cyberArkExitCode) {
    throw "CyberArk diagnostic returned unexpected exit code $cyberArkExitCode."
}

$cyberArk = $null
try {
    $cyberArk = $cyberArkOutput | ConvertFrom-Json
}
catch {
    throw "CyberArk diagnostic did not return valid JSON: $($_.Exception.Message)"
}

$detected = $false
if ($null -ne $cyberArk.result) {
    $detected = [bool]$cyberArk.result.Detected
}

if ($RequireCyberArkDetection -and -not $detected) {
    throw "CyberArk/EPM was not detected on the EPM lab runner."
}

Write-Host "Running non-destructive elevation probe..."
$probeOutput = & $ExePath --cli --action elevation-probe --json 2>&1 | Out-String
$probeExitCode = $LASTEXITCODE
$probeOutput | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "elevation-probe.txt")

if ($probeExitCode -ne 0) {
    throw "Elevation probe failed with exit code $probeExitCode. Check the CyberArk EPM elevation policy for the executable."
}

Write-Host "Validating mutating-action dry-run path..."
$dryRunOutput = & $ExePath --cli --action safe-fixes --dry-run --no-restart 2>&1 | Out-String
$dryRunExitCode = $LASTEXITCODE
$dryRunOutput | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "safe-fixes-dry-run.txt")

if ($dryRunExitCode -ne 0) {
    throw "Safe Fixes dry-run returned exit code $dryRunExitCode."
}

$result = [ordered]@{
    CyberArkDetected = [bool]$detected
    ElevationProbeExitCode = [int]$probeExitCode
    SafeFixesDryRunExitCode = [int]$dryRunExitCode
    Passed = $true
    TimestampUtc = [DateTime]::UtcNow.ToString("o")
}

$result | ConvertTo-Json -Depth 4 |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.json")

Write-Host "CyberArk/EPM live validation completed successfully."
