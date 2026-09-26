param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [string]$PreferredDc = "",
    [string]$ComputerName = $env:COMPUTERNAME,
    [ValidateSet("smoke", "healthy")]
    [string]$Profile = "smoke",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot "artifacts"
}

$ExePath = [System.IO.Path]::GetFullPath($ExePath)
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

if (-not (Test-Path $ExePath)) {
    throw "Executable not found: $ExePath"
}

New-Item -ItemType Directory -Force $OutputDirectory | Out-Null

$computerSystem = Get-CimInstance Win32_ComputerSystem
$environment = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    PartOfDomain = [bool]$computerSystem.PartOfDomain
    LocalDomain = [string]$computerSystem.Domain
    RequestedDomain = $Domain
    PreferredDc = $PreferredDc
    Profile = $Profile
    TimestampUtc = [DateTime]::UtcNow.ToString("o")
}

$environment | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "environment.json")

if (-not $computerSystem.PartOfDomain) {
    throw "The AD integration runner is not domain joined."
}

if (-not [string]::Equals($computerSystem.Domain, $Domain, [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Warning "Runner domain '$($computerSystem.Domain)' differs from requested test domain '$Domain'."
}

$actions = @(
    "self-test",
    "dc-matrix",
    "ldap-compatibility",
    "rpc-endpoints",
    "kerberos-deep",
    "identity-consistency",
    "replication-timeline",
    "spn-collisions",
    "smb-kerberos",
    "ad-recycle-bin",
    "ad-deleted",
    "next-action",
    "advanced",
    "history",
    "history-compare"
)

$allowedDiagnosticExitCodes = @(0, 20, 21, 22, 23)
$summary = New-Object System.Collections.Generic.List[object]
$failures = New-Object System.Collections.Generic.List[string]

foreach ($action in $actions) {
    Write-Host ""
    Write-Host "=== $action ==="

    $stdoutPath = Join-Path $OutputDirectory ($action + ".json")
    $stderrPath = Join-Path $OutputDirectory ($action + ".stderr.txt")

    $arguments = @("--cli", "--action", $action, "--domain", $Domain, "--computer", $ComputerName, "--json")
    if (-not [string]::IsNullOrWhiteSpace($PreferredDc)) {
        $arguments += @("--dc", $PreferredDc)
    }

    $process = Start-Process -FilePath $ExePath -ArgumentList $arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $exitCode = [int]$process.ExitCode

    $jsonText = ""
    if (Test-Path $stdoutPath) {
        $jsonText = Get-Content $stdoutPath -Raw
    }

    $parsed = $null
    $parseError = ""
    try {
        $parsed = $jsonText | ConvertFrom-Json
    }
    catch {
        $parseError = $_.Exception.Message
        $failures.Add("$action did not return valid JSON: $parseError")
    }

    if ($allowedDiagnosticExitCodes -notcontains $exitCode) {
        $failures.Add("$action returned unexpected exit code $exitCode")
    }

    if ($null -ne $parsed) {
        if (-not [string]::Equals([string]$parsed.action, $action, [System.StringComparison]::OrdinalIgnoreCase)) {
            $failures.Add("$action JSON envelope reports action '$($parsed.action)'")
        }

        if ([int]$parsed.exitCode -ne $exitCode) {
            $failures.Add("$action process exit code $exitCode differs from JSON exitCode $($parsed.exitCode)")
        }
    }

    if ($Profile -eq "healthy" -and $exitCode -eq 20) {
        $failures.Add("$action detected a diagnostic finding in healthy profile")
    }

    $stderr = ""
    if (Test-Path $stderrPath) {
        $stderr = (Get-Content $stderrPath -Raw).Trim()
    }

    $summary.Add([pscustomobject]@{
        Action = $action
        ExitCode = $exitCode
        ExitMeaning = if ($null -ne $parsed) { [string]$parsed.exitMeaning } else { "" }
        JsonValid = ($null -ne $parsed)
        StdErr = $stderr
    })

    Write-Host "$action -> exit $exitCode"
}

$summary | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.json")
$summary | Format-Table -AutoSize | Out-String | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.txt")

Write-Host ""
Write-Host ($summary | Format-Table -AutoSize | Out-String)

if ($failures.Count -gt 0) {
    $failurePath = Join-Path $OutputDirectory "failures.txt"
    $failures | Set-Content -Encoding UTF8 $failurePath
    $message = "AD integration test failed with " + $failures.Count + " issue(s):" + [Environment]::NewLine + "- " + ($failures -join ([Environment]::NewLine + "- "))
    Write-Error $message
}

Write-Host "AD integration test completed successfully."
