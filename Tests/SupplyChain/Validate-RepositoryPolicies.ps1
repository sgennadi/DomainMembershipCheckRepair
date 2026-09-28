param(
    [string]$RepositoryRoot = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
else {
    $RepositoryRoot = (Resolve-Path $RepositoryRoot).Path
}

$failures = New-Object System.Collections.Generic.List[string]

Write-Host "Repository policy validation"
Write-Host "============================"

# Parse every PowerShell script in the repository. This catches syntax errors in
# manual lab harnesses even when the corresponding self-hosted runner is offline.
$psFiles = Get-ChildItem -Path $RepositoryRoot -Recurse -File -Filter *.ps1 |
    Where-Object {
        $_.FullName -notmatch '[\\/]bin[\\/]' -and
        $_.FullName -notmatch '[\\/]obj[\\/]'
    }

foreach ($file in $psFiles) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName,
        [ref]$tokens,
        [ref]$parseErrors)

    foreach ($parseError in @($parseErrors)) {
        $relative = $file.FullName.Substring($RepositoryRoot.Length).TrimStart('\', '/')
        $failures.Add(
            "PowerShell syntax error in $relative at line $($parseError.Extent.StartLineNumber): $($parseError.Message)")
    }
}

$workflowDirectory = Join-Path $RepositoryRoot ".github\workflows"
$workflowFiles = Get-ChildItem -Path $workflowDirectory -File |
    Where-Object { $_.Extension -in @(".yml", ".yaml") }

foreach ($workflow in $workflowFiles) {
    $relative = $workflow.FullName.Substring($RepositoryRoot.Length).TrimStart('\', '/')
    $text = Get-Content -Path $workflow.FullName -Raw
    $lines = Get-Content -Path $workflow.FullName

    if ($text -match '(?m)^\s*pull_request_target\s*:') {
        $failures.Add("$relative uses pull_request_target, which is not permitted by repository policy.")
    }

    if ($text -notmatch '(?m)^permissions\s*:') {
        $failures.Add("$relative does not declare an explicit top-level permissions block.")
    }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = [string]$lines[$i]
        $match = [regex]::Match($line, '^\s*uses:\s*([^\s#]+)')
        if (-not $match.Success) {
            continue
        }

        $usesValue = $match.Groups[1].Value.Trim()
        if ($usesValue.StartsWith("./", [System.StringComparison]::Ordinal) -or
            $usesValue.StartsWith(".\\", [System.StringComparison]::Ordinal)) {
            continue
        }

        $at = $usesValue.LastIndexOf('@')
        if ($at -le 0 -or $at -eq ($usesValue.Length - 1)) {
            $failures.Add("$relative has an invalid remote action reference: $usesValue")
            continue
        }

        $reference = $usesValue.Substring($at + 1)
        if ($reference -notmatch '^[0-9a-fA-F]{40}$') {
            $failures.Add("$relative must pin remote action '$usesValue' to a full 40-character commit SHA.")
        }

        if ($usesValue.StartsWith("actions/checkout@", [System.StringComparison]::OrdinalIgnoreCase)) {
            $foundPersistCredentials = $false
            for ($j = $i + 1; $j -lt [Math]::Min($lines.Count, $i + 8); $j++) {
                $next = [string]$lines[$j]
                if ($next -match '^\s*-\s+name\s*:') {
                    break
                }
                if ($next -match '^\s*persist-credentials\s*:\s*false\s*(?:#.*)?$') {
                    $foundPersistCredentials = $true
                    break
                }
            }

            if (-not $foundPersistCredentials) {
                $failures.Add("$relative checkout step must set persist-credentials: false.")
            }
        }
    }
}

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "Repository policy validation failed:"
    foreach ($failure in $failures) {
        Write-Host " - $failure"
    }
    exit 1
}

Write-Host "Validated $($psFiles.Count) PowerShell scripts."
Write-Host "Validated $($workflowFiles.Count) GitHub Actions workflows."
Write-Host "All remote actions are pinned to immutable commit SHAs."
Write-Host "All checkout steps disable persisted Git credentials."
Write-Host "Repository policy validation passed."
