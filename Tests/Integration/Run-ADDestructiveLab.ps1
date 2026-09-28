param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,
    [Parameter(Mandatory = $true)]
    [ValidateSet("preflight", "safe-fixes", "repair-if-broken", "mii-disable-rollback", "recycle-bin-restore")]
    [string]$Scenario,
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [string]$PreferredDc = "",
    [string]$ExpectedComputerName = "",
    [string]$TestOuDn = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot "destructive-artifacts"
}

$ExePath = [System.IO.Path]::GetFullPath($ExePath)
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

if (-not (Test-Path $ExePath)) {
    throw "Executable not found: $ExePath"
}

New-Item -ItemType Directory -Force $OutputDirectory | Out-Null

function Invoke-Dmcr {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [string[]]$InputLines = @(),
        [string]$ArtifactName = "command"
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExePath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true

    foreach ($argument in $Arguments) {
        [void]$psi.ArgumentList.Add($argument)
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi

    if (-not $process.Start()) {
        throw "Unable to start DomainMembershipCheckRepair."
    }

    foreach ($line in $InputLines) {
        $process.StandardInput.WriteLine($line)
    }
    $process.StandardInput.Close()

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    if (-not $process.WaitForExit(180000)) {
        try { $process.Kill() } catch {}
        throw "DomainMembershipCheckRepair timed out after 180 seconds: $($Arguments -join ' ')"
    }

    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $exitCode = [int]$process.ExitCode

    $stdout | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory ($ArtifactName + ".stdout.txt"))
    $stderr | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory ($ArtifactName + ".stderr.txt"))

    return [pscustomobject]@{
        ExitCode = $exitCode
        StdOut = $stdout
        StdErr = $stderr
    }
}

function Get-BaseArguments {
    $args = @("--cli", "--domain", $Domain, "--no-restart", "--no-log")
    if (-not [string]::IsNullOrWhiteSpace($PreferredDc)) {
        $args += @("--dc", $PreferredDc)
    }
    return $args
}

function Assert-DomainLab {
    $cs = Get-CimInstance Win32_ComputerSystem
    if (-not $cs.PartOfDomain) {
        throw "The destructive lab runner must be domain joined."
    }

    if (-not [string]::Equals([string]$cs.Domain, $Domain, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Runner domain '$($cs.Domain)' does not match configured lab domain '$Domain'."
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedComputerName) -and
        -not [string]::Equals($env:COMPUTERNAME, $ExpectedComputerName, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "This workflow is running on '$env:COMPUTERNAME' but AD_LAB_COMPUTER is '$ExpectedComputerName'."
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The destructive lab runner must run from an elevated administrator token."
    }
}

Assert-DomainLab

$environment = [ordered]@{
    Scenario = $Scenario
    ComputerName = $env:COMPUTERNAME
    Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Domain = $Domain
    PreferredDc = $PreferredDc
    TestOuDn = $TestOuDn
    TimestampUtc = [DateTime]::UtcNow.ToString("o")
}
$environment | ConvertTo-Json -Depth 5 |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "environment.json")

$baseArgs = Get-BaseArguments
$summary = New-Object System.Collections.Generic.List[object]

function Add-Summary {
    param([string]$Step, [string]$Status, [string]$Details)
    $summary.Add([pscustomobject]@{
        Step = $Step
        Status = $Status
        Details = $Details
    })
}

$preflight = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "self-test", "--json")) -ArtifactName "preflight-self-test"
if (@(0, 20, 21, 22, 23) -notcontains $preflight.ExitCode) {
    throw "Self-test preflight returned unexpected exit code $($preflight.ExitCode)."
}
Add-Summary "self-test" "PASS" "Exit code $($preflight.ExitCode)"

$recycleStatus = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "ad-recycle-bin", "--json")) -ArtifactName "preflight-recycle-bin"
if (@(0, 20, 21, 22, 23) -notcontains $recycleStatus.ExitCode) {
    throw "Recycle Bin preflight returned unexpected exit code $($recycleStatus.ExitCode)."
}
Add-Summary "ad-recycle-bin" "PASS" "Exit code $($recycleStatus.ExitCode)"

if ($Scenario -eq "preflight") {
    Add-Summary "scenario" "PASS" "Preflight-only run completed."
}
elseif ($Scenario -eq "safe-fixes") {
    $result = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "safe-fixes")) -InputLines @("y") -ArtifactName "safe-fixes"
    if ($result.ExitCode -ne 0) {
        throw "Safe Fixes failed with exit code $($result.ExitCode)."
    }
    Add-Summary "safe-fixes" "PASS" "Safe Fixes completed successfully."
}
elseif ($Scenario -eq "repair-if-broken") {
    $check = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "check")) -ArtifactName "trust-check"
    if ($check.ExitCode -eq 0) {
        Add-Summary "repair-if-broken" "SKIP" "Secure channel is already healthy."
    }
    elseif ($check.ExitCode -eq 2) {
        $repair = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "repair")) -ArtifactName "trust-repair"
        if ($repair.ExitCode -ne 0) {
            throw "Trust repair failed with exit code $($repair.ExitCode)."
        }

        $verify = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "check")) -ArtifactName "trust-verify"
        if ($verify.ExitCode -ne 0) {
            throw "Secure channel is still unhealthy after repair. Exit code $($verify.ExitCode)."
        }
        Add-Summary "repair-if-broken" "PASS" "Broken secure channel was repaired and verified."
    }
    else {
        throw "Trust check returned unexpected exit code $($check.ExitCode)."
    }
}
elseif ($Scenario -eq "mii-disable-rollback") {
    $dry = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "mii-disable", "--dry-run")) -ArtifactName "mii-preflight"
    if ($dry.StdOut -match "not enabled") {
        Add-Summary "mii-disable-rollback" "SKIP" "Machine Identity Isolation is not enabled on this lab runner."
    }
    else {
        $disable = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "mii-disable")) -InputLines @("y") -ArtifactName "mii-disable"
        if ($disable.ExitCode -ne 0) {
            throw "MII disable failed with exit code $($disable.ExitCode)."
        }

        $rollback = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "rollback-local")) -InputLines @("y") -ArtifactName "mii-rollback"
        if ($rollback.ExitCode -ne 0) {
            throw "Rollback Local failed with exit code $($rollback.ExitCode)."
        }
        Add-Summary "mii-disable-rollback" "PASS" "MII local change and rollback completed without reboot."
    }
}
elseif ($Scenario -eq "recycle-bin-restore") {
    if ([string]::IsNullOrWhiteSpace($TestOuDn)) {
        throw "AD_LAB_TEST_OU_DN is required for recycle-bin-restore."
    }

    $labUser = [string]$env:AD_LAB_USER
    $labPassword = [string]$env:AD_LAB_PASSWORD
    if ([string]::IsNullOrWhiteSpace($labUser) -or [string]::IsNullOrEmpty($labPassword)) {
        throw "AD_LAB_USER repository variable and AD_LAB_PASSWORD repository secret are required for recycle-bin-restore."
    }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "The recycle-bin-restore scenario requires the RSAT ActiveDirectory PowerShell module."
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    $runSuffix = [string]$env:GITHUB_RUN_ID
    if ([string]::IsNullOrWhiteSpace($runSuffix)) {
        $runSuffix = [DateTime]::UtcNow.ToString("HHmmss")
    }
    if ($runSuffix.Length -gt 8) {
        $runSuffix = $runSuffix.Substring($runSuffix.Length - 8)
    }

    $testName = ("DCRLAB" + $runSuffix).ToUpperInvariant()
    if ($testName.Length -gt 15) {
        $testName = $testName.Substring(0, 15)
    }

    $server = $PreferredDc.TrimStart('\')
    $adParams = @{}
    if (-not [string]::IsNullOrWhiteSpace($server)) {
        $adParams["Server"] = $server
    }

    $filter = '(sAMAccountName=' + $testName + '$)'
    $existing = Get-ADComputer -LDAPFilter $filter @adParams -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        throw "Disposable test account '$testName$' already exists. Refusing to touch a pre-existing object."
    }

    Write-Host "Creating disposable AD computer object $testName in $TestOuDn"
    New-ADComputer -Name $testName -SamAccountName ($testName + '
    try {
        Remove-ADComputer -Identity $created.DistinguishedName -Confirm:$false @adParams -ErrorAction Stop

        $foundDeleted = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            Start-Sleep -Seconds 5
            $deleted = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "ad-deleted", "--computer", $testName, "--json")) -ArtifactName ("ad-deleted-" + $attempt)
            if ($deleted.ExitCode -eq 20) {
                $foundDeleted = $true
                break
            }
        }

        if (-not $foundDeleted) {
            throw "The disposable deleted object was not detected within 60 seconds."
        }

        $restoreArgs = $baseArgs + @(
            "--action", "ad-restore",
            "--computer", $testName,
            "--user", $labUser,
            "--password-stdin"
        )
        $restore = Invoke-Dmcr -Arguments $restoreArgs -InputLines @($labPassword, "y") -ArtifactName "ad-restore"
        if ($restore.ExitCode -ne 0) {
            throw "Application AD restore failed with exit code $($restore.ExitCode)."
        }

        $restoredMatches = @(Get-ADComputer -LDAPFilter $filter -Properties ObjectGuid @adParams -ErrorAction Stop)
        if ($restoredMatches.Count -ne 1) {
            throw "Expected exactly one restored disposable object for '$testName            throw "Restored computer ObjectGUID differs from the original object."
        }

        Add-Summary "recycle-bin-restore" "PASS" "Disposable object $testName was deleted, restored by the application, and verified by ObjectGUID."
    }
    finally {
        $cleanup = Get-ADComputer -LDAPFilter $filter @adParams -ErrorAction SilentlyContinue
        if ($null -ne $cleanup) {
            Remove-ADComputer -Identity $cleanup.DistinguishedName -Confirm:$false @adParams -ErrorAction SilentlyContinue
        }
    }
}

$summary | ConvertTo-Json -Depth 5 |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.json")
$summary | Format-Table -AutoSize | Out-String |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.txt")

Write-Host ($summary | Format-Table -AutoSize | Out-String)
Write-Host "Destructive/disposable AD lab scenario completed successfully."
) -Path $TestOuDn @adParams -ErrorAction Stop
    $createdMatches = @(Get-ADComputer -LDAPFilter $filter -Properties ObjectGuid @adParams -ErrorAction Stop)
    if ($createdMatches.Count -ne 1) {
        throw "Expected exactly one newly created disposable object for '$testName
    try {
        Remove-ADComputer -Identity $created.DistinguishedName -Confirm:$false @adParams -ErrorAction Stop

        $foundDeleted = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            Start-Sleep -Seconds 5
            $deleted = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "ad-deleted", "--computer", $testName, "--json")) -ArtifactName ("ad-deleted-" + $attempt)
            if ($deleted.ExitCode -eq 20) {
                $foundDeleted = $true
                break
            }
        }

        if (-not $foundDeleted) {
            throw "The disposable deleted object was not detected within 60 seconds."
        }

        $restoreArgs = $baseArgs + @(
            "--action", "ad-restore",
            "--computer", $testName,
            "--user", $labUser,
            "--password-stdin"
        )
        $restore = Invoke-Dmcr -Arguments $restoreArgs -InputLines @($labPassword, "y") -ArtifactName "ad-restore"
        if ($restore.ExitCode -ne 0) {
            throw "Application AD restore failed with exit code $($restore.ExitCode)."
        }

        $restored = Get-ADComputer -Identity $testName -Properties ObjectGuid @adParams -ErrorAction Stop
        if ([Guid]$restored.ObjectGuid -ne $originalGuid) {
            throw "Restored computer ObjectGUID differs from the original object."
        }

        Add-Summary "recycle-bin-restore" "PASS" "Disposable object $testName was deleted, restored by the application, and verified by ObjectGUID."
    }
    finally {
        $cleanup = Get-ADComputer -LDAPFilter $filter @adParams -ErrorAction SilentlyContinue
        if ($null -ne $cleanup) {
            Remove-ADComputer -Identity $cleanup.DistinguishedName -Confirm:$false @adParams -ErrorAction SilentlyContinue
        }
    }
}

$summary | ConvertTo-Json -Depth 5 |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.json")
$summary | Format-Table -AutoSize | Out-String |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.txt")

Write-Host ($summary | Format-Table -AutoSize | Out-String)
Write-Host "Destructive/disposable AD lab scenario completed successfully."
, found $($createdMatches.Count)."
    }
    $created = $createdMatches[0]
    $originalGuid = [Guid]$created.ObjectGuid

    try {
        Remove-ADComputer -Identity $created.DistinguishedName -Confirm:$false @adParams -ErrorAction Stop

        $foundDeleted = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            Start-Sleep -Seconds 5
            $deleted = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "ad-deleted", "--computer", $testName, "--json")) -ArtifactName ("ad-deleted-" + $attempt)
            if ($deleted.ExitCode -eq 20) {
                $foundDeleted = $true
                break
            }
        }

        if (-not $foundDeleted) {
            throw "The disposable deleted object was not detected within 60 seconds."
        }

        $restoreArgs = $baseArgs + @(
            "--action", "ad-restore",
            "--computer", $testName,
            "--user", $labUser,
            "--password-stdin"
        )
        $restore = Invoke-Dmcr -Arguments $restoreArgs -InputLines @($labPassword, "y") -ArtifactName "ad-restore"
        if ($restore.ExitCode -ne 0) {
            throw "Application AD restore failed with exit code $($restore.ExitCode)."
        }

        $restored = Get-ADComputer -Identity $testName -Properties ObjectGuid @adParams -ErrorAction Stop
        if ([Guid]$restored.ObjectGuid -ne $originalGuid) {
            throw "Restored computer ObjectGUID differs from the original object."
        }

        Add-Summary "recycle-bin-restore" "PASS" "Disposable object $testName was deleted, restored by the application, and verified by ObjectGUID."
    }
    finally {
        $cleanup = Get-ADComputer -LDAPFilter $filter @adParams -ErrorAction SilentlyContinue
        if ($null -ne $cleanup) {
            Remove-ADComputer -Identity $cleanup.DistinguishedName -Confirm:$false @adParams -ErrorAction SilentlyContinue
        }
    }
}

$summary | ConvertTo-Json -Depth 5 |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.json")
$summary | Format-Table -AutoSize | Out-String |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.txt")

Write-Host ($summary | Format-Table -AutoSize | Out-String)
Write-Host "Destructive/disposable AD lab scenario completed successfully."
, found $($restoredMatches.Count)."
        }
        $restored = $restoredMatches[0]
        if ([Guid]$restored.ObjectGuid -ne $originalGuid) {
            throw "Restored computer ObjectGUID differs from the original object."
        }

        Add-Summary "recycle-bin-restore" "PASS" "Disposable object $testName was deleted, restored by the application, and verified by ObjectGUID."
    }
    finally {
        $cleanup = Get-ADComputer -LDAPFilter $filter @adParams -ErrorAction SilentlyContinue
        if ($null -ne $cleanup) {
            Remove-ADComputer -Identity $cleanup.DistinguishedName -Confirm:$false @adParams -ErrorAction SilentlyContinue
        }
    }
}

$summary | ConvertTo-Json -Depth 5 |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.json")
$summary | Format-Table -AutoSize | Out-String |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.txt")

Write-Host ($summary | Format-Table -AutoSize | Out-String)
Write-Host "Destructive/disposable AD lab scenario completed successfully."
) -Path $TestOuDn @adParams -ErrorAction Stop
    $createdMatches = @(Get-ADComputer -LDAPFilter $filter -Properties ObjectGuid @adParams -ErrorAction Stop)
    if ($createdMatches.Count -ne 1) {
        throw "Expected exactly one newly created disposable object for '$testName
    try {
        Remove-ADComputer -Identity $created.DistinguishedName -Confirm:$false @adParams -ErrorAction Stop

        $foundDeleted = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            Start-Sleep -Seconds 5
            $deleted = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "ad-deleted", "--computer", $testName, "--json")) -ArtifactName ("ad-deleted-" + $attempt)
            if ($deleted.ExitCode -eq 20) {
                $foundDeleted = $true
                break
            }
        }

        if (-not $foundDeleted) {
            throw "The disposable deleted object was not detected within 60 seconds."
        }

        $restoreArgs = $baseArgs + @(
            "--action", "ad-restore",
            "--computer", $testName,
            "--user", $labUser,
            "--password-stdin"
        )
        $restore = Invoke-Dmcr -Arguments $restoreArgs -InputLines @($labPassword, "y") -ArtifactName "ad-restore"
        if ($restore.ExitCode -ne 0) {
            throw "Application AD restore failed with exit code $($restore.ExitCode)."
        }

        $restored = Get-ADComputer -Identity $testName -Properties ObjectGuid @adParams -ErrorAction Stop
        if ([Guid]$restored.ObjectGuid -ne $originalGuid) {
            throw "Restored computer ObjectGUID differs from the original object."
        }

        Add-Summary "recycle-bin-restore" "PASS" "Disposable object $testName was deleted, restored by the application, and verified by ObjectGUID."
    }
    finally {
        $cleanup = Get-ADComputer -LDAPFilter $filter @adParams -ErrorAction SilentlyContinue
        if ($null -ne $cleanup) {
            Remove-ADComputer -Identity $cleanup.DistinguishedName -Confirm:$false @adParams -ErrorAction SilentlyContinue
        }
    }
}

$summary | ConvertTo-Json -Depth 5 |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.json")
$summary | Format-Table -AutoSize | Out-String |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.txt")

Write-Host ($summary | Format-Table -AutoSize | Out-String)
Write-Host "Destructive/disposable AD lab scenario completed successfully."
, found $($createdMatches.Count)."
    }
    $created = $createdMatches[0]
    $originalGuid = [Guid]$created.ObjectGuid

    try {
        Remove-ADComputer -Identity $created.DistinguishedName -Confirm:$false @adParams -ErrorAction Stop

        $foundDeleted = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            Start-Sleep -Seconds 5
            $deleted = Invoke-Dmcr -Arguments ($baseArgs + @("--action", "ad-deleted", "--computer", $testName, "--json")) -ArtifactName ("ad-deleted-" + $attempt)
            if ($deleted.ExitCode -eq 20) {
                $foundDeleted = $true
                break
            }
        }

        if (-not $foundDeleted) {
            throw "The disposable deleted object was not detected within 60 seconds."
        }

        $restoreArgs = $baseArgs + @(
            "--action", "ad-restore",
            "--computer", $testName,
            "--user", $labUser,
            "--password-stdin"
        )
        $restore = Invoke-Dmcr -Arguments $restoreArgs -InputLines @($labPassword, "y") -ArtifactName "ad-restore"
        if ($restore.ExitCode -ne 0) {
            throw "Application AD restore failed with exit code $($restore.ExitCode)."
        }

        $restored = Get-ADComputer -Identity $testName -Properties ObjectGuid @adParams -ErrorAction Stop
        if ([Guid]$restored.ObjectGuid -ne $originalGuid) {
            throw "Restored computer ObjectGUID differs from the original object."
        }

        Add-Summary "recycle-bin-restore" "PASS" "Disposable object $testName was deleted, restored by the application, and verified by ObjectGUID."
    }
    finally {
        $cleanup = Get-ADComputer -LDAPFilter $filter @adParams -ErrorAction SilentlyContinue
        if ($null -ne $cleanup) {
            Remove-ADComputer -Identity $cleanup.DistinguishedName -Confirm:$false @adParams -ErrorAction SilentlyContinue
        }
    }
}

$summary | ConvertTo-Json -Depth 5 |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.json")
$summary | Format-Table -AutoSize | Out-String |
    Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "summary.txt")

Write-Host ($summary | Format-Table -AutoSize | Out-String)
Write-Host "Destructive/disposable AD lab scenario completed successfully."
