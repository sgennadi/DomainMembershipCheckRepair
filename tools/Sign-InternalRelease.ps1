[CmdletBinding(DefaultParameterSetName = "Pfx")]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Files,

    [Parameter(Mandatory = $true, ParameterSetName = "Pfx")]
    [string]$PfxPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Store")]
    [string]$Thumbprint,

    [Parameter()]
    [string]$TimestampUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Find-SignTool {
    $roots = @(
        "$([Environment]::GetFolderPath('ProgramFilesX86'))\Windows Kits\10\bin",
        "$([Environment]::GetFolderPath('ProgramFiles'))\Windows Kits\10\bin"
    )

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) {
            continue
        }

        $candidate = Get-ChildItem -Path $root -Filter signtool.exe -Recurse -File -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1

        if ($candidate) {
            return $candidate.FullName
        }
    }

    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw "signtool.exe was not found. Install the Windows SDK signing tools."
}

$signtool = Find-SignTool
$passwordText = $null

if ($PSCmdlet.ParameterSetName -eq "Pfx") {
    if (-not (Test-Path $PfxPath)) {
        throw "PFX not found: $PfxPath"
    }

    $securePassword = Read-Host "Enter the PFX password" -AsSecureString
    $credential = New-Object Management.Automation.PSCredential("unused", $securePassword)
    $passwordText = $credential.GetNetworkCredential().Password
}

try {
    foreach ($file in $Files) {
        $resolved = (Resolve-Path $file).Path
        Write-Host "Signing $resolved"

        $arguments = @("sign", "/fd", "SHA256")

        if ($PSCmdlet.ParameterSetName -eq "Pfx") {
            $arguments += @("/f", $PfxPath, "/p", $passwordText)
        }
        else {
            $arguments += @("/sha1", $Thumbprint, "/sm")
        }

        if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) {
            $arguments += @("/tr", $TimestampUrl, "/td", "SHA256")
        }

        $arguments += $resolved

        & $signtool @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "signtool sign failed for $resolved with exit code $LASTEXITCODE"
        }

        & $signtool verify /pa /v $resolved
        if ($LASTEXITCODE -ne 0) {
            throw "signtool verify failed for $resolved with exit code $LASTEXITCODE"
        }
    }
}
finally {
    $passwordText = $null
}

Write-Host "Signing and verification completed successfully."
