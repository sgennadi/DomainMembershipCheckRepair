param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Drawing

$fullPath = [System.IO.Path]::GetFullPath($OutputPath)
$directory = [System.IO.Path]::GetDirectoryName($fullPath)

if (-not [string]::IsNullOrWhiteSpace($directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

$stream = [System.IO.File]::Open(
    $fullPath,
    [System.IO.FileMode]::Create,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None
)

try {
    [System.Drawing.SystemIcons]::Shield.Save($stream)
}
finally {
    $stream.Dispose()
}

if (-not (Test-Path -LiteralPath $fullPath)) {
    throw "Application icon was not created: $fullPath"
}

Write-Host "Application icon: $fullPath"
