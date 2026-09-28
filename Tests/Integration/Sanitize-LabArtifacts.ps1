param(
    [Parameter(Mandatory = $true)]
    [string]$InputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [string[]]$SensitiveEnvironmentVariables = @(
        "AD_LAB_DOMAIN",
        "AD_LAB_DC",
        "AD_LAB_COMPUTER",
        "AD_LAB_TEST_OU_DN",
        "AD_LAB_USER",
        "AD_LAB_PASSWORD",
        "COMPUTERNAME",
        "USERDOMAIN",
        "USERNAME"
    )
)

$ErrorActionPreference = "Stop"

$InputDirectory = [System.IO.Path]::GetFullPath($InputDirectory)
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

if (-not (Test-Path -LiteralPath $InputDirectory -PathType Container)) {
    throw "Input artifact directory does not exist."
}

if (Test-Path -LiteralPath $OutputDirectory) {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$key = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($key)
}
finally {
    $rng.Dispose()
}

$tokenCache = New-Object "System.Collections.Generic.Dictionary[string,string]" ([System.StringComparer]::OrdinalIgnoreCase)
$counts = New-Object "System.Collections.Generic.Dictionary[string,int]" ([System.StringComparer]::OrdinalIgnoreCase)

function Add-Count {
    param([string]$Category)

    if ($counts.ContainsKey($Category)) {
        $counts[$Category] = $counts[$Category] + 1
    }
    else {
        $counts[$Category] = 1
    }
}

function Get-OpaqueToken {
    param(
        [string]$Category,
        [string]$Value
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return ("<" + $Category + ">")
    }

    $cacheKey = $Category + [char]0 + $Value
    if ($tokenCache.ContainsKey($cacheKey)) {
        return $tokenCache[$cacheKey]
    }

    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $key
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())
        $hash = $hmac.ComputeHash($bytes)
        $short = ([System.BitConverter]::ToString($hash, 0, 6)).Replace("-", "").ToLowerInvariant()
        $token = "<" + $Category + ":" + $short + ">"
        $tokenCache[$cacheKey] = $token
        return $token
    }
    finally {
        $hmac.Dispose()
    }
}

function Replace-Pattern {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Category,
        [switch]$Secret
    )

    $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant

    $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{
        param($match)
        Add-Count $Category
        if ($Secret) {
            return "[REDACTED]"
        }
        return Get-OpaqueToken -Category $Category -Value $match.Value
    }

    return [System.Text.RegularExpressions.Regex]::Replace(
        $Text,
        $Pattern,
        $evaluator,
        $options)
}

$knownValues = New-Object System.Collections.Generic.List[object]
foreach ($name in $SensitiveEnvironmentVariables) {
    if ([string]::IsNullOrWhiteSpace($name)) {
        continue
    }

    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        continue
    }

    $secret = $name -match '(?i)(password|secret|token|key)'
    $knownValues.Add([pscustomobject]@{
        Name = $name
        Value = $value
        Secret = [bool]$secret
    })
}

$knownValues = @($knownValues | Sort-Object { $_.Value.Length } -Descending)
$textExtensions = @(".txt", ".json", ".log", ".xml", ".csv", ".md")
$processedFiles = 0
$omittedFiles = 0

$files = Get-ChildItem -LiteralPath $InputDirectory -Recurse -File
foreach ($file in $files) {
    $relativePath = $file.FullName.Substring($InputDirectory.Length).TrimStart([char[]]@('\', '/'))
    $destination = Join-Path $OutputDirectory $relativePath
    $destinationDirectory = Split-Path -Parent $destination

    if (-not (Test-Path -LiteralPath $destinationDirectory)) {
        New-Item -ItemType Directory -Force -Path $destinationDirectory | Out-Null
    }

    if ($textExtensions -notcontains $file.Extension.ToLowerInvariant()) {
        "[OMITTED: non-text lab artifact]" |
            Set-Content -LiteralPath ($destination + ".omitted.txt") -Encoding UTF8
        $omittedFiles++
        Add-Count "NON_TEXT_OMITTED"
        continue
    }

    try {
        $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop

        foreach ($entry in $knownValues) {
            $escaped = [System.Text.RegularExpressions.Regex]::Escape([string]$entry.Value)
            if ([bool]$entry.Secret) {
                $text = Replace-Pattern -Text $text -Pattern $escaped -Category "SECRET_ENV" -Secret
            }
            else {
                $text = Replace-Pattern -Text $text -Pattern $escaped -Category "ENV"
            }
        }

        $text = Replace-Pattern -Text $text -Pattern '(?im)\b(?:password|passwd|pwd|client[_-]?secret|access[_-]?token|refresh[_-]?token|authorization)\b\s*[:=]\s*[^\s,;]+' -Category "SECRET" -Secret
        $text = Replace-Pattern -Text $text -Pattern '(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*' -Category "BEARER" -Secret
        $text = Replace-Pattern -Text $text -Pattern '(?i)\bS-1-(?:\d+-){1,14}\d+\b' -Category "SID"
        $text = Replace-Pattern -Text $text -Pattern '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b' -Category "GUID"
        $text = Replace-Pattern -Text $text -Pattern '(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b' -Category "MAC"
        $text = Replace-Pattern -Text $text -Pattern '(?i)\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b' -Category "IPV4"
        $text = Replace-Pattern -Text $text -Pattern '(?i)(?:^|\s)(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?=$|\s|[,;\]\)])' -Category "IPV6"
        $text = Replace-Pattern -Text $text -Pattern '(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b' -Category "UPN"
        $text = Replace-Pattern -Text $text -Pattern '(?i)\b[A-Za-z0-9._-]{1,64}\\[A-Za-z0-9.$_-]{1,64}\b' -Category "DOMAIN_ACCOUNT"
        $text = Replace-Pattern -Text $text -Pattern '(?i)(?:CN|OU|DC)=[^,\r\n]+(?:,(?:CN|OU|DC)=[^,\r\n]+)+' -Category "DN"
        $text = Replace-Pattern -Text $text -Pattern '(?i)\\\\[A-Za-z0-9._-]+(?:\\[^\s\\/:*?"<>|]+)+' -Category "UNC"
        $text = Replace-Pattern -Text $text -Pattern '(?i)\b(?=[A-Za-z0-9.-]*[A-Za-z])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b' -Category "FQDN"

        $text | Set-Content -LiteralPath $destination -Encoding UTF8
        $processedFiles++
    }
    catch {
        "[OMITTED: artifact could not be sanitized safely]" |
            Set-Content -LiteralPath $destination -Encoding UTF8
        $omittedFiles++
        Add-Count "SANITIZE_FAILURE"
    }
}

$summary = New-Object System.Collections.Generic.List[string]
$summary.Add("Sanitized lab artifact set")
$summary.Add("==========================")
$summary.Add("Processed text files: $processedFiles")
$summary.Add("Omitted files: $omittedFiles")
$summary.Add("")
$summary.Add("Replacement counts:")
foreach ($category in @($counts.Keys | Sort-Object)) {
    $summary.Add("$category=$($counts[$category])")
}
$summary.Add("")
$summary.Add("Opaque identifiers use a per-run random HMAC key that is not written to disk.")
$summary.Add("No original sensitive values are included in this summary.")

$summary | Set-Content -LiteralPath (Join-Path $OutputDirectory "redaction-summary.txt") -Encoding UTF8
Write-Host "Sanitized lab artifacts: $processedFiles text file(s), $omittedFiles omitted file(s)."
