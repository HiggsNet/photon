[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [Parameter(Mandatory=$true)][string]$Checksum,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$BackendDirectory,
    [switch]$RunVersionChecks
)
$ErrorActionPreference = 'Stop'
$Archive = (Resolve-Path -LiteralPath $Archive).Path
$OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Verification output directory must be new' }
$line = (Get-Content -LiteralPath $Checksum -Raw).Trim()
if ($line -notmatch '^([0-9a-fA-F]{64})\s+\*?([^\r\n]+)$') { throw 'Invalid archive checksum file' }
$expectedHash = $matches[1]
if ($matches[2] -cne [IO.Path]::GetFileName($Archive)) { throw 'Archive checksum filename mismatch' }
if ((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash -ine $expectedHash) { throw 'Archive checksum mismatch' }

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($Archive)
try {
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName.Replace('\', '/')
        if ($name.StartsWith('/') -or $name.Contains(':') -or $name.Split('/') -contains '..') { throw "Invalid archive path: $name" }
        if (!$names.Add($name)) { throw "Duplicate archive path: $name" }
    }
} finally { $zip.Dispose() }
Expand-Archive -LiteralPath $Archive -DestinationPath $OutputDirectory
$manifest = Join-Path $OutputDirectory 'SHA256SUMS'
if (!(Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Package checksum manifest missing' }
$listed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($line in Get-Content -LiteralPath $manifest) {
    if ($line -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') { throw 'Invalid package checksum line' }
    $expectedHash = $matches[1]
    $name = $matches[2].Replace('\', '/')
    if ($name.StartsWith('/') -or $name.Contains(':') -or $name.Split('/') -contains '..' -or !$listed.Add($name)) { throw "Invalid manifest path: $name" }
    $file = Join-Path $OutputDirectory $name
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw "Package file missing: $name" }
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ine $expectedHash) { throw "Package checksum mismatch: $name" }
}
foreach ($file in Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse) {
    $name = $file.FullName.Substring($OutputDirectory.Length + 1).Replace('\', '/')
    if ($name -ne 'SHA256SUMS' -and !$listed.Contains($name)) { throw "Package file has no checksum: $name" }
    if ($name -match '(?i)(^|/)(config\.yaml|photon\.yaml|[^/]+\.(db|sqlite|sqlite3|key|pem|log))$') { throw "Unexpected private file in package: $name" }
}
foreach ($name in @('photon-windows.exe', 'wintun.dll')) {
    $file = Join-Path $OutputDirectory $name
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw "Required package file missing: $name" }
    if ($BackendDirectory) {
        $original = Join-Path $BackendDirectory $name
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash) { throw "Shared backend mismatch: $name" }
    }
}
if ($BackendDirectory -and !(Test-Path -LiteralPath (Join-Path $OutputDirectory 'FlClash.exe') -PathType Leaf)) { throw 'FlClash executable missing' }
if ($RunVersionChecks) {
    foreach ($name in @('photon-windows.exe', 'photon-windows-gui.exe')) {
        & (Join-Path $OutputDirectory $name) version
        if ($LASTEXITCODE -ne 0) { throw "Portable executable failed: $name" }
    }
}
Write-Output "Verified $($listed.Count) package files: $Archive"
