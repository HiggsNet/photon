$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$verify = Join-Path $PSScriptRoot 'windows-portable-verify.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ('photon-package-verification-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$script:passed = 0
function New-Fixture([string]$FixtureName, [hashtable]$Files, [string]$Manifest) {
    $archive = Join-Path $root ($FixtureName + '.zip')
    if (!$Manifest) {
        $Manifest = (@(foreach ($name in $Files.Keys) {
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Files[$name]))).Replace('-', '').ToLowerInvariant() }
            finally { $sha.Dispose() }
            "$hash  $name"
        }) -join "`n")
    }
    $content = $Files.Clone()
    $content['SHA256SUMS'] = $Manifest
    $zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $content.Keys) {
            $stream = $zip.CreateEntry($name).Open()
            try {
                $bytes = [Text.Encoding]::UTF8.GetBytes($content[$name])
                $stream.Write($bytes, 0, $bytes.Length)
            } finally { $stream.Dispose() }
        }
    } finally { $zip.Dispose() }
    $checksum = $archive + '.sha256'
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $FixtureName.zip" | Set-Content -Encoding ascii $checksum
    return @{Archive=$archive; Checksum=$checksum; OutputDirectory=(Join-Path $root ($FixtureName + '-unpacked'))}
}
function Expect-Rejection([scriptblock]$Action, [string]$Message) {
    try {
        & $Action
        throw 'Invalid package was accepted'
    } catch {
        if ($_.Exception.Message -notlike $Message) { throw }
        $script:passed++
    }
}
try {
    $files = @{'photon-windows.exe'='backend'; 'wintun.dll'='driver'; 'FlClash.exe'='frontend'}
    $fixture = New-Fixture 'valid' $files
    & $verify @fixture
    $script:passed++

    $fixture = New-Fixture 'bad-archive' $files
    (('0' * 64) + '  bad-archive.zip') | Set-Content -Encoding ascii $fixture.Checksum
    Expect-Rejection { & $verify @fixture } 'Archive checksum mismatch'

    $fixture = New-Fixture 'bad-manifest' $files (('0' * 64) + '  photon-windows.exe')
    Expect-Rejection { & $verify @fixture } 'Package checksum mismatch:*'

    $fixture = New-Fixture 'unlisted' $files
    $zip = [IO.Compression.ZipFile]::Open($fixture.Archive, [IO.Compression.ZipArchiveMode]::Update)
    try { $zip.CreateEntry('unexpected.txt') | Out-Null } finally { $zip.Dispose() }
    $hash = (Get-FileHash -LiteralPath $fixture.Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  unlisted.zip" | Set-Content -Encoding ascii $fixture.Checksum
    Expect-Rejection { & $verify @fixture } 'Package file has no checksum:*'

    $private = $files.Clone()
    $private['config.yaml'] = 'private configuration'
    $fixture = New-Fixture 'private' $private
    Expect-Rejection { & $verify @fixture } 'Unexpected private file in package:*'

    $traversal = $files.Clone()
    $traversal['../escape.txt'] = 'outside archive'
    $fixture = New-Fixture 'traversal' $traversal
    Expect-Rejection { & $verify @fixture } 'Invalid archive path:*'
    if (Test-Path -LiteralPath (Join-Path $root 'escape.txt')) { throw 'Archive escaped extraction directory' }

    $fixture = New-Fixture 'wrong-backend' $files
    $backend = Join-Path $root 'backend'
    New-Item -ItemType Directory -Path $backend | Out-Null
    [IO.File]::WriteAllText((Join-Path $backend 'photon-windows.exe'), 'different backend')
    Expect-Rejection { & $verify @fixture -BackendDirectory $backend } 'Shared backend mismatch:*'
    Write-Output "WINDOWS_PORTABLE_VERIFY_PASS ($script:passed cases)"
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
