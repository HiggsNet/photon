[CmdletBinding(DefaultParameterSetName='Directory')]
param(
    [Parameter(Mandatory=$true)][string]$Checkout,
    [Parameter(Mandatory=$true)][string]$BackendDirectory,
    [Parameter(Mandatory=$true, ParameterSetName='Directory')][string]$OutputDirectory,
    [Parameter(Mandatory=$true, ParameterSetName='Archive')][string]$ArchivePath,
    [string]$SigningCertificateThumbprint = $env:PHOTON_FLCLASH_SIGNING_THUMBPRINT
)
$ErrorActionPreference = 'Stop'
$Checkout = (Resolve-Path -LiteralPath $Checkout).Path
$BackendDirectory = (Resolve-Path -LiteralPath $BackendDirectory).Path
$stage = $null
if ($ArchivePath) {
    $ArchivePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ArchivePath)
    if ([IO.Path]::GetExtension($ArchivePath) -ne '.zip' -or (Test-Path -LiteralPath $ArchivePath -PathType Container)) {
        throw 'ArchivePath must name a ZIP file'
    }
    $stage = Join-Path (Split-Path -Parent $ArchivePath) ('.flclash-' + [Guid]::NewGuid().ToString('N'))
    $OutputDirectory = Join-Path $stage 'bundle'
} else {
    $OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
}
$signTool = $null
$signedDirectory = $null
if ($SigningCertificateThumbprint) {
    if ($SigningCertificateThumbprint -notmatch '^[0-9a-fA-F]{40}$') {
        throw 'SigningCertificateThumbprint must be a 40-digit certificate thumbprint'
    }
    $certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$SigningCertificateThumbprint" -ErrorAction SilentlyContinue
    if (!$certificate) { throw 'The selected code signing certificate is missing from the CurrentUser\My store' }
    if (!$certificate.HasPrivateKey) { throw 'The selected code signing certificate has no accessible private key' }
    $signTool = (Get-Command signtool.exe -CommandType Application).Source
    if (!$stage) {
        if (Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory must be new' }
        $signedDirectory = $OutputDirectory
        $stage = Join-Path (Split-Path -Parent $signedDirectory) ('.flclash-' + [Guid]::NewGuid().ToString('N'))
        $OutputDirectory = Join-Path $stage 'bundle'
    }
}
$lock = @{}
Get-Content -LiteralPath (Join-Path $PSScriptRoot 'upstream.env') | ForEach-Object {
    if ($_ -match '^([A-Z_]+)=(.+)$') { $lock[$matches[1]] = $matches[2] }
}
function Check-Exit([string]$Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed: $LASTEXITCODE" }
}
function Invoke-BuildTool([string]$Program, [string[]]$ToolArguments) {
    # Windows PowerShell 5 can promote successful native stderr progress to an error.
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Program @ToolArguments
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    if ($code -ne 0) { throw "$Program failed: $code" }
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory must be new' }
if ((Get-Content -LiteralPath (Join-Path $Checkout '.photon-flclash') -Raw).Trim() -cne $lock.FLCLASH_COMMIT) { throw 'Checkout was not prepared by Photon' }
$head = & git -C $Checkout rev-parse HEAD
Check-Exit 'Read FlClash revision'
if ($head -cne $lock.FLCLASH_COMMIT) { throw 'FlClash revision mismatch' }
& git -C $Checkout apply --reverse --check (Join-Path $PSScriptRoot 'patches\photon.patch')
Check-Exit 'Verify Photon integration patch'
foreach ($dependency in @(@('core/Clash.Meta','FLCLASH_MIHOMO_COMMIT'), @('plugins/prism_ui','FLCLASH_PRISM_COMMIT'))) {
    $revision = & git -C (Join-Path $Checkout $dependency[0]) rev-parse HEAD
    Check-Exit 'Read dependency revision'
    if ($revision -cne $lock[$dependency[1]]) { throw 'Dependency revision mismatch' }
    & git -C (Join-Path $Checkout $dependency[0]) diff --quiet HEAD
    Check-Exit 'Verify dependency sources'
}
foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'overlay') -File -Recurse)) {
    $relative = $file.FullName.Substring((Join-Path $PSScriptRoot 'overlay').Length + 1)
    $staged = Join-Path $Checkout $relative
    if (!(Test-Path -LiteralPath $staged) -or (Get-FileHash -LiteralPath $staged).Hash -cne (Get-FileHash -LiteralPath $file.FullName).Hash) { throw "Integration source mismatch: $relative" }
}
$version = (& flutter --version --machine | Out-String | ConvertFrom-Json)
Check-Exit 'Read Flutter version'
if ($version.frameworkVersion -cne $lock.FLCLASH_FLUTTER_VERSION -or $version.frameworkRevision -cne $lock.FLCLASH_FLUTTER_COMMIT) { throw 'Flutter version mismatch' }
$goVersion = & go env GOVERSION
Check-Exit 'Read Go version'
if ($goVersion -cne ('go' + $lock.FLCLASH_GO_VERSION)) { throw 'FlClash Go version mismatch' }
$rustVersion = & rustc --version
Check-Exit 'Read Rust version'
if ($rustVersion -notmatch ('^rustc ' + [regex]::Escape($lock.FLCLASH_RUST_VERSION) + ' ')) { throw 'FlClash Rust version mismatch' }
if ((Get-Content -LiteralPath (Join-Path $Checkout 'pubspec.yaml') -Raw) -match 'build_assets:\s*false') { throw 'Native build hooks must be enabled for packaging' }
foreach ($name in @('photon-windows.exe','wintun.dll')) {
    if (!(Test-Path -LiteralPath (Join-Path $BackendDirectory $name) -PathType Leaf)) { throw "Missing $name" }
}
$notices = @('wintun\README.md', 'wintun\LICENSE-go.txt', 'wintun\LICENSE-binary.txt', 'ranet-lite\README.md', 'ranet-lite\LICENSE')
foreach ($notice in $notices) {
    if (!(Test-Path -LiteralPath (Join-Path $BackendDirectory ('third_party\' + $notice)) -PathType Leaf)) { throw "Missing backend notice: $notice" }
}
Push-Location $Checkout
try {
    Invoke-BuildTool 'flutter' @('pub', 'get')
    Invoke-BuildTool 'dart' @('run', 'intl_utils:generate')
    Invoke-BuildTool 'flutter' @('build', 'windows', '--release')
    $bundle = Join-Path $Checkout 'build\windows\x64\runner\Release'
    if (!(Test-Path -LiteralPath (Join-Path $bundle 'FlClash.exe'))) { throw 'Windows x64 bundle missing' }
    if ($stage) { [IO.Directory]::CreateDirectory($stage) | Out-Null }
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    Copy-Item -Path (Join-Path $bundle '*') -Destination $OutputDirectory -Recurse
    foreach ($name in @('photon-windows.exe','wintun.dll')) {
        Copy-Item -LiteralPath (Join-Path $BackendDirectory $name) -Destination $OutputDirectory
    }
    Copy-Item -LiteralPath (Join-Path $Checkout 'LICENSE') -Destination (Join-Path $OutputDirectory 'LICENSE.FlClash')
    foreach ($notice in $notices) {
        $destination = Join-Path $OutputDirectory ('third_party\' + $notice)
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $BackendDirectory ('third_party\' + $notice)) -Destination $destination
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination (Join-Path $OutputDirectory 'README.Photon.md')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'upstream.env') -Destination $OutputDirectory
    if ($signTool) {
        $binaries = Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse |
            Where-Object { $_.Extension -in '.exe', '.dll' }
        foreach ($binary in $binaries) {
            $signature = Get-AuthenticodeSignature -LiteralPath $binary.FullName
            if ($signature.Status -eq 'NotSigned' -or $signature.SignatureType -eq 'Catalog') {
                Invoke-BuildTool $signTool @(
                    'sign', '/sha1', $SigningCertificateThumbprint, '/fd', 'SHA256',
                    '/tr', 'http://timestamp.digicert.com', '/td', 'SHA256', $binary.FullName
                )
                Invoke-BuildTool $signTool @('verify', '/pa', '/tw', $binary.FullName)
            } else {
                Invoke-BuildTool $signTool @('verify', '/pa', $binary.FullName)
            }
        }
    } else {
        Write-Warning 'This preview bundle has no Photon publisher signature. Set PHOTON_FLCLASH_SIGNING_THUMBPRINT for signed distribution.'
    }
    $hashes = @(Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse | Sort-Object FullName | ForEach-Object {
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.FullName.Substring((Get-Item -LiteralPath $OutputDirectory).FullName.Length + 1).Replace('\','/')
    })
    $hashes | Set-Content -Encoding ASCII (Join-Path $OutputDirectory 'SHA256SUMS')
    if ($ArchivePath) {
        $stagedZip = Join-Path $stage 'portable.zip'
        Compress-Archive -Path (Join-Path $OutputDirectory '*') -DestinationPath $stagedZip
        Move-Item -LiteralPath $stagedZip -Destination $ArchivePath -Force
        Write-Output "Prepared Windows ZIP: $ArchivePath"
    } else {
        if ($signedDirectory) {
            [IO.Directory]::Move($OutputDirectory, $signedDirectory)
            $OutputDirectory = $signedDirectory
        }
        Write-Output "Prepared Windows bundle: $OutputDirectory"
    }
} finally {
    Pop-Location
    if ($stage -and (Test-Path -LiteralPath $stage)) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
