param(
    [Parameter(Mandatory=$true)][string]$Checkout,
    [Parameter(Mandatory=$true)][string]$BackendDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$Checkout = (Resolve-Path -LiteralPath $Checkout).Path
$BackendDirectory = (Resolve-Path -LiteralPath $BackendDirectory).Path
$OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$lock = @{}
Get-Content -LiteralPath (Join-Path $PSScriptRoot 'upstream.env') | ForEach-Object {
    if ($_ -match '^([A-Z_]+)=(.+)$') { $lock[$matches[1]] = $matches[2] }
}
function Check-Exit([string]$Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed: $LASTEXITCODE" }
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
if ((Get-Content -LiteralPath (Join-Path $Checkout 'pubspec.yaml') -Raw) -match 'build_assets:\s*false') { throw 'Native build hooks must be enabled for packaging' }
foreach ($name in @('photon-windows.exe','wintun.dll')) {
    if (!(Test-Path -LiteralPath (Join-Path $BackendDirectory $name) -PathType Leaf)) { throw "Missing $name" }
}
Push-Location $Checkout
try {
    & flutter pub get
    Check-Exit 'Flutter dependencies'
    & dart run intl_utils:generate
    Check-Exit 'Generate localizations'
    & flutter build windows --release
    Check-Exit 'Windows release build'
    $bundle = Join-Path $Checkout 'build\windows\x64\runner\Release'
    if (!(Test-Path -LiteralPath (Join-Path $bundle 'FlClash.exe'))) { throw 'Windows x64 bundle missing' }
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    Copy-Item -Path (Join-Path $bundle '*') -Destination $OutputDirectory -Recurse
    foreach ($name in @('photon-windows.exe','wintun.dll')) {
        Copy-Item -LiteralPath (Join-Path $BackendDirectory $name) -Destination $OutputDirectory
    }
    Copy-Item -LiteralPath (Join-Path $Checkout 'LICENSE') -Destination (Join-Path $OutputDirectory 'LICENSE.FlClash')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'upstream.env') -Destination $OutputDirectory
    $hashes = @(Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse | Sort-Object FullName | ForEach-Object {
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.FullName.Substring((Get-Item -LiteralPath $OutputDirectory).FullName.Length + 1).Replace('\','/')
    })
    $hashes | Set-Content -Encoding ASCII (Join-Path $OutputDirectory 'SHA256SUMS')
} finally { Pop-Location }
Write-Output "Prepared Windows bundle: $OutputDirectory"
