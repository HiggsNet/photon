$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$originalLocation = Get-Location
try {
    Write-Output ('Windows version: ' + [Environment]::OSVersion.Version)
    foreach ($package in @('internal/photonwindows', 'app/photon-windows', 'internal/photonclient/ike')) {
        Set-Location (Join-Path $root $package)
        Write-Output ('Testing ' + $package)
        & '.\native.test.exe' '-test.v' '-test.timeout=120s'
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
} finally {
    Set-Location $originalLocation
}
