$ErrorActionPreference = 'Stop'
$env:PHOTON_WINDOWS_TUNNEL_CROSS_CONFIG = Join-Path $PSScriptRoot 'windows.json'
try {
    & (Join-Path $PSScriptRoot 'cross.test.exe') '-test.run=^TestWindowsStrongSwanCrossHost$' '-test.v' '-test.count=1' '-test.timeout=90s'
    $result = $LASTEXITCODE
} finally {
    Remove-Item Env:PHOTON_WINDOWS_TUNNEL_CROSS_CONFIG -ErrorAction SilentlyContinue
}
exit $result
