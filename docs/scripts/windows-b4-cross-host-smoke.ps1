$ErrorActionPreference = 'Stop'
$env:PHOTON_WINDOWS_B4_CONFIG = $PSScriptRoot
try {
    & (Join-Path $PSScriptRoot 'b4.test.exe') '-test.run=^TestWindowsB4DaemonCrossHost$' '-test.v' '-test.count=1' '-test.timeout=240s'
    $result = $LASTEXITCODE
} finally {
    Remove-Item Env:PHOTON_WINDOWS_B4_CONFIG -ErrorAction SilentlyContinue
}
exit $result
