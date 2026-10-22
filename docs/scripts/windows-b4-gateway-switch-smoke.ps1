$ErrorActionPreference = 'Stop'
$env:PHOTON_WINDOWS_B4_SWITCH_CONFIG = $PSScriptRoot
try {
    & (Join-Path $PSScriptRoot 'b4.test.exe') '-test.run=^TestWindowsB4GatewaySwitch$' '-test.v' '-test.count=1' '-test.timeout=170s'
    $result = $LASTEXITCODE
} finally {
    Remove-Item Env:PHOTON_WINDOWS_B4_SWITCH_CONFIG -ErrorAction SilentlyContinue
}
exit $result
