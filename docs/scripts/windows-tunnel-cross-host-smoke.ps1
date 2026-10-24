$ErrorActionPreference = 'Stop'
$env:PHOTON_WINDOWS_TUNNEL_CROSS_CONFIG = Join-Path $PSScriptRoot 'windows.json'
try {
    $testTimeout = if ($env:PHOTON_WINDOWS_TIMED_REKEY_SMOKE -eq '1') { '8m' } else { '90s' }
    & (Join-Path $PSScriptRoot 'cross.test.exe') '-test.run=^TestWindowsStrongSwanCrossHost$' '-test.v' '-test.count=1' ("-test.timeout=" + $testTimeout)
    $result = $LASTEXITCODE
} finally {
    Remove-Item Env:PHOTON_WINDOWS_TUNNEL_CROSS_CONFIG -ErrorAction SilentlyContinue
}
exit $result
