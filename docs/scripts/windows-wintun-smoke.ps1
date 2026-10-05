$ErrorActionPreference = 'Stop'
$env:PHOTON_WINTUN_SMOKE = '1'
try {
    & (Join-Path $PSScriptRoot 'wintun.test.exe') '-test.run=^TestWintunNativeLifecycle$' '-test.v' '-test.timeout=45s'
    $result = $LASTEXITCODE
} finally {
    Remove-Item Env:PHOTON_WINTUN_SMOKE -ErrorAction SilentlyContinue
}
exit $result
