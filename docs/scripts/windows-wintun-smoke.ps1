$ErrorActionPreference = 'Stop'
$env:PHOTON_WINTUN_SMOKE = '1'
$env:PHOTON_IPHELPER_SMOKE = '1'
try {
    & (Join-Path $PSScriptRoot 'wintun.test.exe') '-test.run=^(TestWintunNative|TestIPHelper|TestConfiguredPacketDevice)' '-test.v' '-test.timeout=90s'
    $result = $LASTEXITCODE
} finally {
    Remove-Item Env:PHOTON_WINTUN_SMOKE -ErrorAction SilentlyContinue
    Remove-Item Env:PHOTON_IPHELPER_SMOKE -ErrorAction SilentlyContinue
}
exit $result
