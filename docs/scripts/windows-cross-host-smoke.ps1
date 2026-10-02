param([Parameter(Mandatory=$true)][string]$LinuxAddress, [Parameter(Mandatory=$true)][int]$Port)
$ErrorActionPreference = 'Stop'
$rule = 'PhotonCrossHost-' + (Split-Path $PSScriptRoot -Leaf)
try {
    foreach ($protocol in @('UDP', 'TCP')) {
        New-NetFirewallRule -Name ($rule + '-' + $protocol) -DisplayName ($rule + '-' + $protocol) -Direction Inbound -Action Allow -Protocol $protocol -LocalPort $Port -RemoteAddress $LinuxAddress | Out-Null
    }
    $env:PHOTON_CROSS_ROLE = 'windows'
    $env:PHOTON_CROSS_DIR = $PSScriptRoot
    & (Join-Path $PSScriptRoot 'cross.test.exe') '-test.run=^TestCrossHostGossip$' '-test.v' '-test.timeout=90s'
    $result = $LASTEXITCODE
} finally {
    foreach ($protocol in @('UDP', 'TCP')) {
        Get-NetFirewallRule -Name ($rule + '-' + $protocol) -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
}
exit $result
