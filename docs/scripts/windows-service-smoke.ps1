param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$FixtureDirectory
)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path $Executable).Path
$FixtureDirectory = (Resolve-Path $FixtureDirectory).Path
$Config = Join-Path $FixtureDirectory 'service.yaml'
$BadConfig = Join-Path $FixtureDirectory 'service-init-failure.yaml'
$name = 'PhotonB5-' + $PID + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$failedName = $name + '-InitFailure'
$collisionName = $name + '-ExistingSource'
$eventStart = Get-Date
$sourceParent = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application'
$collisionPath = Join-Path $sourceParent $collisionName
$collisionCreated = $false
$runFailure = $null
$created = @()
$ownedIndices = @()
function Quote-Yaml([string]$Value) { return "'" + $Value.Replace("'", "''") + "'" }
$fixture = Get-Content (Join-Path $FixtureDirectory 'config.json') -Raw | ConvertFrom-Json
$yaml = @(
    'schema_version: 1',
    ('trusted_root_public_key: ' + (Quote-Yaml $fixture.TrustedRootPublicKey)),
    ('managed_zone: ' + (Quote-Yaml $fixture.ManagedZone)),
    ('gossip_listen: ' + (Quote-Yaml $fixture.GossipListen)),
    'state:',
    ('  path: ' + (Quote-Yaml (Join-Path $FixtureDirectory 'windows.db'))),
    'overlay:',
    ('  id: ' + (Quote-Yaml $fixture.Overlay.ID)),
    '  split_routes:'
)
foreach ($route in $fixture.Overlay.SplitRoutes) { $yaml += '    - ' + (Quote-Yaml $route) }
$yaml += @('gateway:', '  allowed_zones:')
foreach ($zone in $fixture.Gateway.AllowedZones) { $yaml += '    - ' + (Quote-Yaml $zone) }
if ($fixture.Gateway.BootstrapHints.Count -gt 0) {
    $yaml += '  bootstrap_hints:'
    foreach ($hint in $fixture.Gateway.BootstrapHints) {
        $yaml += @(('    - peer: ' + (Quote-Yaml $hint.Peer)), ('      address: ' + (Quote-Yaml $hint.Address)))
    }
}
$yaml += @('wintun:', ('  adapter_name: ' + (Quote-Yaml $name)), '  mtu: 1400', 'log:', '  level: debug')
[IO.File]::WriteAllLines($Config, [string[]]$yaml, (New-Object Text.UTF8Encoding($false)))
$badYaml = $yaml | ForEach-Object { if ($_ -like '  path:*') { '  path: ' + (Quote-Yaml (Join-Path $FixtureDirectory 'missing-state.db')) } else { $_ } }
[IO.File]::WriteAllLines($BadConfig, [string[]]$badYaml, (New-Object Text.UTF8Encoding($false)))
function Invoke-Photon([string[]]$Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "photon-windows $Arguments exited $LASTEXITCODE" }
}
function Expect-PhotonFailure([string[]]$Arguments) {
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Executable @Arguments
        $result = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousErrorAction }
    if ($result -eq 0) { throw "Expected command failure: $Arguments" }
}
function Check-EventSource([string]$ServiceName) {
    $source = Get-ItemProperty (Join-Path $sourceParent $ServiceName)
    if ($source.PhotonWindowsOwner -ne 'photon-windows-event-source-v1') { throw 'Event Log source ownership marker is absent' }
    if ($source.TypesSupported -ne 7) { throw 'Event Log source does not support Error/Warning/Information' }
}
function Check-Events([string]$ServiceName, [int]$StartedCount, [int]$StoppedCount, [int]$FailedCount) {
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $events = @(Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName=$ServiceName; StartTime=$eventStart} -ErrorAction SilentlyContinue)
        $started = @($events | Where-Object { $_.Id -eq 101 -and $_.Level -eq 4 })
        $stopped = @($events | Where-Object { $_.Id -eq 103 -and $_.Level -eq 4 })
        $failed = @($events | Where-Object { $_.Id -eq 102 -and $_.Level -eq 2 })
        if ($started.Count -eq $StartedCount -and $stopped.Count -eq $StoppedCount -and $failed.Count -eq $FailedCount) {
            if (@($events | Where-Object { $_.Id -eq 104 }).Count -ne 0) { throw 'Unexpected runtime_stop_failed event' }
            $events | Select-Object TimeCreated, ProviderName, Id, Level, Message | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $FixtureDirectory ($ServiceName + '-events.json'))
            Write-Output "Event Log passed: source=$ServiceName started101=$($started.Count) stopped103=$($stopped.Count) failed102=$($failed.Count)"
            return
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Event Log mismatch: source=$ServiceName started=$($started.Count) stopped=$($stopped.Count) failed=$($failed.Count)"
}
function Read-Service([string]$ServiceName) {
    return Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
}
function Read-Status {
    $text = & $Executable status --config $Config
    if ($LASTEXITCODE -ne 0) { throw 'Live status IPC failed' }
    $response = $text | ConvertFrom-Json
    if ($response.version -ne 1 -or $response.error) { throw 'Invalid status response' }
    return $response.result
}
function Probe-UDP([string]$Local, [string]$Remote, [string]$Phase) {
    $deadline = [DateTime]::UtcNow.AddSeconds(40)
    $payload = [Text.Encoding]::UTF8.GetBytes("SCM-$Phase-$Remote")
    do {
        $udp = $null
        try {
            $localIP = [Net.IPAddress]::Parse($Local)
            $udp = New-Object Net.Sockets.UdpClient($localIP.AddressFamily)
            $udp.Client.Bind((New-Object Net.IPEndPoint($localIP, 0)))
            $udp.Client.ReceiveTimeout = 700
            $udp.Connect([Net.IPAddress]::Parse($Remote), 19096)
            [void]$udp.Send($payload, $payload.Length)
            $anyAddress = [Net.IPAddress]::Any
            if ($localIP.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $anyAddress = [Net.IPAddress]::IPv6Any }
            $sender = New-Object Net.IPEndPoint($anyAddress, 0)
            $reply = $udp.Receive([ref]$sender)
            if ([Convert]::ToBase64String($reply) -ne [Convert]::ToBase64String($payload)) { throw 'Unexpected echo payload' }
            Write-Output "business echo passed: $Phase $Local -> $Remote"
            return
        } catch { $lastFailure = $_.Exception.Message } finally { if ($udp) { $udp.Dispose() } }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Business echo timed out: $Phase $Local -> $Remote : $lastFailure"
}
function Check-Business([string]$Phase) {
    Probe-UDP '198.18.253.2' '198.18.253.1' $Phase
    Probe-UDP 'fd00:7068:b4::2' 'fd00:7068:b4::1' $Phase
    $status = Read-Status
    if (!$status.running -or !$status.tunnel_ready) { throw 'Business passed but daemon readiness is false' }
    Write-Output "live status: running=$($status.running) tunnel_ready=$($status.tunnel_ready)"
    foreach ($method in @('peers','routes','diagnostics')) {
        $text = & $Executable $method --config $Config
        if ($LASTEXITCODE -ne 0) { throw "Live $method IPC failed" }
        $response = $text | ConvertFrom-Json
        if ($response.version -ne 1 -or $response.method -ne $method -or $response.error -or $null -eq $response.result) { throw "Invalid $method response" }
        [IO.File]::WriteAllText((Join-Path $FixtureDirectory ($Phase + '-' + $method + '.json')), ($text -join "`n"))
    }
}
try {
    if ((Read-Service $name) -or (Read-Service $failedName)) { throw 'Refusing to reuse an existing service name' }
    $created += $name
    Invoke-Photon @('service','install','--name',$name,'--config',$Config)
    Check-EventSource $name
    $installed = Read-Service $name
    if ($installed.StartName -ne 'LocalSystem' -or $installed.State -ne 'Stopped') { throw 'Unexpected installed service account/state' }
    if ($installed.PathName -notlike '*run --service*' -or $installed.PathName -notlike "*$Config*") { throw 'Installed command line omitted SCM mode or config' }
    Write-Output "installed: $($installed.Name) account=$($installed.StartName) command=$($installed.PathName)"
    Invoke-Photon @('service','start','--name',$name)
    $running = Read-Service $name
    if ($running.State -ne 'Running' -or $running.ProcessId -eq 0) { throw 'Service never reached Running' }
    Write-Output "running: pid=$($running.ProcessId) (daemon initialized; tunnel readiness is independent)"
    $initialStatus = Read-Status
    Write-Output "initial live status: running=$($initialStatus.running) tunnel_ready=$($initialStatus.tunnel_ready)"
    Check-Business 'initial'
    $ownedIndices += (Get-NetAdapter -Name $name).ifIndex
    Invoke-Photon @('service','stop','--name',$name)
    $stopped = Read-Service $name
    if ($stopped.State -ne 'Stopped' -or $stopped.ExitCode -ne 0 -or $stopped.ServiceSpecificExitCode -ne 0) { throw 'Stop did not join cleanly' }
    Invoke-Photon @('service','start','--name',$name)
    Check-Business 'restart'
    $ownedIndices += (Get-NetAdapter -Name $name).ifIndex
    Invoke-Photon @('stop','--config',$Config)
    $stopDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $stopped = Read-Service $name
        if ($stopped.State -eq 'Stopped') { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $stopDeadline)
    if ($stopped.State -ne 'Stopped' -or $stopped.ExitCode -ne 0 -or $stopped.ServiceSpecificExitCode -ne 0) { throw 'IPC stop did not cleanly join SCM process' }
    Expect-PhotonFailure @('status','--config',$Config)
    Check-Events $name 2 2 0
    Invoke-Photon @('service','remove','--name',$name)
    if (Read-Service $name) { throw 'Service remains after removal' }
    Write-Output 'SCM install/start/stop/restart/remove passed'

    $created += $failedName
    Invoke-Photon @('service','install','--name',$failedName,'--config',$BadConfig)
    Check-EventSource $failedName
    Expect-PhotonFailure @('service','start','--name',$failedName)
    $failure = Read-Service $failedName
    if ($failure.State -ne 'Stopped' -or ($failure.ExitCode -eq 0 -and $failure.ServiceSpecificExitCode -eq 0)) { throw 'Initialization error did not exit as failed' }
    Write-Output "initialization failed as expected: Win32=$($failure.ExitCode) service=$($failure.ServiceSpecificExitCode)"
    Check-Events $failedName 0 0 1
    Invoke-Photon @('service','remove','--name',$failedName)
    if ((Read-Service $collisionName) -or (Test-Path $collisionPath)) { throw 'Refusing an existing collision-test resource' }
    [void](New-Item $collisionPath)
    $collisionCreated = $true
    [void](New-ItemProperty $collisionPath -Name 'FixtureOwner' -Value $name -PropertyType String)
    Expect-PhotonFailure @('service','install','--name',$collisionName,'--config',$Config)
    if (Read-Service $collisionName) { throw 'Event source collision did not roll back newly created SCM service' }
    if ((Get-ItemProperty $collisionPath).FixtureOwner -ne $name -or (Get-ItemProperty $collisionPath).PhotonWindowsOwner) { throw 'Existing unowned Event Log source was changed' }
    Write-Output 'Existing Event Log source preserved; failed install rolled back SCM registration'
} catch {
    $runFailure = $_
} finally {
    $cleanupFailures = @()
    foreach ($ownedName in $created) {
        try {
            $remaining = Read-Service $ownedName
            if ($remaining) {
                if ($remaining.State -ne 'Stopped') { Invoke-Photon @('service','stop','--name',$ownedName) }
                Invoke-Photon @('service','remove','--name',$ownedName)
            }
            if (Read-Service $ownedName) { throw "Temporary service cleanup failed: $ownedName" }
            if (Test-Path (Join-Path $sourceParent $ownedName)) { throw "Temporary Event Log source remains: $ownedName" }
        } catch { $cleanupFailures += $_.Exception.Message }
    }
    if ($collisionCreated) {
        try {
            if (Read-Service $collisionName) { Invoke-Photon @('service','remove','--name',$collisionName) }
            if ((Get-ItemProperty $collisionPath).FixtureOwner -ne $name) { throw 'Collision source ownership changed; refusing cleanup' }
            Remove-Item $collisionPath
            if (Test-Path $collisionPath) { throw 'Collision source cleanup failed' }
        } catch { $cleanupFailures += $_.Exception.Message }
    }
    try {
        if (Get-NetAdapter -Name $name -ErrorAction SilentlyContinue) { throw 'Temporary Wintun adapter remains after stop' }
        foreach ($index in ($ownedIndices | Select-Object -Unique)) {
            if (Get-NetIPAddress -InterfaceIndex $index -ErrorAction SilentlyContinue) { throw "Owned address remains on interface $index" }
            if (Get-NetRoute -InterfaceIndex $index -ErrorAction SilentlyContinue) { throw "Owned route remains on interface $index" }
        }
    } catch { $cleanupFailures += $_.Exception.Message }
    if ($cleanupFailures.Count -gt 0) {
        throw "SCM smoke failure: $runFailure; cleanup: $($cleanupFailures -join '; ')"
    }
}
if ($runFailure) { throw $runFailure }
Write-Output 'Temporary SCM services removed'
