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
$networkAddressOwned = $false
$networkAddress = $null
$networkIndex = $null
$gossipEvidence = $null
$gossipConvergedRevision = $null
$gossipEvidencePath = Join-Path $FixtureDirectory 'gossip-evidence.json'
if (Test-Path $gossipEvidencePath) {
    $gossipEvidence = Get-Content $gossipEvidencePath -Raw | ConvertFrom-Json
    if (!$gossipEvidence.gateway -or !$gossipEvidence.missing_record -or $null -eq $gossipEvidence.initial_revision) { throw 'Incomplete remote Gossip fixture evidence' }
}
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
function Read-OwnedProcess {
    $service = Read-Service $name
    if (!$service -or $service.State -ne 'Running' -or $service.ProcessId -eq 0 -or $service.StartName -ne 'LocalSystem') { throw 'Owned SCM service is not running as LocalSystem' }
    $process = Get-Process -Id $service.ProcessId
    $details = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
    if (!$details -or $details.ExecutablePath -ne $Executable -or $details.CommandLine -notlike "*$Config*" -or $details.CommandLine -notlike "*$name*") { throw 'Refusing to terminate a process not owned by this fixture service/config' }
    if ($process.StartTime -lt $eventStart) { throw 'Refusing to terminate a pre-existing process' }
    $current = Read-Service $name
    if ($current.ProcessId -ne $process.Id -or $current.State -ne 'Running') { throw 'SCM process changed during ownership check' }
    return $process
}
function Read-StateFileIdentity {
    $path = Join-Path $FixtureDirectory 'windows.db'
    $identity = & fsutil.exe file queryfileid $path
    if ($LASTEXITCODE -ne 0 -or !$identity) { throw 'Cannot establish fixture Bolt file identity' }
    $fileIDs = [regex]::Matches(($identity -join "`n"), '(?i)\b0x[0-9a-f]+\b')
    if ($fileIDs.Count -ne 1) { throw 'Cannot extract an unambiguous native Bolt file ID' }
    return $fileIDs[0].Value.ToLowerInvariant()
}
function Save-OwnedNetworkSnapshot([string]$Phase) {
    # Query only the unique fixture adapter name; do not collect or alter the
    # management interface, or infer ownership from a destination prefix.
    $adapters = @(Get-NetAdapter -Name $name -IncludeHidden -ErrorAction SilentlyContinue)
    $interfaces = @()
    foreach ($adapter in $adapters) {
        $interfaces += [pscustomobject]@{
            Name = $adapter.Name
            InterfaceGuid = [string]$adapter.InterfaceGuid
            InterfaceIndex = $adapter.ifIndex
            Status = [string]$adapter.Status
            Addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Select-Object IPAddress, PrefixLength, AddressFamily)
            Routes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, RouteMetric, AddressFamily)
        }
    }
    $service = Read-Service $name
    [pscustomobject]@{
        Phase = $Phase
        ObservedAt = [DateTime]::UtcNow.ToString('o')
        ServiceState = $service.State
        ProcessId = $service.ProcessId
        ExitCode = $service.ExitCode
        ServiceSpecificExitCode = $service.ServiceSpecificExitCode
        Interfaces = $interfaces
    } | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $FixtureDirectory ($Phase + '-owned-network.json'))
    Write-Output "owned network snapshot: phase=$Phase adapters=$($adapters.Count) SCM=$($service.State) exit=$($service.ExitCode)"
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
    if ($gossipEvidence) {
        if ([uint64]$status.revision -le [uint64]$gossipEvidence.initial_revision) { throw 'Ready daemon did not advance beyond the deliberately incomplete initial database' }
        if ($null -ne $script:gossipConvergedRevision -and [uint64]$status.revision -lt $script:gossipConvergedRevision) { throw 'Restart lost the previously synchronized database revision' }
    }
    Write-Output "live status: running=$($status.running) tunnel_ready=$($status.tunnel_ready)"
    foreach ($method in @('peers','routes','diagnostics')) {
        $text = & $Executable $method --config $Config
        if ($LASTEXITCODE -ne 0) { throw "Live $method IPC failed" }
        $response = $text | ConvertFrom-Json
        if ($response.version -ne 1 -or $response.method -ne $method -or $response.error -or $null -eq $response.result) { throw "Invalid $method response" }
        if ($method -eq 'peers' -and $gossipEvidence -and $null -eq $script:gossipConvergedRevision) {
            $synchronizedPeer = @($response.result.peers | Where-Object { $_.peer -eq $gossipEvidence.gateway -and $_.pull_successes -gt 0 })
            if ($synchronizedPeer.Count -ne 1) { throw 'Initial business readiness lacks a successful real gateway Gossip pull' }
            $script:gossipConvergedRevision = [uint64]$status.revision
            [pscustomobject]@{
                Gateway = $gossipEvidence.gateway
                InitiallyMissingRecord = $gossipEvidence.missing_record
                InitialRevision = $gossipEvidence.initial_revision
                ConvergedRevision = $script:gossipConvergedRevision
                Peer = $synchronizedPeer[0]
            } | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $FixtureDirectory 'gossip-convergence.json')
            Write-Output "remote Gossip convergence passed: peer=$($gossipEvidence.gateway) revision=$($gossipEvidence.initial_revision) -> $script:gossipConvergedRevision pulls=$($synchronizedPeer[0].pull_successes)"
        }
        [IO.File]::WriteAllText((Join-Path $FixtureDirectory ($Phase + '-' + $method + '.json')), ($text -join "`n"))
    }
}
function Remove-OwnedNetworkAddress {
    if (!$script:networkAddressOwned) { return }
    $addresses = @(Get-NetIPAddress -InterfaceIndex $networkIndex -IPAddress $networkAddress -ErrorAction SilentlyContinue)
    foreach ($address in $addresses) {
        if ($address.PrefixLength -ne 32 -or !$address.SkipAsSource) { throw 'Temporary loopback address properties changed; refusing cleanup' }
        Remove-NetIPAddress -InterfaceIndex $networkIndex -IPAddress $networkAddress -PolicyStore ActiveStore -Confirm:$false
    }
    if (Get-NetIPAddress -InterfaceIndex $networkIndex -IPAddress $networkAddress -ErrorAction SilentlyContinue) { throw 'Temporary loopback address remains' }
    if (Get-NetRoute -InterfaceIndex $networkIndex -DestinationPrefix ($networkAddress + '/32') -ErrorAction SilentlyContinue) { throw 'Temporary loopback host route remains' }
    $script:networkAddressOwned = $false
}
function Wait-NetworkRecovery([string]$Phase, $Before, [int]$ServiceProcessId, [DateTime]$TriggeredAt) {
    $deadline = [DateTime]::UtcNow.AddSeconds(40)
    do {
        $process = Read-OwnedProcess
        if ($process.Id -ne $ServiceProcessId) { throw 'Network notification restarted SCM instead of rebinding the existing daemon' }
        $status = Read-Status
        if ($status.tunnel_ready -and $status.ike.live -and $status.ike.child_live -and [uint64]$status.ike.generation -gt [uint64]$Before.ike.generation -and $status.ike.expires_at -ne $Before.ike.expires_at -and $status.ike.child_expires_at -ne $Before.ike.child_expires_at) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if (!$status.tunnel_ready -or !$status.ike.live -or !$status.ike.child_live -or [uint64]$status.ike.generation -le [uint64]$Before.ike.generation -or $status.ike.expires_at -eq $Before.ike.expires_at -or $status.ike.child_expires_at -eq $Before.ike.child_expires_at) { throw "Network notification did not rebuild live IKE/CHILD within the observation timeout: $Phase" }
    Check-Business $Phase | Out-Host
    $script:ownedIndices += (Get-NetAdapter -Name $name).ifIndex
    $completed = [DateTime]::UtcNow
    Write-Host "network change recovered: $Phase pid=$ServiceProcessId generation=$($Before.ike.generation) -> $($status.ike.generation) observed_ms=$(($completed - $TriggeredAt).TotalMilliseconds)"
    return [pscustomobject]@{
        Phase = $Phase
        ProcessId = $ServiceProcessId
        TriggeredAt = $TriggeredAt.ToString('o')
        CompletedAt = $completed.ToString('o')
        ObservationMilliseconds = ($completed - $TriggeredAt).TotalMilliseconds
        BeforeIKE = $Before.ike
        AfterIKE = $status.ike
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

    # Kill only the exact SCM-owned process after real bidirectional business.
    # This deliberately skips Daemon.Stop and tests recovery of the same Bolt
    # database, pipe endpoint, Wintun adapter name and split-route intent.
    $beforeCrash = Read-Status
    if (!$beforeCrash.ike.live -or !$beforeCrash.ike.child_live) { throw 'Crash precondition requires live IKE and CHILD' }
    $stateFileIdentity = Read-StateFileIdentity
    $crashProcess = Read-OwnedProcess
    $crashProcessId = $crashProcess.Id
    $crashProcessStart = $crashProcess.StartTime.ToUniversalTime()
    Save-OwnedNetworkSnapshot 'before-crash'
    Stop-Process -InputObject $crashProcess -Force
    if (!$crashProcess.WaitForExit(10000)) { throw 'Owned process did not terminate' }
    $stopDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $crashed = Read-Service $name
        if ($crashed.State -eq 'Stopped') { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $stopDeadline)
    if ($crashed.State -ne 'Stopped' -or ($crashed.ExitCode -eq 0 -and $crashed.ServiceSpecificExitCode -eq 0)) { throw 'Forced process termination was not reported as an abnormal SCM stop' }
    Save-OwnedNetworkSnapshot 'after-crash'
    Expect-PhotonFailure @('status','--config',$Config)
    Check-Events $name 2 1 0
    Write-Output "forced crash confirmed: pid=$crashProcessId SCM=$($crashed.State) Win32=$($crashed.ExitCode) service=$($crashed.ServiceSpecificExitCode), no graceful runtime_stopped event"

    Invoke-Photon @('service','start','--name',$name)
    $recoveredProcess = Read-OwnedProcess
    if ($recoveredProcess.StartTime.ToUniversalTime() -le $crashProcessStart) { throw 'SCM did not create a new process lifetime after crash' }
    $recovering = Read-Status
    Write-Output "post-crash initialized: pid=$($recoveredProcess.Id) running=$($recovering.running) tunnel_ready=$($recovering.tunnel_ready)"
    Check-Business 'crash-recovery'
    $afterCrash = Read-Status
    if (!$afterCrash.ike.live -or !$afterCrash.ike.child_live -or $afterCrash.ike.generation -lt 1) { throw 'Recovered daemon has no live IKE/CHILD generation' }
    # Generation is process-local and may reset. Compare process lifetime and
    # both SA leases; do not mistake equal numeric counters for an old SA.
    if ($afterCrash.ike.expires_at -eq $beforeCrash.ike.expires_at -or $afterCrash.ike.child_expires_at -eq $beforeCrash.ike.child_expires_at) { throw 'Crash recovery reused old IKE/CHILD lease evidence' }
    if ((Read-StateFileIdentity) -ne $stateFileIdentity) { throw 'Crash recovery replaced the fixture Bolt database' }
    $ownedIndices += (Get-NetAdapter -Name $name).ifIndex
    Save-OwnedNetworkSnapshot 'after-crash-recovery'
    [pscustomobject]@{
        BeforeProcessId = $crashProcessId
        BeforeProcessStart = $crashProcessStart.ToString('o')
        AfterProcessId = $recoveredProcess.Id
        AfterProcessStart = $recoveredProcess.StartTime.ToUniversalTime().ToString('o')
        StateFileIdentity = $stateFileIdentity
        BeforeIKE = $beforeCrash.ike
        AfterIKE = $afterCrash.ike
    } | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $FixtureDirectory 'crash-recovery.json')
    Write-Output "crash recovery passed: pid=$crashProcessId -> $($recoveredProcess.Id), fresh IKE/CHILD, same Bolt file, dual-stack business"

    # Trigger actual IPHelper notifications without changing the management
    # NIC or a default route. .NET's loopback type is the native type 24; reject
    # ambiguity before selecting its IPv4 index. The host address is never a
    # source candidate and lives only in ActiveStore for this test.
    $loopbacks = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { [int]$_.NetworkInterfaceType -eq 24 })
    if ($loopbacks.Count -ne 1) { throw 'Expected one concrete type-24 loopback interface' }
    $networkIndex = $loopbacks[0].GetIPProperties().GetIPv4Properties().Index
    $loopbackIP = @(Get-NetIPInterface -InterfaceIndex $networkIndex -AddressFamily IPv4)
    if ($loopbackIP.Count -ne 1 -or $loopbackIP[0].Dhcp -ne 'Disabled') { throw 'Refusing a non-static or ambiguous IPv4 loopback row' }
    for ($attempt = 0; $attempt -lt 32; $attempt++) {
        $candidate = '192.0.2.' + (Get-Random -Minimum 1 -Maximum 255)
        if (!(Get-NetIPAddress -IPAddress $candidate -ErrorAction SilentlyContinue) -and !(Get-NetRoute -DestinationPrefix ($candidate + '/32') -ErrorAction SilentlyContinue)) { $networkAddress = $candidate; break }
    }
    if (!$networkAddress) { throw 'No unused TEST-NET host address for isolated network change' }
    $beforeNetwork = Read-Status
    $networkProcess = Read-OwnedProcess
    $triggeredAt = [DateTime]::UtcNow
    $networkAddressOwned = $true # Also clean up a partially applied cmdlet.
    New-NetIPAddress -InterfaceIndex $networkIndex -IPAddress $networkAddress -PrefixLength 32 -SkipAsSource $true -PolicyStore ActiveStore | Out-Null
    $added = Wait-NetworkRecovery 'network-address-added' $beforeNetwork $networkProcess.Id $triggeredAt
    $beforeRemoval = Read-Status
    $removedAt = [DateTime]::UtcNow
    Remove-OwnedNetworkAddress
    $removed = Wait-NetworkRecovery 'network-address-removed' $beforeRemoval $networkProcess.Id $removedAt
    [pscustomobject]@{
        InterfaceType = 24
        InterfaceIndex = $networkIndex
        Address = $networkAddress
        PrefixLength = 32
        SkipAsSource = $true
        PolicyStore = 'ActiveStore'
        Added = $added
        Removed = $removed
    } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $FixtureDirectory 'network-change.json')
    Invoke-Photon @('stop','--config',$Config)
    $stopDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $stopped = Read-Service $name
        if ($stopped.State -eq 'Stopped') { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $stopDeadline)
    if ($stopped.State -ne 'Stopped' -or $stopped.ExitCode -ne 0 -or $stopped.ServiceSpecificExitCode -ne 0) { throw 'IPC stop did not cleanly join SCM process' }
    Expect-PhotonFailure @('status','--config',$Config)
    Check-Events $name 3 2 0
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
    try { Remove-OwnedNetworkAddress } catch { $cleanupFailures += $_.Exception.Message }
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
