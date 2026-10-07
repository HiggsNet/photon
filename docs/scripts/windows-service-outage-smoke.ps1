# Dot-sourced only by the full-daemon fixture when its Linux coordinator is active.
# Existing service helper functions and the exact owned service/config stay in scope.
function Test-GatewayTransportOutage {
    $before = Read-Status
    $owner = Read-OwnedProcess
    if (!$before.running -or !$before.tunnel_ready -or !$before.ike.live -or !$before.ike.child_live) { throw 'Outage requires an established business tunnel' }
    $samples = New-Object System.Collections.Generic.List[object]
    $probes = New-Object System.Collections.Generic.List[object]
    $request = Join-Path $FixtureDirectory 'outage-request.txt'
    $restoreRequested = $false
    $runtimeLog = Join-Path $FixtureDirectory 'windows.db.log'
    $logBefore = [string](Get-Content -LiteralPath $runtimeLog -Raw)
    function Check-OutageOwner {
        $current = Read-OwnedProcess
        if ($current.Id -ne $owner.Id -or $current.FixtureStartedAtUtc -ne $owner.FixtureStartedAtUtc) { throw 'SCM process changed during transport outage' }
    }
    function Wait-OutageAck([string]$Phase) {
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        $path = Join-Path $FixtureDirectory ('outage-' + $Phase + '.ack')
        do {
            Check-OutageOwner
            if ((Test-Path $path) -and (Get-Content $path -Raw).Trim() -eq $Phase) { return }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $deadline)
        throw "Linux coordinator did not acknowledge $Phase"
    }
    function Expect-NoOutageEcho([string]$Local, [string]$Remote, [bool]$RequireLiveSend = $false) {
        $udp = $null
        $received = $false
        $sent = $false
        $socketError = $null
        try {
            $address = [Net.IPAddress]::Parse($Local)
            $udp = New-Object Net.Sockets.UdpClient($address.AddressFamily)
            $udp.Client.Bind((New-Object Net.IPEndPoint($address, 0)))
            $udp.Client.ReceiveTimeout = 600
            $udp.Connect([Net.IPAddress]::Parse($Remote), 19096)
            $payload = [Text.Encoding]::UTF8.GetBytes('outage-' + [Guid]::NewGuid().ToString('N'))
            [void]$udp.Send($payload, $payload.Length)
            $sent = $true
            $any = [Net.IPAddress]::Any
            if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $any = [Net.IPAddress]::IPv6Any }
            $peer = New-Object Net.IPEndPoint($any, 0)
            [void]$udp.Receive([ref]$peer)
            $received = $true
        } catch [Net.Sockets.SocketException] {
            $cause = $_.Exception
            while ($cause -isnot [Net.Sockets.SocketException] -and $cause.InnerException) { $cause = $cause.InnerException }
            $socketError = [string]$cause.SocketErrorCode
            if ($RequireLiveSend -and (!$sent -or $cause.SocketErrorCode -ne [Net.Sockets.SocketError]::TimedOut)) { throw }
            # Address/route removal and receive timeout both mean no business
            # response; IPC separately proves that the old SA was retired.
        } finally { if ($udp) { $udp.Dispose() } }
        if ($received) { throw "Business response escaped the transport blackout: $Local -> $Remote" }
        $probes.Add([pscustomobject]@{ At = [DateTime]::UtcNow; Local = $Local; Remote = $Remote; Sent = $sent; SocketError = $socketError; RequiredLiveSend = $RequireLiveSend })
    }
    try {
        [IO.File]::WriteAllText($request, 'block')
        Wait-OutageAck 'blocked'
        $blockedAt = [DateTime]::UtcNow
        $blockedWhileLive = Read-Status
        if (!$blockedWhileLive.tunnel_ready -or !$blockedWhileLive.ike.live -or !$blockedWhileLive.ike.child_live) { throw 'Cannot prove transport blackout while the old SA is still live' }
        Expect-NoOutageEcho '198.18.253.2' '198.18.253.1' $true
        Expect-NoOutageEcho 'fd00:7068:b4::2' 'fd00:7068:b4::1' $true
        $afterLiveProbes = Read-Status
        if (!$afterLiveProbes.tunnel_ready -or !$afterLiveProbes.ike.live -or !$afterLiveProbes.ike.child_live) { throw 'Old SA retired before live blackout probes completed' }
        $deadline = $blockedAt.AddSeconds(90)
        $retired = $null
        do {
            Check-OutageOwner
            $status = Read-Status
            if (!$status.running) { throw 'Daemon stopped instead of reconnecting' }
            $samples.Add([pscustomobject]@{ At = [DateTime]::UtcNow; Generation = $status.ike.generation; Ready = $status.tunnel_ready; IKELive = $status.ike.live; ChildLive = $status.ike.child_live })
            if (!$status.tunnel_ready -and !$status.ike.live -and !$status.ike.child_live) { $retired = $status; break }
            Start-Sleep -Milliseconds 500
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($null -eq $retired) { throw 'Old IKE/CHILD did not retire within outage observation deadline' }
        $logNow = [string](Get-Content -LiteralPath $runtimeLog -Raw)
        if ($logNow.Length -lt $logBefore.Length -or $logNow.Substring($logBefore.Length) -notmatch 'tunnel_stopped[^\r\n]*IKE retransmission budget exhausted') { throw 'SA retirement lacks a new production IKE retransmission exhaustion event' }
        for ($i = 0; $i -lt 3; $i++) {
            Check-OutageOwner
            Expect-NoOutageEcho '198.18.253.2' '198.18.253.1'
            Expect-NoOutageEcho 'fd00:7068:b4::2' 'fd00:7068:b4::1'
        }
        [IO.File]::WriteAllText($request, 'restore')
        $restoreRequested = $true
        Wait-OutageAck 'restored'
        $restoredAt = [DateTime]::UtcNow
        $deadline = $restoredAt.AddSeconds(90)
        function Test-OutageRecovered($Value) {
            # Observe intentionally reports generation zero for a non-live SA;
            # the recovered live generation must still exceed the old live SA.
            return $Value.tunnel_ready -and $Value.ike.live -and $Value.ike.child_live -and [uint64]$Value.ike.generation -gt [uint64]$before.ike.generation -and [uint64]$Value.ike.generation -ge [uint64]$retired.ike.generation -and $Value.ike.expires_at -ne $before.ike.expires_at -and $Value.ike.child_expires_at -ne $before.ike.child_expires_at
        }
        do {
            Check-OutageOwner
            $after = Read-Status
            if (!$after.running) { throw 'Daemon stopped during outage recovery' }
            if (Test-OutageRecovered $after) { break }
            Start-Sleep -Milliseconds 500
        } while ([DateTime]::UtcNow -lt $deadline)
        if (!(Test-OutageRecovered $after)) { throw 'New SA did not recover after transport restoration' }
        Check-Business 'transport-outage-recovery'
        Check-OutageOwner
        [IO.File]::WriteAllText($request, 'recovered')
        Wait-OutageAck 'verified'
        [pscustomobject]@{ ProcessID = $owner.Id; ProcessStartedAt = $owner.FixtureStartedAtUtc; BlockedAt = $blockedAt; RestoredAt = $restoredAt; CompletedAt = [DateTime]::UtcNow; Before = $before; BlockedWhileLive = $blockedWhileLive; AfterLiveProbes = $afterLiveProbes; Retired = $retired; After = $after; Samples = $samples.ToArray(); Probes = $probes.ToArray() } | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $FixtureDirectory 'transport-outage.json')
        Write-Output "transport blackout recovery passed: same SCM pid=$($owner.Id), old SA retired, fresh SA and dual-stack business recovered"
    } finally {
        if (!$restoreRequested) {
            [IO.File]::WriteAllText($request, 'restore')
            Wait-OutageAck 'restored'
        }
    }
}
Test-GatewayTransportOutage
