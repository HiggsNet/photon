# Dot-sourced only by the isolated SCM fixture with its Linux tc coordinator.
# Distinct sockets/nonces per point prevent replies from another point counting.
function Test-ServiceImpairment {
    $owner = Read-OwnedProcess
    $before = Read-Status
    if (!$before.running -or !$before.tunnel_ready -or !$before.ike.live -or !$before.ike.child_live) { throw 'Impairment requires a live authenticated business tunnel' }
    $request = Join-Path $FixtureDirectory 'impairment-request.txt'
    if (Test-Path $request) { throw 'Refusing stale impairment request' }
    foreach ($phase in @('loss','duplicate','reorder')) {
        foreach ($ack in @($phase, ('restore-' + $phase))) {
            if (Test-Path (Join-Path $FixtureDirectory ('impairment-' + $ack + '.ack'))) { throw 'Refusing stale impairment acknowledgement' }
        }
    }
    if (Test-Path (Join-Path $FixtureDirectory 'impairment-complete.ack')) { throw 'Refusing stale completion acknowledgement' }
    $samples = New-Object System.Collections.Generic.List[object]
    $points = New-Object System.Collections.Generic.List[object]
    $active = $null
    $completed = $false
    $failure = $null
    function Assert-ImpairmentOwner {
        $current = Read-OwnedProcess
        if ($current.Id -ne $owner.Id -or $current.FixtureStartedAtUtc -ne $owner.FixtureStartedAtUtc) { throw 'SCM process changed during impairment' }
        $status = Read-Status
        $samples.Add([pscustomobject]@{ AtUTC = [DateTime]::UtcNow.ToString('o'); Status = $status })
        if (!$status.running -or !$status.tunnel_ready -or !$status.ike.live -or !$status.ike.child_live -or [uint64]$status.ike.generation -ne [uint64]$before.ike.generation) { throw 'Impairment retired or rebuilt the live tunnel' }
        if ($status.ike.expires_at -ne $before.ike.expires_at -or $status.ike.child_expires_at -ne $before.ike.child_expires_at) { throw 'Impairment changed the established IKE/CHILD leases' }
    }
    function Save-ImpairmentDTO([string]$Label) {
        foreach ($method in @('status','diagnostics')) {
            $raw = & $Executable $method --config $Config
            if ($LASTEXITCODE -ne 0) { throw "Impairment $method IPC failed" }
            [IO.File]::WriteAllText((Join-Path $FixtureDirectory ('impairment-' + $Label + '-' + $method + '.json')), ($raw -join "`n"))
            $dto = $raw | ConvertFrom-Json
            if ($dto.version -ne 1 -or $dto.method -ne $method -or $dto.error -or $null -eq $dto.result) { throw "Invalid impairment $method response" }
        }
    }
    function Wait-ImpairmentAck([string]$Phase) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $path = Join-Path $FixtureDirectory ('impairment-' + $Phase + '.ack')
        do {
            # Restoration must remain available after an ownership/readiness
            # assertion failed. The next recovery point verifies the owner.
            if ($Phase -notlike 'restore-*') { Assert-ImpairmentOwner }
            if ((Test-Path $path) -and (Get-Content $path -Raw).Trim() -eq $Phase) { return }
            Start-Sleep -Milliseconds 200
        } while ($clock.Elapsed.TotalSeconds -lt 30)
        throw "Linux impairment coordinator did not acknowledge $Phase"
    }
    $worker = {
        param($Local, $Remote, $Directory, $Label, $Family, $Count)
        $ErrorActionPreference = 'Stop'
        $udp = $null
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $seen = New-Object 'System.Collections.Generic.HashSet[int]'
        $order = New-Object 'System.Collections.Generic.List[int]'
        $nonce = [Guid]::NewGuid().ToString('N')
        $sent = 0; $duplicates = 0; $corrupt = 0; $reordered = 0; $highest = -1
        $nextSend = 0.0; $sendEnded = $null; $workerFailure = $null
        try {
            $address = [Net.IPAddress]::Parse($Local)
            $udp = New-Object Net.Sockets.UdpClient($address.AddressFamily)
            $udp.Client.ReceiveBufferSize = 1048576
            $udp.Client.Bind((New-Object Net.IPEndPoint($address, 0)))
            $udp.Connect([Net.IPAddress]::Parse($Remote), 19096)
            $any = [Net.IPAddress]::Any
            if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $any = [Net.IPAddress]::IPv6Any }
            $peer = New-Object Net.IPEndPoint($any, 0)
            while ($null -eq $sendEnded -or $clock.Elapsed.TotalSeconds -lt $sendEnded + 2) {
                if ($clock.Elapsed.TotalSeconds -gt 45) { throw 'Impairment worker exceeded bounded deadline' }
                if ($sent -lt $Count -and $clock.Elapsed.TotalSeconds -ge $nextSend) {
                    $text = ($nonce + ':' + $sent.ToString('D6')).PadRight(96, '#')
                    $payload = [Text.Encoding]::ASCII.GetBytes($text)
                    if ($udp.Send($payload, $payload.Length) -ne $payload.Length) { throw 'Partial impairment datagram send' }
                    $sent++
                    # No catch-up burst when the generator was descheduled.
                    $nextSend = $clock.Elapsed.TotalSeconds + 0.01
                    if ($sent -eq $Count) { $sendEnded = $clock.Elapsed.TotalSeconds }
                }
                for ($n = 0; $n -lt 128 -and $udp.Available -gt 0; $n++) {
                    $replyBytes = $udp.Receive([ref]$peer)
                    $reply = [Text.Encoding]::ASCII.GetString($replyBytes)
                    $sequence = -1
                    $valid = $replyBytes.Length -eq 96 -and $reply.Substring(0,33) -eq ($nonce + ':') -and [int]::TryParse($reply.Substring(33,6), [ref]$sequence) -and $sequence -ge 0 -and $sequence -lt $sent
                    if ($valid) { $valid = $reply -ceq ($nonce + ':' + $sequence.ToString('D6')).PadRight(96, '#') }
                    if (!$valid) { $corrupt++; throw 'Foreign, corrupt, stale or unsent impairment reply' }
                    if (!$seen.Add($sequence)) { $duplicates++; continue }
                    if ($sequence -lt $highest) { $reordered++ }
                    $highest = [Math]::Max($highest, $sequence)
                    $order.Add($sequence)
                }
                Start-Sleep -Milliseconds 1
            }
        } catch { $workerFailure = $_.Exception.Message } finally {
            if ($udp) { $udp.Dispose() }
            $result = [pscustomobject]@{
                Label = $Label; Family = $Family; Nonce = $nonce; Requested = $Count
                PayloadBytes = 96; MaximumPacketsPerSecond = 100; DrainSeconds = 2
                Sent = $sent; UniqueReceived = $seen.Count; Missing = $sent - $seen.Count
                Duplicates = $duplicates; Corrupt = $corrupt; OutOfOrder = $reordered
                ReceiveOrder = $order.ToArray(); Seconds = $clock.Elapsed.TotalSeconds
                SendSeconds = $sendEnded; Failure = $workerFailure
            }
            $result | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $Directory ('impairment-' + $Label + '-' + $Family + '-traffic.json'))
        }
        return $result
    }
    function Run-ImpairmentTraffic([string]$Label, [int]$Count, [string]$Expectation) {
        $point = [pscustomobject]@{ Label = $Label; Expectation = $Expectation; StartedAtUTC = [DateTime]::UtcNow.ToString('o'); Completed = $false; Traffic = @() }
        $points.Add($point)
        $trafficJobs = @()
        try {
            $trafficJobs += Start-Job -ScriptBlock $worker -ArgumentList '198.18.253.2','198.18.253.1',$FixtureDirectory,$Label,'ipv4',$Count
            $trafficJobs += Start-Job -ScriptBlock $worker -ArgumentList 'fd00:7068:b4::2','fd00:7068:b4::1',$FixtureDirectory,$Label,'ipv6',$Count
            $clock = [Diagnostics.Stopwatch]::StartNew()
            while (@($trafficJobs | Where-Object { $_.State -eq 'Running' -or $_.State -eq 'NotStarted' }).Count -gt 0) {
                Assert-ImpairmentOwner
                if ($clock.Elapsed.TotalSeconds -gt 50) { throw 'Impairment jobs exceeded parent deadline' }
                Start-Sleep -Milliseconds 500
            }
            $point.Traffic = @($trafficJobs | Receive-Job -ErrorAction Stop)
            if (@($trafficJobs | Where-Object State -ne 'Completed').Count -gt 0 -or $point.Traffic.Count -ne 2) { throw 'Impairment jobs did not return both families' }
            foreach ($r in $point.Traffic) {
                if ($r.Failure -or $r.Sent -ne $Count -or $r.Corrupt -ne 0 -or $r.Duplicates -ne 0 -or $r.UniqueReceived -lt $Count / 2) { throw "Impairment integrity or continuity failed: $Label $($r.Family)" }
                if ($Expectation -eq 'loss' -and $r.Missing -eq 0) { throw 'Loss point did not observe actual business loss' }
                if ($Expectation -ne 'loss' -and $r.Missing -ne 0) { throw "Impairment point lost unique business replies: $Label $($r.Family)" }
                if ($Expectation -eq 'reorder' -and $r.OutOfOrder -eq 0) { throw 'Reorder point did not observe actual business reply reordering' }
            }
            Assert-ImpairmentOwner
            $point.Completed = $true
        } finally {
            $trafficJobs | Stop-Job
            $trafficJobs | Remove-Job -Force
        }
    }
    try {
        Save-ImpairmentDTO 'before'
        Run-ImpairmentTraffic 'control' 100 'complete'
        foreach ($phase in @('loss','duplicate','reorder')) {
            Save-ImpairmentDTO ($phase + '-before')
            $active = $phase # Cleanup also covers a partially applied coordinator request.
            [IO.File]::WriteAllText($request, $phase)
            Wait-ImpairmentAck $phase
            Run-ImpairmentTraffic $phase 1000 $phase
            Save-ImpairmentDTO ($phase + '-after')
            [IO.File]::WriteAllText($request, ('restore-' + $phase))
            Wait-ImpairmentAck ('restore-' + $phase)
            $active = $null
            Run-ImpairmentTraffic ($phase + '-recovery') 100 'complete'
            Save-ImpairmentDTO ($phase + '-recovery')
        }
        Check-Business 'impairment-recovery'
        Assert-ImpairmentOwner
        [IO.File]::WriteAllText($request, 'complete')
        Wait-ImpairmentAck 'complete'
        $completed = $true
        Write-Output "loss/duplicate/reorder passed: same SCM pid=$($owner.Id), live generation=$($before.ike.generation), dual-stack nonce/sequence integrity and recovery"
    } catch { $failure = $_.Exception.Message } finally {
        if ($active) {
            try {
                [IO.File]::WriteAllText($request, ('restore-' + $active))
                Wait-ImpairmentAck ('restore-' + $active)
            } catch { $failure = "$failure; impairment restoration failed: $($_.Exception.Message)" }
        }
        [pscustomobject]@{
            SchemaVersion = 1; ProcessID = $owner.Id; ProcessStartedAtUTC = $owner.FixtureStartedAtUtc.ToString('o')
            Before = $before; Completed = $completed; Failure = $failure
            Points = $points.ToArray(); StatusSamples = $samples.ToArray()
        } | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'impairment-traffic.json')
    }
    if ($failure) { throw $failure }
}
Test-ServiceImpairment
