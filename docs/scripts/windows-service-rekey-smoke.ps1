# Dot-sourced in the owned full-daemon service fixture. Independent UDP workers
# keep both OS business sockets active while the parent performs IPC and SSH
# coordination; one nonce/sequence namespace per worker detects stale replies.
function Test-RekeyTraffic {
    $before = Read-Status
    $owner = Read-OwnedProcess
    if (!$before.tunnel_ready -or !$before.ike.live -or !$before.ike.child_live) { throw 'Rekey requires a live business tunnel' }
    $jobs = @()
    $samples = New-Object System.Collections.Generic.List[object]
    $phases = New-Object System.Collections.Generic.List[object]
    $stop = Join-Path $FixtureDirectory 'rekey-traffic-stop'
    $worker = {
        param($Local, $Remote, $Directory, $Family)
        $ErrorActionPreference = 'Stop'
        $udp = $null
        $received = New-Object 'System.Collections.Generic.HashSet[int]'
        $nonce = [Guid]::NewGuid().ToString('N')
        $sent = 0; $duplicates = 0; $lastReply = [DateTime]::UtcNow; $maxGap = 0.0
        $started = [DateTime]::UtcNow
        $windows = New-Object System.Collections.Generic.List[object]
        try {
            $address = [Net.IPAddress]::Parse($Local)
            $udp = New-Object Net.Sockets.UdpClient($address.AddressFamily)
            $udp.Client.Bind((New-Object Net.IPEndPoint($address, 0)))
            $udp.Connect([Net.IPAddress]::Parse($Remote), 19096)
            $any = [Net.IPAddress]::Any
            if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $any = [Net.IPAddress]::IPv6Any }
            $peer = New-Object Net.IPEndPoint($any, 0)
            $nextSample = $started
            while (!(Test-Path (Join-Path $Directory 'rekey-traffic-stop'))) {
                if (([DateTime]::UtcNow - $started).TotalSeconds -gt 150) { throw 'Traffic worker deadline exceeded' }
                $payload = [Text.Encoding]::ASCII.GetBytes($nonce + ':' + $sent)
                if ($udp.Send($payload, $payload.Length) -ne $payload.Length) { throw 'Partial datagram send' }
                $sent++
                # Bound draining even if a broken peer floods this socket.
                for ($n = 0; $n -lt 128 -and $udp.Available -gt 0; $n++) {
                    $reply = [Text.Encoding]::ASCII.GetString($udp.Receive([ref]$peer))
                    $parts = $reply.Split(':')
                    $sequence = 0
                    if ($parts.Length -ne 2 -or $parts[0] -ne $nonce -or ![int]::TryParse($parts[1], [ref]$sequence) -or $sequence -lt 0 -or $sequence -ge $sent) { throw 'Unexpected or stale business reply' }
                    if (!$received.Add($sequence)) { $duplicates++; continue }
                    $now = [DateTime]::UtcNow
                    $maxGap = [Math]::Max($maxGap, ($now - $lastReply).TotalMilliseconds)
                    $lastReply = $now
                }
                if ([DateTime]::UtcNow -ge $nextSample) {
                    $windows.Add([pscustomobject]@{ At = [DateTime]::UtcNow; Sent = $sent; Received = $received.Count })
                    $nextSample = [DateTime]::UtcNow.AddMilliseconds(500)
                }
                if ($received.Count -ge 5) { [IO.File]::WriteAllText((Join-Path $Directory ('rekey-traffic-' + $Family + '.ready')), 'ready') }
                Start-Sleep -Milliseconds 50
            }
            if ($received.Count -lt 20 -or $duplicates -ne 0 -or ([DateTime]::UtcNow - $lastReply).TotalSeconds -gt 2 -or $maxGap -gt 3000) { throw 'Rekey traffic stopped, duplicated, or exceeded 3 second continuity budget' }
            [pscustomobject]@{ Family = $Family; StartedAt = $started; CompletedAt = [DateTime]::UtcNow; Sent = $sent; Received = $received.Count; Duplicates = $duplicates; MaxReplyGapMilliseconds = $maxGap; Samples = $windows.ToArray() }
        } finally { if ($udp) { $udp.Dispose() } }
    }
    function Assert-RekeyOwner {
        $current = Read-OwnedProcess
        if ($current.Id -ne $owner.Id -or $current.FixtureStartedAtUtc -ne $owner.FixtureStartedAtUtc) { throw 'SCM process changed during rekey' }
        $status = Read-Status
        if (!$status.running -or !$status.tunnel_ready -or !$status.ike.live -or !$status.ike.child_live -or $status.ike.generation -ne $before.ike.generation) { throw 'Rekey rebuilt or retired the active tunnel' }
        $samples.Add([pscustomobject]@{ At = [DateTime]::UtcNow; Status = $status })
        return $status
    }
    try {
        $jobs += Start-Job -ScriptBlock $worker -ArgumentList '198.18.253.2','198.18.253.1',$FixtureDirectory,'ipv4'
        $jobs += Start-Job -ScriptBlock $worker -ArgumentList 'fd00:7068:b4::2','fd00:7068:b4::1',$FixtureDirectory,'ipv6'
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (!(Test-Path (Join-Path $FixtureDirectory 'rekey-traffic-ipv4.ready')) -or !(Test-Path (Join-Path $FixtureDirectory 'rekey-traffic-ipv6.ready'))) {
            if ([DateTime]::UtcNow -ge $deadline -or @($jobs | Where-Object State -ne 'Running').Count -gt 0) { throw 'Continuous dual-stack workers did not become ready' }
            Start-Sleep -Milliseconds 200
        }
        foreach ($kind in @('child','ike')) {
            $phaseBefore = Assert-RekeyOwner
            $started = [DateTime]::UtcNow
            [IO.File]::WriteAllText((Join-Path $FixtureDirectory 'rekey-request.txt'), $kind)
            $deadline = $started.AddSeconds(60)
            do {
                $after = Assert-RekeyOwner
                if (@($jobs | Where-Object State -ne 'Running').Count -gt 0) { throw 'Continuous traffic worker failed during rekey' }
                $ack = Join-Path $FixtureDirectory ('rekey-' + $kind + '.ack')
                $changed = ($kind -eq 'child' -and $after.ike.child_expires_at -ne $phaseBefore.ike.child_expires_at) -or ($kind -eq 'ike' -and $after.ike.expires_at -ne $phaseBefore.ike.expires_at)
                if ((Test-Path $ack) -and (Get-Content $ack -Raw).Trim() -eq $kind -and $changed) { break }
                Start-Sleep -Milliseconds 200
            } while ([DateTime]::UtcNow -lt $deadline)
            if ([DateTime]::UtcNow -ge $deadline) { throw "$kind rekey did not converge" }
            $phases.Add([pscustomobject]@{ Kind = $kind; StartedAt = $started; CompletedAt = [DateTime]::UtcNow; Before = $phaseBefore; After = $after })
            Start-Sleep -Seconds 2
        }
        [IO.File]::WriteAllText($stop, 'stop')
        $null = $jobs | Wait-Job -Timeout 10
        if (@($jobs | Where-Object State -ne 'Completed').Count -gt 0) { throw 'Traffic worker did not finish successfully' }
        $traffic = @($jobs | Receive-Job -ErrorAction Stop)
        Check-Business 'rekey-traffic'
        $null = Assert-RekeyOwner
        [pscustomobject]@{ ProcessID = $owner.Id; ProcessStartedAt = $owner.FixtureStartedAtUtc; Before = $before; Phases = $phases.ToArray(); StatusSamples = $samples.ToArray(); Traffic = $traffic } | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $FixtureDirectory 'rekey-traffic.json')
        [IO.File]::WriteAllText((Join-Path $FixtureDirectory 'rekey-request.txt'), 'complete')
        Write-Output "CHILD and IKE rekey under dual-stack traffic passed: same SCM pid=$($owner.Id), generation=$($before.ike.generation)"
    } finally {
        [IO.File]::WriteAllText($stop, 'stop')
        $jobs | Stop-Job
        $jobs | Remove-Job -Force
    }
}
Test-RekeyTraffic
