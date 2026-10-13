# Dot-sourced only by the isolated full-daemon fixture; independent of the historical baseline.
function Test-ServiceThroughput {
    param([ValidateRange(1,30)][int]$MeasureSeconds = 15)
    $tool = Join-Path $FixtureDirectory 'udp-perf.exe'
    if (!(Test-Path -LiteralPath $tool)) { throw 'Missing bounded UDP performance tool' }
    $profileHelper = Join-Path $FixtureDirectory 'windows-service-profile.ps1'
    $profileEnabled = Test-Path $profileHelper
    if ($profileEnabled) { . $profileHelper }
    $dropMarker = Join-Path $FixtureDirectory 'fixture-packet-drop-profile'
    $dropDiagnostic = Test-Path $dropMarker
    $profileLabel = 'f1-w64-IPv4'
    if ($dropDiagnostic) {
        if (!$profileEnabled -or [IO.File]::ReadAllText($dropMarker) -ne "f4-w1024-IPv4`n") { throw 'Invalid fixture packet-drop profile marker' }
        $profileLabel = 'f4-w1024-IPv4'
    }
    $profileCaptured = $false
    $owner = Read-OwnedProcess
    $before = Read-Status
    if (!$before.tunnel_ready -or !$before.ike.live -or !$before.ike.child_live) { throw 'Throughput requires live authenticated business tunnel' }
    $results = New-Object System.Collections.Generic.List[object]
    $metadata = [ordered]@{
        SchemaVersion = 1
        StartedAtUTC = [DateTime]::UtcNow.ToString('o')
        ServicePID = $owner.Id
        ServiceStartedAtUTC = $owner.FixtureStartedAtUtc.ToString('o')
        ExecutableSHA256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
        GeneratorSHA256 = (Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        OSVersion = (Get-CimInstance Win32_OperatingSystem).Version
        CPUs = @(Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors)
        PayloadBytes = 1200
        SendSeconds = $MeasureSeconds
        WarmupSeconds = 2
        EchoDeadlineMS = 1000
        Round = 1
        CPUProfileEnabled = $profileEnabled
        ThroughputUnit = 'unique fully validated UDP echo application payload Mbps per direction; two traversals per echo'
        Results = $results
    }
    if ($dropDiagnostic) { $metadata.PacketDropDiagnostic = $true; $metadata.CPUProfileLabel = $profileLabel }
    try {
        foreach ($point in @(@(1,64),@(4,64),@(4,1024))) {
            $flows = $point[0]; $window = $point[1]
            foreach ($family in @(@('IPv4','198.18.253.2','198.18.253.1'),@('IPv6','fd00:7068:b4::2','fd00:7068:b4::1'))) {
                $label = "f$flows-w$window-$($family[0])"
                $warmupFile = Join-Path $FixtureDirectory "throughput-$label-warmup.json"
                & $tool -mode client -local $family[1] -remote $family[2] -port 19100 -flows $flows -window $window -seconds 2 -payload 1200 -service-pid $owner.Id -output $warmupFile | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "Throughput warmup tool failed: $label" }
                $warmup = Get-Content -LiteralPath $warmupFile -Raw | ConvertFrom-Json
                $profilePrefix = $null
                if ($profileEnabled -and !$profileCaptured -and $label -eq $profileLabel) { $profilePrefix = Start-FixtureCPUProfile $owner }
                $measurementFile = Join-Path $FixtureDirectory "throughput-$label.json"
                try {
                    & $tool -mode client -local $family[1] -remote $family[2] -port 19100 -flows $flows -window $window -seconds $MeasureSeconds -payload 1200 -service-pid $owner.Id -output $measurementFile | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "Throughput tool failed: $label" }
                } finally {
                    if ($profilePrefix) { Stop-FixtureCPUProfile $profilePrefix; $profileCaptured = $true }
                }
                $measurement = Get-Content -LiteralPath $measurementFile -Raw | ConvertFrom-Json
                $entry = [pscustomobject]@{ Label=$label; Warmup=$warmup; Measurement=$measurement; RecoveryPassed=$false }
                $results.Add($entry)
                if (!$measurement.Completed -or $measurement.Totals.Corrupt -ne 0 -or $measurement.Totals.Unsent -ne 0) { throw "Incomplete or corrupt throughput measurement: $label" }
                Check-Business "throughput-$label-recovery"
                $current = Read-OwnedProcess
                if ($current.Id -ne $owner.Id -or $current.FixtureStartedAtUtc -ne $owner.FixtureStartedAtUtc) { throw 'Throughput SCM process changed' }
                $status = Read-Status
                if (!$status.tunnel_ready -or !$status.ike.live -or !$status.ike.child_live) { throw 'Throughput lost readiness' }
                $entry.RecoveryPassed = $true
                Write-Host "throughput $label Mbps=$($measurement.GoodputMbps) deadline_Mbps=$($measurement.DeadlineGoodputMbps) echo_loss=$($measurement.EchoLossPercent)% service_core_cpu=$($measurement.ServiceCPUCorePercent)% generator_core_cpu=$($measurement.GeneratorCPUCorePercent)%"
            }
        }
        $metadata.CompletedAtUTC = [DateTime]::UtcNow.ToString('o')
        $metadata.Completed = $true
    } finally {
        $metadata | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'throughput.json')
    }
}
