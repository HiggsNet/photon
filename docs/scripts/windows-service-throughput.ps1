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
    $packetTiming = $null
    if (Test-Path -LiteralPath (Join-Path $FixtureDirectory 'fixture-packet-timing-profile')) {
        if (!$profileEnabled -or $dropDiagnostic) { throw 'Packet timing requires the independent CPU profile helper' }
        $packetTiming = Read-FixturePacketTimingMode
        $profileLabel = $packetTiming.Label
    }
    $threadMarker = Join-Path $FixtureDirectory 'fixture-thread-cpu'
    $threadSampling = Test-Path -LiteralPath $threadMarker
    $sampleArguments = @()
    $originalGeneratorP = $env:GOMAXPROCS
    $runtimeReport = $null
    $round = 1
    $sweep = $null
    if ($threadSampling) {
        if ([IO.File]::ReadAllText($threadMarker) -ne "250ms`n" -or !$profileEnabled -or $dropDiagnostic) { throw 'Invalid runtime thread-sampling fixture mode' }
        $sampleArguments = @('-thread-cpu')
        $roundText = [IO.File]::ReadAllText((Join-Path $FixtureDirectory 'fixture-performance-round'))
        $sweepText = [IO.File]::ReadAllText((Join-Path $FixtureDirectory 'fixture-performance-sweep'))
        if ($roundText -notmatch '\A[1-3]\n\z' -or $sweepText -notin @("gomaxprocs`n","affinity`n")) { throw 'Invalid runtime sweep/round marker' }
        $round = [int]$roundText.Trim()
        $sweep = $sweepText.Trim()
    }
    $owner = Read-OwnedProcess
    if ($threadSampling) {
        $runtimePath = Join-Path $FixtureDirectory ("runtime-" + $owner.Id + '.json')
        $runtimeReport = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json
        $requestedP = [IO.File]::ReadAllText((Join-Path $FixtureDirectory 'fixture-gomaxprocs'))
        $requestedCPUs = [IO.File]::ReadAllText((Join-Path $FixtureDirectory 'fixture-cpu-affinity'))
        if ($requestedP -notmatch '\A(1|2|4|8)\n\z' -or $requestedCPUs -notmatch '\A(1|2|4|8)\n\z') { throw 'Invalid runtime settings markers' }
        if ($runtimeReport.SchemaVersion -ne 1 -or $runtimeReport.PID -ne $owner.Id -or [DateTime]::Parse($runtimeReport.StartedUTC).ToUniversalTime() -ne $owner.FixtureStartedAtUtc -or $runtimeReport.GoVersion -ne 'go1.26.5' -or $runtimeReport.NumCPU -ne 8) { throw 'Runtime report differs from actual owned process/startup' }
        if (!$runtimeReport.Explicit -or !$runtimeReport.ExplicitAffinity -or $runtimeReport.GOMAXPROCSRequested -ne [int]$requestedP.Trim() -or $runtimeReport.GOMAXPROCSActual -ne [int]$requestedP.Trim() -or $runtimeReport.RequestedCPUCount -ne [int]$requestedCPUs.Trim() -or $runtimeReport.AvailableCPUCountBefore -ne 8 -or $runtimeReport.AvailableCPUCountActual -ne [int]$requestedCPUs.Trim()) { throw 'Runtime report did not apply requested Go P / CPU affinity' }
        if (($sweep -eq 'gomaxprocs' -and $runtimeReport.AvailableCPUCountActual -ne 8) -or ($sweep -eq 'affinity' -and $runtimeReport.GOMAXPROCSActual -ne 8)) { throw 'Runtime sweep changed its fixed dimension' }
        $expectedProcessMask = ('0x{0:x}' -f [UInt64]$runtimeReport.ProcessorAffinityActual)
        if ($runtimeReport.ProcessorAffinityBefore -ne 255 -or $runtimeReport.SystemMask -ne 255) { throw 'Runtime original affinity differs from eight-CPU VM' }
    }
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
        Round = $round
        CPUProfileEnabled = $profileEnabled
        ThroughputUnit = 'unique fully validated UDP echo application payload Mbps per direction; two traversals per echo'
        Results = $results
    }
    if ($dropDiagnostic) { $metadata.PacketDropDiagnostic = $true; $metadata.CPUProfileLabel = $profileLabel }
    if ($packetTiming) { $metadata.PacketTimingMode = $packetTiming.Mode; $metadata.CPUProfileLabel = $profileLabel }
    if ($threadSampling) { $metadata.RuntimeSweep = $sweep; $metadata.ServiceRuntime = $runtimeReport; $metadata.ThreadCPUSampling = $true; $metadata.SampleIntervalMS = 250; $metadata.GeneratorGOMAXPROCS = 8 }
    try {
        if ($threadSampling) { $env:GOMAXPROCS = '8' }
        foreach ($point in @(@(1,64),@(4,64),@(4,1024))) {
            $flows = $point[0]; $window = $point[1]
            foreach ($family in @(@('IPv4','198.18.253.2','198.18.253.1'),@('IPv6','fd00:7068:b4::2','fd00:7068:b4::1'))) {
                $label = "f$flows-w$window-$($family[0])"
                $warmupFile = Join-Path $FixtureDirectory "throughput-$label-warmup.json"
                & $tool -mode client -local $family[1] -remote $family[2] -port 19100 -flows $flows -window $window -seconds 2 -payload 1200 -service-pid $owner.Id @sampleArguments -output $warmupFile | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "Throughput warmup tool failed: $label" }
                $warmup = Get-Content -LiteralPath $warmupFile -Raw | ConvertFrom-Json
                $profilePrefix = $null
                if ($profileEnabled -and !$profileCaptured -and $label -eq $profileLabel) { $profilePrefix = Start-FixtureCPUProfile $owner }
                $measurementFile = Join-Path $FixtureDirectory "throughput-$label.json"
                try {
                    & $tool -mode client -local $family[1] -remote $family[2] -port 19100 -flows $flows -window $window -seconds $MeasureSeconds -payload 1200 -service-pid $owner.Id @sampleArguments -output $measurementFile | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "Throughput tool failed: $label" }
                } finally {
                    if ($profilePrefix) { Stop-FixtureCPUProfile $profilePrefix; $profileCaptured = $true }
                }
                $measurement = Get-Content -LiteralPath $measurementFile -Raw | ConvertFrom-Json
                $entry = [pscustomobject]@{ Label=$label; Warmup=$warmup; Measurement=$measurement; RecoveryPassed=$false }
                $results.Add($entry)
                if (!$measurement.Completed -or $measurement.Totals.Corrupt -ne 0 -or $measurement.Totals.Unsent -ne 0) { throw "Incomplete or corrupt throughput measurement: $label" }
                if ($threadSampling) {
                    foreach ($run in @($warmup,$measurement)) {
                        if (!$run.Completed -or $run.Totals.PacketLimitReached -or $run.Totals.Corrupt -ne 0 -or $run.Totals.Unsent -ne 0 -or $run.Totals.Foreign -ne 0 -or $run.Totals.Duplicates -ne 0 -or $run.Totals.SendErrors -ne 0) { throw 'Runtime sweep phase incomplete or contains integrity/send/budget anomalies' }
                        if (!$run.ThreadCPUSampling -or $run.SampleIntervalMS -ne 250 -or $run.GeneratorGOMAXPROCS -ne 8 -or !$run.GeneratorAffinity.Complete -or $run.GeneratorAffinity.Error -or $run.GeneratorAffinity.ProcessGroupCount -ne 1 -or $run.GeneratorAffinity.SystemGroupCount -ne 1 -or $run.GeneratorAffinity.ProcessMask -ne '0xff' -or $run.GeneratorAffinity.CPUCountLowerBound -ne 8 -or $run.GeneratorAffinity.CPUCountUpperBound -ne 8) { throw 'Generator actual runtime or affinity changed' }
                        if ($run.Samples.Count -lt 2) { throw 'Insufficient service samples for thread CPU comparison' }
                        $previousThreads = @{}
                        $busyObserved = $false
                        foreach ($sample in $run.Samples) {
                            if ($sample.StartToken -ne $owner.FixtureStartedAtUtc.ToFileTimeUtc() -or !$sample.Threads -or !$sample.Threads.EnumerationComplete -or $sample.Threads.Errors -or !$sample.Affinity -or !$sample.Affinity.Complete -or $sample.Affinity.Error -or $sample.Affinity.ProcessGroupCount -ne 1 -or $sample.Affinity.SystemGroupCount -ne 1 -or $sample.Affinity.ProcessMask -ne $expectedProcessMask -or $sample.Affinity.CPUCountLowerBound -ne $runtimeReport.AvailableCPUCountActual -or $sample.Affinity.CPUCountUpperBound -ne $runtimeReport.AvailableCPUCountActual) { throw 'Service sample identity/affinity/enum differs from startup' }
                            $valid = @($sample.Threads.Threads | Where-Object { !$_.Error -and $_.StartToken -match '\A[1-9][0-9]*\z' -and $_.TID -gt 0 })
                            if ($valid.Count -eq 0 -or @($sample.Threads.Threads | Where-Object { $_.ErrorCode -eq 5 }).Count -ne 0) { throw 'Thread snapshot has no valid observations or denied access' }
                            $currentThreads = @{}
                            foreach ($thread in $valid) {
                                $key = ([string]$thread.TID) + '/' + $thread.StartToken
                                if ($previousThreads.ContainsKey($key)) {
                                    $previous = $previousThreads[$key]
                                    if ($thread.CPUSeconds -lt $previous.CPUSeconds -or $thread.ObservedSeconds -le $previous.ObservedSeconds) { throw 'Same-thread counter/time regressed' }
                                    if ($thread.CPUSeconds -gt $previous.CPUSeconds) { $busyObserved = $true }
                                }
                                $currentThreads[$key] = $thread
                            }
                            $previousThreads = $currentThreads
                        }
                        if (!$busyObserved) { throw 'No nonzero CPU interval observed for an identified service thread' }
                    }
                }
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
        if ($threadSampling) { $env:GOMAXPROCS = $originalGeneratorP }
        $metadata | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'throughput.json')
    }
}
