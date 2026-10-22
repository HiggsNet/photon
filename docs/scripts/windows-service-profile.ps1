# Test-tag binary only. PID ownership comes from the existing SCM fixture.
function Read-FixturePacketTimingMode {
    $marker = Join-Path $FixtureDirectory 'fixture-packet-timing-profile'
    if (!(Test-Path -LiteralPath $marker)) { return $null }
    if ((Get-Item -LiteralPath $marker).Length -gt 32) { throw 'Oversized fixture packet timing marker' }
    $value = [IO.File]::ReadAllText($marker)
    if ($value -cnotmatch '\A(off|on):(f1-w64-IPv4|f4-w64-IPv4)\n\z') { throw 'Invalid fixture packet timing marker' }
    return [pscustomobject]@{ Mode=$Matches[1]; Label=$Matches[2] }
}
function Assert-FixtureTimingUInt($Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [bool] -or $Value -is [double] -or $Value -is [single] -or [string]$Value -notmatch '\A\d+\z') { throw 'Invalid unsigned packet timing value' }
    return [UInt64]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture)
}
function Assert-FixtureTimingFields($Value, [string[]]$Expected) {
    $fields = @($Value.PSObject.Properties.Name)
    if ($fields.Count -ne $Expected.Count -or @($Expected | Where-Object { $_ -cnotin $fields }).Count -ne 0) { throw 'Invalid fixed packet timing fields' }
}
function Test-FixtureTimingHistogram($Histogram, [decimal]$ClassTotal, [bool]$Enabled) {
    Assert-FixtureTimingFields $Histogram @('count','sum_ns','min_ns','max_ns','buckets')
    if ($Histogram.buckets.Count -ne 64) { throw 'Invalid bounded stage histogram' }
    $count = Assert-FixtureTimingUInt $Histogram.count
    $sum = Assert-FixtureTimingUInt $Histogram.sum_ns
    $minimum = Assert-FixtureTimingUInt $Histogram.min_ns
    $maximum = Assert-FixtureTimingUInt $Histogram.max_ns
    $bucketCount = [decimal]0
    foreach ($bucket in $Histogram.buckets) { $bucketCount += [decimal](Assert-FixtureTimingUInt $bucket) }
    if ($count -ne $bucketCount -or $count -gt $ClassTotal -or $minimum -gt $maximum -or ($count -eq 0 -and ($sum -ne 0 -or $minimum -ne 0 -or $maximum -ne 0)) -or (!$Enabled -and ($count -ne 0 -or $sum -ne 0))) { throw 'Timing histogram ledger mismatch' }
    return [pscustomobject]@{ Count=$count; Sum=$sum }
}
function Test-FixturePacketTimingReport([string]$Path, [bool]$Enabled) {
    $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $expected = @('schema_version','enabled','epoch','clock','frequency_hz','sample_every','histogram_unit','bucket_upper_bounds_ns','directions','clock_errors','invalid_samples')
    Assert-FixtureTimingFields $report $expected
    if ($report.enabled -isnot [bool] -or $report.enabled -ne $Enabled -or $report.clock -cne 'query_performance_counter' -or $report.histogram_unit -cne 'nanoseconds') { throw 'Invalid fixture packet timing schema or mode' }
    if ((Assert-FixtureTimingUInt $report.schema_version) -ne 2 -or (Assert-FixtureTimingUInt $report.sample_every) -ne 256) { throw 'Invalid fixture packet timing schema or sample interval' }
    if ((Assert-FixtureTimingUInt $report.frequency_hz) -eq 0 -or (Assert-FixtureTimingUInt $report.clock_errors) -ne 0 -or (Assert-FixtureTimingUInt $report.invalid_samples) -ne 0) { throw 'Invalid packet timing clock or samples' }
    if ((Assert-FixtureTimingUInt $report.epoch) -eq 0) { throw 'Missing packet timing capture epoch' }
    if ($report.bucket_upper_bounds_ns.Count -ne 64 -or $report.directions.Count -ne 2) { throw 'Invalid bounded timing shape' }
    $boundExpected = [UInt64]1
    for ($boundIndex = 0; $boundIndex -lt 63; $boundIndex++) {
        if ((Assert-FixtureTimingUInt $report.bucket_upper_bounds_ns[$boundIndex]) -ne $boundExpected) { throw 'Invalid timing histogram bounds' }
        if ($boundIndex -lt 62) { $boundExpected *= [UInt64]2 }
    }
    if ((Assert-FixtureTimingUInt $report.bucket_upper_bounds_ns[63]) -ne [UInt64]::MaxValue) { throw 'Missing timing histogram overflow bin' }
    $directionNames = @('outbound','inbound')
    $classNames = @('unknown','business','control')
    $outcomeNames = @('delivered','rejected','crypto_error','delivery_error','queue_rejected','canceled')
    $stageNames = @('queue_wait','precheck','aes','fresh_gate','delivery','owner_total')
    $udpStageNames = @('writer_lock_wait','validation_state','deadline','udp_write')
    for ($index = 0; $index -lt 2; $index++) {
        $direction = $report.directions[$index]
        Assert-FixtureTimingFields $direction @('direction','selected','finished','unfinished','classes')
        if ($direction.direction -cne $directionNames[$index] -or $direction.classes.Count -ne 3) { throw 'Invalid timing direction/classes' }
        $selected = Assert-FixtureTimingUInt $direction.selected
        $finished = Assert-FixtureTimingUInt $direction.finished
        $unfinished = Assert-FixtureTimingUInt $direction.unfinished
        if ([decimal]$selected -ne ([decimal]$finished + [decimal]$unfinished) -or (!$Enabled -and $selected -ne 0)) { throw 'Timing sample ledger mismatch' }
        $outcomeTotal = [decimal]0
        for ($classIndex = 0; $classIndex -lt 3; $classIndex++) {
            $class = $direction.classes[$classIndex]
            Assert-FixtureTimingFields $class @('class','outcomes','stages','udp_delivery')
            Assert-FixtureTimingFields $class.outcomes $outcomeNames
            Assert-FixtureTimingFields $class.stages $stageNames
            Assert-FixtureTimingFields $class.udp_delivery $udpStageNames
            if ($class.class -cne $classNames[$classIndex]) { throw 'Invalid timing class outcomes/stages' }
            $classTotal = [decimal]0
            foreach ($name in $outcomeNames) { $classTotal += [decimal](Assert-FixtureTimingUInt $class.outcomes.$name) }
            $outcomeTotal += $classTotal
            $stages = @{}
            foreach ($name in $stageNames) {
                $stages[$name] = Test-FixtureTimingHistogram $class.stages.$name $classTotal $Enabled
            }
            $previousCount = $stages.delivery.Count
            $udpSum = [decimal]0
            foreach ($name in $udpStageNames) {
                $histogram = Test-FixtureTimingHistogram $class.udp_delivery.$name $classTotal $Enabled
                if ($histogram.Count -gt $previousCount -or (($index -ne 0 -or $classIndex -ne 1) -and ($histogram.Count -ne 0 -or $histogram.Sum -ne 0))) { throw 'Invalid UDP timing direction or stage coverage' }
                $previousCount = $histogram.Count
                $udpSum += [decimal]$histogram.Sum
            }
            if ($udpSum -gt [decimal]$stages.delivery.Sum) { throw 'UDP timing exceeds inclusive delivery span' }
        }
        if ($finished -ne $outcomeTotal) { throw 'Timing completion ledger mismatch' }
    }
}
function Start-FixtureCPUProfile($Owner) {
    $prefix = Join-Path $FixtureDirectory ("profile-" + $Owner.Id)
    foreach ($suffix in @('.request','.started','.stop','.done','.error','.pprof','.packet-drops.json','.packet-timing.json')) {
        if (Test-Path ($prefix + $suffix)) { throw "Refusing stale profile artifact: $suffix" }
    }
    [IO.File]::WriteAllText(($prefix + '.request'), "start`n")
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        if (Test-Path ($prefix + '.error')) { throw ([IO.File]::ReadAllText($prefix + '.error')) }
        if (Test-Path ($prefix + '.started')) { return $prefix }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Test-tag CPU profiler did not acknowledge start'
}
function Stop-FixtureCPUProfile([string]$Prefix) {
    [IO.File]::WriteAllText(($Prefix + '.stop'), "stop`n")
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        if (Test-Path ($Prefix + '.error')) { throw ([IO.File]::ReadAllText($Prefix + '.error')) }
        if (Test-Path ($Prefix + '.done')) {
            if ([IO.File]::ReadAllText($Prefix + '.done') -ne "stopped`n") { throw 'CPU profile exceeded its hard limit' }
            if ((Get-Item ($Prefix + '.pprof')).Length -eq 0) { throw 'CPU profile was empty' }
            $packetTiming = Read-FixturePacketTimingMode
            if ($packetTiming) { Test-FixturePacketTimingReport ($Prefix + '.packet-timing.json') ($packetTiming.Mode -eq 'on') }
            if (Test-Path (Join-Path $FixtureDirectory 'fixture-packet-drop-profile')) {
                $drops = Get-Content -LiteralPath ($Prefix + '.packet-drops.json') -Raw | ConvertFrom-Json
                $fields = @($drops.PSObject.Properties.Name)
                if ($fields.Count -ne 4 -or $drops.schema_version -ne 1) { throw 'Invalid fixture packet-drop schema' }
                foreach ($name in @('raw_ingress_drops','leaf_ingress_drops','esp_ingress_drops')) {
                    if ($name -notin $fields -or [string]$drops.$name -notmatch '^\d+$') { throw 'Invalid fixture packet-drop count' }
                }
            }
            return
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Test-tag CPU profiler did not finish flushing'
}
