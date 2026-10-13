# Test-tag binary only. PID ownership comes from the existing SCM fixture.
function Start-FixtureCPUProfile($Owner) {
    $prefix = Join-Path $FixtureDirectory ("profile-" + $Owner.Id)
    foreach ($suffix in @('.request','.started','.stop','.done','.error','.pprof')) {
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
            return
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Test-tag CPU profiler did not finish flushing'
}
