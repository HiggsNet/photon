param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$FixtureDirectory
)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path $Executable).Path
$FixtureDirectory = (Resolve-Path $FixtureDirectory).Path
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$consoleUser = (Get-CimInstance Win32_ComputerSystem).UserName
if (!$consoleUser -or $consoleUser -ine $identity) { throw 'Log in to the Windows console as the SSH fixture user before GUI testing' }
$taskName = 'PhotonGuiSmoke-' + [Guid]::NewGuid().ToString('N')
$runner = Join-Path $FixtureDirectory 'gui-session-runner.ps1'
$done = Join-Path $FixtureDirectory 'gui-session.done'
$log = Join-Path $FixtureDirectory 'gui-session.log'
if ((Test-Path $runner) -or (Test-Path $done) -or (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { throw 'Refusing an existing GUI session fixture' }
@'
param([string]$Executable, [string]$FixtureDirectory)
$ErrorActionPreference = 'Stop'
$code = 1
try {
    if (![Environment]::UserInteractive) { throw 'Task did not receive an interactive desktop' }
    & (Join-Path $FixtureDirectory 'windows-service-smoke.ps1') -Executable $Executable -FixtureDirectory $FixtureDirectory *> (Join-Path $FixtureDirectory 'gui-session.log')
    $code = 0
} catch {
    ($_ | Out-String) | Add-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'gui-session.log')
} finally {
    $temporaryDone = Join-Path $FixtureDirectory 'gui-session.done.new'
    [IO.File]::WriteAllText($temporaryDone, [string]$code)
    Move-Item -LiteralPath $temporaryDone -Destination (Join-Path $FixtureDirectory 'gui-session.done') -ErrorAction Stop
}
exit $code
'@ | Set-Content -Encoding UTF8 -LiteralPath $runner
$registered = $false
$result = 1
try {
    $arguments = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $runner + '" -Executable "' + $Executable + '" -FixtureDirectory "' + $FixtureDirectory + '"'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $null = Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings
    $registered = $true
    [pscustomobject]@{ TaskName = $taskName; User = $identity; ConsoleUser = $consoleUser; RegisteredAtUTC = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'gui-session.json')
    Start-ScheduledTask -TaskName $taskName
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path $done)) {
        if ($clock.Elapsed.TotalMinutes -gt 15) { throw 'Interactive GUI fixture exceeded its deadline' }
        Start-Sleep -Milliseconds 500
    }
    $raw = (Get-Content -LiteralPath $done -Raw).Trim()
    if ($raw -ne '0' -and $raw -ne '1') { throw 'Invalid interactive fixture completion' }
    $result = [int]$raw
    $exitClock = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running') {
        if ($exitClock.Elapsed.TotalSeconds -gt 10) { throw 'Interactive task did not exit after completion' }
        Start-Sleep -Milliseconds 100
    }
    $taskResult = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
    if ($taskResult -ne $result) { throw "Interactive task exit $taskResult differs from completion $result" }
    [pscustomobject]@{ Completed = ($result -eq 0); TaskName = $taskName; ActualTaskExit = $taskResult } | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'gui-session-result.json')
} finally {
    if (Test-Path $log) { Get-Content -LiteralPath $log }
    if ($registered) {
        $task = Get-ScheduledTask -TaskName $taskName
        if ($task.State -eq 'Running') {
            Stop-ScheduledTask -TaskName $taskName
            Start-Sleep -Milliseconds 200
        }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Owned GUI task remains' }
    }
}
exit $result
