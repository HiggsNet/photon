param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$FixtureDirectory,
    [ValidateSet('windows-service-smoke.ps1','windows-tray-smoke.ps1')][string]$MainScript = 'windows-service-smoke.ps1',
    [switch]$StartOnly,
    [switch]$CollectOnly,
    [ValidateRange(5,900)][int]$WaitSeconds = 900
)
$ErrorActionPreference = 'Stop'
if ($StartOnly -and $CollectOnly) { throw 'StartOnly and CollectOnly are mutually exclusive' }
$Executable = (Resolve-Path $Executable).Path
$FixtureDirectory = (Resolve-Path $FixtureDirectory).Path
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$consoleUser = (Get-CimInstance Win32_ComputerSystem).UserName
if (!$consoleUser -or $consoleUser -ine $identity) { throw 'Log in to the Windows console as the SSH fixture user before GUI testing' }
$taskName = $null
$runner = Join-Path $FixtureDirectory 'gui-session-runner.ps1'
$done = Join-Path $FixtureDirectory 'gui-session.done'
$log = Join-Path $FixtureDirectory 'gui-session.log'
$manifestPath = Join-Path $FixtureDirectory 'gui-session.json'
$arguments = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $runner + '" -Executable "' + $Executable + '" -FixtureDirectory "' + $FixtureDirectory + '" -MainScript "' + $MainScript + '"'
$identitySID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function Read-OwnedGuiTask {
    if ($taskName -cnotmatch '^PhotonGuiSmoke-[0-9a-f]{32}$') { throw 'Invalid owned GUI task name' }
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
    $actions = @($task.Actions)
    if ($task.TaskPath -cne '\' -or $task.TaskName -cne $taskName -or $actions.Count -ne 1 -or $actions[0].Execute -ine 'powershell.exe' -or $actions[0].Arguments -cne $arguments -or $actions[0].WorkingDirectory) { throw 'GUI task action no longer belongs to this fixture' }
    $principalSID = $task.Principal.UserId
    if ($principalSID -notmatch '^S-1-') {
        $account = New-Object Security.Principal.NTAccount($principalSID)
        $principalSID = $account.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($principalSID -cne $identitySID -or [string]$task.Principal.RunLevel -ne 'Highest' -or [string]$task.Principal.LogonType -ne 'Interactive') { throw 'GUI task principal no longer belongs to this interactive user' }
    $task
}
$registered = $false
$detached = $false
$result = 1
if ($CollectOnly) {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($manifest.FixtureDirectory -cne $FixtureDirectory -or $manifest.Executable -cne $Executable -or $manifest.MainScript -cne $MainScript -or $manifest.Runner -cne $runner -or $manifest.Arguments -cne $arguments -or $manifest.UserSID -cne $identitySID -or $manifest.User -ine $identity) { throw 'GUI task manifest does not belong to this fixture and user' }
    $taskName = $manifest.TaskName
    $null = Read-OwnedGuiTask
    $registered = $true
} else {
    $taskName = 'PhotonGuiSmoke-' + [Guid]::NewGuid().ToString('N')
    if ((Test-Path -LiteralPath $runner) -or (Test-Path -LiteralPath $done) -or (Test-Path -LiteralPath $manifestPath) -or (Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue)) { throw 'Refusing an existing GUI session fixture' }
@'
param([string]$Executable, [string]$FixtureDirectory, [string]$MainScript)
$ErrorActionPreference = 'Stop'
$code = 1
try {
    if (![Environment]::UserInteractive) { throw 'Task did not receive an interactive desktop' }
    & (Join-Path $FixtureDirectory $MainScript) -Executable $Executable -FixtureDirectory $FixtureDirectory *> (Join-Path $FixtureDirectory 'gui-session.log')
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
}
try {
    if (!$CollectOnly) {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
        $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $null = Register-ScheduledTask -TaskPath '\' -TaskName $taskName -Action $action -Principal $principal -Settings $settings
        $registered = $true
        $null = Read-OwnedGuiTask
        [pscustomobject]@{ TaskName = $taskName; User = $identity; UserSID = $identitySID; ConsoleUser = $consoleUser; RegisteredAtUTC = [DateTime]::UtcNow.ToString('o'); FixtureDirectory = $FixtureDirectory; Executable = $Executable; MainScript = $MainScript; Runner = $runner; Arguments = $arguments } | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath $manifestPath
        Start-ScheduledTask -TaskPath '\' -TaskName $taskName
        if ($StartOnly) {
            Write-Output "GUI_SESSION_STARTED $taskName"
            $detached = $true
            exit 0
        }
    }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path $done)) {
        if ($clock.Elapsed.TotalSeconds -gt $WaitSeconds) { throw 'Interactive GUI fixture exceeded its collection deadline' }
        Start-Sleep -Milliseconds 500
    }
    $raw = (Get-Content -LiteralPath $done -Raw).Trim()
    if ($raw -ne '0' -and $raw -ne '1') { throw 'Invalid interactive fixture completion' }
    $result = [int]$raw
    $exitClock = [Diagnostics.Stopwatch]::StartNew()
    while ((Read-OwnedGuiTask).State -eq 'Running') {
        if ($exitClock.Elapsed.TotalSeconds -gt 10) { throw 'Interactive task did not exit after completion' }
        Start-Sleep -Milliseconds 100
    }
    $taskResult = (Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName).LastTaskResult
    if ($null -eq $taskResult -or $taskResult -ne $result) { throw "Interactive task exit $taskResult differs from completion $result" }
    [pscustomobject]@{ Completed = ($result -eq 0); TaskName = $taskName; ActualTaskExit = $taskResult } | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'gui-session-result.json')
} finally {
    if ($registered -and !$detached) {
        $task = Read-OwnedGuiTask
        if ($task.State -eq 'Running') {
            Stop-ScheduledTask -TaskPath '\' -TaskName $taskName
            $stopClock = [Diagnostics.Stopwatch]::StartNew()
            while ((Read-OwnedGuiTask).State -eq 'Running') {
                if ($stopClock.Elapsed.TotalSeconds -gt 10) { throw 'Owned GUI task did not stop; leaving its registration for inspection' }
                Start-Sleep -Milliseconds 100
            }
        }
        $null = Read-OwnedGuiTask
        Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false
        if (Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Owned GUI task remains' }
    }
    if (!$detached -and (Test-Path -LiteralPath $log)) { Get-Content -LiteralPath $log }
}
exit $result
