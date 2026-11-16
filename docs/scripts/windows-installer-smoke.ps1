[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Installer,
    [Parameter(Mandatory=$true)][string]$BundleDirectory
)
$ErrorActionPreference = 'Stop'
$Installer = (Resolve-Path -LiteralPath $Installer).Path
$BundleDirectory = (Resolve-Path -LiteralPath $BundleDirectory).Path
$uninstallKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{8E4E8F6B-3275-48AC-9762-678DE7BAA930}_is1'
if (Test-Path $uninstallKey) { throw 'Smoke test requires a machine without an existing Photon-FlClash installation' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run installer smoke tests as administrator' }
$root = Join-Path ([IO.Path]::GetTempPath()) ('photon-installer-smoke-' + [Guid]::NewGuid().ToString('N'))
$app = Join-Path $root 'app'
$userData = Join-Path $env:APPDATA ('com.follow\clash\installer-smoke-' + [Guid]::NewGuid().ToString('N'))
$running = $null
New-Item -ItemType Directory -Path $root, $userData | Out-Null
function Invoke-Setup([string]$Program, [string]$Log, [switch]$ExpectFailure) {
    $arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', "/LOG=`"$root\$Log.log`"")
    if ($Program -eq $Installer) { $arguments += "/DIR=`"$app`"" }
    $process = Start-Process -FilePath $Program -ArgumentList $arguments -Wait -PassThru
    if ($ExpectFailure) {
        if ($process.ExitCode -eq 0) { throw "$Log unexpectedly succeeded while an installed process was running" }
    } elseif ($process.ExitCode -ne 0) {
        throw "$Log failed: $($process.ExitCode); logs: $root"
    }
}
function Assert-Bundle {
    foreach ($file in Get-ChildItem -LiteralPath $BundleDirectory -Recurse -File) {
        $relative = $file.FullName.Substring($BundleDirectory.Length + 1)
        $installed = Join-Path $app $relative
        if ((Get-FileHash -LiteralPath $installed).Hash -cne (Get-FileHash -LiteralPath $file.FullName).Hash) {
            throw "Installed payload mismatch: $relative"
        }
    }
    if (!(Test-Path -LiteralPath (Join-Path $app 'unins000.exe'))) { throw 'Installer data-directory marker missing' }
    if ((Get-ItemProperty -LiteralPath $uninstallKey).InstallLocation.TrimEnd('\') -ine $app) { throw 'Uninstall registration mismatch' }
    $shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Photon-FlClash.lnk'
    $shell = New-Object -ComObject WScript.Shell
    if ($shell.CreateShortcut($shortcut).TargetPath -ine (Join-Path $app 'FlClash.exe')) { throw 'Start menu shortcut mismatch' }
}
try {
    Invoke-Setup $Installer 'install'
    Assert-Bundle
    # Identity/config stand-ins in AppData and an unowned file in the install
    # directory must survive both reinstall and uninstall byte-for-byte.
    $identity = Join-Path $userData 'identity.db'
    $config = Join-Path $userData 'photon.yaml'
    $unowned = Join-Path $app 'keep-user-data.txt'
    foreach ($path in @($identity, $config, $unowned)) { [IO.File]::WriteAllText($path, [Guid]::NewGuid().ToString()) }
    $before = @{}
    foreach ($path in @($identity, $config, $unowned)) { $before[$path] = (Get-FileHash -LiteralPath $path).Hash }

    # Run an isolated process inside this installation. The installer must
    # refuse replacement/removal and leave the process alive.
    $fixture = Join-Path $app 'installer-lock-test.exe'
    $fixtureSource = Join-Path $root 'InstallerLockTest.cs'
    'public class InstallerLockTest { public static void Main() { System.Threading.Thread.Sleep(300000); } }' | Set-Content -Encoding ascii $fixtureSource
    # .NET Framework csc emits an executable that works from both Windows
    # PowerShell 5 and pwsh 7; Add-Type cannot emit console EXEs on pwsh 7.
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $compiler /nologo /target:exe "/out:$fixture" $fixtureSource
    if ($LASTEXITCODE -ne 0) { throw 'Could not compile the isolated process fixture' }
    $running = Start-Process -FilePath $fixture -PassThru
    Invoke-Setup $Installer 'blocked-install' -ExpectFailure
    Invoke-Setup (Join-Path $app 'unins000.exe') 'blocked-uninstall' -ExpectFailure
    $running.Refresh()
    if ($running.HasExited) { throw 'Installer killed the owned test process' }
    Stop-Process -Id $running.Id
    $running.WaitForExit()
    $running = $null
    Remove-Item -LiteralPath $fixture

    Invoke-Setup $Installer 'reinstall'
    Assert-Bundle
    foreach ($path in $before.Keys) {
        if ((Get-FileHash -LiteralPath $path).Hash -cne $before[$path]) { throw "Reinstall modified user data: $path" }
    }
    Invoke-Setup (Join-Path $app 'unins000.exe') 'uninstall'
    if (Test-Path -LiteralPath $uninstallKey) { throw 'Uninstall registry entry remains' }
    if (Test-Path -LiteralPath (Join-Path $app 'FlClash.exe')) { throw 'Installed executable remains' }
    if (Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Photon-FlClash.lnk')) { throw 'Start menu shortcut remains' }
    foreach ($path in $before.Keys) {
        if ((Get-FileHash -LiteralPath $path).Hash -cne $before[$path]) { throw "Uninstall modified user data: $path" }
    }
    Write-Output 'WINDOWS_INSTALLER_SMOKE_PASS (install, payload, shortcut, active-process refusal, reinstall, uninstall, data preservation)'
} finally {
    if ($running -and !$running.HasExited) { Stop-Process -Id $running.Id; $running.WaitForExit() }
    # On failure leave the installation and logs for diagnosis. Never recursively
    # delete files of a registered installation or real user data.
    Remove-Item -LiteralPath $userData -Recurse -Force
    Write-Output "Installer smoke evidence: $root"
}
