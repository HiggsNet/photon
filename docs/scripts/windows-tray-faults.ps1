# Dot-source only after the explicit fixture-tray-faults opt-in marker.
# The parent tray fixture owns all processes, paths and public identity evidence.
function Initialize-TrayFaultNative {
    if('PhotonTrayFaultNative' -as [type]){return}
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class PhotonTrayFaultNative {
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetProcessId(IntPtr process);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool TerminateProcess(IntPtr process,uint code);
    public static void KillOwned(IntPtr process,uint expectedPID,uint code) {
        if(process==IntPtr.Zero||expectedPID==0||GetProcessId(process)!=expectedPID)throw new InvalidOperationException("Retained process handle ownership changed");
        if(!TerminateProcess(process,code))throw new Win32Exception(Marshal.GetLastWin32Error(),"Terminate owned tray process");
    }
}
'@
}
$faultRequestPath=Join-Path $FixtureDirectory 'tray-fault-request.txt'
$faultFailure=$null;$faultError=$null;$faultCompleted=$false
$faultCrash=$null;$faultCrashRecovery=$null;$faultNetworkBefore=$null;$faultNetworkAfter=$null
$faultPhysical=[pscustomobject]@{Before=$null;Down=$null;Up=$null}
$faultProbes=New-Object System.Collections.Generic.List[object]
$faultSameOwner=$null;$faultDownDuration=$null
function Write-TrayFaultPhase([string]$Phase) {
    [IO.File]::WriteAllText($faultRequestPath,$Phase,(New-Object Text.UTF8Encoding($false)))
}
function Read-TrayFaultPhysical {
    $physicalCandidates=@(Get-NetAdapter -Physical -IncludeHidden -ErrorAction Stop|Where-Object { ([string]$_.MacAddress).Replace('-',':').ToUpperInvariant() -ceq 'BC:24:11:BE:0E:E0' })
    if($physicalCandidates.Count -ne 1 -or !$physicalCandidates[0].HardwareInterface){throw 'Expected exactly one physical adapter with MAC BC-24-11-BE-0E-E0'}
    $physicalCandidates[0]|Select-Object Name,InterfaceDescription,ifIndex,MacAddress,Status,MediaConnectionState,HardwareInterface,LinkSpeed
}
function Assert-TrayFaultIdentity($Status) {
    if((Read-TrayFileID) -cne $stateID){throw 'Fault recovery replaced the stable identity database'}
    if(!$Status.running -or $Status.admission.pending -or $Status.admission.reason -cne 'adopted' -or $Status.admission.managed_zone -cne $request.zone){throw 'Fault recovery lost the original admitted identity'}
    # Adopted means the common owner still holds a private key matching the
    # zone authority. The fixture's verified single-key authority binds exactly
    # the original public request; no private database reader or new DTO is used.
    $keys=@($authority.authority.Keys)
    if(!$authority.chain_verified -or $authority.request.public_key -cne $request.public_key -or $authority.root_public_key -cne $fixture.TrustedRootPublicKey -or $keys.Count -ne 1 -or $keys[0].Key -cne $request.public_key){throw 'Original public request no longer has its verified single-key delegation'}
}
function Assert-TrayFaultSameOwner {
    Assert-TrayOwner $gui
    if($gui.Process.Id -ne $faultSameOwner.PID -or $gui.Creation -ne $faultSameOwner.Creation -or $gui.Path -ine $faultSameOwner.Path){throw 'Physical outage restarted or replaced the GUI process'}
}
function Probe-TrayFaultNoEcho([string]$Local,[string]$Remote) {
    Assert-TrayFaultSameOwner
    $physicalBefore=Read-TrayFaultPhysical
    if([string]$physicalBefore.Status -eq 'Up'){throw 'Physical link restored before the negative business probe'}
    $payload=[Text.Encoding]::UTF8.GetBytes('TRAY-FAULT-'+[Guid]::NewGuid().ToString('N'))
    $probe=[pscustomobject]@{AtUTC=[DateTime]::UtcNow.ToString('o');Local=$Local;Remote=$Remote;Stage='Parse';Sent=$false;SentBytes=0;Received=$false;ReceivedBytes=0;SocketErrorCode=$null;NativeSocketErrorCode=$null;ExpectedNetworkFailure=$false;Failure=$null;PhysicalBefore=$physicalBefore;PhysicalAfter=$null;PhysicalAfterError=$null}
    $udp=$null
    try {
        $localIP=[Net.IPAddress]::Parse($Local);$remoteIP=[Net.IPAddress]::Parse($Remote)
        $probe.Stage='Create';$udp=New-Object Net.Sockets.UdpClient($localIP.AddressFamily)
        $udp.Client.ReceiveTimeout=1000
        $probe.Stage='Bind';$udp.Client.Bind((New-Object Net.IPEndPoint($localIP,0)))
        $probe.Stage='Connect';$udp.Connect($remoteIP,19096)
        $probe.Stage='Send';$probe.SentBytes=$udp.Send($payload,$payload.Length)
        if($probe.SentBytes -ne $payload.Length){throw 'Negative business probe sent an incomplete datagram'}
        $probe.Sent=$true
        $any=[Net.IPAddress]::Any;if($localIP.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){$any=[Net.IPAddress]::IPv6Any}
        $peer=New-Object Net.IPEndPoint($any,0)
        $probe.Stage='Receive';$reply=$udp.Receive([ref]$peer)
        $probe.Received=$true;$probe.ReceivedBytes=$reply.Length
        throw 'Business response escaped the physically disconnected link'
    } catch {
        $probe.Failure=$_.Exception.Message
        $cause=$_.Exception
        while($cause -isnot [Net.Sockets.SocketException] -and $cause.InnerException){$cause=$cause.InnerException}
        if($cause -isnot [Net.Sockets.SocketException]){throw}
        $probe.SocketErrorCode=[string]$cause.SocketErrorCode;$probe.NativeSocketErrorCode=[int]$cause.NativeErrorCode
        $allowed=@('NetworkDown','NetworkUnreachable','HostUnreachable','AddressNotAvailable')
        if($probe.SocketErrorCode -eq 'TimedOut') {
            if(!$probe.Sent -or $probe.Stage -ne 'Receive'){throw}
        } elseif($allowed -notcontains $probe.SocketErrorCode) {throw}
        $probe.ExpectedNetworkFailure=$true
    } finally {
        if($udp){$udp.Dispose()}
        try {$probe.PhysicalAfter=Read-TrayFaultPhysical} catch {$probe.PhysicalAfterError=$_.Exception.Message}
        $faultProbes.Add($probe)
    }
    if($probe.PhysicalAfterError){throw $probe.PhysicalAfterError}
    if([string]$probe.PhysicalAfter.Status -eq 'Up'){throw 'Physical link restored during the negative business probe'}
    Assert-TrayFaultSameOwner
}
try {
    Initialize-TrayFaultNative
    if(Test-Path -LiteralPath $faultRequestPath){throw 'Refusing stale tray fault coordination state'}
    $faultPhysical.Before=Read-TrayFaultPhysical
    if([string]$faultPhysical.Before.Status -ne 'Up'){throw 'Physical adapter was not initially Up'}
    $beforeCrash=Check-TrayBusiness 'before-force-kill';Assert-TrayFaultIdentity $beforeCrash
    $killed=$gui;$killedWindow=$window;$killedIndex=$script:trayOwnedIndex
    Assert-TrayOwner $killed;[PhotonGuiSmokeNative]::Verify($killedWindow,$killed.Process.Id)
    $faultCrash=[pscustomobject]@{PID=$killed.Process.Id;Creation=$killed.Creation;Path=$killed.Path;RetainedHandleAcquired=($killed.Process.Handle -ne [IntPtr]::Zero);InterfaceIndex=$killedIndex;ExpectedExitCode=71;ActualExitCode=$null;StateFileID=$stateID;OriginalPublicKey=$request.public_key;Before=$beforeCrash;Released=$false;ReleaseEvidence=$null}
    [PhotonTrayFaultNative]::KillOwned($killed.Process.Handle,[uint32]$killed.Process.Id,71)
    $killed.ExpectedForcedExit=$true
    if(!$killed.Process.WaitForExit(10000)){throw 'Force-killed GUI did not terminate within its deadline'}
    $faultCrash.ActualExitCode=$killed.Process.ExitCode
    if($faultCrash.ActualExitCode -ne 71){throw 'Force-killed GUI did not retain the requested nonzero exit code'}
    $gui=$null;$window=[IntPtr]::Zero
    Assert-TrayReleased $killed.Process.Id $killedIndex 'force-killed';$faultCrash.Released=$true
    $faultCrash.ReleaseEvidence=$lifecycle[$lifecycle.Count-1]
    $gui=Start-OwnedTray $killed.Path 'fault-reopened';$window=Find-TrayWindow $gui
    if($gui.Process.Id -eq $killed.Process.Id){throw 'Reopened GUI reused the killed PID'}
    Click-Tray $window 1102
    $faultCrashRecovery=Check-TrayBusiness 'force-kill-recovered';Assert-TrayFaultIdentity $faultCrashRecovery
    if($faultCrashRecovery.ike.expires_at -ceq $beforeCrash.ike.expires_at -or $faultCrashRecovery.ike.child_expires_at -ceq $beforeCrash.ike.child_expires_at){throw 'Force-kill recovery did not establish fresh IKE and CHILD lifetimes'}
    Save-TrayPhase 'force-kill-recovered'
    $faultNetworkBefore=Read-TrayStatus;Assert-TrayFaultIdentity $faultNetworkBefore
    $faultSameOwner=[pscustomobject]@{PID=$gui.Process.Id;Creation=$gui.Creation;Path=$gui.Path;StateFileID=$stateID;OriginalPublicKey=$request.public_key}
    Write-TrayFaultPhase 'network-ready'
    Wait-Tray {$candidate=Read-TrayFaultPhysical;if([string]$candidate.Status -ne 'Up'){$faultPhysical.Down=$candidate;return $true};$false} 'physical net0 link down' 45
    $downClock=[Diagnostics.Stopwatch]::StartNew()
    Probe-TrayFaultNoEcho '198.18.253.2' '198.18.253.1'
    Probe-TrayFaultNoEcho 'fd00:7068:b4::2' 'fd00:7068:b4::1'
    Assert-TrayFaultSameOwner
    Wait-Tray {$candidate=Read-TrayFaultPhysical;if([string]$candidate.Status -eq 'Up'){$faultPhysical.Up=$candidate;return $true};$false} 'physical net0 link restored by external coordinator/watchdog' 75
    $faultDownDuration=$downClock.Elapsed.TotalSeconds
    # Do not click Start/Stop/Restart: the existing runtime must recover itself.
    $faultNetworkAfter=Check-TrayBusiness 'physical-network-recovered'
    Assert-TrayFaultSameOwner;Assert-TrayFaultIdentity $faultNetworkAfter
    if($faultProbes.Count -ne 2 -or @($faultProbes|Where-Object { !$_.ExpectedNetworkFailure -or $_.Received }).Count -ne 0){throw 'Both address families did not prove an expected physical outage failure'}
    Save-TrayPhase 'physical-network-recovered'
    Write-TrayFaultPhase 'network-complete'
    $faultCompleted=$true
} catch {
    $faultError=$_;$faultFailure=$_.Exception.Message
    try {Write-TrayFaultPhase 'failed'} catch {$faultFailure+="; fault coordination failure: $($_.Exception.Message)"}
} finally {
    $trayFaultsResult=[pscustomobject]@{SchemaVersion=1;Completed=$faultCompleted;Failure=$faultFailure;FailurePosition=$(if($faultError){$faultError.InvocationInfo.PositionMessage}else{$null});FailureStack=$(if($faultError){$faultError.ScriptStackTrace}else{$null});Crash=$faultCrash;CrashRecovered=$faultCrashRecovery;PhysicalAdapter=$faultPhysical;ObservedDownSeconds=$faultDownDuration;NetworkOwner=$faultSameOwner;NetworkBefore=$faultNetworkBefore;NetworkAfter=$faultNetworkAfter;Probes=$faultProbes.ToArray();AutomaticRecovery=$faultCompleted;ReconnectClicked=$false;OSPowerTest='Not run: guest reports S1/S2/S3/hibernate/S0 unavailable; guest configuration unchanged'}
    try {$trayFaultsResult|ConvertTo-Json -Depth 18|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'tray-faults.json')} catch {
        $trayFaultsResult.Completed=$false
        $trayFaultsResult.Failure="$faultFailure; fault evidence persistence failed: $($_.Exception.Message)"
        if(!$faultError){$faultError=$_}
        try {Write-TrayFaultPhase 'failed'} catch {}
    }
}
if($faultError){throw $faultError}
Write-Host 'Tray force-kill and physical-link recovery passed with stable identity and automatic dual-stack recovery'
