param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$FixtureDirectory
)
$ErrorActionPreference='Stop'
$Executable=(Resolve-Path -LiteralPath $Executable).Path
$FixtureDirectory=(Resolve-Path -LiteralPath $FixtureDirectory).Path
$fixture=Get-Content -LiteralPath (Join-Path $FixtureDirectory 'config.json') -Raw | ConvertFrom-Json
. (Join-Path $FixtureDirectory 'windows-gui-support.ps1')
Initialize-PhotonGuiSmokeNative
Add-Type -AssemblyName System.Windows.Forms
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
public static class PhotonTrayControl {
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetNamedPipeServerProcessId(IntPtr pipe,out uint pid);
    private static int Remaining(Stopwatch clock) {
        long remaining=5000-clock.ElapsedMilliseconds;
        if(remaining<=0)throw new TimeoutException("Owned status absolute deadline");
        return (int)remaining;
    }
    private static void ReadExact(Stream pipe,byte[] bytes,Stopwatch clock) {
        int offset=0;
        while(offset<bytes.Length) {
            var read=pipe.ReadAsync(bytes,offset,bytes.Length-offset);
            if(!read.Wait(Remaining(clock)))throw new TimeoutException("Owned status read deadline");
            int count=read.Result;
            if(count==0)throw new EndOfStreamException();
            offset+=count;
        }
    }
    public static string Status(string statePath,uint expectedPID) {
        if(expectedPID==0)throw new InvalidOperationException("Expected GUI PID is required");
        var clock=Stopwatch.StartNew();
        string suffix;
        using(var sha=SHA256.Create())suffix=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(Path.GetFullPath(statePath).ToLowerInvariant()))).Replace("-","").ToLowerInvariant();
        using(var pipe=new NamedPipeClientStream(".","Photon.Control.v1."+suffix,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification)) {
            pipe.Connect(Math.Min(1000,Remaining(clock)));
            uint actual;
            if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(),out actual)||actual!=expectedPID)throw new InvalidOperationException("Control endpoint belongs to a different process");
            var body=Encoding.UTF8.GetBytes("{\"version\":1,\"method\":\"status\"}");
            var frame=new byte[4+body.Length];
            frame[3]=(byte)body.Length;
            Buffer.BlockCopy(body,0,frame,4,body.Length);
            if(!pipe.WriteAsync(frame,0,frame.Length).Wait(Remaining(clock)))throw new TimeoutException("Owned status write deadline");
            var header=new byte[4];ReadExact(pipe,header,clock);
            uint length=((uint)header[0]<<24)|((uint)header[1]<<16)|((uint)header[2]<<8)|header[3];
            if(length==0||length>1048576)throw new InvalidOperationException("Invalid status frame length");
            var reply=new byte[length];ReadExact(pipe,reply,clock);return Encoding.UTF8.GetString(reply);
        }
    }
}
'@
$token=[Guid]::NewGuid().ToString('N').Substring(0,12)
$adapterName='PhotonTray-'+$token
$oldService='PhotonTrayOld-'+$token
$Config=Join-Path $FixtureDirectory 'tray.yaml'
$statePath=Join-Path $FixtureDirectory 'windows.db'
$phaseFile=Join-Path $FixtureDirectory 'autojoin-request-phase.txt'
$session=(Get-Process -Id $PID).SessionId
$interactive=(Get-CimInstance Win32_ComputerSystem).UserName
$explorer=@(Get-Process explorer -ErrorAction SilentlyContinue|Where-Object SessionId -eq $session)
$gui=$null; $conflict=$null; $window=[IntPtr]::Zero; $conflictWindow=[IntPtr]::Zero; $settings=[IntPtr]::Zero
$failure=$null; $completed=$false; $oldInstalled=$false; $oldBefore=$null; $firstRun=$null
$requestText=$null; $request=$null; $authority=$null; $stateID=$null
$trayFaultsResult=$null
$clipboardBackup=$null; $clipboardCaptured=$false; $clipboardRoundtrip=$false; $clipboardRestored=$false
$clipboardOwnedTexts=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
$diagnosticEvidence=New-Object System.Collections.Generic.List[object]
$diagnosticChecks=[pscustomobject]@{ClosedWindowBusiness=$false;PauseHeldAcrossStop=$false;ManualRefreshWhilePaused=$false;ClipboardRoundtrip=$false;RestartLogFresh=$false;RestartSAMatches=$false}
$samples=New-Object System.Collections.Generic.List[object]
$lifecycle=New-Object System.Collections.Generic.List[object]
$visualEvidence=New-Object System.Collections.Generic.List[object]
$owned=New-Object System.Collections.Generic.List[object]
function Quote-TrayYaml([string]$Value) { "'"+$Value.Replace("'","''")+"'" }
function Invoke-TrayCLI([string[]]$Arguments) {
    $output=& $Executable @Arguments
    if($LASTEXITCODE -ne 0){throw "Tray fixture CLI failed: $Arguments"}
    $output
}
function Start-OwnedTray([string]$Path,[string]$Label) {
    $process=Start-Process -FilePath $Path -ArgumentList @('gui','--config',('"'+$Config+'"')) -PassThru -RedirectStandardError (Join-Path $FixtureDirectory ('tray-'+$Label+'-error.log'))
    if($process.Handle -eq [IntPtr]::Zero){throw 'Cannot retain owned GUI process handle'}
    $entry=[pscustomobject]@{Process=$process;Path=$Path;Creation=$process.StartTime.ToUniversalTime();Label=$Label;ExpectedForcedExit=$false}
    $owned.Add($entry)
    Assert-TrayOwner $entry
    $entry
}
function Assert-TrayOwner($Owner) {
    if(!$Owner -or $Owner.Process.HasExited){throw 'Owned tray GUI exited early'}
    $current=Get-Process -Id $Owner.Process.Id -ErrorAction Stop
    $details=Get-CimInstance Win32_Process -Filter "ProcessId=$($Owner.Process.Id)"
    if(!$details -or $details.ExecutablePath -ine $Owner.Path -or $current.StartTime.ToUniversalTime() -ne $Owner.Creation -or $current.SessionId -ne $session -or $details.CommandLine -notlike ('*'+$Config+'*')){throw 'Tray GUI process ownership changed'}
}
function Wait-Tray([scriptblock]$Condition,[string]$Label,[int]$Seconds=90) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    do {if($gui){Assert-TrayOwner $gui}; if(& $Condition){return}; Start-Sleep -Milliseconds 200}while($clock.Elapsed.TotalSeconds -lt $Seconds)
    throw "Tray fixture timed out: $Label"
}
function Read-TrayStatus {
    Assert-TrayOwner $gui
    $raw=[PhotonTrayControl]::Status($statePath,[uint32]$gui.Process.Id)
    $response=$raw|ConvertFrom-Json
    if($response.version -ne 1 -or $response.method -ne 'status' -or $response.error -or !$response.result){throw 'Invalid owned GUI status DTO'}
    $response.result
}
function Read-TrayFileID {
    $raw=& fsutil.exe file queryfileid $statePath
    if($LASTEXITCODE -ne 0){throw 'Cannot read tray Bolt file identity'}
    $ids=[regex]::Matches(($raw -join "`n"),'(?i)\b0x[0-9a-f]+\b')
    if($ids.Count -ne 1){throw 'Ambiguous tray Bolt file identity'}
    $ids[0].Value.ToLowerInvariant()
}
function Wait-TrayAck([string]$Phase) {
    Wait-Tray {$path=Join-Path $FixtureDirectory ('autojoin-'+$Phase+'.ack'); (Test-Path -LiteralPath $path) -and (Get-Content -LiteralPath $path -Raw).Trim() -eq $Phase} "coordinator $Phase"
}
function Click-Tray([IntPtr]$Target,[int]$ControlID) {
    Wait-Tray {[PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($Target,$ControlID))} "enabled control $ControlID"
    [PhotonGuiSmokeNative]::Click($Target,$ControlID)
}
function Assert-OldRegistration {
    $current=Get-CimInstance Win32_Service -Filter "Name='$oldService'"
    if(!$current -or $current.State -ne 'Stopped' -or $current.ProcessId -ne 0 -or $current.PathName -cne $oldBefore.PathName -or $current.StartName -cne $oldBefore.StartName){throw 'Portable GUI changed the old stopped SCM registration'}
}
function Assert-TrayStopped {
    Assert-TrayOwner $gui
    $available=$false
    try{$null=Read-TrayStatus;$available=$true}catch{}
    if($available){throw 'Stopped tray runtime retained an available IPC endpoint'}
    Wait-Tray {@(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count -eq 0} 'owned adapter removed' 20
    if($script:trayOwnedIndex -and @(Get-NetRoute -InterfaceIndex $script:trayOwnedIndex -ErrorAction SilentlyContinue).Count -ne 0){throw 'Stopped tray retained routes on its owned interface'}
    Wait-Tray {![PhotonGuiSmokeNative]::Text($window,1001).Contains('已连接') -and [PhotonGuiSmokeNative]::Text($window,1003) -eq '活动网关：—'} 'stopped UI cleared live gateway' 10
    $offline=Invoke-TrayCLI @('gateways','--config',$Config)
    if(!$offline){throw 'Stopped GUI did not release Bolt for the real offline reader'}
    if($stateID -and (Read-TrayFileID) -cne $stateID){throw 'Stop/restart replaced the stable identity database'}
    Assert-OldRegistration
}
function Assert-TrayReleased([uint32]$PreviousPID,[int]$InterfaceIndex,[string]$Phase) {
    Wait-Tray {@(Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue).Count -eq 0} 'exited GUI adapter removed' 20
    if(@(Get-NetRoute -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue).Count -ne 0){throw 'Exiting GUI retained routes on its owned interface'}
    $pipeAvailable=$false
    try{$null=[PhotonTrayControl]::Status($statePath,$PreviousPID);$pipeAvailable=$true}catch{}
    if($pipeAvailable){throw 'Exiting GUI left its IPC endpoint available'}
    $null=Invoke-TrayCLI @('gateways','--config',$Config)
    if((Read-TrayFileID) -cne $stateID){throw 'GUI exit replaced the stable database'}
    $lifecycle.Add([pscustomobject]@{Phase=$Phase;PID=$PreviousPID;InterfaceIndex=$InterfaceIndex;PipeUnavailable=$true;RoutesAbsent=$true;AdapterAbsent=$true;OfflineDatabaseOpened=$true;StateFileID=$stateID})
}
function Probe-TrayUDP([string]$Local,[string]$Remote,[string]$Phase) {
    $timer=[Diagnostics.Stopwatch]::StartNew();$payload=[Text.Encoding]::UTF8.GetBytes('TRAY-'+$token+'-'+$Phase+'-'+$Remote)
    do{$udp=$null;try{
        $localIP=[Net.IPAddress]::Parse($Local);$udp=New-Object Net.Sockets.UdpClient($localIP.AddressFamily)
        $udp.Client.Bind((New-Object Net.IPEndPoint($localIP,0)));$udp.Client.ReceiveTimeout=700
        $udp.Connect([Net.IPAddress]::Parse($Remote),19096);$null=$udp.Send($payload,$payload.Length)
        $any=[Net.IPAddress]::Any;if($localIP.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){$any=[Net.IPAddress]::IPv6Any}
        $sender=New-Object Net.IPEndPoint($any,0);$reply=$udp.Receive([ref]$sender)
        if([Convert]::ToBase64String($reply) -cne [Convert]::ToBase64String($payload)){throw 'Unexpected tray echo'}
        Write-Host "tray business echo passed: $Phase $Local -> $Remote";return
    }catch{$lastFailure=$_.Exception.Message}finally{if($udp){$udp.Dispose()}};Start-Sleep -Milliseconds 200}while($timer.Elapsed.TotalSeconds -lt 40)
    throw "Tray UDP echo failed: $Phase $lastFailure"
}
function Check-TrayBusiness([string]$Phase) {
    Wait-Tray {try{$s=Read-TrayStatus;$s.running -and $s.tunnel_ready -and $s.ike.live -and $s.ike.child_live}catch{$false}} "authenticated tunnel $Phase"
    Probe-TrayUDP '198.18.253.2' '198.18.253.1' $Phase
    Probe-TrayUDP 'fd00:7068:b4::2' 'fd00:7068:b4::1' $Phase
    $s=Read-TrayStatus
    foreach($prefix in @('198.18.253.1/32','fd00:7068:b4::1/128')){if(@($s.babel.routes|Where-Object prefix -eq $prefix).Count -ne 1){throw 'Tray runtime lacks an authorized dual-stack route'}}
    if((Read-TrayFileID) -cne $stateID){throw 'Tray runtime replaced its stable database'}
    $children=@(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($gui.Process.Id)")
    if($children.Count -ne 0){throw 'GUI launched a child process instead of owning the daemon in process'}
    $adapter=@(Get-NetAdapter -Name $adapterName -ErrorAction Stop)
    if($adapter.Count -ne 1){throw 'Cannot identify exactly one owned tray adapter'}
    $script:trayOwnedIndex=[int]$adapter[0].ifIndex
    Wait-Tray {[PhotonGuiSmokeNative]::Text($window,1001).Contains('已连接')} 'connected GUI observation' 15
    Assert-OldRegistration
    $s
}
function Assert-TrayUnassignedBusiness {
    $probes=New-Object System.Collections.Generic.List[object]
    try {
        foreach($pair in @(@('198.18.253.2','198.18.253.1'),@('fd00:7068:b4::2','fd00:7068:b4::1'))){
            $udp=$null;$probe=[pscustomobject]@{Local=$pair[0];Remote=$pair[1];Stage='bind';Sent=$false;Received=$false;SocketError=$null;NativeError=$null}
            $probes.Add($probe)
            try {
                $ip=[Net.IPAddress]::Parse($pair[0]);$udp=New-Object Net.Sockets.UdpClient($ip.AddressFamily)
                $udp.Client.Bind((New-Object Net.IPEndPoint($ip,0)));$udp.Client.ReceiveTimeout=500
                $probe.Stage='send';$udp.Connect([Net.IPAddress]::Parse($pair[1]),19096)
                $payload=[Text.Encoding]::UTF8.GetBytes('TRAY-UNASSIGNED-'+$token);$null=$udp.Send($payload,$payload.Length);$probe.Sent=$true
                $probe.Stage='receive';$sender=New-Object Net.IPEndPoint($(if($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){[Net.IPAddress]::IPv6Any}else{[Net.IPAddress]::Any}),0)
                $null=$udp.Receive([ref]$sender);$probe.Received=$true
                throw 'Unassigned business address unexpectedly received a response'
            }catch [Net.Sockets.SocketException] {
                $probe.SocketError=$_.Exception.SocketErrorCode.ToString();$probe.NativeError=$_.Exception.NativeErrorCode
            }finally{if($udp){$udp.Dispose()}}
        }
    }finally{$probes|ConvertTo-Json -Depth 5|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'tray-address-waiting-probes.json')}
}
function Save-TrayPhase([string]$Phase) {
    $s=Read-TrayStatus
    if((Read-TrayFileID) -cne $stateID){throw 'Tray phase changed the generated identity file'}
    $entry=[pscustomobject]@{Phase=$Phase;AtUTC=[DateTime]::UtcNow.ToString('o');PID=$gui.Process.Id;Creation=$gui.Creation;StateFileID=Read-TrayFileID;Status=$s;Connection=[PhotonGuiSmokeNative]::Text($window,1001);Runtime=[PhotonGuiSmokeNative]::Text($window,1002);Admission=[PhotonGuiSmokeNative]::Text($window,1007);Request=[PhotonGuiSmokeNative]::Text($window,1008);CopyEnabled=[PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($window,1107));PhysicalGeometry=[PhotonGuiSmokeNative]::Geometry($window);Screenshot=[PhotonGuiSmokeNative]::Screenshot($window,(Join-Path $FixtureDirectory ('tray-'+$Phase+'.png')))}
    $samples.Add($entry);$entry|ConvertTo-Json -Depth 13|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory ('tray-'+$Phase+'.json'))
}
function Find-TrayWindow($Owner) {
    $found=[pscustomobject]@{Handle=[IntPtr]::Zero}
    Wait-Tray {$found.Handle=[PhotonGuiSmokeNative]::Find($Owner.Process.Id);$found.Handle -ne [IntPtr]::Zero} 'owned tray window' 20
    $found.Handle
}
function Exit-OwnedTray($Owner,[IntPtr]$Handle) {
    Assert-TrayOwner $Owner;[PhotonGuiSmokeNative]::Verify($Handle,$Owner.Process.Id)
    [PhotonGuiSmokeNative]::Exit($Handle)
    if(!$Owner.Process.WaitForExit(15000) -or $null -eq $Owner.Process.ExitCode -or $Owner.Process.ExitCode -ne 0){throw 'Tray exit did not join and return zero'}
}
function Open-TrayDiagnostics {
    Click-Tray $window 1111
    $found=[pscustomobject]@{Handle=[IntPtr]::Zero}
    Wait-Tray {$found.Handle=[PhotonGuiSmokeNative]::FindDiagnostics($gui.Process.Id);$found.Handle -ne [IntPtr]::Zero} 'owned diagnostics window' 20
    [PhotonGuiSmokeNative]::Verify($found.Handle,$gui.Process.Id)
    [PhotonGuiSmokeNative]::ResizeDiagnostics($found.Handle)
    $found.Handle
}
function Save-TrayDiagnostics([IntPtr]$Target,[string]$Phase,[string]$Page) {
    [PhotonGuiSmokeNative]::Verify($Target,$gui.Process.Id)
    $geometry=[PhotonGuiSmokeNative]::Geometry($Target)
    $record=[pscustomobject]@{Phase=$Phase;Page=$Page;PID=$gui.Process.Id;Creation=$gui.Creation;AtUTC=[DateTime]::UtcNow.ToString('o');Text=[PhotonGuiSmokeNative]::Text($Target,2310);Metadata=[PhotonGuiSmokeNative]::Text($Target,2314);PhysicalGeometry=$geometry;Screenshot=$null}
    $diagnosticEvidence.Add($record)
    $record|ConvertTo-Json -Depth 7|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory ('tray-diagnostics-'+$Phase+'-'+$Page+'.json'))
    foreach($controlID in @(2301,2302,2303,2310,2311,2312,2313,2314)) {
        $metrics=@($geometry.Controls|Where-Object ID -eq $controlID)
        if($metrics.Count -ne 1 -or !$metrics[0].Visible -or !$metrics[0].InsideClient -or $metrics[0].FontHeight -le 0){throw "Diagnostics $Page has a missing, clipped or unstyled control $controlID"}
    }
    $record.Screenshot=[PhotonGuiSmokeNative]::Screenshot($Target,(Join-Path $FixtureDirectory ('tray-diagnostics-'+$Phase+'-'+$Page+'.png')))
    if($record.Screenshot -notmatch 'saved; varied pixels'){throw "Diagnostics $Page did not render a real screenshot"}
    $record|ConvertTo-Json -Depth 7|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory ('tray-diagnostics-'+$Phase+'-'+$Page+'.json'))
}
function Assert-TrayDiagnosticLog([IntPtr]$Target,[string]$RequiredEvent) {
    Click-Tray $Target 2301;Click-Tray $Target 2311
    Wait-Tray {[PhotonGuiSmokeNative]::Text($Target,2314).Contains($statePath+'.log') -and [PhotonGuiSmokeNative]::Text($Target,2310).Contains('msg='+$RequiredEvent)} 'real runtime log tail'
    $shown=[PhotonGuiSmokeNative]::Text($Target,2310)
    $stream=[IO.File]::Open($statePath+'.log',[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $start=[Math]::Max(0,$stream.Length-262144);$null=$stream.Seek($start,[IO.SeekOrigin]::Begin)
        $buffer=New-Object byte[] 262144;$count=$stream.Read($buffer,0,$buffer.Length)
        $source=[Text.Encoding]::UTF8.GetString($buffer,0,$count)
    } finally {$stream.Dispose()}
    $lines=@($shown.TrimEnd([char[]]"`r`n") -split '\r?\n')
    if([Text.Encoding]::UTF8.GetByteCount($shown.Replace("`r`n","`n")) -gt 262144 -or $lines.Count -gt 1000 -or !$source.Contains($lines[$lines.Count-1])){throw 'Displayed log is not a bounded tail of this owned runtime log file'}
}
function Check-TrayDiagnostics([IntPtr]$Target,[string]$Phase,[bool]$Running) {
    Click-Tray $Target 2302;Click-Tray $Target 2311
    if($Running) {
        Wait-Tray {
            $fresh=Read-TrayStatus;$peer=@($fresh.peers|Where-Object peer -eq 'gateway.catofes.')
            $text=[PhotonGuiSmokeNative]::Text($Target,2310)
            $peer.Count -eq 1 -and $text.Contains('gateway.catofes.') -and $text.Contains('pull_state="'+$peer[0].pull_state+'"') -and $text.Contains('对象拉取累计')
        } 'real Gossip peer and raw pull state'
    } else {
        Wait-Tray {$text=[PhotonGuiSmokeNative]::Text($Target,2310);$text.Contains('已清空上次节点数据') -and !$text.Contains('gateway.catofes.')} 'stopped peer view clears stale nodes'
    }
    Save-TrayDiagnostics $Target $Phase 'peers'
    Click-Tray $Target 2303;Click-Tray $Target 2311
    Wait-Tray {try {
        $detail=[PhotonGuiSmokeNative]::Text($Target,2310)|ConvertFrom-Json
        if(!$Running){return $detail.runtime_state -eq 'stopped' -and !$detail.available -and @($detail.PSObject.Properties|Where-Object Name -eq 'observation').Count -eq 0}
        $detail.runtime_state -eq 'running' -and $detail.available -and $detail.observation.running -and $detail.observation.tunnel_ready -and $detail.observation.ike.live -and $detail.observation.ike.gateway -ceq 'gateway.catofes.' -and @($detail.observation.babel.routes|Where-Object prefix -eq '198.18.253.1/32').Count -eq 1 -and @($detail.observation.babel.routes|Where-Object prefix -eq 'fd00:7068:b4::1/128').Count -eq 1
    }catch{$false}} 'public diagnostics DTO reflects this runtime'
    Save-TrayDiagnostics $Target $Phase 'details'
    Assert-TrayDiagnosticLog $Target $(if($Running){'runtime_started'}else{'runtime_stopped'})
    Save-TrayDiagnostics $Target $Phase 'log'
}
function Read-TrayLogStart([string]$Text) {
    $records=[regex]::Matches($Text,'(?m)^time=(\S+)[^\r\n]*\bmsg=runtime_started\b')
    if($records.Count -eq 0){throw 'Real diagnostic log has no timestamped runtime_started event'}
    [DateTimeOffset]::Parse($records[$records.Count-1].Groups[1].Value)
}
try {
    if($session -le 0 -or ![Environment]::UserInteractive -or !$interactive -or $interactive -ine [Security.Principal.WindowsIdentity]::GetCurrent().Name -or $explorer.Count -eq 0){throw 'Tray acceptance requires the logged-in Explorer desktop'}
    if((Test-Path -LiteralPath $statePath) -or (Test-Path -LiteralPath $Config) -or (Test-Path -LiteralPath $phaseFile)){throw 'Tray autojoin fixture must begin without DB/config/coordination files'}
    $firstRun=Test-GuiFirstRun -ExpectedSessionID $session
    $yaml=@('schema_version: 1',('trusted_root_public_key: '+(Quote-TrayYaml $fixture.TrustedRootPublicKey)),('managed_zone: '+(Quote-TrayYaml $fixture.ManagedZone)),('gossip_listen: '+(Quote-TrayYaml $fixture.GossipListen)),'state:',('  path: '+(Quote-TrayYaml $statePath)),'overlay:',('  id: '+(Quote-TrayYaml $fixture.Overlay.ID)),'  split_routes:')
    foreach($route in $fixture.Overlay.SplitRoutes){$yaml+='    - '+(Quote-TrayYaml $route)}
    $yaml+=@('gateway:','  allowed_zones:');foreach($allowed in $fixture.Gateway.AllowedZones){$yaml+='    - '+(Quote-TrayYaml $allowed)}
    $yaml+='  bootstrap_hints:';foreach($hint in $fixture.Gateway.BootstrapHints){$yaml+=@(('    - peer: '+(Quote-TrayYaml $hint.Peer)),('      address: '+(Quote-TrayYaml $hint.Address)))}
    $yaml+=@('wintun:',('  adapter_name: '+(Quote-TrayYaml $adapterName)),'  mtu: 1400','log:','  level: debug')
    [IO.File]::WriteAllLines($Config,[string[]]$yaml,(New-Object Text.UTF8Encoding($false)))
    $null=Invoke-TrayCLI @('service','install','--name',$oldService,'--config',$Config);$oldInstalled=$true
    $oldBefore=Get-CimInstance Win32_Service -Filter "Name='$oldService'";Assert-OldRegistration
    $portableB=Join-Path $FixtureDirectory 'portable-b';$portableC=Join-Path $FixtureDirectory 'portable-c'
    $null=New-Item -ItemType Directory -Path $portableB,$portableC
    foreach($dir in @($portableB,$portableC)){[IO.File]::Copy($Executable,(Join-Path $dir 'photon-windows.exe'),$false);[IO.File]::Copy((Join-Path (Split-Path $Executable) 'wintun.dll'),(Join-Path $dir 'wintun.dll'),$false)}
    $gui=Start-OwnedTray (Join-Path $portableB 'photon-windows.exe') 'b';$window=Find-TrayWindow $gui
    if([PhotonGuiSmokeNative]::HasControl($window,1101)){throw 'Portable GUI retained the SCM install control'}
    Start-Sleep -Milliseconds 500
    if(Test-Path -LiteralPath $statePath){throw 'Opening GUI automatically initialized a daemon before Start'}
    Click-Tray $window 1102
    Wait-Tray {try{$s=Read-TrayStatus;$s.running -and $s.admission.pending}catch{$false}} 'owned same-process pending daemon'
    $initial=Read-TrayStatus;$stateID=Read-TrayFileID;$requestText=[string]$initial.admission.join_request_b64
    if(!$requestText -or $initial.tunnel_ready -or $initial.ike.live -or (Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue)){throw 'Pending tray initialized a data plane or lacks a request'}
    $outer=$requestText.Replace('-','+').Replace('_','/');if($outer.Length%4 -eq 1){throw 'Malformed rawurl request'};$outer=$outer.PadRight($outer.Length+((4-$outer.Length%4)%4),'=')
    $request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($outer))|ConvertFrom-Json
    if($request.version -ne 1 -or $request.zone -cne $fixture.ManagedZone -or [Convert]::FromBase64String($request.public_key).Length -ne 32){throw 'Invalid generated tray identity'}
    [IO.File]::WriteAllText((Join-Path $FixtureDirectory 'autojoin-request.b64'),$requestText,(New-Object Text.UTF8Encoding($false)))
    Wait-Tray {[PhotonGuiSmokeNative]::Text($window,1008) -ceq $requestText -and [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($window,1107))} 'pending request UI'
    $clipboardBackup=[Windows.Forms.Clipboard]::GetDataObject();$clipboardCaptured=$true;$null=$clipboardOwnedTexts.Add($requestText);Click-Tray $window 1107
    Wait-Tray {[Windows.Forms.Clipboard]::GetText([Windows.Forms.TextDataFormat]::UnicodeText) -ceq $requestText} 'complete clipboard request' 10;$clipboardRoundtrip=$true
    Save-TrayPhase 'pending';[IO.File]::WriteAllText($phaseFile,'request');Wait-TrayAck 'wrong-issued'
    Wait-Tray {$s=Read-TrayStatus;$s.admission.pending -and $s.admission.reason -eq 'delegation_key_mismatch' -and $s.admission.join_request_b64 -ceq $requestText -and !$s.ike.live -and !$s.tunnel_ready -and [PhotonGuiSmokeNative]::Text($window,1007).Contains('本机公钥不匹配')} 'signed wrong-key rejection'
    Save-TrayPhase 'wrong-key';[IO.File]::WriteAllText($phaseFile,'wrong-seen');Wait-TrayAck 'correct-issued'
    Wait-Tray {try{
        $s=Read-TrayStatus
        $s.running -and !$s.admission.pending -and $s.admission.reason -eq 'adopted' -and !$s.tunnel_ready -and $s.readiness.stage -eq 'address_assignment' -and $s.ike.live -and $s.ike.child_live -and $s.babel.live -and [Net.IPAddress]::Parse([string]$s.babel.local).IsIPv6LinkLocal -and [Net.IPAddress]::Parse([string]$s.babel.neighbor).IsIPv6LinkLocal -and !$s.wintun.configured -and @($s.wintun.addresses|Where-Object {$null -ne $_}).Count -eq 0 -and @($s.wintun.split_routes|Where-Object {$null -ne $_}).Count -eq 0 -and @($s.babel.routes|Where-Object {$null -ne $_}).Count -eq 0 -and [PhotonGuiSmokeNative]::Text($window,1001).Contains('等待业务IP分配')
    }catch{$false}} 'adopted identity waits for its first authorized business address'
    $addressWaitingPID=$gui.Process.Id;$addressWaitingCreation=$gui.Creation
    $authority=Get-Content (Join-Path $FixtureDirectory 'autojoin-authority.json') -Raw|ConvertFrom-Json
    if(!$authority.chain_verified -or $authority.request.public_key -cne $request.public_key -or $authority.root_public_key -cne $fixture.TrustedRootPublicKey -or @($authority.authority.Keys|Where-Object Key -ceq $request.public_key).Count -ne 1){throw 'Correct fixture delegation does not bind the generated identity/root'}
    Wait-Tray {[PhotonGuiSmokeNative]::Text($window,1008) -eq '' -and ![PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($window,1107))} 'adopted request cleared'
    Assert-TrayUnassignedBusiness
    Save-TrayPhase 'address-waiting';[IO.File]::WriteAllText($phaseFile,'address-waiting');Wait-TrayAck 'address-assigned'
    $adopted=Check-TrayBusiness 'adopted'
    if($gui.Process.Id -ne $addressWaitingPID -or $gui.Creation -ne $addressWaitingCreation -or (Read-TrayFileID) -cne $stateID){throw 'First address assignment restarted the GUI or replaced its identity database'}
    if($adopted.admission.pending -or $adopted.admission.reason -ne 'adopted' -or $adopted.readiness.stage){throw 'Address assignment did not automatically resume the adopted runtime'}
    $lifecycle.Add([pscustomobject]@{Phase='first-address-assigned';PID=$gui.Process.Id;Creation=$gui.Creation;StateFileID=$stateID;SameProcess=$true;NoRestartClick=$true;TunnelReady=$adopted.tunnel_ready;AddressWaitingStage='address_assignment'})
    Save-TrayPhase 'adopted';[IO.File]::WriteAllText($phaseFile,'adopted');Wait-TrayAck 'verified'
    $diagnostics=Open-TrayDiagnostics
    Check-TrayDiagnostics $diagnostics 'running' $true
    [PhotonGuiSmokeNative]::Close($diagnostics)
    if([PhotonGuiSmokeNative]::IsWindowVisible($diagnostics)){throw 'Closing diagnostics did not hide its owned window'}
    $afterDiagnostics=Check-TrayBusiness 'diagnostics-closed'
    if($afterDiagnostics.ike.expires_at -cne $adopted.ike.expires_at){throw 'Diagnostics close changed the running IKE lifetime'}
    $diagnosticChecks.ClosedWindowBusiness=$true
    Wait-Tray {[PhotonGuiSmokeNative]::TrayPresent($window)} 'owned Explorer icon'
    [PhotonGuiSmokeNative]::Close($window);Wait-Tray {![PhotonGuiSmokeNative]::IsWindowVisible($window)} 'tray hide'
    $null=Check-TrayBusiness 'hidden';[PhotonGuiSmokeNative]::Open($window)
    [PhotonGuiSmokeNative]::RebuildOwnedTray($window);Wait-Tray {[PhotonGuiSmokeNative]::TrayPresent($window)} 'owned icon rebuilt'
    $diagnostics=Open-TrayDiagnostics;Assert-TrayDiagnosticLog $diagnostics 'runtime_started'
    Click-Tray $diagnostics 2312
    Wait-Tray {[PhotonGuiSmokeNative]::Text($diagnostics,2312) -ceq '继续刷新'} 'diagnostics pause enabled'
    $pausedLog=[PhotonGuiSmokeNative]::Text($diagnostics,2310)
    Click-Tray $window 1103;Wait-Tray {try{Assert-TrayStopped;$true}catch{$false}} 'full runtime stop and resource release' 30
    if([PhotonGuiSmokeNative]::Text($diagnostics,2310) -cne $pausedLog){throw 'Paused diagnostics changed while main runtime stopped'}
    $diagnosticChecks.PauseHeldAcrossStop=$true
    Assert-TrayDiagnosticLog $diagnostics 'runtime_stopped'
    if([PhotonGuiSmokeNative]::Text($diagnostics,2310) -ceq $pausedLog){throw 'Explicit refresh did not update the paused log after runtime stop'}
    $diagnosticChecks.ManualRefreshWhilePaused=$true
    $copyText=[PhotonGuiSmokeNative]::Text($diagnostics,2310);$null=$clipboardOwnedTexts.Add($copyText)
    $stoppedLogStart=Read-TrayLogStart $copyText
    Click-Tray $diagnostics 2313
    Wait-Tray {[Windows.Forms.Clipboard]::GetText([Windows.Forms.TextDataFormat]::UnicodeText) -ceq $copyText} 'complete diagnostic log clipboard copy' 10
    $diagnosticChecks.ClipboardRoundtrip=$true
    Check-TrayDiagnostics $diagnostics 'stopped' $false
    Click-Tray $diagnostics 2312
    Wait-Tray {[PhotonGuiSmokeNative]::Text($diagnostics,2312) -ceq '暂停刷新'} 'diagnostics auto refresh resumed'
    [PhotonGuiSmokeNative]::Close($diagnostics)
    $lifecycle.Add([pscustomobject]@{Phase='stopped';PID=$gui.Process.Id;PipeUnavailable=$true;OfflineDatabaseOpened=$true;AdapterAbsent=$true})
    Click-Tray $window 1102;$started=Check-TrayBusiness 'started'
    if($started.ike.expires_at -ceq $adopted.ike.expires_at){throw 'Start reused the previous IKE lifetime'}
    Save-TrayPhase 'started'
    $beforeSaveOwner=$gui.Process.Id;$bytesBefore=[IO.File]::ReadAllBytes($Config)
    Click-Tray $window 1110;$found=[pscustomobject]@{Handle=[IntPtr]::Zero}
    Wait-Tray {$found.Handle=[PhotonGuiSmokeNative]::FindSettings($gui.Process.Id);$found.Handle -ne [IntPtr]::Zero} 'settings';$settings=$found.Handle
    [PhotonGuiSmokeNative]::ResizeSettings($settings)
    Click-Tray $settings 2103
    [PhotonGuiSmokeNative]::SelectRow($settings,2003,0);[PhotonGuiSmokeNative]::SetText($settings,2021,'*');Click-Tray $settings 2122
    Click-Tray $settings 2102
    [PhotonGuiSmokeNative]::SetText($settings,2015,'1279');Click-Tray $settings 1105
    Wait-Tray {[PhotonGuiSmokeNative]::Text($settings,2019).StartsWith('操作失败：')} 'invalid MTU rejected'
    if([Convert]::ToBase64String([IO.File]::ReadAllBytes($Config)) -cne [Convert]::ToBase64String($bytesBefore)){throw 'Invalid portable form changed configuration bytes'}
    [PhotonGuiSmokeNative]::SetText($settings,2015,'1360');Click-Tray $settings 1105
    Wait-Tray {[PhotonGuiSmokeNative]::Text($settings,2019).StartsWith('配置已保存')} 'MTU saved'
    if([IO.File]::ReadAllText($Config) -notmatch '(?m)^\s*-\s+(?:''\*''|"\*")\s*$'){throw 'Portable wildcard save did not quote YAML'}
    $saved=Read-TrayStatus;if($gui.Process.Id -ne $beforeSaveOwner -or $saved.ike.expires_at -cne $started.ike.expires_at){throw 'Save restarted the owned runtime'}
    Click-Tray $settings 1106;Wait-Tray {[PhotonGuiSmokeNative]::Text($settings,2019).StartsWith('配置已读取') -and [PhotonGuiSmokeNative]::Text($settings,2015) -ceq '1360'} 'real saved MTU reloaded'
    $allowedRows=@([PhotonGuiSmokeNative]::ListItems($settings,2003));if($allowedRows.Count -ne 1 -or $allowedRows[0] -cne '*'){throw 'Portable wildcard did not survive actual reload'}
    foreach($page in @(
        [pscustomobject]@{ID=2101;Name='identity';Controls=@(2001,2002)},
        [pscustomobject]@{ID=2103;Name='gateway';Controls=@(2003,2021,2121,2122,2123,2124,2005,2006,2007,2111,2112,2113,2114)},
        [pscustomobject]@{ID=2104;Name='routes';Controls=@(2004,2022,2131,2132,2133,2134)},
        [pscustomobject]@{ID=2102;Name='advanced';Controls=@(2011,2012,2013,2014,2015,2016,2017,2018)}
    )) {
        Click-Tray $settings $page.ID
        $geometry=[PhotonGuiSmokeNative]::Geometry($settings)
        $geometry|ConvertTo-Json -Depth 6|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory ('tray-settings-'+$page.Name+'.json'))
        foreach($controlID in @($page.Controls)+@(2101,2103,2104,2102,1105,1106,2019)) {
            $metrics=@($geometry.Controls|Where-Object ID -eq $controlID)
            if($metrics.Count -ne 1 -or !$metrics[0].Visible -or !$metrics[0].InsideClient -or $metrics[0].FontHeight -le 0){throw "Settings page $($page.Name) has a missing, clipped or unstyled control $controlID"}
        }
        $shot=[PhotonGuiSmokeNative]::Screenshot($settings,(Join-Path $FixtureDirectory ('tray-settings-'+$page.Name+'.png')))
        if($shot -notmatch 'saved; varied pixels'){throw "Settings page $($page.Name) did not render a real screenshot: $shot"}
        $visualEvidence.Add([pscustomobject]@{Page=$page.Name;DPIEvidence='Real HWND DPI; monitor scaling unchanged';PhysicalGeometry=$geometry;Screenshot=$shot})
    }
    $visualEvidence.ToArray()|ConvertTo-Json -Depth 8|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'tray-settings-visual.json')
    $null=[PhotonGuiSmokeNative]::Screenshot($settings,(Join-Path $FixtureDirectory 'tray-settings.png'));[PhotonGuiSmokeNative]::Close($settings)
    Click-Tray $window 1104;Wait-Tray {try{$s=Read-TrayStatus;$s.tunnel_ready -and $s.ike.expires_at -cne $started.ike.expires_at}catch{$false}} 'same-GUI runtime restart with fresh SA'
    $restarted=Check-TrayBusiness 'restarted';$interfaces=@(Get-NetIPInterface -InterfaceAlias $adapterName -ErrorAction Stop)
    if($interfaces.Count -ne 2 -or @($interfaces|Where-Object {$_.NlMtu -ne 1360}).Count -ne 0 -or @($interfaces|Where-Object AddressFamily -eq 'IPv4').Count -ne 1 -or @($interfaces|Where-Object AddressFamily -eq 'IPv6').Count -ne 1){throw 'Restart did not apply MTU1360 to both owned address families'}
    Save-TrayPhase 'restarted';[IO.File]::WriteAllText($phaseFile,'restarted');Wait-TrayAck 'restart-verified'
    $diagnostics=Open-TrayDiagnostics;Check-TrayDiagnostics $diagnostics 'restarted' $true
    $diagnosticDetail=@($diagnosticEvidence|Where-Object {$_.Phase -eq 'restarted' -and $_.Page -eq 'details'})[0].Text|ConvertFrom-Json
    if($diagnosticDetail.observation.ike.expires_at -cne $restarted.ike.expires_at){throw 'Diagnostics retained the pre-restart SA snapshot'}
    $diagnosticChecks.RestartSAMatches=$true
    $restartedLog=@($diagnosticEvidence|Where-Object {$_.Phase -eq 'restarted' -and $_.Page -eq 'log'})[0].Text
    if((Read-TrayLogStart $restartedLog) -le $stoppedLogStart){throw 'Reconnected diagnostics retained the old runtime log snapshot'}
    $diagnosticChecks.RestartLogFresh=$true
    [PhotonGuiSmokeNative]::Close($diagnostics)
    $conflict=Start-OwnedTray (Join-Path $portableC 'photon-windows.exe') 'conflict';$conflictWindow=Find-TrayWindow $conflict
    Click-Tray $conflictWindow 1102
    Wait-Tray {[PhotonGuiSmokeNative]::Text($conflictWindow,1002).Contains('失败') -and ![PhotonGuiSmokeNative]::Text($conflictWindow,1001).Contains('已连接') -and [PhotonGuiSmokeNative]::Text($conflictWindow,1006).Contains('不会接管')} 'foreign active database rejected with actionable hint'
    [pscustomobject]@{PID=$conflict.Process.Id;Creation=$conflict.Creation;Note=[PhotonGuiSmokeNative]::Text($conflictWindow,1006);Runtime=[PhotonGuiSmokeNative]::Text($conflictWindow,1002);OriginalOwnerPID=$gui.Process.Id;Screenshot=[PhotonGuiSmokeNative]::Screenshot($conflictWindow,(Join-Path $FixtureDirectory 'tray-conflict.png'))}|ConvertTo-Json -Depth 4|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'tray-conflict.json')
    Click-Tray $conflictWindow 1103;Exit-OwnedTray $conflict $conflictWindow
    $afterConflict=Check-TrayBusiness 'foreign-rejected';if($afterConflict.ike.expires_at -cne $restarted.ike.expires_at){throw 'Conflicting GUI changed the original runtime IKE lifetime'};$conflict=$null
    $firstOwner=$gui.Process.Id;$firstIndex=$script:trayOwnedIndex;Exit-OwnedTray $gui $window;$gui=$null
    Assert-TrayReleased $firstOwner $firstIndex 'exited-b'
    $gui=Start-OwnedTray (Join-Path $portableC 'photon-windows.exe') 'moved';$window=Find-TrayWindow $gui
    Click-Tray $window 1102;$moved=Check-TrayBusiness 'moved'
    if($gui.Process.Id -eq $firstOwner -or $moved.admission.pending -or (Read-TrayFileID) -cne $stateID){throw 'Moving the portable executable lost the stable admitted identity'}
    Save-TrayPhase 'moved'
    $faultMarker=Join-Path $FixtureDirectory 'fixture-tray-faults'
    if(Test-Path -LiteralPath $faultMarker){
        if((Get-Content -LiteralPath $faultMarker -Raw).Trim() -cne '1'){throw 'Invalid explicit tray faults opt-in marker'}
        $faultHelper=Join-Path $FixtureDirectory 'windows-tray-faults.ps1'
        if(!(Test-Path -LiteralPath $faultHelper -PathType Leaf)){throw 'Tray faults opt-in requires its helper script'}
        . $faultHelper
    }
    $movedOwner=$gui.Process.Id;$movedIndex=$script:trayOwnedIndex;Exit-OwnedTray $gui $window;$gui=$null
    Assert-TrayReleased $movedOwner $movedIndex 'exited-c';Assert-OldRegistration
    $completed=$true
}catch{$failure=$_.Exception.Message;$failurePosition=$_.InvocationInfo.PositionMessage;$failureStack=$_.ScriptStackTrace;[IO.File]::WriteAllText($phaseFile,'failed')}finally{
    if($clipboardCaptured){try{if($clipboardOwnedTexts.Contains([Windows.Forms.Clipboard]::GetText([Windows.Forms.TextDataFormat]::UnicodeText))){if($null -eq $clipboardBackup){[Windows.Forms.Clipboard]::Clear()}else{[Windows.Forms.Clipboard]::SetDataObject($clipboardBackup,$true)};$clipboardRestored=$true}}catch{$failure="$failure; clipboard restore: $($_.Exception.Message)";$completed=$false}}
    foreach($entry in $owned){try{if(!$entry.Process.HasExited){Assert-TrayOwner $entry;$handle=[PhotonGuiSmokeNative]::Find($entry.Process.Id);if($handle -ne [IntPtr]::Zero){[PhotonGuiSmokeNative]::Exit($handle)};if(!$entry.Process.WaitForExit(15000)){Assert-TrayOwner $entry;Stop-Process -Id $entry.Process.Id -ErrorAction Stop;if(!$entry.Process.WaitForExit(10000)){throw 'Owned GUI cleanup deadline'}}}}catch{$failure="$failure; GUI cleanup: $($_.Exception.Message)";$completed=$false}}
    if($oldInstalled){try{Assert-OldRegistration;$null=Invoke-TrayCLI @('service','remove','--name',$oldService,'--config',$Config)}catch{$failure="$failure; old registration cleanup: $($_.Exception.Message)";$completed=$false}}
    try {
        [pscustomobject]@{Checks=$diagnosticChecks;Views=$diagnosticEvidence.ToArray()}|ConvertTo-Json -Depth 10|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'tray-diagnostics.json')
    } catch {$failure="$failure; diagnostic evidence persistence: $($_.Exception.Message)";$completed=$false}
    [pscustomobject]@{SchemaVersion=1;Completed=$completed;Failure=$failure;FailurePosition=$failurePosition;FailureStack=$failureStack;SessionID=$session;InteractiveUser=$interactive;Explorer=@($explorer|Select-Object Id,SessionId);FirstRun=$firstRun;OldStoppedRegistration=$oldBefore|Select-Object Name,PathName,State,ProcessId,StartName;Request=$request;Authority=$authority;StateFileID=$stateID;AppliedInterfaces=@($interfaces|Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,NlMtu);ClipboardRoundtrip=$clipboardRoundtrip;ClipboardRestored=$clipboardRestored;Faults=$trayFaultsResult;Lifecycle=$lifecycle.ToArray();Samples=$samples.ToArray();Processes=@($owned|ForEach-Object{[pscustomobject]@{PID=$_.Process.Id;Path=$_.Path;Creation=$_.Creation;Exited=$_.Process.HasExited;ExitCode=$(if($_.Process.HasExited){$_.Process.ExitCode}else{$null});ExpectedForcedExit=$_.ExpectedForcedExit}})}|ConvertTo-Json -Depth 20|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'tray-smoke.json')
    foreach($entry in $owned){$entry.Process.Dispose()}
}
if($failure){throw $failure}
Write-Output 'PORTABLE_TRAY_REAL_RUNTIME_PASS'
