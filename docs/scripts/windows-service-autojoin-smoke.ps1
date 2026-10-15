# The only signer is the sibling Linux disposable fixture's production daemon.
# The Windows node starts from no DB and receives no import/key/bundle file.
function Test-ServiceAutojoin($Initial) {
    $owner = Read-OwnedProcess
    $fileID = Read-StateFileIdentity
    $phaseFile = Join-Path $FixtureDirectory 'autojoin-request-phase.txt'
    if (Test-Path $phaseFile) { throw 'Refusing stale autojoin coordination file' }
    $withGui = Test-Path (Join-Path $FixtureDirectory 'windows-service-gui-smoke.ps1')
    $gui = $null; $guiStarted = $null; $guiWindow = [IntPtr]::Zero
    $clipboardBackup = $null; $clipboardCaptured = $false; $clipboardRoundtrip = $false; $clipboardRestored = $false
    $failure = $null; $completed = $false
    $samples = New-Object System.Collections.Generic.List[object]
    $requestText = $null; $request = $null
    $session = (Get-Process -Id $PID).SessionId
    if ($withGui -and !('PhotonAutojoinNative' -as [type])) {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
public static class PhotonAutojoinNative {
    private delegate bool Visitor(IntPtr window,IntPtr unused);
    [DllImport("user32.dll")] private static extern bool EnumWindows(Visitor visitor,IntPtr unused);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr window,StringBuilder name,int capacity);
    [DllImport("user32.dll")] private static extern IntPtr GetDlgItem(IntPtr window,int id);
    [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr window);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr SendMessageTimeout(IntPtr window,uint message,UIntPtr wp,IntPtr lp,uint flags,uint timeout,out UIntPtr result);
    [DllImport("user32.dll",EntryPoint="SendMessageTimeoutW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr ReadMessage(IntPtr window,uint message,UIntPtr wp,StringBuilder text,uint flags,uint timeout,out UIntPtr result);
    [StructLayout(LayoutKind.Sequential)] private struct Rect {public int Left,Top,Right,Bottom;}
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr window,out Rect rectangle);
    [DllImport("user32.dll")] private static extern bool PrintWindow(IntPtr window,IntPtr dc,uint flags);
    public static IntPtr Find(uint owner) {
        IntPtr found=IntPtr.Zero;
        EnumWindows(delegate(IntPtr w,IntPtr unused) {uint pid;GetWindowThreadProcessId(w,out pid);var name=new StringBuilder(256);GetClassName(w,name,name.Capacity);if(pid==owner&&name.ToString()=="PhotonWindowsDesktop"){found=w;return false;}return true;},IntPtr.Zero);
        return found;
    }
    public static void Verify(IntPtr window,uint expected) {uint pid;GetWindowThreadProcessId(window,out pid);if(pid!=expected||window==IntPtr.Zero)throw new InvalidOperationException("Autojoin GUI ownership changed");}
    public static IntPtr Control(IntPtr window,int id) {var child=GetDlgItem(window,id);if(child==IntPtr.Zero)throw new InvalidOperationException("Missing autojoin GUI control "+id);return child;}
    private static UIntPtr Send(IntPtr window,uint message,UIntPtr wp,IntPtr lp) {UIntPtr result;if(SendMessageTimeout(window,message,wp,lp,2,3000,out result)==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());return result;}
    public static string Text(IntPtr window,int id) {var child=Control(window,id);ulong length=Send(child,14,UIntPtr.Zero,IntPtr.Zero).ToUInt64();if(length>1048576)throw new InvalidOperationException("GUI text exceeds limit");var text=new StringBuilder((int)length+1);UIntPtr result;if(ReadMessage(child,13,new UIntPtr((uint)text.Capacity),text,2,3000,out result)==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());return text.ToString();}
    public static void Copy(IntPtr window) {var button=Control(window,1107);if(!IsWindowEnabled(button))throw new InvalidOperationException("Copy request button disabled");Send(button,0x00f5,UIntPtr.Zero,IntPtr.Zero);}
    public static void Exit(IntPtr window) {Send(window,0x0111,new UIntPtr(1204),IntPtr.Zero);}
    public static string Screenshot(IntPtr window,string path) {
        var task=Task.Factory.StartNew<string>(delegate {Rect r;if(!GetWindowRect(window,out r))return "unavailable: rectangle";int width=r.Right-r.Left,height=r.Bottom-r.Top;if(width<1||height<1||width>4096||height>4096)return "unavailable: dimensions";using(var image=new Bitmap(width,height)){using(var g=Graphics.FromImage(image)){var dc=g.GetHdc();try{if(!PrintWindow(window,dc,2))return "unavailable: PrintWindow";}finally{g.ReleaseHdc(dc);}}image.Save(path,ImageFormat.Png);return "saved; visual inspection required";}});
        try {if(!task.Wait(5000))return "unavailable: capture timeout";return task.Result;}catch(Exception e){return "unavailable: "+e.GetBaseException().Message;}
    }
}
'@
    }
    function Assert-AutojoinGuiOwner {
            $p = Get-Process -Id $gui.Id -ErrorAction Stop
            $details = Get-CimInstance Win32_Process -Filter "ProcessId=$($gui.Id)"
            if ($p.StartTime.ToUniversalTime() -ne $guiStarted -or !$details -or $details.ExecutablePath -ne $Executable -or $details.CommandLine -notlike "*$Config*" -or $details.CommandLine -notlike "*$name*") { throw 'Autojoin GUI process ownership changed' }
    }
    function Assert-AutojoinOwner {
        $current = Read-OwnedProcess
        if ($current.Id -ne $owner.Id -or $current.FixtureStartedAtUtc -ne $owner.FixtureStartedAtUtc -or (Read-StateFileIdentity) -cne $fileID) { throw 'Autojoin changed the SCM process or initialized Bolt file identity' }
        if ($gui) { Assert-AutojoinGuiOwner; if ($guiWindow -ne [IntPtr]::Zero) { [PhotonAutojoinNative]::Verify($guiWindow,$gui.Id) } }
    }
    function Wait-Autojoin([scriptblock]$Condition,[string]$Label,[int]$Seconds=90) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        do { Assert-AutojoinOwner; if (& $Condition) { return }; Start-Sleep -Milliseconds 200 } while ($clock.Elapsed.TotalSeconds -lt $Seconds)
        throw "Autojoin timed out waiting for $Label"
    }
    function Wait-AutojoinAck([string]$Phase) {
        Wait-Autojoin { $p=Join-Path $FixtureDirectory ('autojoin-'+$Phase+'.ack'); (Test-Path $p) -and (Get-Content $p -Raw).Trim() -eq $Phase } "Linux $Phase acknowledgement"
    }
    function Save-Autojoin([string]$Phase) {
        $status = Read-Status
        $entry = [ordered]@{Phase=$Phase; AtUTC=[DateTime]::UtcNow.ToString('o'); PID=$owner.Id; StateFileID=Read-StateFileIdentity; Status=$status}
        if ($withGui) {
            $entry.GUI = [pscustomobject]@{Connection=[PhotonAutojoinNative]::Text($guiWindow,1001);Admission=[PhotonAutojoinNative]::Text($guiWindow,1007);Request=[PhotonAutojoinNative]::Text($guiWindow,1008);CopyEnabled=[PhotonAutojoinNative]::IsWindowEnabled([PhotonAutojoinNative]::Control($guiWindow,1107))}
            $entry.Screenshot = [PhotonAutojoinNative]::Screenshot($guiWindow,(Join-Path $FixtureDirectory ('autojoin-'+$Phase+'.png')))
        }
        $samples.Add([pscustomobject]$entry)
        $entry | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory ('autojoin-'+$Phase+'.json'))
    }
    function Assert-AutojoinPending($Status) {
        if (!$Status.running -or !$Status.admission.pending -or !$Status.admission.has_zone_private_key -or !$Status.admission.join_request_b64 -or $Status.tunnel_ready -or $Status.ike.live -or $Status.ike.child_live) { throw 'Pending node exposed a business tunnel or lacks its generated request' }
        if (Get-NetAdapter -Name $name -IncludeHidden -ErrorAction SilentlyContinue) { throw 'Pending node created a Wintun adapter before authorization' }
        if ($requestText -and $Status.admission.join_request_b64 -cne $requestText) { throw 'Pending generated identity changed between sync stages' }
    }
    try {
        Assert-AutojoinPending $Initial
        $requestText = [string]$Initial.admission.join_request_b64
        [IO.File]::WriteAllText((Join-Path $FixtureDirectory 'autojoin-request.b64'),$requestText,(New-Object Text.UTF8Encoding($false)))
        # share.EncodeBase64JSON uses unpadded URL-safe Base64. The public_key
        # inside its JSON is the separate, standard Go []byte Base64 encoding.
        $outer = $requestText.Trim().Replace('-','+').Replace('_','/')
        if ($outer.Length % 4 -eq 1) { throw 'Invalid Base64 JSON join request length' }
        $outer = $outer.PadRight($outer.Length + ((4 - ($outer.Length % 4)) % 4), '=')
        $request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($outer)) | ConvertFrom-Json
        if ($request.version -ne 1 -or $request.zone -ne $fixture.ManagedZone -or [Convert]::FromBase64String($request.public_key).Length -ne 32) { throw 'Invalid generated public join request' }
        if ($withGui) {
            $interactive = (Get-CimInstance Win32_ComputerSystem).UserName
            if ($session -le 0 -or ![Environment]::UserInteractive -or $interactive -ine [Security.Principal.WindowsIdentity]::GetCurrent().Name -or @(Get-Process explorer -ErrorAction SilentlyContinue | Where-Object SessionId -eq $session).Count -eq 0) { throw 'Pending GUI acceptance requires this user interactive Explorer session' }
            $gui = Start-Process -FilePath $Executable -ArgumentList @('gui','--config',('"'+$Config+'"'),'--name',$name) -PassThru
            $null = $gui.Handle
            $guiStarted = $gui.StartTime.ToUniversalTime()
            if ($gui.SessionId -ne $session) { throw 'Pending GUI session differs from its interactive launcher' }
            $found=[pscustomobject]@{Window=[IntPtr]::Zero}
            Wait-Autojoin { $found.Window=[PhotonAutojoinNative]::Find($gui.Id); $found.Window -ne [IntPtr]::Zero } 'pending GUI window' 20
            $guiWindow=$found.Window
            Wait-Autojoin { [PhotonAutojoinNative]::Text($guiWindow,1001).Contains('待授权') -and [PhotonAutojoinNative]::Text($guiWindow,1008) -ceq $requestText -and [PhotonAutojoinNative]::IsWindowEnabled([PhotonAutojoinNative]::Control($guiWindow,1107)) } 'actual generated request and copy button'
            $clipboardBackup = [Windows.Forms.Clipboard]::GetDataObject()
            $clipboardCaptured = $true
            [PhotonAutojoinNative]::Copy($guiWindow)
            Wait-Autojoin { [Windows.Forms.Clipboard]::GetText([Windows.Forms.TextDataFormat]::UnicodeText) -ceq $requestText } 'clipboard roundtrip of the complete public request' 10
            $clipboardRoundtrip = $true
        }
        Save-Autojoin 'pending'
        [IO.File]::WriteAllText($phaseFile,'request')
        Wait-AutojoinAck 'wrong-issued'
        Wait-Autojoin { $s=Read-Status; Assert-AutojoinPending $s; $s.admission.reason -eq 'delegation_key_mismatch' } 'rejection of a parent-signed wrong public key'
        if ($withGui) { Wait-Autojoin { [PhotonAutojoinNative]::Text($guiWindow,1007).Contains('本机公钥不匹配') -and [PhotonAutojoinNative]::Text($guiWindow,1008) -ceq $requestText } 'wrong-key admission explanation with unchanged request' }
        Save-Autojoin 'wrong-key'
        [IO.File]::WriteAllText($phaseFile,'wrong-seen')
        Wait-AutojoinAck 'correct-issued'
        Wait-Autojoin { $s=Read-Status; !$s.admission.pending -and $s.admission.reason -eq 'adopted' -and $s.tunnel_ready -and $s.ike.live -and $s.ike.child_live } 'same-process signed adoption and authenticated tunnel'
        $authority = Get-Content -LiteralPath (Join-Path $FixtureDirectory 'autojoin-authority.json') -Raw | ConvertFrom-Json
        if (!$authority.chain_verified -or $authority.request.public_key -cne $request.public_key -or $authority.root_public_key -cne $fixture.TrustedRootPublicKey -or @($authority.authority.Keys | Where-Object { $_.Key -ceq $request.public_key }).Count -ne 1) { throw 'Verified fixture authority does not bind the generated request public key/root' }
        Check-Business 'autojoin-adopted'
        Assert-AutojoinOwner
        if ($withGui) {
            Wait-Autojoin { [PhotonAutojoinNative]::Text($guiWindow,1001).Contains('已连接') -and [PhotonAutojoinNative]::Text($guiWindow,1008) -eq '' -and ![PhotonAutojoinNative]::IsWindowEnabled([PhotonAutojoinNative]::Control($guiWindow,1107)) } 'adopted GUI clears request and copy command'
        }
        Save-Autojoin 'adopted'
        [IO.File]::WriteAllText($phaseFile,'adopted')
        Wait-AutojoinAck 'verified'
        if ($withGui) {
            [PhotonAutojoinNative]::Exit($guiWindow)
            if (!$gui.WaitForExit(10000) -or $null -eq $gui.ExitCode -or $gui.ExitCode -ne 0) { throw 'Pending/adopted GUI did not exit cleanly' }
            $gui.Dispose(); $gui=$null
            Assert-AutojoinOwner
        }
        $script:autojoinIdentityEvidence = [pscustomobject]@{Request=$request; StateFileID=$fileID; InitialPID=$owner.Id; InitialCreation=$owner.FixtureStartedAtUtc; Authority=$authority}
        $completed=$true
    } catch { $failure=$_.Exception.Message; [IO.File]::WriteAllText($phaseFile,'failed') } finally {
        if ($withGui -and $clipboardCaptured) {
            try {
                # Preserve a user's newer clipboard copy instead of overwriting it.
                if ([Windows.Forms.Clipboard]::GetText([Windows.Forms.TextDataFormat]::UnicodeText) -ceq $requestText) {
                    if ($null -eq $clipboardBackup) { [Windows.Forms.Clipboard]::Clear() } else { [Windows.Forms.Clipboard]::SetDataObject($clipboardBackup,$true) }
                    $clipboardRestored=$true
                }
            } catch { $failure="$failure; clipboard restoration failed: $($_.Exception.Message)" }
        }
        if ($gui) {
            try { if (!$gui.HasExited) { Assert-AutojoinGuiOwner; Stop-Process -Id $gui.Id -ErrorAction Stop; if (!$gui.WaitForExit(10000)) { throw 'Owned pending GUI did not terminate' } } } catch { $failure="$failure; pending GUI cleanup failed: $($_.Exception.Message)" } finally { $gui.Dispose() }
        }
        if ($failure) { $completed=$false; [IO.File]::WriteAllText($phaseFile,'failed') }
        [pscustomobject]@{SchemaVersion=1;Completed=$completed;Failure=$failure;InitialPID=$owner.Id;StateFileID=$fileID;RawJoinRequest=$requestText;Request=$request;GUIEnabled=$withGui;SessionID=$session;ClipboardRoundtrip=$clipboardRoundtrip;ClipboardRestored=$clipboardRestored;Samples=$samples.ToArray()} | ConvertTo-Json -Depth 15 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'autojoin-smoke.json')
    }
    if ($failure) { throw $failure }
}

function Assert-AutojoinRestart {
    $before=$script:autojoinIdentityEvidence
    if (!$before) { throw 'Missing original autojoin identity evidence' }
    $after=Read-Status
    $owner=Read-OwnedProcess
    if ($owner.Id -eq $before.InitialPID -or (Read-StateFileIdentity) -cne $before.StateFileID -or $after.admission.pending -or $after.admission.reason -ne 'adopted' -or !$after.tunnel_ready) { throw 'Restart did not retain the admitted identity/database with a new service process' }
    [IO.File]::WriteAllText((Join-Path $FixtureDirectory 'autojoin-request-phase.txt'),'restarted')
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $ack=Join-Path $FixtureDirectory 'autojoin-restart-verified.ack'
    while (!(Test-Path $ack)) { if ($clock.Elapsed.TotalSeconds -gt 90) { throw 'Linux restart authority verification timed out' }; Start-Sleep -Milliseconds 200 }
    [pscustomobject]@{OriginalPID=$before.InitialPID;RestartPID=$owner.Id;StateFileID=$before.StateFileID;Request=$before.Request;Authority=$before.Authority;Status=$after;Evidence='Same signed authority/request public key and original Bolt file; authenticated dual-stack business after restart'} | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'autojoin-restart.json')
}
