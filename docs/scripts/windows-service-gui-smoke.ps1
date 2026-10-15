# Dot-source from the owned full-daemon SCM fixture, then call Test-ServiceGui.
# Controls are real Win32 controls. Session 0 evidence is not Explorer acceptance.
function Test-ServiceGui {
    param([int]$ExpectedSessionID = -1)
    if ($null -eq $script:guiExtraStarts) { $script:guiExtraStarts = 0 }
    if ($null -eq $script:guiExtraStops) { $script:guiExtraStops = 0 }
    if (!('PhotonGuiSmokeNative' -as [type])) {
        Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
public static class PhotonGuiSmokeNative {
    private delegate bool WindowVisitor(IntPtr window, IntPtr parameter);
    [DllImport("user32.dll")] private static extern bool EnumWindows(WindowVisitor visitor, IntPtr parameter);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr window, StringBuilder text, int maximum);
    [DllImport("user32.dll")] private static extern IntPtr GetDlgItem(IntPtr window, int id);
    [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr window);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr wp, IntPtr lp, uint flags, uint timeout, out UIntPtr result);
    [DllImport("user32.dll", EntryPoint="SendMessageTimeoutW", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr ReadMessage(IntPtr window, uint message, UIntPtr wp, StringBuilder lp, uint flags, uint timeout, out UIntPtr result);
    [DllImport("user32.dll", EntryPoint="SendMessageTimeoutW", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr TextMessage(IntPtr window, uint message, UIntPtr wp, string lp, uint flags, uint timeout, out UIntPtr result);
    [StructLayout(LayoutKind.Sequential)] private struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] private static extern bool PrintWindow(IntPtr window, IntPtr dc, uint flags);
    [StructLayout(LayoutKind.Sequential)] private struct NotifyIdentifier { public uint Size; public IntPtr Window; public uint ID; public Guid GUID; }
    [DllImport("shell32.dll")] private static extern int Shell_NotifyIconGetRect(ref NotifyIdentifier icon, out Rect rect);
    [DllImport("shell32.dll", EntryPoint="Shell_NotifyIconW")] private static extern bool NotifyIcon(uint message, IntPtr data);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern uint RegisterWindowMessage(string name);
    public static IntPtr Find(uint expectedPID) {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr window, IntPtr ignored) {
            uint pid; GetWindowThreadProcessId(window, out pid);
            var name = new StringBuilder(256); GetClassName(window, name, name.Capacity);
            if (pid == expectedPID && name.ToString() == "PhotonWindowsDesktop") { found = window; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static void Verify(IntPtr window, uint expectedPID) {
        uint pid; GetWindowThreadProcessId(window, out pid);
        if (window == IntPtr.Zero || pid != expectedPID) throw new InvalidOperationException("GUI window ownership changed");
    }
    public static IntPtr Control(IntPtr window, int id) {
        var child = GetDlgItem(window, id);
        if (child == IntPtr.Zero) throw new InvalidOperationException("Missing GUI control " + id);
        return child;
    }
    private static UIntPtr Send(IntPtr window, uint message, UIntPtr wp, IntPtr lp) {
        UIntPtr result;
        if (SendMessageTimeout(window, message, wp, lp, 2, 3000, out result) == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "GUI message timed out or failed");
        return result;
    }
    public static string Text(IntPtr window, int id) {
        var child = Control(window, id);
        ulong size = Send(child, 0x000e, UIntPtr.Zero, IntPtr.Zero).ToUInt64();
        if (size > 1048576) throw new InvalidOperationException("GUI text exceeds bounded limit");
        var text = new StringBuilder((int)size + 1); UIntPtr result;
        if (ReadMessage(child, 0x000d, new UIntPtr((uint)text.Capacity), text, 2, 3000, out result) == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        return text.ToString();
    }
    public static void SetText(IntPtr window, int id, string text) {
        var editor = Control(window, id);
        // Multiline WM_SETTEXT does not send EN_CHANGE. Replace the selection
        // to exercise the same edit notification as typing or pasting.
        Send(editor, 0x00b1, UIntPtr.Zero, new IntPtr(-1));
        UIntPtr result;
        if (TextMessage(editor, 0x00c2, new UIntPtr(1), text, 2, 3000, out result) == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Replace editor text failed");
    }
    public static void Click(IntPtr window, int id) {
        var button = Control(window, id);
        if (!IsWindowEnabled(button)) throw new InvalidOperationException("GUI button is disabled: " + id);
        Send(button, 0x00f5, UIntPtr.Zero, IntPtr.Zero);
    }
    public static void Exit(IntPtr window) { Send(window, 0x0111, new UIntPtr(1204), IntPtr.Zero); }
    public static void Open(IntPtr window) { Send(window, 0x0111, new UIntPtr(1201), IntPtr.Zero); }
    public static void Close(IntPtr window) { Send(window, 0x0010, UIntPtr.Zero, IntPtr.Zero); }
    public static bool TrayPresent(IntPtr window) {
        var icon = new NotifyIdentifier { Window=window, ID=1 };
        icon.Size = (uint)Marshal.SizeOf(typeof(NotifyIdentifier));
        Rect rect; return Shell_NotifyIconGetRect(ref icon, out rect) == 0 && rect.Right>rect.Left && rect.Bottom>rect.Top;
    }
    public static void RebuildOwnedTray(IntPtr window) {
        if (IntPtr.Size != 8) throw new InvalidOperationException("GUI acceptance requires Windows amd64");
        // NOTIFYICONDATAW amd64 has cbSize=976, hWnd at 8 and uID at 16.
        // NIM_DELETE reads only this owned HWND/ID; no Explorer process is changed.
        var data = Marshal.AllocHGlobal(976);
        try {
            Marshal.Copy(new byte[976], 0, data, 976);
            Marshal.WriteInt32(data, 0, 976); Marshal.WriteIntPtr(data, 8, window); Marshal.WriteInt32(data, 16, 1);
            if (!NotifyIcon(2, data)) throw new InvalidOperationException("Delete own tray icon failed");
        } finally { Marshal.FreeHGlobal(data); }
        if (TrayPresent(window)) throw new InvalidOperationException("Deleted owned tray icon still present");
        uint message = RegisterWindowMessage("TaskbarCreated");
        if (message == 0) throw new InvalidOperationException("Register TaskbarCreated failed");
        Send(window, message, UIntPtr.Zero, IntPtr.Zero);
    }
    public static string Screenshot(IntPtr window, string path) {
        // A hung PrintWindow must not block the fixture. At most four bounded
        // attempts are made; thread-pool workers never operate on another HWND.
        var task = Task.Factory.StartNew<string>(delegate {
            Rect r; if (!GetWindowRect(window, out r)) return "unavailable: window rectangle";
            int width = r.Right-r.Left, height = r.Bottom-r.Top;
            if (width < 1 || height < 1 || width > 4096 || height > 4096) return "unavailable: window dimensions";
            using (var image = new Bitmap(width, height)) {
                bool rendered;
                using (var graphics = Graphics.FromImage(image)) {
                    var dc = graphics.GetHdc();
                    try { rendered = PrintWindow(window, dc, 2); }
                    finally { graphics.ReleaseHdc(dc); }
                }
                if (!rendered) return "unavailable: PrintWindow returned false";
                image.Save(path, ImageFormat.Png);
                int first = image.GetPixel(0, 0).ToArgb(); bool varied = false;
                for (int y=0; y<height; y+=Math.Max(1,height/32)) for (int x=0; x<width; x+=Math.Max(1,width/32)) if (image.GetPixel(x,y).ToArgb()!=first) varied=true;
                return varied ? "saved; varied pixels; visual inspection required" : "saved; uniform pixels; rendering not established";
            }
        });
        try {
            if (!task.Wait(5000)) return "unavailable: PrintWindow exceeded five seconds";
            return task.Result;
        } catch (Exception error) { return "unavailable: " + error.GetBaseException().Message; }
    }
}
'@
    }
    $guiProcess = $null
    $guiHandle = [IntPtr]::Zero
    $guiExitCode = $null
    $guiStart = $null
    $window = [IntPtr]::Zero
    $failure = $null
    $completed = $false
    $evidence = New-Object System.Collections.Generic.List[object]
    $originalBytes = [IO.File]::ReadAllBytes($Config)
    $before = Read-Status
    $beforeOwner = Read-OwnedProcess
    $initialStarts = $script:guiExtraStarts
    $initialStops = $script:guiExtraStops
    $currentSession = (Get-Process -Id $PID).SessionId
    if ($ExpectedSessionID -lt 0) { $ExpectedSessionID = $currentSession }
    $interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName
    $explorer = @(Get-Process explorer -ErrorAction SilentlyContinue | Where-Object SessionId -eq $currentSession)
    $guiSession = $null
    $foundWindow = [pscustomobject]@{ Handle = [IntPtr]::Zero }
    $mtuEvidence = @()
    function Assert-GuiProcess {
        $current = Get-Process -Id $guiProcess.Id -ErrorAction Stop
        $details = Get-CimInstance Win32_Process -Filter "ProcessId=$($guiProcess.Id)"
        if ($current.StartTime.ToUniversalTime() -ne $guiStart -or !$details -or $details.ExecutablePath -ne $Executable -or $details.CommandLine -notlike "*--config*" -or $details.CommandLine -notlike "*$Config*" -or $details.CommandLine -notlike "*$name*") { throw 'GUI process ownership changed' }
        if ($window -ne [IntPtr]::Zero) { [PhotonGuiSmokeNative]::Verify($window, $guiProcess.Id) }
    }
    function Read-GuiView {
        Assert-GuiProcess
        [pscustomobject]@{
            Connection = [PhotonGuiSmokeNative]::Text($window,1001)
            Service = [PhotonGuiSmokeNative]::Text($window,1002)
            Gateway = [PhotonGuiSmokeNative]::Text($window,1003)
            Routes = [PhotonGuiSmokeNative]::Text($window,1004)
            Hint = [PhotonGuiSmokeNative]::Text($window,1006)
        }
    }
    function Wait-Gui([scriptblock]$Condition, [string]$Label, [int]$Seconds = 60) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        do {
            Assert-GuiProcess
            if (& $Condition) { return }
            Start-Sleep -Milliseconds 200
        } while ($clock.Elapsed.TotalSeconds -lt $Seconds)
        throw "GUI did not reach $Label within $Seconds seconds"
    }
    function Wait-GuiButton([int]$Id) {
        Wait-Gui { [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($window,$Id)) } "enabled button $Id"
    }
    function Wait-GuiConnected {
        Wait-Gui {
            $v = Read-GuiView
            if (!$v.Connection.Contains('已连接') -or !$v.Gateway.Contains([string]$before.ike.gateway)) { return $false }
            foreach ($route in $before.babel.routes) { if (!$v.Routes.Contains([string]$route.prefix)) { return $false } }
            return $true
        } 'live gateway and authorized dual-stack routes'
    }
    function Save-GuiEvidence([string]$Phase, [bool]$Screenshot = $false) {
        $service = Read-Service $name
        $dto = $null
        if ($service.State -eq 'Running') {
            $raw = & $Executable status --config $Config
            if ($LASTEXITCODE -ne 0) { throw 'GUI evidence status IPC failed' }
            [IO.File]::WriteAllText((Join-Path $FixtureDirectory ('gui-' + $Phase + '-status.json')), ($raw -join "`n"))
            $dto = ($raw | ConvertFrom-Json).result
        }
        $shot = $null
        if ($Screenshot) {
            $shot = [PhotonGuiSmokeNative]::Screenshot($window, (Join-Path $FixtureDirectory ('gui-' + $Phase + '.png')))
        }
        $entry = [pscustomobject]@{
            Phase = $Phase; AtUTC = [DateTime]::UtcNow.ToString('o'); View = Read-GuiView
            ServiceState = $service.State; ServicePID = $service.ProcessId; Status = $dto; Screenshot = $shot
        }
        $evidence.Add($entry)
        $entry | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory ('gui-' + $Phase + '.json'))
    }
    try {
        if ($currentSession -le 0 -or $currentSession -ne $ExpectedSessionID -or ![Environment]::UserInteractive -or !$interactiveUser -or $explorer.Count -eq 0 -or [Security.Principal.WindowsIdentity]::GetCurrent().Name -ine $interactiveUser) { throw 'GUI fixture requires the expected logged-in user desktop with Explorer; refusing session 0 or another user/session' }
        if (!$before.running -or !$before.tunnel_ready -or !$before.ike.live -or !$before.ike.child_live -or @($before.babel.routes).Count -lt 2) { throw 'GUI test requires real authenticated dual-stack service business' }
        $guiProcess = Start-Process -FilePath $Executable -ArgumentList @('gui','--config',('"' + $Config + '"'),'--name',$name) -PassThru -RedirectStandardError (Join-Path $FixtureDirectory 'gui-process-error.log')
        # Start-Process can otherwise defer opening its process handle until
        # after exit. Acquire and retain it now so ExitCode remains observable.
        $guiHandle = $guiProcess.Handle
        if ($guiHandle -eq [IntPtr]::Zero) { throw 'Cannot retain the owned GUI process handle' }
        $guiStart = $guiProcess.StartTime.ToUniversalTime()
        $guiSession = $guiProcess.SessionId
        if ($guiSession -ne $currentSession) { throw 'GUI started outside the verified interactive session' }
        Wait-Gui { $foundWindow.Handle = [PhotonGuiSmokeNative]::Find($guiProcess.Id); $foundWindow.Handle -ne [IntPtr]::Zero } 'owned Photon desktop window' 20
        $window = $foundWindow.Handle
        Wait-GuiConnected
        Wait-GuiButton 1105
        $originalText = [PhotonGuiSmokeNative]::Text($window,1005)
        if (!$originalText.Contains('schema_version:')) { throw 'GUI did not load actual fixture YAML' }
        Save-GuiEvidence 'connected' $true
        Wait-Gui { [PhotonGuiSmokeNative]::TrayPresent($window) } 'owned Explorer tray icon'
        [PhotonGuiSmokeNative]::Close($window)
        Wait-Gui { ![PhotonGuiSmokeNative]::IsWindowVisible($window) -and [PhotonGuiSmokeNative]::TrayPresent($window) } 'window hidden with owned tray and GUI process still running'
        [PhotonGuiSmokeNative]::Open($window)
        Wait-Gui { [PhotonGuiSmokeNative]::IsWindowVisible($window) } 'window reopened from its own tray command'
        [PhotonGuiSmokeNative]::RebuildOwnedTray($window)
        Wait-Gui { [PhotonGuiSmokeNative]::TrayPresent($window) } 'owned tray rebuilt after simulated TaskbarCreated'

        [PhotonGuiSmokeNative]::Click($window,1103)
        Wait-Gui { (Read-Service $name).State -eq 'Stopped' } 'SCM stopped'
        $script:guiExtraStops++
        Wait-Gui {
            $v = Read-GuiView
            $v.Service.Contains('已停止') -and $v.Gateway -eq '活动网关：—' -and $v.Routes -eq '尚无实时路由' -and !$v.Connection.Contains('已连接')
        } 'stopped GUI with cleared live state'
        Save-GuiEvidence 'stopped' $true
        Wait-GuiButton 1102
        [PhotonGuiSmokeNative]::Click($window,1102)
        Wait-Gui { (Read-Service $name).State -eq 'Running' } 'SCM started'
        $script:guiExtraStarts++
        Check-Business 'gui-start'
        Wait-GuiConnected

        Wait-GuiButton 1105
        [PhotonGuiSmokeNative]::SetText($window,1005,($originalText + "`r`nunknown_gui_smoke_field: true`r`n"))
        [PhotonGuiSmokeNative]::Click($window,1105)
        Wait-Gui { ([PhotonGuiSmokeNative]::Text($window,1006)).StartsWith('操作失败：') -and [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($window,1105)) } 'invalid YAML refusal'
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($Config)) -cne [Convert]::ToBase64String($originalBytes)) { throw 'Invalid GUI save changed original configuration bytes' }
        Save-GuiEvidence 'invalid-save'
        $mtuPattern = '(?m)^([ \t]*mtu:[ \t]*)1400([ \t]*\r?)$'
        if ([regex]::Matches($originalText,$mtuPattern).Count -ne 1) { throw 'Expected exactly one fixture MTU 1400 before GUI edit' }
        $editedText = [regex]::Replace($originalText,$mtuPattern,'${1}1360${2}')
        $preSaveOwner = Read-OwnedProcess
        [PhotonGuiSmokeNative]::SetText($window,1005,$editedText)
        [PhotonGuiSmokeNative]::Click($window,1105)
        Wait-Gui { ([PhotonGuiSmokeNative]::Text($window,1006)).StartsWith('配置已保存') -and [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($window,1105)) } 'valid YAML saved'
        $saved = [IO.File]::ReadAllText($Config)
        if ($saved -notmatch '(?m)^[ \t]*mtu:[ \t]*1360[ \t]*\r?$' -or $saved.Contains('unknown_gui_smoke_field')) { throw 'Valid GUI save did not persist expected YAML' }
        Invoke-Photon @('config','validate','--config',$Config)
        $savedOwner = Read-OwnedProcess
        if ($savedOwner.Id -ne $preSaveOwner.Id -or $savedOwner.FixtureStartedAtUtc -ne $preSaveOwner.FixtureStartedAtUtc) { throw 'Configuration save restarted the service' }
        Save-GuiEvidence 'saved' $true
        Wait-GuiButton 1104
        [PhotonGuiSmokeNative]::Click($window,1104)
        Wait-Gui { $s = Read-Service $name; $s.State -eq 'Running' -and $s.ProcessId -ne $savedOwner.Id } 'new SCM process after GUI restart'
        $script:guiExtraStops++
        $script:guiExtraStarts++
        Check-Business 'gui-restart'
        Wait-GuiConnected
        $restarted = Read-OwnedProcess
        # The native IP Helper structure uses NlMtuBytes; the actual NetTCPIP
        # CIM/PowerShell object exposes NlMtu (UInt32). Check each address family.
        $adapter = @(Get-NetAdapter -Name $name -ErrorAction Stop)
        if ($adapter.Count -ne 1) { throw 'Cannot identify exactly one owned adapter after GUI restart' }
        foreach ($interface in @(Get-NetIPInterface -InterfaceAlias $name -ErrorAction Stop)) {
            if ($null -eq $interface.PSObject.Properties['NlMtu']) { throw 'NetIPInterface object has no NlMtu property' }
            $mtuEvidence += [pscustomobject]@{
                InterfaceAlias = [string]$interface.InterfaceAlias
                InterfaceIndex = [int]$interface.InterfaceIndex
                AddressFamily = [string]$interface.AddressFamily
                NlMtu = [uint32]$interface.NlMtu
            }
        }
        $mtuEvidence | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'gui-interface-mtu.json')
        if ($mtuEvidence.Count -ne 2 -or @($mtuEvidence | Where-Object AddressFamily -eq 'IPv4').Count -ne 1 -or @($mtuEvidence | Where-Object AddressFamily -eq 'IPv6').Count -ne 1 -or @($mtuEvidence | Where-Object { $_.NlMtu -ne 1360 -or $_.InterfaceIndex -ne $adapter[0].ifIndex -or $_.InterfaceAlias -ne $name }).Count -ne 0) { throw 'GUI restart did not apply MTU 1360 to both address families of the exact owned adapter' }
        Save-GuiEvidence 'restarted' $true
        [PhotonGuiSmokeNative]::Exit($window)
        if (!$guiProcess.WaitForExit(10000)) { throw 'GUI did not exit within ten seconds' }
        $guiExitCode = $guiProcess.ExitCode
        if ($null -eq $guiExitCode) { throw 'GUI exit code is unavailable despite the retained process handle' }
        if ($guiExitCode -ne 0) { throw "GUI exited $guiExitCode" }
        $remaining = Read-OwnedProcess
        if ($remaining.Id -ne $restarted.Id -or $remaining.FixtureStartedAtUtc -ne $restarted.FixtureStartedAtUtc) { throw 'Exiting GUI changed the running service process' }
        $after = Read-Status
        if (!$after.running -or !$after.tunnel_ready -or !$after.ike.live -or !$after.ike.child_live) { throw 'Exiting GUI stopped the business tunnel' }
        Check-Business 'gui-exited'
        if ($script:guiExtraStarts -ne $initialStarts+2 -or $script:guiExtraStops -ne $initialStops+2) { throw 'GUI lifecycle event offsets are incomplete' }
        $completed = $true
        Write-Output 'GUI real controls passed: status/stop/start/invalid save/atomic save/restart/exit; service survives GUI exit'
    } catch { $failure = $_.Exception.Message } finally {
        if ($guiProcess -and !$guiProcess.HasExited) {
            try {
                Assert-GuiProcess
                Stop-Process -Id $guiProcess.Id -ErrorAction Stop
                if (!$guiProcess.WaitForExit(10000)) { throw 'Owned GUI process did not terminate' }
            } catch { $failure = "$failure; GUI cleanup failed: $($_.Exception.Message)" }
        }
        try { [pscustomobject]@{
            SchemaVersion = 1; Completed = $completed; Failure = $failure
            GUIProcessID = $(if ($guiProcess) { $guiProcess.Id } else { $null }); GUIStartedAtUTC = $guiStart
            GUIProcessHandleAcquired = ($guiHandle -ne [IntPtr]::Zero); GUIExitCode = $guiExitCode
            SessionID = $guiSession; LauncherSessionID = $currentSession; ExpectedSessionID = $ExpectedSessionID
            InteractiveUser = $interactiveUser; ExplorerProcesses = @($explorer | Select-Object Id,SessionId)
            EvidenceKind = 'Real logged-in desktop, Win32 controls and owned Explorer tray; programmatic messages; PrintWindow only this GUI window'
            TrayRecovery = 'Delete only this GUI HWND/ID1, then send simulated TaskbarCreated to this GUI; Explorer was not restarted'
            BeforeServicePID = $beforeOwner.Id; ExtraStarts = $script:guiExtraStarts-$initialStarts; ExtraStops = $script:guiExtraStops-$initialStops
            AppliedInterfaces = $mtuEvidence
            Phases = $evidence.ToArray()
        } | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'gui-smoke.json')
        } finally { if ($guiProcess) { $guiProcess.Dispose() } }
    }
    if ($failure) { throw $failure }
}
