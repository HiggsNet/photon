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
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] private static extern int MapWindowPoints(IntPtr from, IntPtr to, ref Rect points, uint count);
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(IntPtr window);
    [DllImport("user32.dll", SetLastError=true)] private static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll", SetLastError=true)] private static extern bool SetWindowPos(IntPtr window, IntPtr after, int x, int y, int width, int height, uint flags);
    [DllImport("user32.dll")] private static extern bool PrintWindow(IntPtr window, IntPtr dc, uint flags);
    [DllImport("user32.dll", SetLastError=true)] private static extern bool RedrawWindow(IntPtr window, IntPtr rect, IntPtr region, uint flags);
    [DllImport("dwmapi.dll")] private static extern int DwmFlush();
    [StructLayout(LayoutKind.Sequential)] private struct NotifyIdentifier { public uint Size; public IntPtr Window; public uint ID; public Guid GUID; }
    [DllImport("shell32.dll")] private static extern int Shell_NotifyIconGetRect(ref NotifyIdentifier icon, out Rect rect);
    [DllImport("shell32.dll", EntryPoint="Shell_NotifyIconW")] private static extern bool NotifyIcon(uint message, IntPtr data);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern uint RegisterWindowMessage(string name);
    private static IntPtr FindClass(uint expectedPID, string className) {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr window, IntPtr ignored) {
            uint pid; GetWindowThreadProcessId(window, out pid);
            var name = new StringBuilder(256); GetClassName(window, name, name.Capacity);
            if (pid == expectedPID && name.ToString() == className) { found = window; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static IntPtr Find(uint expectedPID) { return FindClass(expectedPID, "PhotonWindowsDesktop"); }
    public static IntPtr FindSettings(uint expectedPID) { return FindClass(expectedPID, "PhotonWindowsSettings"); }
    public static void Verify(IntPtr window, uint expectedPID) {
        uint pid; GetWindowThreadProcessId(window, out pid);
        if (window == IntPtr.Zero || pid != expectedPID) throw new InvalidOperationException("GUI window ownership changed");
    }
    public static IntPtr Control(IntPtr window, int id) {
        var child = GetDlgItem(window, id);
        if (child == IntPtr.Zero) throw new InvalidOperationException("Missing GUI control " + id);
        return child;
    }
    public static bool HasControl(IntPtr window, int id) { return GetDlgItem(window, id) != IntPtr.Zero; }
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
        // WM_SETTEXT does not reliably send EN_CHANGE. Replace the selection
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
    public static string[] ListItems(IntPtr window, int id) {
        var list = Control(window, id);
        long count = (long)Send(list, 0x018b, UIntPtr.Zero, IntPtr.Zero).ToUInt64();
        if (count < 0 || count > 256) throw new InvalidOperationException("GUI list exceeds fixture bounds");
        var items = new string[count];
        for (int i=0; i<count; i++) {
            long size = (long)Send(list, 0x018a, new UIntPtr((uint)i), IntPtr.Zero).ToUInt64();
            if (size < 0 || size > 1048576) throw new InvalidOperationException("GUI list item exceeds fixture bounds");
            var text = new StringBuilder((int)size + 1); UIntPtr result;
            if (ReadMessage(list, 0x0189, new UIntPtr((uint)i), text, 2, 3000, out result) == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            items[i] = text.ToString();
        }
        return items;
    }
    public static void SelectRow(IntPtr window, int id, int index) {
        var list = Control(window, id);
        if (index < 0 || index >= ListItems(window,id).Length) throw new InvalidOperationException("GUI row index outside owned list");
        Send(list, 0x0186, new UIntPtr((uint)index), IntPtr.Zero);
        Send(window, 0x0111, new UIntPtr((uint)id | (1u<<16)), list);
    }
    public static void SelectLogLevel(IntPtr window, string level) {
        var combo = Control(window, 2016); UIntPtr result;
        if (TextMessage(combo, 0x0158, new UIntPtr(uint.MaxValue), level, 2, 3000, out result) == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        long index = (long)result.ToUInt64();
        if (index < 0 || index > 3) throw new InvalidOperationException("Expected log level missing from dropdown");
        Send(combo, 0x014e, new UIntPtr((uint)index), IntPtr.Zero);
        Send(window, 0x0111, new UIntPtr(2016u | (1u<<16)), combo);
    }
    private static IntPtr EnterPhysicalDpiContext() {
        var previous = SetThreadDpiAwarenessContext(new IntPtr(-4));
        if (previous == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot enter physical DPI context");
        return previous;
    }
    private static void RestoreDpiContext(IntPtr previous) {
        if (SetThreadDpiAwarenessContext(previous) == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot restore DPI context");
    }
    public static void ResizeSettings(IntPtr window) {
        var previous = EnterPhysicalDpiContext();
        try {
            if (!SetWindowPos(window, IntPtr.Zero, 0, 0, 700, 700, 0x0016)) throw new Win32Exception(Marshal.GetLastWin32Error());
            Send(window, 0, UIntPtr.Zero, IntPtr.Zero); // Bounded owner-thread WM_NULL synchronization.
            Rect rect;
            if (!GetWindowRect(window, out rect) || rect.Right-rect.Left != 700 || rect.Bottom-rect.Top != 700) throw new InvalidOperationException("Settings minimum-size evidence is not 700x700 physical pixels");
        } finally { RestoreDpiContext(previous); }
    }
    public sealed class ChildMetrics {
        public int ID, Left, Top, Right, Bottom;
        public bool Visible, Enabled, InsideClient;
    }
    public sealed class WindowMetrics {
        public int WindowWidth, WindowHeight, ClientWidth, ClientHeight;
        public uint DPI;
        public ChildMetrics[] Controls;
    }
    public static WindowMetrics Geometry(IntPtr window) {
        var previous = EnterPhysicalDpiContext();
        try {
            Send(window, 0, UIntPtr.Zero, IntPtr.Zero);
            Rect rect, client;
            if (!GetWindowRect(window,out rect) || !GetClientRect(window,out client)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var children = new System.Collections.Generic.List<ChildMetrics>();
            foreach (int id in new int[] { 2001, 1105, 1106 }) {
                var child = GetDlgItem(window,id);
                if (child == IntPtr.Zero) continue;
                Rect bounds;
                if (!GetWindowRect(child,out bounds)) throw new Win32Exception(Marshal.GetLastWin32Error());
                MapWindowPoints(IntPtr.Zero,window,ref bounds,2);
                children.Add(new ChildMetrics { ID=id, Left=bounds.Left, Top=bounds.Top, Right=bounds.Right, Bottom=bounds.Bottom,
                    Visible=IsWindowVisible(child), Enabled=IsWindowEnabled(child), InsideClient=bounds.Left>=client.Left && bounds.Top>=client.Top && bounds.Right<=client.Right && bounds.Bottom<=client.Bottom });
            }
            return new WindowMetrics { WindowWidth=rect.Right-rect.Left, WindowHeight=rect.Bottom-rect.Top,
                ClientWidth=client.Right-client.Left, ClientHeight=client.Bottom-client.Top, DPI=GetDpiForWindow(window), Controls=children.ToArray() };
        } finally { RestoreDpiContext(previous); }
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
        // A hung PrintWindow must not block the fixture. Each requested frame
        // has one bounded attempt; workers only operate on an owned HWND.
        var task = Task.Factory.StartNew<string>(delegate {
            // Task workers do not inherit the calling thread's DPI context.
            var previous = EnterPhysicalDpiContext();
            try {
            Send(window, 0, UIntPtr.Zero, IntPtr.Zero);
            if (!RedrawWindow(window, IntPtr.Zero, IntPtr.Zero, 0x0181)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Owned window redraw failed");
            int flushResult = DwmFlush();
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
                return "physical " + width + "x" + height + "; DwmFlush=" + flushResult + "; " + (varied ? "saved; varied pixels; visual inspection required" : "saved; uniform pixels; rendering not established");
            }
            } finally { RestoreDpiContext(previous); }
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
    $settingsWindow = [IntPtr]::Zero
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
    $formBefore = $null
    $formAfter = $null
    $bootstrapEvidence = $null
    # The optional Linux fixture uses this actual configured pattern as its
    # public marker; default exact-zone lifecycle/B6 fixtures stay unchanged.
    $gatewayGlobEnabled = @($fixture.Gateway.AllowedZones).Count -eq 1 -and [string]$fixture.Gateway.AllowedZones[0] -ceq '*.catofes.'
    $gatewayGlobEvidence = $null
    $firstRunEvidence = $null
    $listEvidence = New-Object System.Collections.Generic.List[object]
    function Assert-GuiProcess {
        $current = Get-Process -Id $guiProcess.Id -ErrorAction Stop
        $details = Get-CimInstance Win32_Process -Filter "ProcessId=$($guiProcess.Id)"
        if ($current.StartTime.ToUniversalTime() -ne $guiStart -or !$details -or $details.ExecutablePath -ne $Executable -or $details.CommandLine -notlike "*--config*" -or $details.CommandLine -notlike "*$Config*" -or $details.CommandLine -notlike "*$name*") { throw 'GUI process ownership changed' }
        if ($window -ne [IntPtr]::Zero) { [PhotonGuiSmokeNative]::Verify($window, $guiProcess.Id) }
        if ($settingsWindow -ne [IntPtr]::Zero) { [PhotonGuiSmokeNative]::Verify($settingsWindow, $guiProcess.Id) }
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
    function Wait-SettingsButton([int]$Id) {
        Wait-Gui { [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($settingsWindow,$Id)) } "enabled settings button $Id"
    }
    function Read-GuiForm {
        $values = [ordered]@{}
        foreach ($pair in @(@('RootPublicKey',2001),@('ManagedZone',2002),@('StatePath',2011),@('OverlayID',2012),@('GossipListen',2013),@('AdapterName',2014),@('MTU',2015),@('LogLevel',2016),@('InitialBackoff',2017),@('MaxBackoff',2018))) {
            $values[$pair[0]] = [PhotonGuiSmokeNative]::Text($settingsWindow,[int]$pair[1])
        }
        $values.AllowedGateways = @([PhotonGuiSmokeNative]::ListItems($settingsWindow,2003)) -join "`r`n"
        $values.SplitRoutes = @([PhotonGuiSmokeNative]::ListItems($settingsWindow,2004)) -join "`r`n"
        $values.BootstrapRows = @([PhotonGuiSmokeNative]::ListItems($settingsWindow,2005))
        [pscustomobject]$values
    }
    function Assert-GuiFormEqual($Expected, $Actual) {
        foreach ($property in $Expected.PSObject.Properties) {
            if ($property.Name -eq 'BootstrapRows') {
                if ((@($property.Value) | ConvertTo-Json -Compress) -cne (@($Actual.BootstrapRows) | ConvertTo-Json -Compress)) { throw 'Settings roundtrip changed the original bootstrap rows' }
            } elseif ([string]$Actual.($property.Name) -cne [string]$property.Value) { throw "Settings roundtrip changed $($property.Name)" }
        }
    }
    function Test-GuiOptionList([string]$Group, [int]$List, [int]$EditorID, [int]$Add, [int]$Update, [int]$Delete, [int]$Clear, [string]$AddedValue, [string]$UpdatedValue) {
        $original = @([PhotonGuiSmokeNative]::ListItems($settingsWindow,$List))
        [PhotonGuiSmokeNative]::Click($settingsWindow,$Clear)
        [PhotonGuiSmokeNative]::SetText($settingsWindow,$EditorID,$AddedValue)
        [PhotonGuiSmokeNative]::Click($settingsWindow,$Add)
        Wait-Gui { @([PhotonGuiSmokeNative]::ListItems($settingsWindow,$List)).Count -eq $original.Count+1 } "$Group list add"
        [PhotonGuiSmokeNative]::SelectRow($settingsWindow,$List,$original.Count)
        if ([PhotonGuiSmokeNative]::Text($settingsWindow,$EditorID) -cne $AddedValue) { throw "$Group list selection did not populate its single input" }
        [PhotonGuiSmokeNative]::SetText($settingsWindow,$EditorID,$UpdatedValue)
        [PhotonGuiSmokeNative]::Click($settingsWindow,$Update)
        [PhotonGuiSmokeNative]::SelectRow($settingsWindow,$List,$original.Count)
        $updated = @([PhotonGuiSmokeNative]::ListItems($settingsWindow,$List))
        if ([PhotonGuiSmokeNative]::Text($settingsWindow,$EditorID) -cne $UpdatedValue -or $updated[$original.Count] -cne $UpdatedValue) { throw "$Group list update did not retain its value" }
        [PhotonGuiSmokeNative]::Click($settingsWindow,$Delete)
        $restored = @([PhotonGuiSmokeNative]::ListItems($settingsWindow,$List))
        if (($original | ConvertTo-Json -Compress) -cne ($restored | ConvertTo-Json -Compress)) { throw "$Group list CRUD changed an original row" }
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($Config)) -cne [Convert]::ToBase64String($originalBytes)) { throw "$Group list CRUD changed configuration before Save" }
        $listEvidence.Add([pscustomobject]@{Group=$Group;OriginalRows=$original;UpdatedRows=$updated;RestoredRows=$restored;OriginalFileUnchanged=$true})
    }
    function Wait-GuiConnected {
        Wait-Gui {
            $v = Read-GuiView
            if (!$v.Connection.Contains('已连接') -or !$v.Gateway.Contains([string]$before.ike.gateway)) { return $false }
            foreach ($route in $before.babel.routes) { if (!$v.Routes.Contains([string]$route.prefix)) { return $false } }
            return $true
        } 'live gateway and authorized dual-stack routes'
    }
    function Save-GuiEvidence([string]$Phase, [bool]$Screenshot = $false, [bool]$SettingsScreenshot = $false) {
        $service = Read-Service $name
        $dto = $null
        if ($service.State -eq 'Running') {
            $raw = & $Executable status --config $Config
            if ($LASTEXITCODE -ne 0) { throw 'GUI evidence status IPC failed' }
            [IO.File]::WriteAllText((Join-Path $FixtureDirectory ('gui-' + $Phase + '-status.json')), ($raw -join "`n"))
            $dto = ($raw | ConvertFrom-Json).result
        }
        $shot = $null
        $geometry = $null
        if ($Screenshot) {
            $capture = $window
            if ($SettingsScreenshot) { $capture = $settingsWindow }
            $geometry = [PhotonGuiSmokeNative]::Geometry($capture)
            $shot = [PhotonGuiSmokeNative]::Screenshot($capture, (Join-Path $FixtureDirectory ('gui-' + $Phase + '.png')))
        }
        $entry = [pscustomobject]@{
            Phase = $Phase; AtUTC = [DateTime]::UtcNow.ToString('o'); View = Read-GuiView
            ServiceState = $service.State; ServicePID = $service.ProcessId; Status = $dto; Screenshot = $shot
            PhysicalGeometry = $geometry
            ScreenshotWindow = $(if ($SettingsScreenshot) { 'owned settings window at 700x700' } else { 'owned main window' })
            Form = $(if ($settingsWindow -ne [IntPtr]::Zero) { Read-GuiForm } else { $null })
        }
        $evidence.Add($entry)
        $entry | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory ('gui-' + $Phase + '.json'))
    }
    try {
        if ($currentSession -le 0 -or $currentSession -ne $ExpectedSessionID -or ![Environment]::UserInteractive -or !$interactiveUser -or $explorer.Count -eq 0 -or [Security.Principal.WindowsIdentity]::GetCurrent().Name -ine $interactiveUser) { throw 'GUI fixture requires the expected logged-in user desktop with Explorer; refusing session 0 or another user/session' }
        if (!$before.running -or !$before.tunnel_ready -or !$before.ike.live -or !$before.ike.child_live -or @($before.babel.routes).Count -lt 2) { throw 'GUI test requires real authenticated dual-stack service business' }
        $firstRunEvidence = Test-GuiFirstRun -ExpectedSessionID $ExpectedSessionID
        $afterFirstRun = Read-OwnedProcess
        if ($afterFirstRun.Id -ne $beforeOwner.Id -or $afterFirstRun.FixtureStartedAtUtc -ne $beforeOwner.FixtureStartedAtUtc) { throw 'Configuration-only first-run GUI changed the existing fixture service' }
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
        if ([PhotonGuiSmokeNative]::HasControl($window,1005)) { throw 'Main window retained the obsolete YAML editor' }
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

        Wait-GuiButton 1110
        [PhotonGuiSmokeNative]::Click($window,1110)
        Wait-Gui { $foundWindow.Handle = [PhotonGuiSmokeNative]::FindSettings($guiProcess.Id); $foundWindow.Handle -ne [IntPtr]::Zero } 'owned settings window'
        $settingsWindow = $foundWindow.Handle
        if ([PhotonGuiSmokeNative]::HasControl($settingsWindow,1005)) { throw 'Settings retained a hidden YAML editor' }
        [PhotonGuiSmokeNative]::ResizeSettings($settingsWindow)
        Wait-SettingsButton 1105
        [PhotonGuiSmokeNative]::Click($settingsWindow,2101)
        Wait-Gui { [PhotonGuiSmokeNative]::IsWindowVisible([PhotonGuiSmokeNative]::Control($settingsWindow,2001)) } 'identity options page'
        $formBefore = Read-GuiForm
        if ($formBefore.RootPublicKey -cne $fixture.TrustedRootPublicKey -or $formBefore.ManagedZone -cne $fixture.ManagedZone -or $formBefore.StatePath -ine (Join-Path $FixtureDirectory 'windows.db') -or $formBefore.OverlayID -cne $fixture.Overlay.ID -or $formBefore.GossipListen -cne $fixture.GossipListen -or $formBefore.AdapterName -cne $name -or $formBefore.MTU -cne '1400' -or $formBefore.LogLevel -cne 'debug') { throw 'Settings did not load the actual fixture options' }
        if ((@($formBefore.AllowedGateways -split '\r?\n' | Where-Object { $_ }) | ConvertTo-Json -Compress) -cne (@($fixture.Gateway.AllowedZones) | ConvertTo-Json -Compress) -or (@($formBefore.SplitRoutes -split '\r?\n' | Where-Object { $_ }) | ConvertTo-Json -Compress) -cne (@($fixture.Overlay.SplitRoutes) | ConvertTo-Json -Compress)) { throw 'Basic settings changed the allowed gateways or split routes' }
        Save-GuiEvidence 'form-identity' $true $true
        [PhotonGuiSmokeNative]::Click($settingsWindow,2103)
        Wait-Gui { [PhotonGuiSmokeNative]::IsWindowVisible([PhotonGuiSmokeNative]::Control($settingsWindow,2003)) } 'gateway and bootstrap page'
        Test-GuiOptionList 'allowed gateways' 2003 2021 2121 2122 2123 2124 'temporary.example.' 'updated-temporary.example.'
        $originalRows = @([PhotonGuiSmokeNative]::ListItems($settingsWindow,2005))
        if ($originalRows.Count -ne @($fixture.Gateway.BootstrapHints).Count -or $originalRows.Count -lt 1) { throw 'Expected the original bootstrap hints in the real list control' }
        [PhotonGuiSmokeNative]::SelectRow($settingsWindow,2005,0)
        $originalPeer = [PhotonGuiSmokeNative]::Text($settingsWindow,2006)
        $originalAddress = [PhotonGuiSmokeNative]::Text($settingsWindow,2007)
        if ($originalPeer -cne $fixture.Gateway.BootstrapHints[0].Peer -or $originalAddress -cne $fixture.Gateway.BootstrapHints[0].Address) { throw 'Bootstrap row did not populate separate identity and address fields' }
        Save-GuiEvidence 'form-basic' $true $true

        # Exercise actual list mutations. Documentation-only addresses remain
        # UI drafts and are removed before any successful configuration save.
        [PhotonGuiSmokeNative]::Click($settingsWindow,2114)
        [PhotonGuiSmokeNative]::SetText($settingsWindow,2006,$originalPeer)
        [PhotonGuiSmokeNative]::SetText($settingsWindow,2007,'192.0.2.123:33434')
        [PhotonGuiSmokeNative]::Click($settingsWindow,2111)
        Wait-Gui { @([PhotonGuiSmokeNative]::ListItems($settingsWindow,2005)).Count -eq $originalRows.Count+1 } 'second bootstrap hint added'
        [PhotonGuiSmokeNative]::SelectRow($settingsWindow,2005,$originalRows.Count)
        if ([PhotonGuiSmokeNative]::Text($settingsWindow,2006) -cne $originalPeer -or [PhotonGuiSmokeNative]::Text($settingsWindow,2007) -cne '192.0.2.123:33434') { throw 'Added bootstrap hint did not roundtrip through row selection' }
        [PhotonGuiSmokeNative]::SetText($settingsWindow,2007,'192.0.2.124:33434')
        [PhotonGuiSmokeNative]::Click($settingsWindow,1105)
        Wait-Gui { ([PhotonGuiSmokeNative]::Text($settingsWindow,2019)).Contains('尚未添加或更新') -and [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($settingsWindow,1105)) } 'save refusal for an unapplied bootstrap draft'
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($Config)) -cne [Convert]::ToBase64String($originalBytes) -or [PhotonGuiSmokeNative]::Text($settingsWindow,2007) -cne '192.0.2.124:33434') { throw 'Unapplied bootstrap draft changed the file or lost the typed address' }
        Save-GuiEvidence 'form-draft-refused' $true $true
        [PhotonGuiSmokeNative]::Click($settingsWindow,2112)
        [PhotonGuiSmokeNative]::SelectRow($settingsWindow,2005,$originalRows.Count)
        if ([PhotonGuiSmokeNative]::Text($settingsWindow,2007) -cne '192.0.2.124:33434') { throw 'Bootstrap update did not persist in the selected list row' }
        $updatedRows = @([PhotonGuiSmokeNative]::ListItems($settingsWindow,2005))
        [PhotonGuiSmokeNative]::Click($settingsWindow,2113)
        Wait-Gui { @([PhotonGuiSmokeNative]::ListItems($settingsWindow,2005)).Count -eq $originalRows.Count } 'temporary bootstrap hint removed'
        if ((@([PhotonGuiSmokeNative]::ListItems($settingsWindow,2005)) | ConvertTo-Json -Compress) -cne ($originalRows | ConvertTo-Json -Compress)) { throw 'Bootstrap CRUD changed an original hint' }
        $bootstrapEvidence = [pscustomobject]@{ OriginalRows=$originalRows; UpdatedRows=$updatedRows; RestoredRows=@([PhotonGuiSmokeNative]::ListItems($settingsWindow,2005)); DraftSaveRefused=$true; OriginalFileUnchanged=$true }

        if ($gatewayGlobEnabled) {
            if ($originalPeer -cne 'gateway.catofes.' -or $before.ike.gateway -cne $originalPeer) { throw 'Glob fixture must discover and authenticate the concrete bootstrap gateway' }
            [PhotonGuiSmokeNative]::SelectRow($settingsWindow,2003,0)
            [PhotonGuiSmokeNative]::SetText($settingsWindow,2021,'*')
            [PhotonGuiSmokeNative]::Click($settingsWindow,2122)
            $globRows = @([PhotonGuiSmokeNative]::ListItems($settingsWindow,2003))
            if ($globRows.Count -ne 1 -or $globRows[0] -cne '*') { throw 'Gateway list update did not retain the literal wildcard' }
            Save-GuiEvidence 'form-gateway-glob' $true $true
        }

        [PhotonGuiSmokeNative]::Click($settingsWindow,2104)
        Wait-Gui { [PhotonGuiSmokeNative]::IsWindowVisible([PhotonGuiSmokeNative]::Control($settingsWindow,2004)) } 'split route options page'
        Test-GuiOptionList 'split routes' 2004 2022 2131 2132 2133 2134 '192.0.2.0/24' '198.51.100.0/24'
        Save-GuiEvidence 'form-routes' $true $true

        [PhotonGuiSmokeNative]::Click($settingsWindow,2102)
        Wait-Gui { [PhotonGuiSmokeNative]::IsWindowVisible([PhotonGuiSmokeNative]::Control($settingsWindow,2015)) } 'advanced options page'
        [PhotonGuiSmokeNative]::SetText($settingsWindow,2015,'1279')
        [PhotonGuiSmokeNative]::Click($settingsWindow,1105)
        Wait-Gui { ([PhotonGuiSmokeNative]::Text($settingsWindow,2019)).StartsWith('操作失败：') -and [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($settingsWindow,1105)) } 'invalid MTU form refusal'
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($Config)) -cne [Convert]::ToBase64String($originalBytes)) { throw 'Invalid form save changed original configuration bytes' }
        Save-GuiEvidence 'invalid-save' $true $true
        $preSaveOwner = Read-OwnedProcess
        [PhotonGuiSmokeNative]::SetText($settingsWindow,2015,'1360')
        [PhotonGuiSmokeNative]::SetText($settingsWindow,2018,'31s')
        [PhotonGuiSmokeNative]::SelectLogLevel($settingsWindow,'info')
        if ([PhotonGuiSmokeNative]::Text($settingsWindow,2016) -cne 'info') { throw 'Log level dropdown did not select an ordinary option' }
        [PhotonGuiSmokeNative]::SelectLogLevel($settingsWindow,'debug')
        [PhotonGuiSmokeNative]::Click($settingsWindow,1105)
        Wait-Gui { ([PhotonGuiSmokeNative]::Text($settingsWindow,2019)).StartsWith('配置已保存') -and [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($settingsWindow,1105)) } 'valid options saved'
        $saved = [IO.File]::ReadAllText($Config)
        if ($saved -notmatch '(?m)^[ \t]*mtu:[ \t]*1360[ \t]*\r?$' -or $saved -notmatch '(?m)^[ \t]*max_backoff:[ \t]*31s[ \t]*\r?$' -or $saved.Contains('192.0.2.12')) { throw 'Valid form save did not persist expected MTU/backoff or retained a temporary hint' }
        if ($gatewayGlobEnabled -and $saved -notmatch '(?m)^[ \t]*-[ \t]+(?:''\*''|"\*")[ \t]*\r?$') { throw 'Saving wildcard gateway did not quote the YAML scalar' }
        Invoke-Photon @('config','validate','--config',$Config)
        $expectedForm = $formBefore | Select-Object *
        $expectedForm.MTU = '1360'
        $expectedForm.MaxBackoff = '31s'
        if ($gatewayGlobEnabled) { $expectedForm.AllowedGateways = '*' }
        Wait-SettingsButton 1106
        [PhotonGuiSmokeNative]::Click($settingsWindow,1106)
        Wait-Gui { ([PhotonGuiSmokeNative]::Text($settingsWindow,2019)).StartsWith('配置已读取') -and [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($settingsWindow,1105)) } 'saved form reloaded from the actual file'
        $formAfter = Read-GuiForm
        Assert-GuiFormEqual $expectedForm $formAfter
        if ($gatewayGlobEnabled) {
            $gatewayGlobEvidence = [pscustomobject]@{ InitialPattern=$formBefore.AllowedGateways; SavedPattern=$formAfter.AllowedGateways; QuotedYAMLVerified=$true; ConcreteBootstrap=$originalPeer; InitialAuthenticatedGateway=$before.ike.gateway; RestartAuthenticatedGateway=$null }
        }
        $savedOwner = Read-OwnedProcess
        if ($savedOwner.Id -ne $preSaveOwner.Id -or $savedOwner.FixtureStartedAtUtc -ne $preSaveOwner.FixtureStartedAtUtc) { throw 'Configuration save restarted the service' }
        Save-GuiEvidence 'form-advanced' $true $true
        [PhotonGuiSmokeNative]::Click($settingsWindow,2103)
        Wait-Gui { [PhotonGuiSmokeNative]::IsWindowVisible([PhotonGuiSmokeNative]::Control($settingsWindow,2003)) } 'reloaded gateway options page'
        [PhotonGuiSmokeNative]::SelectRow($settingsWindow,2005,0)
        if ([PhotonGuiSmokeNative]::Text($settingsWindow,2006) -cne $originalPeer -or [PhotonGuiSmokeNative]::Text($settingsWindow,2007) -cne $originalAddress) { throw 'Saving and reloading lost the original bootstrap identity/address pair' }
        Save-GuiEvidence 'form-reloaded-basic' $true $true
        [PhotonGuiSmokeNative]::Close($settingsWindow)
        Wait-Gui { ![PhotonGuiSmokeNative]::IsWindowVisible($settingsWindow) } 'settings closed while main window remains available'
        Save-GuiEvidence 'saved' $true
        Wait-GuiButton 1104
        [PhotonGuiSmokeNative]::Click($window,1104)
        Wait-Gui { $s = Read-Service $name; $s.State -eq 'Running' -and $s.ProcessId -ne $savedOwner.Id } 'new SCM process after GUI restart'
        $script:guiExtraStops++
        $script:guiExtraStarts++
        Check-Business 'gui-restart'
        Wait-GuiConnected
        $restarted = Read-OwnedProcess
        if ($gatewayGlobEnabled) {
            $globStatus = Read-Status
            if (!$globStatus.tunnel_ready -or !$globStatus.ike.live -or !$globStatus.ike.child_live -or $globStatus.ike.gateway -cne $originalPeer) { throw 'Wildcard gateway options did not reconnect to the authenticated concrete gateway' }
            $gatewayGlobEvidence.RestartAuthenticatedGateway = $globStatus.ike.gateway
        }
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
        Write-Output 'GUI real controls passed: status/tray/stop/start/form validation/bootstrap CRUD/options roundtrip/save/restart/exit; service survives GUI exit'
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
            FormBefore = $formBefore; FormAfterReload = $formAfter; BootstrapCRUD = $bootstrapEvidence
            GatewayGlob = $gatewayGlobEvidence
            FirstRun = $firstRunEvidence; OptionListCRUD = $listEvidence.ToArray()
            Phases = $evidence.ToArray()
        } | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'gui-smoke.json')
        } finally { if ($guiProcess) { $guiProcess.Dispose() } }
    }
    if ($failure) { throw $failure }
}

# Runs before the live-service GUI tests, in the same verified desktop session.
# The executable directory and process working directory are both new and
# deliberately different. No configuration, database or service is preloaded.
function Test-GuiFirstRun {
    param([int]$ExpectedSessionID)
    $token = [Guid]::NewGuid().ToString('N')
    $firstName = 'PhotonFirstRun-' + $token
    $root = Join-Path $FixtureDirectory ('gui-first-run-' + $token)
    $bin = Join-Path $root 'bin'
    $working = Join-Path $root 'cwd'
    $copiedExecutable = Join-Path $bin 'photon-windows.exe'
    $expectedConfig = Join-Path $bin 'config.yaml'
    $expectedState = Join-Path $bin 'config.db'
    $firstProcess = $null
    $firstStarted = $null
    $firstMain = [IntPtr]::Zero
    $firstSettings = [IntPtr]::Zero
    $defaults = $null
    $savedForm = $null
    $failure = $null
    $completed = $false
    $exitCode = $null
    $session = (Get-Process -Id $PID).SessionId
    function Assert-FirstRunOwner {
        if (!$firstProcess -or $firstProcess.HasExited) { throw 'First-run GUI exited before the test completed' }
        $process = Get-Process -Id $firstProcess.Id -ErrorAction Stop
        $details = Get-CimInstance Win32_Process -Filter "ProcessId=$($firstProcess.Id)"
        if (!$details -or $process.StartTime.ToUniversalTime() -ne $firstStarted -or $details.ExecutablePath -ine $copiedExecutable -or $details.CommandLine -notlike ('*'+$firstName+'*') -or $details.CommandLine -match '(?i)--config(?:\s|=|$)' -or $process.SessionId -ne $session) { throw 'First-run GUI ownership or default-path launch changed' }
        if ($firstMain -ne [IntPtr]::Zero) { [PhotonGuiSmokeNative]::Verify($firstMain,$firstProcess.Id) }
        if ($firstSettings -ne [IntPtr]::Zero) { [PhotonGuiSmokeNative]::Verify($firstSettings,$firstProcess.Id) }
    }
    function Wait-FirstRun([scriptblock]$Condition, [string]$Label) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        do { Assert-FirstRunOwner; if (& $Condition) { return }; Start-Sleep -Milliseconds 100 } while ($clock.Elapsed.TotalSeconds -lt 30)
        throw "First-run GUI timed out waiting for $Label"
    }
    function Read-FirstRunForm {
        [pscustomobject]@{
            RootPublicKey=[PhotonGuiSmokeNative]::Text($firstSettings,2001); ManagedZone=[PhotonGuiSmokeNative]::Text($firstSettings,2002)
            AllowedGateways=@([PhotonGuiSmokeNative]::ListItems($firstSettings,2003)); SplitRoutes=@([PhotonGuiSmokeNative]::ListItems($firstSettings,2004))
            StatePath=[PhotonGuiSmokeNative]::Text($firstSettings,2011); OverlayID=[PhotonGuiSmokeNative]::Text($firstSettings,2012)
            GossipListen=[PhotonGuiSmokeNative]::Text($firstSettings,2013); AdapterName=[PhotonGuiSmokeNative]::Text($firstSettings,2014)
            MTU=[PhotonGuiSmokeNative]::Text($firstSettings,2015); LogLevel=[PhotonGuiSmokeNative]::Text($firstSettings,2016)
            InitialBackoff=[PhotonGuiSmokeNative]::Text($firstSettings,2017); MaxBackoff=[PhotonGuiSmokeNative]::Text($firstSettings,2018)
            BootstrapRows=@([PhotonGuiSmokeNative]::ListItems($firstSettings,2005)); Note=[PhotonGuiSmokeNative]::Text($firstSettings,2019)
        }
    }
    try {
        if ($session -le 0 -or $session -ne $ExpectedSessionID -or ![Environment]::UserInteractive) { throw 'First-run GUI requires the same verified interactive desktop' }
        if (Test-Path -LiteralPath $root) { throw 'Refusing an existing first-run fixture directory' }
        $null = New-Item -ItemType Directory -Path $bin,$working
        [IO.File]::Copy($Executable,$copiedExecutable,$false)
        $sourceHash=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
        if ((Get-FileHash -LiteralPath $copiedExecutable -Algorithm SHA256).Hash -cne $sourceHash) { throw 'First-run copy does not match the tested executable' }
        if ((Test-Path -LiteralPath $expectedConfig) -or (Test-Path -LiteralPath $expectedState) -or @(Get-ChildItem -LiteralPath $working -Force).Count -ne 0 -or (Get-CimInstance Win32_Service -Filter "Name='$firstName'")) { throw 'First-run fixture was not initially blank' }
        $firstProcess = Start-Process -FilePath $copiedExecutable -WorkingDirectory $working -ArgumentList @('gui','--name',$firstName) -PassThru -RedirectStandardError (Join-Path $FixtureDirectory 'gui-first-run-process-error.log')
        if ($firstProcess.Handle -eq [IntPtr]::Zero) { throw 'Cannot retain the first-run GUI process handle' }
        $firstStarted=$firstProcess.StartTime.ToUniversalTime()
        $found=[pscustomobject]@{Handle=[IntPtr]::Zero}
        Wait-FirstRun { $found.Handle=[PhotonGuiSmokeNative]::Find($firstProcess.Id); $found.Handle -ne [IntPtr]::Zero } 'main window without an explicit --config'
        $firstMain=$found.Handle
        Wait-FirstRun { $found.Handle=[PhotonGuiSmokeNative]::FindSettings($firstProcess.Id); $found.Handle -ne [IntPtr]::Zero } 'automatically opened first-run settings'
        $firstSettings=$found.Handle
        $defaultSizeGeometry=[PhotonGuiSmokeNative]::Geometry($firstSettings)
        $defaultSizeShot=[PhotonGuiSmokeNative]::Screenshot($firstSettings,(Join-Path $FixtureDirectory 'gui-first-run-default-size.png'))
        [PhotonGuiSmokeNative]::ResizeSettings($firstSettings)
        Wait-FirstRun { [PhotonGuiSmokeNative]::IsWindowVisible([PhotonGuiSmokeNative]::Control($firstSettings,2001)) -and [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($firstSettings,1105)) -and [PhotonGuiSmokeNative]::Text($firstSettings,2019).Contains('首次使用') } 'editable missing-file defaults'
        $defaults=Read-FirstRunForm
        if ((Test-Path -LiteralPath $expectedConfig) -or $defaults.RootPublicKey -ne '' -or $defaults.ManagedZone -ne '' -or $defaults.AllowedGateways.Count -ne 0 -or $defaults.SplitRoutes.Count -ne 0 -or $defaults.BootstrapRows.Count -ne 0 -or $defaults.StatePath -ine $expectedState) { throw 'Missing-file defaults were preloaded or resolved beside the wrong path' }
        $defaultGeometry=[PhotonGuiSmokeNative]::Geometry($firstSettings)
        $defaultShot=[PhotonGuiSmokeNative]::Screenshot($firstSettings,(Join-Path $FixtureDirectory 'gui-first-run-defaults.png'))
        [PhotonGuiSmokeNative]::SetText($firstSettings,2001,[string]$fixture.TrustedRootPublicKey)
        [PhotonGuiSmokeNative]::SetText($firstSettings,2002,[string]$fixture.ManagedZone)
        [PhotonGuiSmokeNative]::Click($firstSettings,2103)
        foreach ($allowed in @($fixture.Gateway.AllowedZones)) {
            [PhotonGuiSmokeNative]::SetText($firstSettings,2021,[string]$allowed)
            [PhotonGuiSmokeNative]::Click($firstSettings,2121)
        }
        foreach ($hint in @($fixture.Gateway.BootstrapHints)) {
            [PhotonGuiSmokeNative]::SetText($firstSettings,2006,[string]$hint.Peer)
            [PhotonGuiSmokeNative]::SetText($firstSettings,2007,[string]$hint.Address)
            [PhotonGuiSmokeNative]::Click($firstSettings,2111)
        }
        [PhotonGuiSmokeNative]::Click($firstSettings,2104)
        foreach ($route in @($fixture.Overlay.SplitRoutes)) {
            [PhotonGuiSmokeNative]::SetText($firstSettings,2022,[string]$route)
            [PhotonGuiSmokeNative]::Click($firstSettings,2131)
        }
        if (Test-Path -LiteralPath $expectedConfig) { throw 'First-run configuration appeared before the first Save' }
        # Never click Reload: the first Save must succeed after defaults were
        # loaded for the genuinely missing executable-adjacent configuration.
        [PhotonGuiSmokeNative]::Click($firstSettings,1105)
        Wait-FirstRun { (Test-Path -LiteralPath $expectedConfig) -and [PhotonGuiSmokeNative]::Text($firstSettings,2019).StartsWith('配置已保存') -and [PhotonGuiSmokeNative]::IsWindowEnabled([PhotonGuiSmokeNative]::Control($firstSettings,1105)) } 'first Save creating executable-adjacent config.yaml'
        $savedForm=Read-FirstRunForm
        $expectedBootstrapRows=@($fixture.Gateway.BootstrapHints | ForEach-Object { [string]$_.Peer + "`t" + [string]$_.Address })
        if ($savedForm.RootPublicKey -cne $fixture.TrustedRootPublicKey -or $savedForm.ManagedZone -cne $fixture.ManagedZone -or ($savedForm.AllowedGateways|ConvertTo-Json -Compress) -cne (@($fixture.Gateway.AllowedZones)|ConvertTo-Json -Compress) -or ($savedForm.SplitRoutes|ConvertTo-Json -Compress) -cne (@($fixture.Overlay.SplitRoutes)|ConvertTo-Json -Compress) -or ($savedForm.BootstrapRows|ConvertTo-Json -Compress) -cne ($expectedBootstrapRows|ConvertTo-Json -Compress)) { throw 'First-run Save lost entered identity, gateway, bootstrap or route values' }
        $validation=& $copiedExecutable config validate --config $expectedConfig
        if ($LASTEXITCODE -ne 0) { throw 'Created first-run configuration failed the real CLI validator' }
        $createdConfigText=[IO.File]::ReadAllText($expectedConfig)
        $savedGeometry=[PhotonGuiSmokeNative]::Geometry($firstSettings)
        $savedShot=[PhotonGuiSmokeNative]::Screenshot($firstSettings,(Join-Path $FixtureDirectory 'gui-first-run-saved.png'))
        [PhotonGuiSmokeNative]::Close($firstSettings)
        $mainShot=[PhotonGuiSmokeNative]::Screenshot($firstMain,(Join-Path $FixtureDirectory 'gui-first-run-main.png'))
        [PhotonGuiSmokeNative]::Exit($firstMain)
        if (!$firstProcess.WaitForExit(10000)) { throw 'First-run GUI did not exit' }
        $exitCode=$firstProcess.ExitCode
        if ($null -eq $exitCode -or $exitCode -ne 0) { throw "First-run GUI exited $exitCode" }
        if (@(Get-ChildItem -LiteralPath $working -Force).Count -ne 0 -or @(Get-ChildItem -LiteralPath $bin -File | Where-Object Extension -eq '.db').Count -ne 0 -or (Get-CimInstance Win32_Service -Filter "Name='$firstName'")) { throw 'Configuration-only first-run GUI created cwd files, a database or an SCM service' }
        $completed=$true
    } catch { $failure=$_.Exception.Message } finally {
        if ($firstProcess -and !$firstProcess.HasExited) {
            try { Assert-FirstRunOwner; Stop-Process -Id $firstProcess.Id -ErrorAction Stop; if (!$firstProcess.WaitForExit(10000)) { throw 'First-run GUI did not terminate' } } catch { $failure="$failure; first-run cleanup: $($_.Exception.Message)"; $completed=$false }
        }
        $result=[pscustomobject]@{
            Completed=$completed; Failure=$failure; SessionID=$session; ServiceName=$firstName; GUIProcessID=$(if($firstProcess){$firstProcess.Id}else{$null}); GUIStartedAtUTC=$firstStarted; GUIExitCode=$exitCode
            Executable=$copiedExecutable; WorkingDirectory=$working; ConfigPath=$expectedConfig; ExpectedStatePath=$expectedState; SourceExecutableSHA256=$sourceHash
            ConfigExistedBeforeLaunch=$false; ExplicitConfigArgument=$false; ReloadClicked=$false
            ConfigExistsAfter=(Test-Path -LiteralPath $expectedConfig); CwdConfigExists=(Test-Path -LiteralPath (Join-Path $working 'config.yaml')); StateExistsAfter=(Test-Path -LiteralPath $expectedState)
            Defaults=$defaults; SavedForm=$savedForm; SavedConfigYAML=$createdConfigText; Validation=$validation; Screenshots=@($defaultSizeShot,$defaultShot,$savedShot,$mainShot)
            PhysicalGeometry=[pscustomobject]@{DefaultSize=$defaultSizeGeometry;Defaults=$defaultGeometry;Saved=$savedGeometry}
        }
        $result|ConvertTo-Json -Depth 12|Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'gui-first-run.json')
        if ($firstProcess) { $firstProcess.Dispose() }
    }
    if ($failure) { throw $failure }
    $result
}
