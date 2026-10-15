# Shared Win32 evidence helpers; this file never starts SCM or a daemon.
function Initialize-PhotonGuiSmokeNative {
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
}

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
        if (!$details -or $process.StartTime.ToUniversalTime() -ne $firstStarted -or $details.ExecutablePath -ine $copiedExecutable -or $details.CommandLine -match '(?i)--config(?:\s|=|$)' -or $process.SessionId -ne $session) { throw 'First-run GUI ownership or default-path launch changed' }
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
        $firstProcess = Start-Process -FilePath $copiedExecutable -WorkingDirectory $working -ArgumentList @('gui') -PassThru -RedirectStandardError (Join-Path $FixtureDirectory 'gui-first-run-process-error.log')
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
