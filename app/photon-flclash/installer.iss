#ifndef BundleDirectory
  #error BundleDirectory is required
#endif
#ifndef PackageVersion
  #error PackageVersion is required
#endif

[Setup]
; A separate identity and directory from the upstream FlClash installer.
AppId={{8E4E8F6B-3275-48AC-9762-678DE7BAA930}
AppName=Photon-FlClash
AppVersion={#PackageVersion}
AppPublisher=Photon
DefaultDirName={autopf}\Photon-FlClash
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\FlClash.exe
SetupIconFile={#BundleDirectory}\data\flutter_assets\assets\images\icon.ico
; The application owns shutdown of Photon, Mihomo and system proxy settings.
; Never force-kill by image name or let Restart Manager restart the backend.
CloseApplications=no
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#BundleDirectory}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Photon-FlClash"; Filename: "{app}\FlClash.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\Photon-FlClash"; Filename: "{app}\FlClash.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\FlClash.exe"; Description: "{cm:LaunchProgram,Photon-FlClash}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
function OwnedPath(Value: String): Boolean;
begin
  Result := Pos(Lowercase(AddBackslash(ExpandConstant('{app}'))), Lowercase(Value)) = 1;
end;

function PrepareApplication: String;
var
  Locator, Wmi, Processes, Process, Services, Service: Variant;
  HelperPath, ServicePath: String;
  ResultCode, i: Integer;
begin
  Result := '';
  try
    Locator := CreateOleObject('WbemScripting.SWbemLocator');
    Wmi := Locator.ConnectServer('', 'root\CIMV2');
    Processes := Wmi.ExecQuery('SELECT ExecutablePath FROM Win32_Process');
    for i := 0 to Processes.Count - 1 do
    begin
      Process := Processes.ItemIndex(i);
      if not VarIsNull(Process.ExecutablePath) then
      begin
        if OwnedPath(Process.ExecutablePath) and
           (CompareText(ExtractFileName(Process.ExecutablePath), 'FlClashHelperService.exe') <> 0) and
           (CompareText(ExtractFileName(Process.ExecutablePath), 'unins000.exe') <> 0) then
        begin
          Result := 'Please exit Photon-FlClash from its tray menu and stop any Photon backend running from this installation, then retry.';
          Exit;
        end;
      end;
    end;

    // Only unregister a helper whose SCM executable belongs to this directory.
    // Another portable or upstream installation may own the shared service.
    HelperPath := ExpandConstant('{app}\FlClashHelperService.exe');
    Services := Wmi.ExecQuery('SELECT PathName FROM Win32_Service WHERE Name="FlClashHelperService"');
    for i := 0 to Services.Count - 1 do
    begin
      Service := Services.ItemIndex(i);
      ServicePath := Service.PathName;
      if Pos('"', ServicePath) = 1 then
        Delete(ServicePath, 1, 1);
      if OwnedPath(ServicePath) then
      begin
        if not FileExists(HelperPath) then
          RaiseException('The installed helper executable is missing.');
        if not Exec(HelperPath, 'uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
          RaiseException('Could not unregister the installed helper service.');
        if ResultCode <> 0 then
          RaiseException('The installed helper service could not stop.');
      end;
    end;
  except
    Result := 'Could not prepare Photon-FlClash: ' + GetExceptionMessage;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := PrepareApplication;
end;

function InitializeUninstall(): Boolean;
var
  Error: String;
begin
  Error := PrepareApplication;
  Result := Error = '';
  if not Result then
    SuppressibleMsgBox(Error, mbError, MB_OK, IDOK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Value, Key: String;
  Schemes: TArrayOfString;
  i: Integer;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;
  Key := 'Software\Microsoft\Windows\CurrentVersion\Run';
  if RegQueryStringValue(HKCU, Key, 'FlClash', Value) then
  begin
    StringChangeEx(Value, '"', '', True);
    if OwnedPath(Value) then
    begin
      RegDeleteValue(HKCU, Key, 'FlClash');
      RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run', 'FlClash');
    end;
  end;
  Schemes := ['clash', 'clashmeta', 'flclash'];
  for i := 0 to GetArrayLength(Schemes) - 1 do
  begin
    Key := 'Software\Classes\' + Schemes[i];
    if RegQueryStringValue(HKCU, Key + '\shell\open\command', '', Value) then
    begin
      StringChangeEx(Value, '"', '', True);
      if OwnedPath(Value) then
        RegDeleteKeyIncludingSubkeys(HKCU, Key);
    end;
  end;
end;

// No recursive deletion of {app} or AppData: keep configurations and identities,
// including user-created files in a custom installation directory.
