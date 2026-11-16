[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [Parameter(Mandatory=$true)][string]$Checksum,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$PackageVersion,
    [string]$Compiler,
    [string]$SigningCertificateThumbprint = $env:PHOTON_FLCLASH_SIGNING_THUMBPRINT
)
$ErrorActionPreference = 'Stop'
if ($PackageVersion -notmatch '^[0-9A-Za-z][0-9A-Za-z.+-]{0,79}$') { throw 'Invalid package version' }
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ([IO.Path]::GetExtension($OutputPath) -ine '.exe') { throw 'OutputPath must name an EXE file' }
if (!$Compiler) {
    $command = Get-Command ISCC.exe -CommandType Application -ErrorAction SilentlyContinue
    if ($command) { $Compiler = $command.Source }
    else { $Compiler = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe' }
}
if (!(Test-Path -LiteralPath $Compiler -PathType Leaf)) { throw 'Install Inno Setup 6 or supply -Compiler with the ISCC.exe path' }
$Compiler = (Resolve-Path -LiteralPath $Compiler).Path
$stage = Join-Path ([IO.Path]::GetTempPath()) ('photon-flclash-installer-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    $bundle = Join-Path $stage 'bundle'
    & (Join-Path $PSScriptRoot '..\..\docs\scripts\windows-portable-verify.ps1') `
        -Archive $Archive -Checksum $Checksum -OutputDirectory $bundle
    foreach ($name in @('FlClash.exe', 'FlClashCore.exe', 'FlClashHelperService.exe', 'LICENSE.FlClash', 'README.Photon.md')) {
        if (!(Test-Path -LiteralPath (Join-Path $bundle $name) -PathType Leaf)) { throw "Missing installer file: $name" }
    }
    # A portable user's data must never become installer-owned files.
    if (Test-Path -LiteralPath (Join-Path $bundle 'data\.photon-portable')) { throw 'A used portable directory cannot be packaged' }
    & $Compiler '/Qp' "/DBundleDirectory=$bundle" "/DPackageVersion=$PackageVersion" "/O$stage" (Join-Path $PSScriptRoot 'installer.iss')
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed: $LASTEXITCODE" }
    $installer = Join-Path $stage 'setup.exe'
    if ($SigningCertificateThumbprint) {
        if ($SigningCertificateThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Invalid signing certificate thumbprint' }
        $signTool = (Get-Command signtool.exe -CommandType Application).Source
        & $signTool sign /sha1 $SigningCertificateThumbprint /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $installer
        if ($LASTEXITCODE -ne 0) { throw 'Installer signing failed' }
        & $signTool verify /pa /tw $installer
        if ($LASTEXITCODE -ne 0) { throw 'Installer signature verification failed' }
    } else {
        Write-Warning 'This installer has no Photon publisher signature.'
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
    Move-Item -LiteralPath $installer -Destination $OutputPath -Force
    $hash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $([IO.Path]::GetFileName($OutputPath))" | Set-Content -Encoding ascii "$OutputPath.sha256"
    Write-Output "Prepared Windows installer: $OutputPath"
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
