#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the rtunnel client on Windows.

.DESCRIPTION
    Downloads a prebuilt rtunnel release, verifies its SHA-256 checksum when
    available, installs rtunnel.exe under the current user's local programs
    directory, adds it to the user PATH, configures Windows OpenSSH, and
    optionally enrolls the client with a one-time token.

    The relay and agent are Linux-only; only the client runs on Windows.

.PARAMETER EnrollmentUri
    Optional one-time enrollment URI printed by `rtunneld token create`.

.PARAMETER Version
    Release tag to install, for example `v0.2.0`. Defaults to the latest release.

.PARAMETER Target
    Override the release asset target triple. Defaults to the host architecture.

.PARAMETER BinDir
    Installation directory. Defaults to
    `%LOCALAPPDATA%\Programs\rtunnel`.

.PARAMETER BinaryPath
    Use an existing rtunnel.exe instead of downloading a release.

.PARAMETER DownloadBase
    Override the release download base URL (for mirrors).

.PARAMETER Repo
    GitHub repository that publishes releases. Defaults to
    `abiiranathan/rtunneld`.

.PARAMETER NoPath
    Do not add the installation directory to the user PATH.

.PARAMETER NoSshConfig
    Do not add the rtunnel snippet include to `%USERPROFILE%\.ssh\config`.

.PARAMETER SkipChecksum
    Install even when the release checksum is missing or cannot be fetched.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1 `
        "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<client_token>"

.EXAMPLE
    .\install.ps1 -Version v0.2.0 -BinDir "$env:LOCALAPPDATA\Programs\rtunnel"
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$EnrollmentUri,

    [string]$Version = 'latest',
    [string]$Target,
    [string]$BinDir,
    [string]$BinaryPath,
    [string]$DownloadBase,
    [string]$Repo = 'abiiranathan/rtunneld',
    [switch]$NoPath,
    [switch]$NoSshConfig,
    [switch]$SkipChecksum
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:OS -ne 'Windows_NT') {
    throw 'scripts/install.ps1 installs the rtunnel client on Windows only'
}

# Windows PowerShell 5.1 disables TLS 1.2 by default on older builds.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    # Newer PowerShell versions negotiate TLS without this setting.
}

# Environment variables mirror scripts/install.sh for parity and CI overrides.
if (-not $PSBoundParameters.ContainsKey('Version') -and $env:RTUNNEL_VERSION) {
    $Version = $env:RTUNNEL_VERSION
}
if (-not $PSBoundParameters.ContainsKey('Repo') -and $env:RTUNNEL_REPO) {
    $Repo = $env:RTUNNEL_REPO
}
if (-not $PSBoundParameters.ContainsKey('Target') -and $env:RTUNNEL_TARGET) {
    $Target = $env:RTUNNEL_TARGET
}
if (-not $PSBoundParameters.ContainsKey('DownloadBase') -and $env:RTUNNEL_DOWNLOAD_BASE) {
    $DownloadBase = $env:RTUNNEL_DOWNLOAD_BASE
}
if (-not $PSBoundParameters.ContainsKey('BinDir') -and $env:RTUNNEL_BIN_DIR) {
    $BinDir = $env:RTUNNEL_BIN_DIR
}
if (-not $PSBoundParameters.ContainsKey('BinaryPath') -and $env:RTUNNEL_BIN) {
    $BinaryPath = $env:RTUNNEL_BIN
}

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "==> $Message"
}

function Write-Warn {
    param([Parameter(Mandatory)][string]$Message)
    Write-Warning $Message
}

function Resolve-Target {
    if ($Target) {
        return $Target
    }

    $architecture = $env:PROCESSOR_ARCHITEW6432
    if (-not $architecture) {
        $architecture = $env:PROCESSOR_ARCHITECTURE
    }

    switch ($architecture) {
        'AMD64' { return 'x86_64-pc-windows-msvc' }
        'ARM64' { return 'aarch64-pc-windows-msvc' }
        default {
            throw "no prebuilt Windows binary for architecture '$architecture'; pass -Target or -BinaryPath"
        }
    }
}

function Get-DownloadBase {
    if ($DownloadBase) {
        return $DownloadBase.TrimEnd('/')
    }
    if ($Version -eq 'latest') {
        return "https://github.com/$Repo/releases/latest/download"
    }

    $tag = $Version
    if (-not $tag.StartsWith('v')) {
        $tag = "v$tag"
    }
    return "https://github.com/$Repo/releases/download/$tag"
}

function Find-Checksum {
    param(
        [Parameter(Mandatory)][string]$SumsPath,
        [Parameter(Mandatory)][string]$AssetName
    )

    foreach ($line in Get-Content -LiteralPath $SumsPath -Encoding ASCII) {
        $match = [regex]::Match($line, '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$')
        if (-not $match.Success) {
            continue
        }
        if ([IO.Path]::GetFileName($match.Groups[2].Value) -eq $AssetName) {
            return $match.Groups[1].Value.ToLowerInvariant()
        }
    }
    return $null
}

function Save-ReleaseArchive {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination
    )

    Write-Log "Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing | Out-Null
}

function Expand-ReleaseBinary {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$TempDir
    )

    $asset = "rtunnel-$Target.zip"
    $base = Get-DownloadBase
    $archive = Join-Path $TempDir $asset
    Save-ReleaseArchive -Url "$base/$asset" -Destination $archive

    if (-not $SkipChecksum) {
        $sums = Join-Path $TempDir 'SHA256SUMS'
        $haveSums = $false
        try {
            Save-ReleaseArchive -Url "$base/SHA256SUMS" -Destination $sums
            $haveSums = $true
        }
        catch {
            Write-Warn 'SHA256SUMS not available; skipping checksum verification'
        }

        if ($haveSums) {
            $expected = Find-Checksum -SumsPath $sums -AssetName $asset
            if (-not $expected) {
                Write-Warn "no checksum for $asset; skipping verification"
            }
            else {
                $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($expected -ne $actual) {
                    throw "checksum verification failed for $asset"
                }
                Write-Log 'Checksum verified'
            }
        }
    }

    Expand-Archive -LiteralPath $archive -DestinationPath $TempDir -Force
    $binary = Join-Path $TempDir 'rtunnel.exe'
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "release archive $asset does not contain rtunnel.exe"
    }
    return $binary
}

function Resolve-LocalBinary {
    $candidates = New-Object System.Collections.Generic.List[string]

    if ($BinaryPath) {
        $candidates.Add($BinaryPath)
    }
    else {
        $repositoryRoot = Split-Path -Parent $PSScriptRoot
        $target = Resolve-Target
        $candidates.Add((Join-Path $repositoryRoot "target\$target\release\rtunnel.exe"))
        $candidates.Add((Join-Path $repositoryRoot 'target\release\rtunnel.exe'))
        $candidates.Add((Join-Path $PSScriptRoot 'rtunnel.exe'))
    }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    if ($BinaryPath) {
        throw "binary not found: $BinaryPath"
    }
    return $null
}

function Send-EnvironmentChanged {
    # Explorer caches the environment block. Broadcast WM_SETTINGCHANGE so newly
    # launched terminals and Explorer windows pick up the updated user PATH.
    try {
        if (-not ('Rtunnel.NativeMethods' -as [type])) {
            Add-Type -Namespace Rtunnel -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr SendMessageTimeout(
    System.IntPtr hWnd,
    uint Msg,
    System.UIntPtr wParam,
    string lParam,
    uint fuFlags,
    uint uTimeout,
    out System.UIntPtr lpdwResult);
'@
        }

        $result = [UIntPtr]::Zero
        [void][Rtunnel.NativeMethods]::SendMessageTimeout(
            [IntPtr]0xffff,
            0x001A, # WM_SETTINGCHANGE
            [UIntPtr]::Zero,
            'Environment',
            0x0002, # SMTO_ABORTIFHUNG
            5000,
            [ref]$result)
    }
    catch {
        Write-Warn "could not notify running applications about the PATH change: $($_.Exception.Message)"
    }
}

$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("rtunnel-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    $binary = Resolve-LocalBinary
    if (-not $binary) {
        $binary = Expand-ReleaseBinary -Target (Resolve-Target) -TempDir $tempDir
    }

    if (-not $BinDir) {
        $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
        if (-not $localAppData) {
            $localAppData = Join-Path $HOME 'AppData\Local'
        }
        $BinDir = Join-Path $localAppData 'Programs\rtunnel'
    }

    $installArguments = @('install')
    if ($EnrollmentUri) {
        $installArguments += $EnrollmentUri
    }
    $installArguments += @('--bin-dir', $BinDir)
    if ($NoSshConfig) {
        $installArguments += '--no-ssh-config'
    }
    if ($NoPath) {
        $installArguments += '--no-path'
    }

    & $binary @installArguments
    if ($LASTEXITCODE -ne 0) {
        throw "rtunnel install failed with exit code $LASTEXITCODE"
    }

    if (-not $NoPath) {
        Send-EnvironmentChanged
    }

    if (-not $NoSshConfig -and -not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
        Write-Warn 'OpenSSH Client was not found on PATH. Install it from Settings > Apps > Optional Features, then run rtunnel install again without --no-ssh-config.'
    }

    Write-Host ''
    Write-Log 'Windows client installation complete.'
    Write-Host 'Open a new terminal so PATH changes take effect, then run:'
    Write-Host '  rtunnel agents'
    Write-Host '  rtunnel ssh-config <agent> --write'
    Write-Host '  ssh user@<agent>'
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
