#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the rtunnel client on Windows.

.DESCRIPTION
    Thin wrapper around install.ps1, matching scripts/install-client.sh.
    All arguments are forwarded unchanged.
#>
$ErrorActionPreference = 'Stop'

& (Join-Path $PSScriptRoot 'install.ps1') @args
exit $LASTEXITCODE
