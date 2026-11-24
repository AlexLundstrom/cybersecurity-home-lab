#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Turns a Windows 11 VM into the CyberLab target for Scenario 01.

.DESCRIPTION
    Run as administrator, after the host-only network works. Renames the
    computer, creates a weak account, shares a planted file, opens SMB and
    ping to the lab subnet only, and turns on the audit policies the
    Detection needs. Refuses to run on a machine with a default gateway.
    Restart afterwards and snapshot as "vulnerable".

.EXAMPLE
    .\Setup-Target.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ComputerName   = 'WIN11-TARGET',
    [string]$LabSubnet      = '192.168.56.0/24',
    [string]$VictimUser     = 'svc_backup',
    [string]$VictimPassword = 'Syksy2026!',
    [string]$SharePath      = 'C:\LabShare\Backup',
    [string]$ShareName      = 'Backup',
    [int]$WordlistSize      = 8,
    [switch]$Force   # skip the isolation check
)

$ErrorActionPreference = 'Stop'
$restartNeeded = $false
function Say([string]$m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note([string]$m) { Write-Host "    $m" }

# 1. Isolation check
Say 'Checking isolation'
if ((Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue) -and -not $Force) {
    throw "This machine has a default gateway. Remove it, or rerun with -Force if you're sure it's isolated."
}
Note "Signed in as: $env:USERNAME (ends up in the event logs)"

# 2. Computer name
Say "Setting computer name to $ComputerName"
if ($env:COMPUTERNAME -ne $ComputerName -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Rename')) {
    Rename-Computer -NewName $ComputerName -Force
    $restartNeeded = $true
}

# 3. Weak account, Users group only
Say "Creating account $VictimUser"
if ($PSCmdlet.ShouldProcess($VictimUser, 'Create or reset account')) {
    $pw = ConvertTo-SecureString $VictimPassword -AsPlainText -Force
    if (Get-LocalUser -Name $VictimUser -ErrorAction SilentlyContinue) {
        Set-LocalUser -Name $VictimUser -Password $pw
        Enable-LocalUser -Name $VictimUser
    } else {
        New-LocalUser -Name $VictimUser -Password $pw -PasswordNeverExpires -AccountNeverExpires `
            -Description 'CyberLab: deliberately weak account' | Out-Null
    }
    # Users group by SID, so this works on any Windows language
    $inUsers = Get-LocalGroupMember -SID 'S-1-5-32-545' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*\$VictimUser" }
    if (-not $inUsers) { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $VictimUser }
}

# 4. Share with a planted file
Say "Sharing $SharePath as \\$ComputerName\$ShareName"
if ($PSCmdlet.ShouldProcess($SharePath, 'Create share and planted file')) {
    New-Item -ItemType Directory -Path $SharePath -Force | Out-Null
    @(
        'FAKE DATA FOR THE CYBERLAB HOME LAB. NONE OF THIS IS REAL.'
        ''
        'router admin   admin / Reititin2026'
        'nas backup     backup / Varmuus#77'
        'wifi (guest)   Vieras-2026'
    ) | Set-Content -Path (Join-Path $SharePath 'network-passwords.txt') -Encoding UTF8

    icacls $SharePath /grant "${VictimUser}:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed ($LASTEXITCODE)" }
