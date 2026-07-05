<#
.SYNOPSIS
  Deploys the mikrotik-wg-provision server on Windows.

.DESCRIPTION
  One-shot deployment for a Windows host (Windows 10/11 or Server 2019+):

    1. Installs Node.js LTS and WireGuard via winget if missing
    2. Builds the provisioning server (npm ci + npm run build)
    3. Generates a WireGuard keypair and installs the management tunnel
       as a Windows service (wireguard.exe /installtunnelservice)
    4. Generates config.json with random tokens (kept if it already exists)
    5. Opens Windows Firewall for the WireGuard UDP port and the HTTP port
    6. Registers the provisioning server as a Scheduled Task that starts at
       boot (runs as SYSTEM, auto-restarts, logs to logs\server.log). The
       server re-applies all peers on startup, so routers reconnect after
       a reboot.
    7. Prints the bootstrap one-liner for field techs

  Run from an elevated PowerShell prompt in the repo (any directory):

    powershell -ExecutionPolicy Bypass -File deploy\windows\deploy.ps1 `
        -PublicUrl "https://provision.example.com" `
        -EndpointHost "provision.example.com"

.PARAMETER PublicUrl
  URL routers use to reach the provisioning HTTP server from the field
  (before any tunnel exists). Put a TLS reverse proxy in front and use
  https:// here — the provisioning response contains router credentials.

.PARAMETER EndpointHost
  Public IP or DNS name routers connect to for WireGuard itself
  (usually this host's public address).

.PARAMETER Uninstall
  Removes the scheduled task, tunnel service and firewall rules.
  Leaves config.json and data\routers.json in place.
#>
#Requires -RunAsAdministrator
[CmdletBinding(DefaultParameterSetName = "Install")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Install")]
    [string]$PublicUrl,

    [Parameter(Mandatory = $true, ParameterSetName = "Install")]
    [string]$EndpointHost,

    [Parameter(ParameterSetName = "Install")] [int]$HttpPort = 8442,
    [Parameter(ParameterSetName = "Install")] [int]$WgPort = 51820,
    [Parameter(ParameterSetName = "Install")] [string]$MgmtCidr = "10.99.0.0/16",
    [Parameter(ParameterSetName = "Install")] [string]$ServerTunnelIp = "10.99.0.1",

    # Name of the server-side tunnel; becomes the Windows interface name.
    [string]$TunnelName = "wg-mgmt-server",

    [Parameter(Mandatory = $true, ParameterSetName = "Uninstall")]
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$RepoRoot   = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$TaskName   = "mtprov-server"
$WgDir      = Join-Path $env:ProgramFiles "WireGuard"
$WgExe      = Join-Path $WgDir "wg.exe"
$WireGuardExe = Join-Path $WgDir "wireguard.exe"
$ConfDir    = Join-Path $env:ProgramData "mtprov"
$ConfPath   = Join-Path $ConfDir "$TunnelName.conf"

function Write-Step([string]$msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# ---------------------------------------------------------------- uninstall
if ($Uninstall) {
    Write-Step "Removing scheduled task '$TaskName'"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

    Write-Step "Removing WireGuard tunnel service '$TunnelName'"
    if (Test-Path $WireGuardExe) {
        try { & $WireGuardExe /uninstalltunnelservice $TunnelName } catch { Write-Warning "tunnel service removal: $_" }
    }

    Write-Step "Removing firewall rules"
    Remove-NetFirewallRule -DisplayName "mtprov WireGuard UDP" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "mtprov HTTP" -ErrorAction SilentlyContinue

    Write-Host "`nUninstalled. config.json, data\ and $ConfPath were left in place." -ForegroundColor Green
    exit 0
}

# ------------------------------------------------------------ prerequisites
Write-Step "Checking prerequisites"

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    if (-not (Get-Command node -ErrorAction SilentlyContinue) -or -not (Test-Path $WgExe)) {
        throw "winget is not available and Node.js/WireGuard are not installed. Install Node.js LTS (https://nodejs.org) and WireGuard (https://www.wireguard.com/install/) manually, then re-run."
    }
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Step "Installing Node.js LTS via winget"
    winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
}

if (-not (Test-Path $WgExe)) {
    Write-Step "Installing WireGuard via winget"
    winget install --id WireGuard.WireGuard -e --accept-source-agreements --accept-package-agreements
}

# Pick up PATH changes made by the installers without reopening the shell.
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [Environment]::GetEnvironmentVariable("Path", "User")

if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw "node is still not on PATH — open a new elevated shell and re-run." }
if (-not (Test-Path $WgExe)) { throw "WireGuard did not install to $WgDir — install it manually and re-run." }

$NodeExe = (Get-Command node).Source
Write-Host "node: $NodeExe ($(node --version))"
Write-Host "wg:   $WgExe"

# ------------------------------------------------------------------- build
Write-Step "Building the provisioning server"
Push-Location $RepoRoot
try {
    npm ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
} finally {
    Pop-Location
}

# ------------------------------------------------- WireGuard tunnel service
$MgmtPrefix = $MgmtCidr.Split("/")[1]

$existingTunnel = Get-Service -Name "WireGuardTunnel`$$TunnelName" -ErrorAction SilentlyContinue
if ($existingTunnel) {
    Write-Step "WireGuard tunnel service '$TunnelName' already installed — keeping it"
    if (-not (Test-Path $ConfPath)) { throw "Tunnel service exists but $ConfPath is missing; cannot read the server public key. Uninstall the tunnel and re-run." }
    $ServerPrivateKey = (Select-String -Path $ConfPath -Pattern "^PrivateKey\s*=\s*(.+)$").Matches[0].Groups[1].Value.Trim()
    $ServerPublicKey  = ($ServerPrivateKey | & $WgExe pubkey).Trim()
} else {
    Write-Step "Creating WireGuard management tunnel '$TunnelName'"
    New-Item -ItemType Directory -Path $ConfDir -Force | Out-Null

    $ServerPrivateKey = (& $WgExe genkey).Trim()
    $ServerPublicKey  = ($ServerPrivateKey | & $WgExe pubkey).Trim()

    @"
[Interface]
PrivateKey = $ServerPrivateKey
Address = $ServerTunnelIp/$MgmtPrefix
ListenPort = $WgPort
"@ | Set-Content -Path $ConfPath -Encoding ascii

    # Lock the conf down — it contains the private key.
    icacls $ConfPath /inheritance:r /grant "SYSTEM:F" /grant "Administrators:F" | Out-Null

    & $WireGuardExe /installtunnelservice $ConfPath
    if ($LASTEXITCODE -ne 0) { throw "wireguard.exe /installtunnelservice failed" }
    Start-Sleep -Seconds 2
}
Write-Host "server public key: $ServerPublicKey"

# ------------------------------------------------------------- config.json
$ConfigPath = Join-Path $RepoRoot "config.json"
if (Test-Path $ConfigPath) {
    Write-Step "config.json already exists — keeping it (delete it to regenerate)"
} else {
    Write-Step "Generating config.json"
    function New-Token {
        $bytes = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        (([Convert]::ToBase64String($bytes)) -replace "[+/=]", "").Substring(0, 40)
    }

    $config = [ordered]@{
        server = [ordered]@{ host = "0.0.0.0"; port = $HttpPort; publicUrl = $PublicUrl }
        auth = [ordered]@{ provisioningToken = (New-Token); adminToken = (New-Token) }
        wireguard = [ordered]@{
            interface = $TunnelName
            serverPublicKey = $ServerPublicKey
            endpointHost = $EndpointHost
            endpointPort = $WgPort
            mgmtCidr = $MgmtCidr
            serverTunnelIp = $ServerTunnelIp
            persistentKeepalive = 25
            applyMode = "wg"
        }
        router = [ordered]@{ wgInterfaceName = "wg-mgmt"; username = "wg-mgmt"; strictTls = $false }
        storePath = "data/routers.json"
    }
    $config | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigPath -Encoding utf8
    icacls $ConfigPath /inheritance:r /grant "SYSTEM:F" /grant "Administrators:F" | Out-Null
}

# ---------------------------------------------------------------- firewall
Write-Step "Configuring Windows Firewall"
if (-not (Get-NetFirewallRule -DisplayName "mtprov WireGuard UDP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "mtprov WireGuard UDP" -Direction Inbound -Protocol UDP -LocalPort $WgPort -Action Allow | Out-Null
}
if (-not (Get-NetFirewallRule -DisplayName "mtprov HTTP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "mtprov HTTP" -Direction Inbound -Protocol TCP -LocalPort $HttpPort -Action Allow | Out-Null
}

# ---------------------------------------------------------- scheduled task
Write-Step "Registering scheduled task '$TaskName' (starts at boot, runs as SYSTEM)"
New-Item -ItemType Directory -Path (Join-Path $RepoRoot "logs") -Force | Out-Null

# cmd wrapper so stdout/stderr land in a log file.
$cmdArgs = "/c `"`"$NodeExe`" dist\cli.js serve >> logs\server.log 2>&1`""
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument $cmdArgs -WorkingDirectory $RepoRoot
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3

# ------------------------------------------------------------ verification
Write-Step "Verifying"
try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:$HttpPort/healthz" -TimeoutSec 5
    if (-not $health.ok) { throw "unexpected /healthz response" }
    Write-Host "provisioning server: OK (http://127.0.0.1:$HttpPort)" -ForegroundColor Green
} catch {
    Write-Warning "Server did not answer /healthz yet — check logs\server.log. ($_)"
}
& $WgExe show $TunnelName | Out-Host

# ----------------------------------------------------------------- summary
Write-Step "Bootstrap one-liner for field techs"
Push-Location $RepoRoot
try { node dist\cli.js bootstrap } finally { Pop-Location }

Write-Host @"

Deployment complete.
  - Tunnel service : WireGuardTunnel`$$TunnelName  ($ConfPath)
  - Server task    : $TaskName (Task Scheduler; logs in $RepoRoot\logs\server.log)
  - Config         : $ConfigPath
  - Inventory      : $RepoRoot\data\routers.json
  - Manage fleet   : node dist\cli.js list | show <serial> | verify <serial> | revoke <serial>

IMPORTANT: put a TLS reverse proxy (IIS ARR, nginx, caddy, or a cloud LB) in
front of port $HttpPort so $PublicUrl serves HTTPS — the provisioning response
contains router credentials.
"@ -ForegroundColor Green
