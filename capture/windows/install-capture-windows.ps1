<#
.SYNOPSIS
  Instala y arranca el sensor de captura (netviz) en Windows.

.DESCRIPTION
  Comprueba Python y tshark, localiza el dispositivo NPF del adaptador indicado,
  registra una tarea programada al iniciar sesión y abre el puerto de métricas
  solo para la LAN.

.EXAMPLE
  .\install-capture-windows.ps1 -Adapter "Ethernet" -Port 9101
#>
param(
    [string]$Adapter = "Ethernet",
    [int]$Port = 9101,
    [string]$AppDir = "$env:USERPROFILE\netviz-capture",
    [string]$Lan = "192.0.2.0/24,198.51.100.0/24",
    [string]$Names = "$AppDir\devices.json"
)

$ErrorActionPreference = "Stop"
function Info($m) { Write-Host "  $m" }
function Fail($m) { Write-Host "  ERROR: $m" -ForegroundColor Red; exit 1 }

Write-Host "== comprobando requisitos =="

$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python -or $python -like "*WindowsApps*") {
    $candidate = Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue |
                 Sort-Object FullName -Descending | Select-Object -First 1
    if ($candidate) { $python = $candidate.FullName }
}
if (-not $python) { Fail "Python no encontrado. Instala con: winget install --id Python.Python.3.12 -e" }
Info "python: $python"

$tshark = "C:\Program Files\Wireshark\tshark.exe"
if (-not (Test-Path $tshark)) {
    $found = (Get-Command tshark -ErrorAction SilentlyContinue).Source
    if ($found) { $tshark = $found } else { Fail "tshark no encontrado. Instala Wireshark." }
}
Info "tshark: $tshark"

if (-not (Test-Path "$AppDir\sensor.py")) { Fail "no está $AppDir\sensor.py (cópialo antes de ejecutar esto)" }

Write-Host "== localizando el adaptador '$Adapter' =="
$listing = & $tshark -D 2>&1
$device = $null
foreach ($line in $listing) {
    if ($line -match "^\s*\d+\.\s+(\S+)") {
        $candidate = $Matches[1]
        if ($line -like "*($Adapter)*") { $device = $candidate; break }
    }
}
if (-not $device) {
    Write-Host $listing
    Fail "no se encontró un dispositivo para '$Adapter' (mira la lista de arriba y pasa -Adapter con el nombre exacto)"
}
Info "dispositivo: $device"

Write-Host "== tarea programada =="
$action = New-ScheduledTaskAction -Execute $python `
    -Argument "`"$AppDir\sensor.py`" --iface $device --port $Port --bind 0.0.0.0 --lan $Lan --names `"$Names`" --tshark `"$tshark`"" -WorkingDirectory $AppDir
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:COMPUTERNAME\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$env:USERNAME" -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "netviz-capture" -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "netviz-capture"
Info "tarea 'netviz-capture' creada y arrancada"

Write-Host "== firewall =="
if (-not (Get-NetFirewallRule -DisplayName "netviz capture $Port" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "netviz capture $Port" -Direction Inbound -Protocol TCP `
        -LocalPort $Port -RemoteAddress 192.0.2.0/24 -Action Allow | Out-Null
    Info "regla creada para TCP $Port desde la LAN"
} else {
    Info "regla ya existente"
}

Write-Host "== comprobación =="
Start-Sleep -Seconds 4
try {
    $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 "http://127.0.0.1:$Port/healthz"
    Info "healthz: $($r.Content)"
} catch {
    Info "sin respuesta todavía; revisa 'Get-ScheduledTaskInfo -TaskName netviz-capture'"
}
Info "métricas: http://$((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -like '*Ethernet*'} | Select-Object -First 1).IPAddress):$Port/metrics"
