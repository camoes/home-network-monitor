<#
.SYNOPSIS
  Instala Npcap en silencio (driver de captura que Wireshark no instala en modo desatendido).
#>
$ErrorActionPreference = "Stop"

$url = "https://npcap.com/dist/npcap-1.82.exe"
$out = Join-Path $env:TEMP "npcap-1.82.exe"

Write-Host "== descargando Npcap =="
Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
Write-Host "  $(Get-Item $out | Select-Object -ExpandProperty Length) bytes"

Write-Host "== instalando (silencioso, modo WinPcap compatible) =="
$proc = Start-Process -FilePath $out -ArgumentList "/S", "/winpcap_mode=yes" -Wait -PassThru
Write-Host "  exit code: $($proc.ExitCode)"

Start-Sleep -Seconds 3

$svc = Get-Service npcap -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "  servicio npcap: $($svc.Status)"
} else {
    Write-Host "  aviso: el servicio npcap no aparece (puede requerir reinicio)"
}

$wpcap = "C:\Windows\System32\Npcap\wpcap.dll"
if (Test-Path $wpcap) { Write-Host "  wpcap.dll: OK" } else { Write-Host "  wpcap.dll: no encontrado" }
