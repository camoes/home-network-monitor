# Muestrea 8 s del adaptador Ethernet y agrupa por IP origen para comprobar
# si el puerto espejo entrega tráfico de otros equipos.
$tshark = "C:\Program Files\Wireshark\tshark.exe"
$iface = (& $tshark -D 2>$null | Select-String -Pattern '\(Ethernet\)' | ForEach-Object {
    if ($_ -match '^\s*(\d+)\.') { $Matches[1] }
}) | Select-Object -First 1

if (-not $iface) { Write-Host "no encontré la interfaz Ethernet"; exit 1 }
Write-Host "interfaz: $iface"

$out = & $tshark -i $iface -a duration:8 -n -T fields -e ip.src 2>$null
$out | Where-Object { $_ -and $_ -ne "" } |
    Group-Object |
    Sort-Object Count -Descending |
    Select-Object -First 10 Count, Name |
    Format-Table -AutoSize | Out-String -Width 60
