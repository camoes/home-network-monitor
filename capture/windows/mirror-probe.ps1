param([int]$Iface = 7, [int]$Seconds = 15, [string]$Out = "$env:USERPROFILE\mirror.pcap")
$tshark = "C:\Program Files\Wireshark\tshark.exe"
& $tshark -i $Iface -a "duration:$Seconds" -w $Out -q 2>&1 | Out-Null
Get-Item $Out | Select-Object FullName, Length
