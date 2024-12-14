Get-NetAdapter -Physical | Get-NetAdapterPowerManagement | Select-Object Name, WakeOnMagicPacket
Get-NetAdapter -Physical | Set-NetAdapterPowerManagement -Name Wi* -WakeOnMagicPacket Enabled