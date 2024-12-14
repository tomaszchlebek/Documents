﻿$PCs = @('localhost','jshdfdjshfg')

ForEach ($Pc in $PCs){

$Ping = Test-Connection -ComputerName $PC -Quiet -Count 3 

If ($Ping) {
            Write-Host "Computer $PC online" -ForegroundColor Green
            Get-ComputerInfo|Select-Object CsDNSHostname,CsManufacturer,CsModel,OSVersion,WindowsVersion
            Get-NetIPConfiguration|Select-Object IPv4Address

}
Else {
            Write-Host "Computer $PC offline" -ForegroundColor Red


}


}