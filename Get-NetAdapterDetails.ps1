#get profiles and adapters
$Profiles = Get-NetConnectionProfile
$Adapters = Get-NetAdapter -Physical

#loop on adapters
$Results = $Adapters | ForEach-Object {
    #get the current adapter
    $Adapter = $PSItem
    #find the associated profiles
    $AdapterProfiles = $Profiles | where {$Adapter.ifIndex -eq $_.InterfaceIndex}

    #output the merged results by looping on the profiles
    $AdapterProfiles | 
         Select-Object @{n='Name';e={$Adapter.Name}},
                       @{n='DeviceName';e={$Adapter.DeviceName}},
                       @{n='InterfaceDescription';e={$Adapter.InterfaceDescription}},
                       @{n='Status';e={$adapter.Status}},
                       IPv4Connectivity,
                       NetworkCategory
}

#view the output in a nice interactive table
$results | Out-GridView