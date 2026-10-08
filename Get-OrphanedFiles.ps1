<#
.SYNOPSIS
    Finds orphaned VHDX/AVHDX files in a Hyper-V cluster.

.DESCRIPTION
    This script queries all cluster nodes for VMs, collects their attached disk paths,
    then scans the storage locations for VHDX/AVHDX files that are not in use.

.NOTES
    Author: Senior Systems Engineer
    Tested on: Windows Server 2019/2022 with Failover Clustering
#>

# ---------------- CONFIGURATION ----------------
# Add all storage paths where VHDX/AVHDX files may reside
$VHDPaths = @(
    "C:\ClusterStorage\Volume1",
    "C:\ClusterStorage\Volume2"
)

# ---------------- SCRIPT ----------------

try {
    # Get all cluster nodes
    $ClusterNodes = Get-ClusterNode -ErrorAction Stop

    # Get all VMs from all nodes
    $VMs = foreach ($Node in $ClusterNodes) {
        Get-VM -ComputerName $Node.Name -ErrorAction SilentlyContinue
    }

    # Collect all VHDX/AVHDX files currently in use
    $UsedDisks = @()
    foreach ($VM in $VMs) {
        $VMHardDisks = Get-VMHardDiskDrive -VMName $VM.Name -ComputerName $VM.ComputerName -ErrorAction SilentlyContinue
        foreach ($Disk in $VMHardDisks) {
            if ($Disk.Path) {
                $UsedDisks += (Resolve-Path $Disk.Path).ProviderPath.ToLower()
            }
        }
    }
    $UsedDisks = $UsedDisks | Sort-Object -Unique

    # Scan storage for all VHDX/AVHDX files
    $AllDisks = @()
    foreach ($Path in $VHDPaths) {
        if (Test-Path $Path) {
            $AllDisks += Get-ChildItem -Path $Path -Recurse -Include *.vhdx, *.avhdx -ErrorAction SilentlyContinue |
                         ForEach-Object { $_.FullName.ToLower() }
        }
    }
    $AllDisks = $AllDisks | Sort-Object -Unique

    # Find orphaned files
    $Orphaned = $AllDisks | Where-Object { $_ -notin $UsedDisks }

    # Output results
    if ($Orphaned.Count -gt 0) {
        Write-Host "Orphaned VHDX/AVHDX files found:" -ForegroundColor Yellow
        $Orphaned | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    }
    else {
        Write-Host "No orphaned VHDX/AVHDX files found." -ForegroundColor Green
    }
}
catch {
    Write-Error "Error: $_"
}
