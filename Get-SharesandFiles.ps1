# Get all SMB shares on the system
$shares = Get-SmbShare | Where-Object { $_.Name -notin @("ADMIN$", "C$", "IPC$") } # Exclude default admin shares

# Loop through each share
foreach ($share in $shares) {
    Write-Host "Processing Share: $($share.Name)" -ForegroundColor Cyan

    # Construct the share path
    $sharePath = "\\$($env:COMPUTERNAME)\$($share.Name)"

    # Check if the share path is accessible
    if (Test-Path $sharePath) {
        # Get all files in the share recursively
        Get-ChildItem -Path $sharePath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                ShareName       = $share.Name
                FilePath        = $_.FullName
                LastModified    = $_.LastWriteTime
            }
        } | Format-Table -AutoSize
    } else {
        Write-Host "Unable to access share: $sharePath" -ForegroundColor Yellow
    }
}