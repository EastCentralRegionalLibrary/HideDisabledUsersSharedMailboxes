# Assumes Domain Controller and ADSync functions on local machine
Import-Module ActiveDirectory
Import-Module ADSync

# Define log file path relative to script location
$logPath = Join-Path -Path $PSScriptRoot -ChildPath "GAL_Hide_Log.txt"

# Get members of the group and filter for disabled accounts that are not already hidden
try {
    $groupMembers = Get-ADGroupMember -Identity "GAL_Hidden_DisabledUsers" | 
                    Get-ADUser -Properties Enabled, msExchHideFromAddressLists -ErrorAction Stop | 
                    Where-Object { $_.Enabled -eq $false -and $_.msExchHideFromAddressLists -eq $false }

    if ($null -eq $groupMembers) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path $logPath -Value "$timestamp - No changes needed. All members are already hidden or are enabled."
        Exit
    }
}
catch {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $errorMsg = $_.Exception.Message
    Add-Content -Path $logPath -Value "$timestamp - Error: Failed to retrieve group members or their properties. Error details: $errorMsg"
    Exit
}

# Variable to indicate if changes were made
$changesMade = $false

foreach ($user in $groupMembers) {
    try {
        # Hide AD user and set the extension attribute
        Set-ADUser -Identity $user.SamAccountName -Replace @{msExchHideFromAddressLists = $true; extensionAttribute15 = "Hidden from Exchange address book by script '$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')'"} -ErrorAction Stop
        
        $changesMade = $true
        
        # Log the successful action
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Successfully hid user '$($user.SamAccountName)' from the GAL."
        Add-Content -Path $logPath -Value $logEntry
    }
    catch {
        # Log the specific error
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $errorMsg = $_.Exception.Message
        $logEntry = "$timestamp - Failure encountered for $($user.SamAccountName): $errorMsg"
        Add-Content -Path $logPath -Value $logEntry
    }
}

# Run AD sync if changes were made
if ($changesMade) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $summary = "$timestamp - Script completed. Changes were made. Delta Sync requested."
    Add-Content -Path $logPath -Value $summary
    Start-ADSyncSyncCycle -PolicyType Delta
} else {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "$timestamp - Script completed. No changes were necessary."
}