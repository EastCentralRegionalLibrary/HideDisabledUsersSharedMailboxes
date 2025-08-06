Import-Module ActiveDirectory
Import-Module ADSync

# Script to retrieve list of users from group and set 

# Variable to indicate that changes have been made
$syncRequired = $false

# Define log file path relative to script location
$logPath = Join-Path -Path $PSScriptRoot -ChildPath "GAL_Hide_Log.txt"

# Get members of the group
$groupMembers = Get-ADGroupMember -Identity "GAL_Hidden_DisabledUsers"

foreach ($user in $groupMembers) {
    try {
        # Set the variable for easy access to the user object properties
        $userProperties = Get-ADUser -Identity $user.SamAccountName -Properties Enabled, msExchHideFromAddressLists
        # Note the date and time
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        # Only continue if user account is not enabled or hidden
        if ( (($userProperties.Enabled -eq $false) && ($userProperties.msExchHideFromAddressLists -eq $false))) {
            # Hide AD user and associated mailbox from GAL
            Set-ADUser -Identity $user.SamAccountName -Replace @{msExchHideFromAddressLists=$true} -ErrorAction SilentlyContinue
            # Fetch msEchHideFromAddressLists attribute to verify success
            $userProperties = Get-ADUser -Identity $user.SamAccountName -Properties Enabled, msExchHideFromAddressLists
            # Only note success if we did actually successfully set the property to true
            if ($userProperties.msExchHideFromAddressLists -eq $true) {
                # Record the action and when it was performed using custom attribute 15
                Set-ADUser -Identity $user.SamAccountName -Replace @{extensionAttribute15="Hidden from Exchange address book by script '$timestamp'"} -ErrorAction SilentlyContinue
                # At least one user has been changed - set sync variable so that sync will run at completion
                $syncRequired = $true
            }
            # Log that we processed this user account
            $logEntry = "$timestamp - Processed user '$($user.SamAccountName)'; Disabled : '$($userProperties.Enabled)'; '$($userProperties.extensionAttribute15)' : '$($userProperties.msExchHideFromAddressLists)';"
            Add-Content -Path $logPath -Value $logEntry
        }
    } catch {
        # Something failed - record the specific error and log it
        $errorMsg = $_.Exception.Message
        $logEntry = "$timestamp - Failure encountered for $($user.SamAccountName): $errorMsg"
        Add-Content -Path $logPath -Value $logEntry
    }

}

# Only continue if changes were made to at least one user account
if ($syncRequired -eq $true) {
    $summary = "$timestamp - Script completed. Sync triggered: $syncRequired"
    Add-Content -Path $logPath -Value $summary
    # Run AD sync
    Start-ADSyncSyncCycle -PolicyType Delta
}
