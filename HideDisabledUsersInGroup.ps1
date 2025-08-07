<#
.SYNOPSIS
    Hides disabled Active Directory users in a specified group from the Exchange Global Address List (GAL).

.DESCRIPTION
    This script identifies disabled user accounts in the "GAL_Hidden_DisabledUsers" Active Directory group 
    that are not currently hidden from the Exchange Global Address List (GAL), and sets the appropriate 
    attributes to hide them.

    Optionally, the script supports a dry-run mode to preview which users would be updated without making changes.

    If changes are made and the script is not in dry-run mode, a delta synchronization is triggered using 
    Start-ADSyncSyncCycle to propagate the updates to Entra ID ( formerly Azure AD ).

.PARAMETER WhatIf
    PowerShell standard switch. When specified, simulates the script's actions without making changes.

.PARAMETER Confirm
    PowerShell standard switch. When specified, prompts for confirmation before applying changes.

.PARAMETER GroupName
    The name of the AD Security Group that contains the disabled users to be hidden. Defaults to GAL_Hidden_DisabledUsers.

.PARAMETER NoSync
    When specified, skips ADSync cycle.

.OUTPUTS
    Write-Verbose, Write-Debug, Write-Warning, Write-Error and a log file at GAL_Hide_Log.txt in the script folder.

.NOTES
    Created     : 2025-08-06
    Last Updated: 2025-08-07
    Requires    : PowerShell 5.1+, ActiveDirectory module, ADSync module
    Run As      : Administrator (elevation required for AD and ADSync cmdlets)

.EXAMPLE
    .\HideDisabledUsersInGroup.ps1
    Hides all disabled users in the "GAL_Hidden_DisabledUsers" group that are not already hidden from the GAL.

.EXAMPLE
    .\HideDisabledUsersInGroup.ps1 -WhatIf
    Simulates the script without making any changes.

.EXAMPLE
    .\HideDisabledUsersInGroup.ps1 -Confirm
    Prompts before each user is updated.

.LINK
    https://learn.microsoft.com/powershell/module/activedirectory/set-aduser

.LINK
    https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-adsync#start-adsyncsynccycle

.LINK
    https://github.com/EastCentralRegionalLibrary/HideDisabledUsersSharedMailboxes

.EXITCODES
    0 - Success. Script completed without errors and all users (if any) were processed successfully.
    1 - Fatal error. Could not retrieve group or user data from Active Directory.
    2 - Partial failure. Some users failed to update, but the script completed and logged the errors.
    3 - Partial failure. All users were processed successfully but Entra ID Connect AD Sync failed.
    4 - Partial failure. Some users failed to update and Entra ID Connect AD Sync failed.

.LICENSE
    MIT License

    See included LICENSE file
#>

# Support WhatIf and Confirm
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
# Allow specifying AD user group name and skipping AD sync
param(
    [ValidateNotNullOrEmpty()]
    [string]    $GroupName = 'GAL_Hidden_DisabledUsers',
    [switch]    $NoSync
)

#Requires -RunAsAdministrator
# Check for elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator." -ErrorAction Stop
}
Write-Verbose "Running with administrative privileges."

# Assumes Domain Controller and ADSync functions on local machine
# ADSync is included with Entra Connect
#Requires -Modules ActiveDirectory, ADSync
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module ADSync -ErrorAction Stop

# Fail fast if the group name cannot be found - no need to create logs etc.
if (-not (Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue)) {
    Write-Error "AD group ‘$GroupName’ not found."
    Exit 1
}

# Strings needed for LDAP query - provided for readability
$disabledUserValue = "userAccountControl:1.2.840.113556.1.4.803:=2"
$msExchHideTrue = "msExchHideFromAddressLists=TRUE"

# Set the location to the same path as our script. Though we don't produce any files other than the logs, we don't want to be in System32 - just in case.
Set-Location -Path $PSScriptRoot

# Define log file path relative to script location
$logPath = Join-Path -Path $PSScriptRoot -ChildPath "GAL_Hide_Log.txt"

# Validate log path
$logDir = Split-Path -Path $logPath -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Rotate and compress log if it grows too large
if (Test-Path $logPath -and (Get-Item $logPath).Length -gt 5MB) {
    try {
        $rotatedLogFilename = (Get-Date).ToString('yyyyMMddHHmm')
        $rotatedLogPath = "$logPath.$rotatedLogFilename.bak"
        $zipPath = "$logPath.$rotatedLogFilename.zip"
        Move-Item $logPath $rotatedLogPath
        # Create a new, empty log file for subsequent logging
        New-Item -Path $logPath -ItemType File -Force | Out-Null
        # Compress the rotated log file
        Compress-Archive -Path $rotatedLogPath -DestinationPath $zipPath
        # Remove the ( now archived ) rotated log file
        Remove-Item -Path $rotatedLogPath
    } 
    catch {
        Write-Warning "Failed to compress or remove log file: $_"
    }
}

# Returns the current timestamp
function Get-Timestamp {
    return (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}

# Write a message to the log and the specified output stream
function Write-LogEntry {
    param(
        [ValidateSet('DEBUG', 'INFO', 'VERBOSE', 'WARN', 'ERROR')]
        [string]$Level,
        [string]$Message
    )
    $ts = Get-Timestamp
    Add-Content $logPath "$ts [$Level] $Message"

    # Define a mapping from log level to output cmdlet
    $logLevelMap = @{
        'DEBUG'   = { Write-Debug $Message }
        'INFO'    = { Write-Information $Message }
        'VERBOSE' = { Write-Verbose $Message }
        'WARN'    = { Write-Warning $Message }
        'ERROR'   = { Write-Error $Message }
    }

    # Invoke the appropriate cmdlet based on the level
    if ($logLevelMap.ContainsKey($Level)) {
        $logLevelMap[$Level].Invoke()
    } else {
        Write-Warning "Unknown log level '$Level'. Message: $Message"
    }

}



# Get members of the group and filter for disabled accounts that are not already hidden
try {
    # PERFORMANCE: Use a single, efficient LDAP filter instead of multiple queries.
    # This finds all users who are members of the group, are disabled, and are not already hidden.
    $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop
    # Debug dump of the group
    Write-LogEntry -Level DEBUG -Message "Group object details:`n$(
        $group |
        Format-List * |
        Out-String -Width 80
    )"
    $escapedDN = [System.DirectoryServices.Protocols.LdapFilter]::Escape($group.DistinguishedName)
    $ldapFilter = "(&(memberOf=$escapedDN)($disabledUserValue)(!($msExchHideTrue)))"
    Write-LogEntry -Level DEBUG -Message "LDAP filter: $ldapFilter"
    $groupMembers = Get-ADUser -LDAPFilter $ldapFilter -Properties msExchHideFromAddressLists -ErrorAction Stop
    # Debug dump of groupMembers collection
    Write-LogEntry -Level DEBUG -Message "Member objects:`n$(
        $groupMembers |
        Format-List SamAccountName,Enabled,msExchHideFromAddressLists |
        Out-String -Width 80
    )"

    if (-not $groupMembers) {
        Write-LogEntry -Level INFO -Message  "No changes needed. All members are already hidden or are enabled."
        Exit 0 # Nothing to do so indicate success
    }
}
catch {
    $errorMsg = "FATAL ERROR: Failed to retrieve group members or their properties. Error details: $($_.Exception.Message)"
    Write-LogEntry -Level ERROR -Message  $errorMsg
    Exit 1  # Error retrieving group
}

# Initial state variables
# Variable to indicate if changes were made that will require sync
$changesMade = $false
# Variable to indicate if an error was encountered for one or more users
$errorsEncountered = $false
$failedUsers = @()
$failedSync = $false
# Get a single timestamp for the entire script run for consistency.
$runTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Log user count before beginning 
Write-LogEntry -Level INFO -Message  "Found $($groupMembers.Count) user(s) to process."

# Iterate through users in the group, set the attribute to hide from address lists, and add record change timestamp in extension attribute 15
foreach ($user in $groupMembers) {
    try {
        if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Hide from GAL and update extensionAttribute15")) {
            # Hide AD user and set the extension attribute
            $changeTimeStampString = "Hidden from Exchange address book by script $runTimestamp"
            Set-ADUser -Identity $user.SamAccountName -Replace @{msExchHideFromAddressLists = $true; extensionAttribute15 = $changeTimeStampString } -ErrorAction Stop
            # Indicate that we have made changes that require sync
            $changesMade = $true
            # Log the successful action
            Write-LogEntry -Level VERBOSE -Message  "Successfully hid user $($user.SamAccountName) from the GAL."
        }
    }
    catch {
        # Error during Set-ADUser
        $errorsEncountered = $true
        # Record which user failed for later summary
        $failedUsers += $user.SamAccountName
        # Log the specific error and user
        $errorMsg = $_ | Out-String
        Write-LogEntry -Level WARN -Message  "Warning: Failed to update user $($user.SamAccountName): $errorMsg"
        # We want to process other users even if one fails, so logging the error and noting it at the end of the run is sufficient
    }
}

# Only sync if changes were made to users or NoSync is not specified
if ($changesMade -and -not $NoSync.IsPresent) {
    Write-LogEntry -Level INFO -Message  "Script completed. Changes were made. Delta Sync requested."
    if ($PSCmdlet.ShouldProcess("Entra ID Connect", "Start Delta Sync")) {
        try {
            Start-ADSyncSyncCycle -PolicyType Delta
        }
        catch {
            $errorsEncountered = $true
            $failedSync = $true
            $failedSyncMsg = "Start-ADSyncSyncCycle Delta sync failed with the following error: $_"
            Write-LogEntry -Level WARN -Message  $failedSyncMsg
        }
    }
}
else {
    Write-LogEntry -Level INFO -Message  "Script completed. No changes were necessary or NoSync was specified."
}

# Set exit code based on whether sync or user errors occurred and indicate which users failed, if any
if ($errorsEncountered) {
    $errorCode = 1 # initial value, should never be returned since errors are either users or sync
    Write-LogEntry -Level WARN -Message  "Script finished with one or more errors."
    if ($failedUsers.Count -gt 0) {
        $errorCode += 1 # results in error code 2 if only users
        $failedUsersMsg = "The following $($failedUsers.Count) user(s) failed to update: $($failedUsers -join ', ')"
        Write-LogEntry -Level WARN -Message  $failedUsersMsg
    }
    if ($failedSync) {
        $errorCode += 2 # results in error code 3 if only sync, 4 if users and sync
        Write-LogEntry -Level WARN -Message  "Entra ID Connect AD Synchronization failed. Review log for details."
    }
    Exit $errorCode # Custom exit codes 2, 3, or 4 for partial failure
}
else {
    Write-LogEntry -Level INFO -Message  "Script finished successfully."
    Exit 0 # Success
}