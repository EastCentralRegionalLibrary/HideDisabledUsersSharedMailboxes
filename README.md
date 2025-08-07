# HideDisabledUsersSharedMailboxes

A PowerShell script to hide disabled Active Directory users in a specified security group from the Exchange Online Global Address List (GAL), optionally triggering an Entra ID AD Connect synchronization to propagate changes to Entra ID.

---

## Table of Contents

* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Usage](#usage)

  * [Parameters](#parameters)
  * [Examples](#examples)
* [Logging](#logging)
* [Exit Codes](#exit-codes)
* [Scheduling](#scheduling)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)

---

## Prerequisites

* **Windows Server** or a machine with:

  * Active Directory PowerShell module.
  * Entra ID AD Connect module (for `Start-ADSyncSyncCycle`).
* **Permissions**:

  * Read and write access to the target AD security group.
  * Permission to modify user `msExchHideFromAddressLists` attribute.
  * Rights to run Entra ID Connect AD synchronization (if using sync).

## Installation

1. Clone the repository:

   ```powershell
   git clone https://github.com/EastCentralRegionalLibrary/HideDisabledUsersSharedMailboxes.git
   ```
2. Navigate to the script folder:

   ```powershell
   cd HideDisabledUsersSharedMailboxes
   ```

## Usage

Run the script in a PowerShell session with the required modules loaded. You can use the standard `-WhatIf` and `-Confirm` switches to simulate or prompt for changes.

```powershell
.\HideDisabledUsersInGroup.ps1 [-GroupName <string>] [-NoSync] [-WhatIf] [-Confirm]
```

### Parameters

| Parameter      | Type     | Description                                                                              | Default                    |
| -------------- | -------- | ---------------------------------------------------------------------------------------- | -------------------------- |
| `-GroupName`   | `String` | Name of the AD security group containing disabled users to hide.                         | `GAL_Hidden_DisabledUsers` |
| `-NoSync`      | `Switch` | When specified, skips the Azure AD Connect synchronization step.                         | `False`                    |
| `-WhatIf`      | `Switch` | Simulates actions without making changes (standard PowerShell WhatIf behavior).          | `False`                    |
| `-Confirm`     | `Switch` | Prompts for confirmation before applying changes (standard PowerShell Confirm behavior). | `False`                    |

### Examples

* **Dry run (simulate changes)**

  ```powershell
  .\HideDisabledUsersInGroup.ps1 -WhatIf
  ```

* **Hide users in a custom group, confirm changes, and skip sync**

  ```powershell
  .\HideDisabledUsersInGroup.ps1 -GroupName "Corp_DisabledUsers" -NoSync -Confirm
  ```

* **Production run (hide and sync)**

  ```powershell
  .\HideDisabledUsersInGroup.ps1
  ```

## Logging

The script writes timestamped log entries and can produce debug or info output to the console. You can redirect console output to a file for auditing:

```powershell
.\HideDisabledUsersInGroup.ps1 2>&1 | Tee-Object -FilePath "C:\Logs\HideDisabledUsers.log"
```

## Exit Codes

| Code | Meaning                                                                   |
| ---- | ------------------------------------------------------------------------- |
| `0`  | Success; all users hidden and sync (if enabled) completed without errors. |
| `1`  | Fatal error. Could not retrieve group or user data from Active Directory. |
| `2`  | One or more user attribute updates failed.                                |
| `3`  | Azure AD Connect sync failed.                                             |
| `4`  | Both user updates and sync failed.                                        |

## Scheduling

To automate the script:

1. Open **Task Scheduler**.
2. Create a new **Basic Task** (e.g., "Hide Disabled Users").
3. In **Action**, choose **Start a program**, and set:

   * **Program/script**: `powershell.exe`
   * **Arguments**: `-ExecutionPolicy Bypass -File "C:\Path\To\HideDisabledUsersInGroup.ps1"`
4. Configure a **Trigger** (e.g., daily at 2:00 AM).
5. Ensure the task runs under an account with necessary permissions and "Run whether user is logged on or not" is selected.

Alternatively, import it into Azure Automation or your preferred orchestration tool.

## Contributing

Contributions are welcome! Please:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m "Add feature"`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a Pull Request.

Please follow PowerShell best practices and include descriptive commit messages.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, please open an [issue](https://github.com/EastCentralRegionalLibrary/HideDisabledUsersSharedMailboxes/issues) or contact the repository maintainers.
