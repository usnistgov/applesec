# NIST Security Configuration Checklist for macOS 10.12
This page contains supplemental resources to NIST Special Publication (SP) 800-179 Revision 1, _Guide to Securing macOS 10.12 Systems for IT Professionals: A NIST Security Configuration Checklist_. The publication is located at [https://csrc.nist.gov/publications/detail/sp/800-179/rev-1/draft](https://csrc.nist.gov/publications/detail/sp/800-179/rev-1/draft).  
Please send any comments to 800-179comments@nist.gov.

## Settings Spreadsheet
The settings spreadsheet contains the information needed to configure a system on a per-setting basis. It includes each setting's identifier, command line instructions, and profile values. For a detailed explanation of the spreadsheet contents, see Appendix A of SP 800-179 Rev. 1.

## Script Overview
The samc10_12 shell script performs 2 functions:

  * set configuration items to specified NIST profile values for macOS version 10.12  
  * read the current system state for settings specified by the NIST profiles

All configuration settings are grouped into batches. This is done to allow specific portions of the settings to be run easily. Every setting has a unique Common Configuration Enumeration (CCE) identifier and its own script function. This is used to track any action performed by a setting throughout the script.

Some settings are user-specific. The script functions for these settings are aggregated in a list where they will be run for a specified user, or all users, as determined by the script options.


### Usage
The script must be run as root. In order to run the script, the execute bit must be enabled. Enable execution with the following command: `chmod +x samc10_12.sh` After running the script, a system restart is required for some settings to take effect. 

| Command                  | Short Description    |
|:-------------------------|:---------------------|
| `samc10_12.sh -a`          | Run user-specific settings for all users |
| `samc10_12.sh -h`          | Display the usage message            |
| `samc10_12.sh -k`          | Skip time-consuming print/set operations  |
| `samc10_12.sh -l`          | List the settings |
| `samc10_12.sh -p`          | Print settings values    |
| `samc10_12.sh -s ent \| sslf \| soho \| oem` | Apply the chosen profile|
| `samc10_12.sh -u username` | Run user-specific settings for this user |
| `samc10_12.sh -v`          | Verbose output           |

The `-p` and `-s` options provide the core functionality, and the other options modify how these behave. Except when using the `-l` or `-h` options, `-p` or `-s` should always be used.

### Options

| Option | Long Description            |
|:-------|:----------------------------|
| `-a`     | Run user-specific settings for all non-system user accounts. If `-a` or `-u` is not specified, the settings are applied to the current user.                                                      |
| `-h`     | Prints a short help message.                            |
| `-k`     | Skip settings that take a significant amount of time to run. Update Apple software is the only setting to use this flag. It may take a long time to run, depending on download speed and the size of updates. |                     
| `-l`     | List the CCE identifiers, function name, and 10.12 testing status for each setting. Does not make changes to the system configuration.                                                     |
| `-p`     | Prints the current state of the system. Does not make changes to the system configuration.                |
| `-s`     | Apply the specified security profile. Accepted profiles are `ent` (enterprise/managed), `soho` (Small Office Home Office/standalone), `sslf` (Specialized-Security Limited Functionality), and `oem` (Original Equipment Manufacturer).                                           | 
| `-u`     | Run user-specific settings for the designated user. If `-a` or `-u` is not specified, the settings are applied to the current user. |
| `-v`     | Output additional settings information. This produces a large quantity of output, which can benefit from saving to a file.                |



### Examples
| Terminal Command            | Result         |
|:--------------------------- |:-------------- |
| `./samc10_12.sh -vp`            | The script runs in print mode. No changes to the system will be made. Any settings that support the verbose option will print more informative output. User-specific settings will print the values for the current user.             |
| `./samc10_12.sh -s ent -u dave` | The script will run in set mode for the enterprise profile. All system-wide settings will be applied, and any user-specific settings will be applied to user __dave__.         |
| `./samc10_12.sh –pak`           | The script will print the state for system-wide settings and user-specific settings will be printed for each non-system user. Time-consuming settings will be skipped.        |


#### Run Script to Assess System State for All Users 

1.	Download the “samc10_12.sh” script. To avoid access permission errors, put the script in a directory accessible to all users, such as the `/Users/Shared` directory.
2.	Open the Terminal program.
3.	In Terminal, navigate to the directory where the script was downloaded using the `cd` command. 
4.	Type `chmod +x samc10_12.sh` and press "enter" to enable the execution permssion on the script. Note that if you have already downloaded the script and run this command, it is not necessary to do this again.
5.	If you are not logged into an admin account, type `su USERNAME`, where USERNAME is an administrator account, and press “enter”. Then type your password when prompted. 
6.	Type `sudo ./samc10_12.sh -pa` and press "enter". This will run the script with the `-p` and `-a` options, which prints the system state for all users on the system. 
7.	Type your password when prompted, and the script will begin execution.

#### Run Script to Apply Enterprise Profile for All Users

1.	Download the “samc10_12.sh” script. To avoid access permission errors, put the script in a directory accessible to all users, such as the `/Users/Shared` directory.
2.	Open the Terminal program.
3.	In Terminal, navigate to the directory where the script was downloaded using the `cd` command. 
4.	Type `chmod +x samc10_12.sh` and press "enter" to enable the execution permssion on the script. Note that if you have already downloaded the script and run this command, it is not necessary to do this again.
5.	If you are not logged into an admin account, type `su USERNAME`, where USERNAME is an administrator account, and press “enter”. Then type your password when prompted.
6.	Type `sudo ./samc10_12.sh -s ent -a` and press "enter". This will run the script with the `-s` and `-a` options, which applies the settings using the enterprise profile for all users on the system. 
7.	Type your password when prompted, and the script will begin execution.


## Password Policy: Formatted `.plist`
The `samc10_12_pwpolicy.plist` file contains the password policies generated by the script and recommended by the publication. 

## FAQ
**What version of macOS is supported by this script?**  
Only macOS 10.12 (Sierra) is supported.

**How do I enable SSH on a host system after applying a configuration profile?**  
The configuration uses multiple methods to prevent SSH access. Using an administrative account, do the following on the host system to re-enable remote login:

1. Open System Preferences -> Sharing. Enable "Remote Login", and add the desired users to the "Allowed Access for" box.
2. In System Preferences -> Security & Privacy, open the "Firewall" tab. Open "Firewall Options" and uncheck "Block all incoming connections". This will allow SSH through the Application Firewall.
3. Open Terminal and run the command `sudo nano /etc/ssh/sshd_config` to edit the config file. Comment out or delete the `Deny Users *` line at the bottom. This line should be `#DenyUsers *` if it is commented out. Save and close the file.
4. Again in Terminal, run the command `sudo nano /etc/pf.anchors/sam_pf_anchors` to edit pf firewall rules. Comment out the line `block in proto { tcp udp } to any port 22` so it becomes `#block in proto { tcp udp } to any port 22`. Save and close the file.
5. Restart the system.

**How do I resync the keychain login password with the user login password?**  
A Keychain sync issue can occur after an account password expires and is reset, and can be fixed with one of the following:

1st Solution:  

1. In the Keychain Access program, make sure the login keychain is selected, and click the lock at the top left.
2. Unlock the keychain, and enter the updated password.
3. A window should appear asking to enter the current password and to create a new password/verify new password.
4. Enter the old password in the first field, and your updated password in the new password/verify password fields.


2nd Solution:  

1. Open Keychain Access, and go to “Preferences".
2. Under the "First Aid" tab, check off "Synchronize login keychain password with account”
3. Close the Preferences and open “Keychain First Aid” under the Keychain Access menu.
4. Click the “Repair” option on the right, and enter your updated password.
