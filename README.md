# NIST Security Configuration Checklist for Apple OS X 10.10
This page contains supplemental resources to Draft NIST Special Publication (SP) 800-179, _Guide to Securing Apple OS X 10.10 Systems for IT Professionals: A NIST Security Configuration Checklist_. The draft is located at [http://csrc.nist.gov/publications/PubsDrafts.html#800-179](http://csrc.nist.gov/publications/PubsDrafts.html#800-179).  
Please send comments to 800-179comments@nist.gov.

## Settings Spreadsheet
The settings spreadsheet contains the information needed to configure a system on a per-setting basis. It includes each setting's identifier, command line instructions, and profile values. For a detailed explanation of the spreadsheet contents, see Appendix A of SP 800-179.

## Script Overview
The samc10_10 shell script performs 2 functions:

  * set configuration items to specified NIST profile values for OS X version 10.10  
  * read the current system state for settings specified by the NIST profiles

All configuration settings are grouped into batches. This is done to allow specific portions of the settings to be run easily. Every setting has a unique Common Configuration Enumeration (CCE) identifier and its own script function. This is used to track any action performed by a setting throughout the script. All file permissions/ownership/group settings are located in a single function, as are the ACL settings.

Some settings are user-specific. The script functions for these settings are aggregated in a list where they will be run for a specified user, or all users, as determined by the script options.


### Usage
The script must be run as root. In order to run the script, the execute bit must be enabled. Enable execution with the following command: `chmod +x samc10_10.sh` After running the script, a system restart is required for some settings to take effect. 

| Command                  | Short Description    |
|:-------------------------|:---------------------|
| `samc10_10.sh -a`          | Run user-specific settings for all users |
| `samc10_10.sh -h`          | Display the usage message            |
| `samc10_10.sh -k`          | Skip time-consuming print/set operations  |
| `samc10_10.sh -l`          | List the settings |
| `samc10_10.sh -p`          | Print settings values    |
| `samc10_10.sh -s ent | sslf | soho | oem` | Apply the chosen profile|
| `samc10_10.sh -u username` | Run user-specific settings for this user |
| `samc10_10.sh -v`          | Verbose output           |

The `-p` and `-s` options provide the core functionality, and the other options modify how these behave. Except when using the `-l` or `-h` options, `-p` or `-s` should always be used.

### Options

| Option | Long Description            |
|:-------|:----------------------------|
| `-a`     | Run user-specific settings for all non-system user accounts. If `-a` or `-u` is not specified, the settings are applied to the current user.                                                      |
| `-h`     | Prints a short help message.                            |
| `-k`     | Skip settings that take a significant amount of time to run. These are included below.<ul><li>Remove .netrc files: requires a search of the entire system.</li><li>Update Apple software: may take a long time, depending on download speed and size of updates.</li><li>File permissions: checks permissions of many system files</li><li>ACLs: checks many files for Access Control Lists</li></ul> |                     
| `-l`     | List the CCE identifiers, function name, and 10.10 testing status for each setting. Does not make changes to the system configuration.                                                     |
| `-p`     | Prints the current state of the system. Does not make changes to the system configuration.                |
| `-s`     | Apply the specified security profile. Accepted profiles are `ent` (enterprise), `soho` (Small Office Home Office), `sslf` (Specialized-Security Limited Functionality), and `oem` (Original Equipment Manufacturer).                                           | 
| `-u`     | Run user-specific settings for the designated user. If `-a` or `-u` is not specified, the settings are applied to the current user. |
| `-v`     | Output additional settings information. This produces a large quantity of output, which can benefit from saving to a file.                |



### Examples
| Terminal Command            | Result         |
|:--------------------------- |:-------------- |
| `./samc10_10.sh -vp`            | The script runs in print mode. No changes to the system will be made. Any settings that support the verbose option will print more informative output. User-specific settings will print the values for the current user.             |
| `./samc10_10.sh -s ent -u dave` | The script will run in set mode for the enterprise profile. All system-wide settings will be applied, and any user-specific settings will be applied to user __dave__.         |
| `./samc10_10.sh –pak`           | The script will print the state for system-wide settings and user-specific settings will be printed for each non-system user. Time-consuming settings will be skipped.        |


#### Run Script to Assess System State for All Users 

1.	Download the “samc10_10.sh” script. To avoid access permission errors, put the script in a directory accessible to all users, such as the `/Users/Shared` directory.
2.	Open the Terminal program.
3.	In Terminal, navigate to the directory where the script was downloaded using the `cd` command. 
4.	Type `chmod +x samc10_10.sh` and press "enter" to enable the execution permssion on the script. Note that if you have already downloaded the script and run this command, it is not necessary to do this again.
5.	If you are not logged into an admin account, type `su USERNAME`, where USERNAME is an administrator account, and press “enter”. Then type your password when prompted. 
6.	Type `sudo ./samc10_10.sh -pa` and press "enter". This will run the script with the `-p` and `-a` options, which prints the system state for all users on the system. 
7.	Type your password when prompted, and the script will begin execution.

#### Run Script to Apply Enterprise Profile for All Users

1.	Download the “samc10_10.sh” script. To avoid access permission errors, put the script in a directory accessible to all users, such as the `/Users/Shared` directory.
2.	Open the Terminal program.
3.	In Terminal, navigate to the directory where the script was downloaded using the `cd` command. 
4.	Type `chmod +x samc10_10.sh` and press "enter" to enable the execution permssion on the script. Note that if you have already downloaded the script and run this command, it is not necessary to do this again.
5.	If you are not logged into an admin account, type `su USERNAME`, where USERNAME is an administrator account, and press “enter”. Then type your password when prompted.
6.	Type `sudo ./samc10_10.sh -s ent -a` and press "enter". This will run the script with the `-s` and `-a` options, which applies the settings using the enterprise profile for all users on the system. 
7.	Type your password when prompted, and the script will begin execution.


## Password Policy: Formatted `.plist`
The `samc10_10_pwpolicy.plist` file contains the password policies generated by the script and recommended by the publication. 
