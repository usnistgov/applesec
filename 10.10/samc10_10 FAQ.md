## FAQ
**What version of OS X is supported by this script?**  
Only OS X 10.10 (Yosemite) is supported.

**How do I enable SSH on a host system after applying a configuration profile?**  
The configuration uses multiple methods to prevent SSH access. Using an administrative account, do the following on the host system to re-enable remote login:

1. Open System Preferences -> Sharing. Enable "Remote Login", and add the desired users to the "Allowed Access for" box.
2. In System Preferences -> Security & Privacy, open the "Firewall" tab. Open "Firewall Options" and uncheck "Block all incoming connections". This will allow SSH through the Application Firewall.
3. Open Terminal and run the command `sudo vi /etc/sshd_config` to edit the config file. Comment out or delete the `Deny Users *` line at the bottom. This line should be `#DenyUsers *` if it is commented out. Save and close the file.
4. Again in Terminal, run the command `sudo vi /etc/pf.anchors/sam_pf_anchors` to edit pf firewall rules. Comment out the line `block in proto { tcp udp } to any port 22` so it becomes `#block in proto { tcp udp } to any port 22`. Save and close the file.
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
