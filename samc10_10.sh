#!/bin/sh

#NIST GitHub repository for related project files:
#https://github.com/usnistgov/applesec

######################################################################
:<<'COMMENT_BLOCK'

License

This data was developed by employees of the National Institute of Standards and Technology (NIST), an agency of the Federal Government. Pursuant to title 15 United States Code Section 105, works of NIST employees are not subject to copyright protection in the United States and are considered to be in the public domain.

The data is provided by NIST as a public service and is expressly provided “AS IS.” NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT AND DATA ACCURACY. NIST does not warrant or make any representations regarding the use of the data or the results thereof, including but not limited to the correctness, accuracy, reliability or usefulness of the data. NIST SHALL NOT BE LIABLE AND YOU HEREBY RELEASE NIST FROM LIABILITY FOR ANY INDIRECT, CONSEQUENTIAL, SPECIAL, OR INCIDENTAL DAMAGES (INCLUDING DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF BUSINESS INFORMATION, AND THE LIKE), WHETHER ARISING IN TORT, CONTRACT, OR OTHERWISE, ARISING FROM OR RELATING TO THE DATA (OR THE USE OF OR INABILITY TO USE THIS DATA), EVEN IF NIST HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

To the extent that NIST may hold copyright in countries other than the United States, you are hereby granted the non-exclusive irrevocable and unconditional right to print, publish, prepare derivative works and distribute the NIST data, in any medium, or authorize others to do so on your behalf, on a royalty-free basis throughout the World.

You may improve, modify, and create derivative works of the data or any portion of the data, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the data and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the data.

Permission to use this data is contingent upon your acceptance of the terms of this agreement and upon your providing appropriate acknowledgments of NIST’s creation of the data.


######################################################################
This shell script performs 2 functions:
    1) set configuration items to specified NIST profile values
    2) query configuration item values

It must be run as root.

usage:

samc -l                             # list the settings
samc -s ent | sslf | soho | oem     # choose the profile
samc -p                             # print settings values
samc -h                             # usage message
samc -v                             # verbose
samc -u username                    # username to apply user-specific settings
samc -a                             # apply user-specific settings to all users
samc -k                             # skip time-consuming print/set operations

Note: "ent" is shorthand for "enterprise".

Commands this script uses to write configation info in OSX:
    defaults
    chmod
    chgrp
    chown
    PlistBuddy
    pwpolicy
    pmset
    scutil
    socketfilterfw
    cupsctl
    dscl
    systemsetup
    kickstart
    visudo
    pfctl

Design note:

All setting batches are invoked from the main function level and different
groups of settings can be commented out to focus on specific issues.
Each setting (that isn't one of the numerous file-attribute settings)
is implemented by a separate function that gets called from different
batch functons. Settings in similar categories are typically grouped  
into each batch, and these batches are called by the main function.  
Each separate setting function is responsible for writing
the various profiles, displaying current values, outputing a brief
message for listing the settings ls-style, and, when additional
verbosity makes sense, supporting the -v option.  The file-attribute
settings are grouped into an umbrella function (or a few) that takes
care of the same responsibilities for sets of files.

Writing, listing, and displaying a setting should be modularized in a
separate function that conforms to the command-line interface flags,
which are passed using the following global variables (ugly, but
easier given Bash's treatment of variables and parameters).


Function status tags:

#Informal testing was unable to be completed on a VM
NEEDS_REAL_HARDWARE

COMMENT_BLOCK

######################################################################
#checks for root user before running any commands
if [ `id -u \`whoami\`` != "0" ]; then
    echo "Sorry, you must be root to run samc, exiting..."
    exit 1
fi

# Global variables.

# This script's command-line options 
list_flag=""
set_flag=""
profile_flag=""
print_flag=""
help_flag=""
v_flag=""
all_users_flag=""
specific_user_flag=""

#Used to skip time-consuming print and set operations. This is used in the functions
#extended_acls_CCEs
#file_attribute_CCEs
#CCE_79848_8_no_netrc_files_on_system
#CCE_79876_9_update_apple_software
skip_flag=""  


home_path=""
owner=""
os_version="" #major release version, such as 10.9 or 10.10
processes_to_kill="" #processes that need to be restarted at the end of the script
new_system_name=""
user_list="" #non system-created user accounts (user accounts created for people)
full_user_list="" #the full list of users on the system

#audit log location is variable, so find it for later
audit_log_path=`grep "^dir:" /etc/security/audit_control | sed "s/dir://"`

#directories containing library files
lib_dirs="/System/Library/Frameworks /Library/Frameworks /usr/lib /usr/local/lib"
#library files
lib_files=`find $lib_dirs -type f 2> /dev/null | egrep "((\.a)|(\.so)|(\.dylib)[\.0-9]*)$"`

#needed for storing script temp files
script_dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

acl_files=0 #counter for number of files with ACLs
non_acl_files=0 #counter for the number of files checked for ACLs with no match

#When using PlistBuddy, array values must be added by index, therefore creating the need
#for a global variable to keep track of the current array position for pwpolicy settings
pw_content_index=0
pw_change_index=0
pw_auth_index=0

# stored function names will be executed for all specified users
user_settings_list=""

######################################################################
main() {
    parse_arguments $@


    #If the power management file doesn't exist, write a default value to create it.
    #This prevents an error when trying to read/write this file.
    if [ ! -e "/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist" ]; then
        pmset -a sleep 10 
    fi
    
    
    if [ "$v_flag" != "" ]; then echo "SAM script to apply settings"; fi
    echo "Executing system-wide settings.";

    # sets the global variables: owner, group, and hw_uuid
    determine_user_and_system_properties


    execute_batch_1
    execute_batch_2
    #batch_3: settings originally in this batch did not pass informal testing on 10.10
    #batch_4 settings are called by file_attribute_CCEs
    #batch_5 settings are called by extended_acls_CCEs
    #batch_6 settings are called by file_attribute_CCEs

    file_attribute_CCEs  # implements multiples CCEs for rwx bits, etc.
    extended_acls_CCEs   # implements multiple CCEs for ACL configs

    #batch_7 settings are called by file_attribute_CCEs and extended_acls_CCEs
    
    execute_batch_8
    execute_batch_9
    execute_batch_10
    execute_batch_11
    execute_batch_12
    execute_batch_13

    execute_batch_14
    execute_batch_15
    execute_batch_16
    execute_batch_17
    execute_batch_18

    execute_batch_19
    #batch_20 is called last due to the settings it modifies (permissions)

    #batch 21, 22, 23 - these 3 batches should not be called here,
    #since the settings they contain are called by file_attribute_CCEs and
    #extended_acls_CCEs

    execute_batch_24
    execute_batch_25

    #batch 26 functions are called by file_attribute_CCEs
    
    #can safely be called- a majority of functions are called by file_attribute_CCEs
    #and extended_acls_CCEs
    execute_batch_27

    execute_batch_28
    execute_batch_29
    execute_batch_30 
    execute_batch_31
        
    
    #Contains functions for setting permissions in home directories 
    #Call this last of all the batch functions
    execute_batch_20


    # allows all user settings to be run for the specified users
    apply_settings_for_selected_users

    # performs tasks such as process killing 
    final_tasks
}


# shorthands for long strings for the defaults command
def_r="defaults read /Library/Preferences/com.apple"
def_w="defaults write /Library/Preferences/com.apple"
def_d="defaults delete /Library/Preferences/com.apple"

def_gr="defaults read /Library/Preferences/.GlobalPreferences"
def_gw="defaults write /Library/Preferences/.GlobalPreferences"
def_gd="defaults delete /Library/Preferences/.GlobalPreferences"

def_sr="defaults read /System/Library/LaunchDaemons"
def_sw="defaults write /System/Library/LaunchDaemons"

def_sd="defaults delete /System/Library/LaunchDaemons"



######################################################################
execute_batch_1 () {
    # settings in /Library/Preferences/com.apple.screensaver.plist
    CCE_79669_8_login_window_idle_time_for_screen_saver
    
    # settings in /Library/Preferences/com.apple.loginwindow.plist
    CCE_79670_6_sleep_restart_shutdown_buttons
    CCE_79671_4_restart_button
    CCE_79672_2_users_list_on_login
    CCE_79673_0_other_users_list_on_login
    CCE_79674_8_shutdown_button
    CCE_79675_5_sleep_button
    CCE_79676_3_retries_until_hint
    
    # settings in /Library/Preferences/.GlobalPreferences
    CCE_79677_1_inactivity_logout
    CCE_79678_9_fast_user_switching
}


######################################################################
execute_batch_2 () {
    # settings in /Library/Preferences/com.apple.loginwindow.plist
    CCE_79679_7_console_login
    CCE_79681_3_admin_accounts_visibility
    CCE_79682_1_local_user_accounts_visibility
    CCE_79684_7_network_users_visibility
    
    # values changed, but effectiveness not confirmed
    CCE_79680_5_external_accounts
    CCE_79683_9_mobile_accounts_visibility
    
    # these are modified in the file_attribute_CCEs function, and should 
    # not be called here
:<<'COMMENT_BLOCK'
    CCE_79685_4_bash_init_files_owner
    CCE_79686_2_bash_init_files_group
    CCE_79687_0_bash_init_files_permissions
    CCE_79688_8_csh_init_files_owner
    CCE_79689_6_csh_init_files_group
    CCE_79690_4_csh_init_files_permissions
COMMENT_BLOCK
}


######################################################################
#This function should not be called; it is here to document the batch in which the CCEs
#are a part of. These CCEs are instead called by the function file_attribute_CCEs.
execute_batch_4 () {
    CCE_79698_7_ipcs_owner
    CCE_79699_5_ipcs_group
    CCE_79700_1_ipcs_permissions
    CCE_79701_9_rcp_owner
    CCE_79702_7_rcp_group
    CCE_79703_5_rcp_permissions
    CCE_79704_3_rlogin_owner
    CCE_79705_0_rlogin_group
    CCE_79706_8_rlogin_permissions
    CCE_79707_6_rsh_owner
    CCE_79708_4_rsh_group
    CCE_79709_2_rsh_permissions
}


######################################################################
#This function should not be called; it is here to document the batch in which the CCEs
#are a part of. These CCEs are instead called by the function extended_acls_CCEs.
execute_batch_5 () {
    CCE_79710_0_aliases_acl
    CCE_79711_8_group_acl
    CCE_79712_6_hosts_acl
    CCE_79713_4_ldap_conf_acl
    CCE_79714_2_passwd_acl
    CCE_79715_9_services_acl
    CCE_79716_7_syslog_conf_acl
    CCE_79717_5_cron_allow_acl
    CCE_79718_3_cron_deny_acl
    CCE_79719_1_traceroute_acl
    CCE_79720_9_resolve_conf_acl
}


######################################################################
#This function should not be called; it is here to document the batch in which the CCEs
#are a part of. These CCEs are instead called by the function file_attribute_CCEs.
execute_batch_6 () {
    CCE_79721_7_services_owner
    CCE_79722_5_services_group
    CCE_79723_3_services_permissions
    CCE_79724_1_syslog_conf_owner
    CCE_79725_8_syslog_conf_group
}


######################################################################
#This function should not be called; it is here to document the batch in which the CCEs
#are a part of. These CCEs are instead called by the functions file_attribute_CCEs and
#extended_acls_CCEs.
execute_batch_7 () {
    # These CCEs are called by the function file_attribute_CCEs.
    CCE_79726_6_audit_logs_owner
    CCE_79727_4_audit_logs_group
    CCE_79728_2_audit_logs_permissions
    CCE_79730_8_audit_config_permissions

    # These CCEs are called by the function extended_acls_CCEs.
    CCE_79729_0_audit_logs_acl
    CCE_79731_6_audit_tool_executables_acl
}


######################################################################
execute_batch_8 () {
    # these functions will be run for the users specified in the script arguments
    user_settings_list="$user_settings_list
CCE_79736_5_screensaver_grace_period
CCE_79737_3_require_password_after_screensaver
CCE_79738_1_start_screen_saver_hot_corner
CCE_79739_9_no_put_to_sleep_corner
CCE_79740_7_no_modifier_keys_for_screen_saver_start
CCE_79743_1_no_prevent_screensaver_corner
CCE_79754_8_desktop_idle_time"
}

######################################################################
execute_batch_9 () {
    user_settings_list="$user_settings_list
CCE_79746_4_show_bluetooth_status_in_menu_bar
CCE_79748_0_bluetooth_disable_wake_computer
CCE_79753_0_bluetooth_disable_file_sharing"

    CCE_79741_5_bluetooth_open_setup_if_no_keyboard
    CCE_79742_3_bluetooth_open_setup_if_no_mouse_trackpad

    CCE_79745_6_bluetooth_turn_off_bluetooth
    CCE_79756_3_bluetooth_unload_uninstall_kext
}


######################################################################
execute_batch_10 () {
    CCE_79767_0_disable_guest_user
    CCE_79770_4_require_admin_password_for_system_prefs
    CCE_79771_2_no_guest_access_to_shared_folders
    CCE_79773_8_login_window_disable_input_menu
    CCE_79774_6_login_window_disable_voiceover
    CCE_79776_1_updates_download_in_background 
    CCE_79777_9_install_system_data_updates
    CCE_79778_7_install_security_updates
}


######################################################################
execute_batch_11() {
    CCE_79785_2_dim_display_on_battery
    CCE_79786_0_wake_when_power_source_changes
    
    CCE_79787_8_no_auto_restart_after_power_fail
    CCE_79789_4_enable_hard_disk_sleep
    CCE_79790_2_enable_display_sleep
    CCE_79791_0_dim_display_before_sleep
    CCE_79792_8_wake_when_lid_opened
}


######################################################################
execute_batch_12 () {
    user_settings_list="$user_settings_list
CCE_79768_8_show_wifi_status_in_menu_bar
CCE_79800_9_disable_airdrop"

    CCE_79763_9_remove_all_preferred_wireless_networks
    CCE_79799_3_disable_bonjour_advertising
    CCE_79801_7_wifi_unload_uninstall_kext

    # the first function run will influence the name for all 4 functions
    CCE_79806_6_change_computer_name
    CCE_79807_4_change_net_bios_name
    CCE_79805_8_change_host_name
    CCE_79772_0_change_local_host_name
}


######################################################################
execute_batch_13() {
    user_settings_list="$user_settings_list
CCE_79783_7_display_file_extensions
CCE_79784_5_show_hidden_files
CCE_79802_5_secure_erase_trash
CCE_79803_3_search_scope_search_this_mac
CCE_79804_1_warn_before_changing_extension
CCE_79809_0_warn_before_emptying_trash"
}


######################################################################
execute_batch_14() {
    CCE_79793_6_sleep_on_power_button
    CCE_79795_1_disable_computer_sleep
    CCE_79796_9_prevent_idle_sleep_if_tty_active
    CCE_79797_7_disable_wake_for_network_access
    CCE_79798_5_turn_hibernate_off
}


######################################################################
execute_batch_15() {
    user_settings_list="$user_settings_list
CCE_79813_2_disable_dictation
CCE_79814_0_disable_voiceover
CCE_79815_7_no_announce_when_alerts_displayed
CCE_79816_5_do_not_speak_selected_text"
}


######################################################################
execute_batch_16 () {
    CCE_79817_3_ssh_login_grace_period
    CCE_79818_1_ssh_remove_non_fips_140_2_ciphers
    CCE_79819_9_ssh_remove_cbc_ciphers
    CCE_79820_7_ssh_remove_non_fips_140_2_macs
    CCE_79821_5_ssh_challenge_response_authentication_disallowed
    CCE_79826_4_ssh_enable_password_authentication
    CCE_79827_2_ssh_disable_pub_key_authentication
    CCE_79828_0_ssh_restrict_users
}


######################################################################
execute_batch_17() {
    CCE_79830_6_ssh_set_client_alive_300_seconds
    CCE_79831_4_ssh_max_auth_tries_4_or_less

    CCE_79844_7_ssh_disable_root_login
    CCE_79862_9_ssh_set_log_level_verbose
    CCE_79863_7_ssh_disallow_empty_passwords
    CCE_79864_5_ssh_turn_off_user_environment
    CCE_79865_2_ssh_use_protocol_version_2
    CCE_79866_0_ssh_disable_x11_forwarding
    CCE_79893_4_ssh_keep_alive_messages
}


######################################################################
execute_batch_18() {
    CCE_79848_8_no_netrc_files_on_system
    CCE_79849_6_at_least_2_DNS_servers
    CCE_79852_0_disable_remote_apple_events
    CCE_79868_6_disable_printer_sharing
    CCE_79889_2_disable_remote_login
}


######################################################################
execute_batch_19() {
    CCE_79834_8_disable_location_services

    user_settings_list="$user_settings_list
CCE_79835_5_disable_auto_actions_on_blank_CD_insertion
CCE_79836_3_disable_auto_actions_on_blank_DVD_insertion
CCE_79837_1_disable_auto_music_CD_play
CCE_79838_9_disable_auto_picture_CD_display
CCE_79839_7_disable_auto_video_DVD_play"
}


######################################################################
execute_batch_20() {
    CCE_79781_1_use_network_time_protocol
    CCE_79782_9_park_disk_heads_on_sudden_motion
    CCE_79833_0_encrypt_system_swap_file
    CCE_79843_9_enable_firewall_logging
    CCE_79845_4_allow_signed_sw_receive_connections
    CCE_79846_2_turn_on_firewall
    CCE_79870_2_do_not_send_diagnostic_info_to_apple

    user_settings_list="$user_settings_list
CCE_79779_5_all_files_in_a_users_home_dir_are_owned_by_that_user
CCE_79780_3_files_in_home_dir_group_owned_by_owners_group"
}


######################################################################
#This function should not be called; it is here to document the batch in which the CCEs
#are a part of. These CCEs are instead called by the functions file_attribute_CCEs and
#extended_acls_CCEs.
execute_batch_21() {
    CCE_79861_1_no_acls_system_command_executables
    CCE_79867_8_crontab_files_no_acls
    CCE_79869_4_etc_shells_no_acls
    CCE_79877_7_library_files_permissions
    CCE_79878_5_system_log_files_permissions
    CCE_79879_3_files_in_user_home_directories_no_ACLs
    CCE_79880_1_user_home_directories_no_ACLs
    CCE_79881_9_etc_shells_permissions
    CCE_79882_7_etc_shells_owner
    CCE_79883_5_etc_group_file_permissions
    CCE_79884_3_etc_group_file_owner
    CCE_79885_0_etc_group_file_group
}


######################################################################
#This function should not be called; it is here to document the batch in which the CCEs
#are a part of. These CCEs are instead called by the function file_attribute_CCEs.
execute_batch_22() {
    CCE_79886_8_etc_hosts_permissions
    CCE_79887_6_etc_hosts_owner
    CCE_79888_4_etc_hosts_group
    CCE_79890_0_var_run_resolv_conf_permissions
    CCE_79891_8_var_run_resolv_conf_owner
    CCE_79892_6_var_run_resolv_conf_group
    CCE_79894_2_etc_openldap_ldap_conf_permissions
    CCE_79895_9_etc_openldap_ldap_conf_owner
    CCE_79896_7_etc_openldap_ldap_conf_group
    CCE_79897_5_etc_passwd_permissions
    CCE_79898_3_etc_passwd_owner
    CCE_79899_1_etc_passwd_group

}


######################################################################
#This function should not be called; it is here to document the batch in which the CCEs
#are a part of. These CCEs are instead called by the function file_attribute_CCEs.
execute_batch_23() {
    CCE_79900_7_usr_sbin_traceroute_permissions
    CCE_79901_5_usr_sbin_traceroute_owner
    CCE_79902_3_usr_sbin_traceroute_group
    CCE_79903_1_etc_motd_permissions
    CCE_79904_9_etc_motd_owner
    CCE_79905_6_etc_motd_group
    CCE_79907_2_var_at_at_deny_owner
    CCE_79909_8_var_at_permissions
    CCE_79913_0_private_var_at_cron_allow_group
    CCE_79916_3_private_var_at_cron_deny_group
    CCE_79917_1_global_preferences_plist_permissions
    CCE_79919_7_etc_aliases_group
}


######################################################################
execute_batch_24() {
    CCE_79857_9_unload_uninstall_isight_camera
    CCE_79858_7_unload_uninstall_infrared_receiver
    CCE_79859_5_disable_infrared_receiver
}


######################################################################
execute_batch_25() {
    CCE_79875_1_restrict_screen_sharing_to_specified_users
    CCE_79876_9_update_apple_software
    
    user_settings_list="$user_settings_list
CCE_79810_8_windows_not_saved_when_quitting_app
CCE_79811_6_dock_enable_autohide
CCE_79829_8_disable_mission_control_dashboard
CCE_79847_0_enable_safari_status_bar"
}


######################################################################
#This function should not be called; it is here to document the batch in which the CCEs
#are a part of. These CCEs are instead called by the function file_attribute_CCEs.
execute_batch_26() {
    CCE_79918_9_system_command_files_permissions
    CCE_79920_5_usr_lib_sa_sadc_permissions
    CCE_79921_3_sbin_route_no_setid_bits
    CCE_79923_9_usr_libexec_dumpemacs_no_setid_bits
    CCE_79924_7_usr_libexec_rexecd_no_setid_bits
    CCE_79925_4_usr_sbin_vpnd_no_setid_bits
    CCE_79926_2_preferences_install_assistant_no_setid_bits
    CCE_79927_0_iodbcadmintool_no_setid_bits
}


######################################################################
#This batch contains many access control functions already called by file_attribute_CCEs
#and extended_acls_CCEs.
#These are commented out so that the other functions in the batch can be called.
execute_batch_27() {
    #This is an actual function
    CCE_79932_0_system_files_and_directories_no_uneven_permissions

    #These are just labels for the ACL/permissions functions called in file_attribute_CCEs
    #and extended_acls_CCEs.
    #CCE_79911_4_library_files_no_acls

    #CCE_79928_8_extensions_webdav_fs_no_setid_bits
    #CCE_79929_6_appleshare_afpLoad_no_setid_bits
    #CCE_79930_4_appleshare_check_afp_no_setid_bits
    #CCE_79931_2_user_home_directories_permissions
    #CCE_79933_8_remote_management_ARD_agent_permissions
}


######################################################################
execute_batch_28() {
    CCE_79908_0_sudo_restrict_to_single_terminal
    CCE_79910_6_sudo_timeout_period_set_to_0
    CCE_79912_2_set_audit_control_flags
    CCE_79934_6_only_root_has_uid_zero
    CCE_79922_1_disable_remote_management
    CCE_79938_7_disable_automatic_system_login
}


######################################################################
execute_batch_29() {
    #clears the current global policy to ensure it is set properly with this script
    if [ "$set_flag" != "" ]; then
        pwpolicy -clearaccountpolicies
        
        while IFS= read -r user_name; do
            if [ "$user_name" != "" ]; then
                pwpolicy -u "$user_name" -clearaccountpolicies
            fi
        
        done <<< "$user_list"
    fi

    #Tested on 10.10
    CCE_79747_2_password_enforce_password_history_restriction
    CCE_79749_8_password_complex_passwords_alphabetic_char
    CCE_79750_6_password_complex_passwords_numeric_char
    CCE_79751_4_password_complex_passwords_symbolic_char
    CCE_79759_7_password_uppercase_and_lowercase
    CCE_79761_3_password_minimum_length
    CCE_79762_1_password_maximum_age
}


######################################################################
execute_batch_30() {
    CCE_79942_9_pf_enable_firewall
    CCE_79943_7_pf_rule_ftp
    CCE_79944_5_pf_rule_ssh
    CCE_79945_2_pf_rule_telnet
    CCE_79946_0_pf_rule_rexec
    CCE_79947_8_pf_rule_rsh
    CCE_79948_6_pf_rule_tftp
    CCE_79949_4_pf_rule_finger
    CCE_79950_2_pf_rule_http
    CCE_79951_0_pf_rule_nfs
    CCE_79952_8_pf_rule_remote_apple_events
    CCE_79953_6_pf_rule_smb
    CCE_79954_4_pf_rule_apple_file_service
    CCE_79955_1_pf_rule_uucp
    CCE_79956_9_pf_rule_screen_sharing
    CCE_79957_7_pf_rule_icmp
    CCE_79958_5_pf_rule_smtp
    CCE_79959_3_pf_rule_pop3
    CCE_79960_1_pf_rule_pop3s
    CCE_79961_9_pf_rule_sftp
    CCE_79962_7_pf_rule_imap
    CCE_79963_5_pf_rule_imaps
    CCE_79964_3_pf_rule_printer_sharing
    CCE_79965_0_pf_rule_bonjour
    CCE_79966_8_pf_rule_mDNSResponder
    CCE_79967_6_pf_rule_itunes_sharing
    CCE_79968_4_pf_rule_optical_drive_sharing
}


######################################################################
execute_batch_31() {
    CCE_79939_5_add_login_banner
    CCE_79940_3_audit_log_max_file_size
    CCE_79941_1_audit_log_retention
    CCE_79915_5_restrict_remote_management_to_specific_users
    CCE_79936_1_restrict_remote_apple_events_to_specific_users
}


######################################################################
CCE_79939_5_add_login_banner () {
    local doc="CCE_79939_5_add_login_banner                   (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local friendly_name="login banner"
    local banner_file="/Library/Security/PolicyBanner.txt"
    local policy_text="You are accessing a U.S. Government information system, which includes: 1) this computer, 2) this computer network, 3) all computers connected to this network, and 4) all devices and storage media attached to this network or to a computer on this network. You understand and consent to the following: you may access this information system for authorized use only; you have no reasonable expectation of privacy regarding any communication of data transiting or stored on this information system; at any time and for any lawful Government purpose, the Government may monitor, intercept, and search and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Government purpose."
    local banner_exists=0;

    if [ -e "$banner_file" ]; then
        banner_exists=`grep -c "$policy_text" "$banner_file"`;
    fi

    
    if [ "$print_flag" != "" ]; then
        if [ "$banner_exists" -gt 0 ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled"
        fi
    
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
        "ent")
            if [ "$banner_exists" -gt 0 ]; then
                echo "$friendly_name already enabled"
            else
                echo "enabling $friendly_name";
                echo "$policy_text" > "$banner_file"
            fi
        ;;
        "soho")
            if [ "$banner_exists" -gt 0 ]; then
                echo "$friendly_name already enabled"
            else
                echo "enabling $friendly_name";
                echo "$policy_text" > "$banner_file"
            fi
        ;;
        "sslf")
            if [ "$banner_exists" -gt 0 ]; then
                echo "$friendly_name already enabled"
            else
                echo "enabling $friendly_name";
                echo "$policy_text" > "$banner_file"
            fi
        ;;
        "oem")
            if [ -e "$banner_file" ]; then
                echo "disabling $friendly_name"
                rm "$policy_file"
            else
                echo "$friendly_name already disabled";
            fi
        ;;
    esac
    fi

#OS X 10.10
#Works on next system start.
}

######################################################################
CCE_79679_7_console_login () {
    local doc="CCE_79679_7_console_login                   (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep DisableConsoleAccess | wc -l`
    if [ $exists == "0" ]; then echo "Console login allowed"; else
        status=`$def_r.loginwindow.plist DisableConsoleAccess`
        if [ "$status" == "false" -o "$status" == "0" ]; then echo "Console login allowed"; fi
        if [ "$status" == "true" ]; then echo "Console login disallowed";fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "disallowing Console login";
        status=`$def_w.loginwindow.plist DisableConsoleAccess true`
        ;;
        "soho")
        echo "disallowing Console login";
        status=`$def_w.loginwindow.plist DisableConsoleAccess true`
        ;;
        "sslf")
        echo "disallowing Console login";
        status=`$def_w.loginwindow.plist DisableConsoleAccess true`
        ;;
        "oem")
        echo "enabling Console login";
        if [ `$def_r.loginwindow.plist |
              grep DisableConsoleAccess | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist DisableConsoleAccess`
        fi
        ;;
    esac
    fi

# If console login is enabled, typing the string ">console" for the user
# name gives a console login.
# Need to have a field for user.

# OS X 10.10
# Restart not required for setting to take effect. When testing on physical
# machine, it froze after attempting to use console login when enabled.
}

######################################################################
# on any external media (flash drive, externa media like hard disk partitions)
CCE_79680_5_external_accounts () {
    local doc="CCE_79680_5_external_accounts      (effects-test-indeterminate)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep EnableExternalAccounts | wc -l`
    if [ $exists == "0" ]; then echo "External accounts allowed"; else
        status=`$def_r.loginwindow.plist EnableExternalAccounts`
        if [ "$status" == "false" -o "$status" == "0" ]; then
        echo "External Accounts disallowed"; fi
        if [ "$status" == "true" ]; then
        echo "External Accounts allowed";fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "disallowing External Accounts";
        status=`$def_w.loginwindow.plist EnableExternalAccounts false`
        ;;
        "soho")
        echo "disallowing External Accounts";
        status=`$def_w.loginwindow.plist EnableExternalAccounts false`
        ;;
        "sslf")
        echo "disallowing External Accounts";
        status=`$def_w.loginwindow.plist EnableExternalAccounts false`
        ;;
        "oem")
        echo "enabling External Accounts";
        if [ `$def_r.loginwindow.plist |
              grep EnableExternalAccounts | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist EnableExternalAccounts`
        fi
        ;;
    esac
    fi

#Effectiveness not confirmed.
}

######################################################################
CCE_79681_3_admin_accounts_visibility () {
    local doc="CCE_79681_3_admin_accounts                  (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep HideAdminUsers | wc -l`
    if [ $exists == "0" ]; then echo "Admin Accounts visible"; else
        status=`$def_r.loginwindow.plist HideAdminUsers`
        if [ "$status" == "false" -o "$status" == "0" ]; then
        echo "Administrator Accounts visible"; fi
        if [ "$status" == "true" ]; then
        echo "Administrator Accounts hidden";fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "hiding Administrator Accounts";
        status=`$def_w.loginwindow.plist HideAdminUsers true`
        ;;
        "soho")
        echo "hiding Administrator Accounts";
        status=`$def_w.loginwindow.plist HideAdminUsers true`
        ;;
        "sslf")
        echo "hiding Administrator Accounts";
        status=`$def_w.loginwindow.plist HideAdminUsers true`
        ;;
        "oem")
        echo "showing Administrator Accounts";
        if [ `$def_r.loginwindow.plist |
              grep HideAdminUsers | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist HideAdminUsers`
        fi
        ;;
    esac
    fi

#With the user list shown on the login window, the admin account was missing from
#the choices when this setting was enabled. In order to login with an admin account,
#the "other..." user option must be chosen, and then a name and password has to be
#entered.

# OS X 10.10 testing
# Works without restart, but user is displayed if still logged in.
}

######################################################################
CCE_79682_1_local_user_accounts_visibility () {
    local doc="CCE_79682_1_local_user_accounts_visibility  (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep HideLocalUsers | wc -l`
    if [ $exists == "0" ]; then echo "Local User Accounts visible"; else
        status=`$def_r.loginwindow.plist HideLocalUsers`
        if [ "$status" == "false" ]; then
        echo "Local User Accounts visible"; fi
        if [ "$status" == "true" ]; then
        echo "Local User Accounts hidden";fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "hiding Local User Accounts";
        status=`$def_w.loginwindow.plist HideLocalUsers true`
        ;;
        "soho")
        echo "hiding Local User Accounts";
        status=`$def_w.loginwindow.plist HideLocalUsers true`
        ;;
        "sslf")
        echo "hiding Local User Accounts";
        status=`$def_w.loginwindow.plist HideLocalUsers true`
        ;;
        "oem")
        echo "showing Local User Accounts";
        if [ `$def_r.loginwindow.plist |
              grep HideLocalUsers | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist HideLocalUsers`
        fi
        ;;
    esac
    fi

#After hiding local user accounts, the login window did not display any user names.
#Instead, the user is prompted for a name and password. This is despite the login window
#being set to display a list of users in the "Login Options" in the system settings.
#All the users on the test system were local users.

# OS X 10.10 testing
# Works without restart, but user is displayed if still logged in.
}

######################################################################
CCE_79683_9_mobile_accounts_visibility () {
    local doc="CCE_79683_9_mobile_accounts_visibility      (effects-test-indeterminate)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep HideMobileAccounts | wc -l`
    if [ $exists == "0" ]; then echo "Mobile Accounts visible"; else
        status=`$def_r.loginwindow.plist HideMobileAccounts`
        if [ "$status" == "false" ]; then
        echo "Mobile Accounts visible"; fi
        if [ "$status" == "true" ]; then
        echo "Mobile Accounts hidden";fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "hiding Mobile Accounts";
        status=`$def_w.loginwindow.plist HideMobileAccounts true`
        ;;
        "soho")
        echo "hiding Mobile Accounts";
        status=`$def_w.loginwindow.plist HideMobileAccounts true`
        ;;
        "sslf")
        echo "hiding Mobile Accounts";
        status=`$def_w.loginwindow.plist HideMobileAccounts true`
        ;;
        "oem")
        echo "showing Mobile Accounts";
        if [ `$def_r.loginwindow.plist |
              grep HideMobileAccounts | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist HideMobileAccounts`
        fi
        ;;
    esac
    fi

#Effectiveness not confirmed.
}

######################################################################
CCE_79684_7_network_users_visibility () {
    local doc="CCE_79684_7_network_users_visibility      (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
        exists=`$def_r.loginwindow.plist | grep -c IncludeNetworkUser`
        if [ "$exists" == "0" ]; then
                echo "Network Users hidden"; 
        else
            status=`$def_r.loginwindow.plist IncludeNetworkUser`
            if [ "$status" == "false" ]; then
                echo "Network Users hidden";
            fi
            if [ "$status" == "true" -o "$status" == "1" ]; then
                echo "Network Users visible";fi
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "hiding Network Users";
        status=`$def_w.loginwindow.plist IncludeNetworkUser false`
        ;;
        "soho")
        echo "hiding Network Users";
        status=`$def_w.loginwindow.plist IncludeNetworkUser false`
        ;;
        "sslf")
        echo "hiding Network Users";
        status=`$def_w.loginwindow.plist IncludeNetworkUser false`
        ;;
        "oem")
        echo "hiding Network Users";
        if [ `$def_r.loginwindow.plist |
              grep IncludeNetworkUser | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist IncludeNetworkUser`
        fi
        ;;
    esac
    fi
    
# Used the server app to create a network user. Had to create an
# Open Directory server first.

# OS X 10.10
# Setting took effect immediately.
}


######################################################################
CCE_79669_8_login_window_idle_time_for_screen_saver () {
    local doc="CCE_79669_8_login_window_idle_time_for_screen_saver  (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local file=$home_path/Library/Preferences/ByHost/com.apple.screensaver.$hw_uuid.plist
    local file2=$home_path/Library/Preferences/com.apple.screensaver.plist

    local friendly_name="Login window idle time"
    local status="1200" # default value is confirmed
    local setting_name=loginWindowIdleTime

    # if the ByHost file exists, then first try to access it
    if [ -e $file ]; then

        local key_exists=`defaults read $file | grep -w "$setting_name" | wc -l`
        if [ $key_exists == 1 ]; then
            status=`defaults read $file $setting_name`
        # if the key is not present, then try to read file2
        else
            if [ -e $file2 ]; then
                key_exists=`defaults read $file2 | grep -w "$setting_name" | wc -l`
                if [ $key_exists == 1 ]; then
                    status=`defaults read $file2 $setting_name`
                    file=$file2  # since $file2 has the key, change that one
                fi
            fi
        fi
    #if ByHost file doesn't exist, try to access file2
    elif [ -e $file2 ]; then
        key_exists=`defaults read $file2 | grep -w "$setting_name" | wc -l`
        if [ $key_exists == 1 ]; then
            status=`defaults read $file2 $setting_name`
            file=$file2  # since $file2 has the key, change that one
        fi
    # else do nothing, since neither file exists, and the default value will be used
    fi
    
    if [ "$print_flag" != "" ]; then
        exists=`$def_r.screensaver.plist 2> /dev/null | grep loginWindowIdleTime | wc -l`
        if [ $exists == "0" ];then 
            echo "Login window idle time is 1200 seconds (20 minutes)"
        else
            status=`$def_r.screensaver.plist loginWindowIdleTime`
            echo "Login Window Idle Time: $status"
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent") 
        echo "setting login window idle time to 900 seconds (15 minutes)";
        #status=`$def_w.loginwindow.plist loginWindowIdleTime -int 900`
        status=`defaults write $file $setting_name -int 900`
        ;;
        "soho")
        echo "setting login window idle time to 900 seconds (15 minutes)";
        status=`defaults write $file $setting_name -int 900`
        ;;
        "sslf")
        echo "setting login window idle time to 900 seconds (15 minutes)";
        status=`defaults write $file $setting_name -int 900`
        ;;
        "oem")
        echo "setting login window idle time to 1200 seconds (20 minutes)";
        if [ `$def_r.screensaver.plist |
              grep loginWindowIdleTime | wc -l` != "0" ]; then
            status=`defaults write $file $setting_name -int 1200`
        fi
        ;;
    esac
    fi

#Note:
#Modifying the suggested file "/Library/Preferences/com.apple.loginWindow.plist" did
#not affect the screensaver on the login window. Using the source
#http://support.apple.com/kb/HT4625, it was determined that
#"/Library/Preferences/com.apple.screensaver.plist" needed to be modified instead.

#OS X 10.10 testing
#Worked immediately upon logging out.
}

######################################################################
CCE_79670_6_sleep_restart_shutdown_buttons () {
    local doc="CCE_79670_6_sleep_restart_shutdown_buttons  (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep PowerOffDisabled | wc -l`
    if [ $exists == "0" ];then
        echo "Login Window Sleep-Restart-Shutdown buttons not hidden";
    else
        status=`$def_r.loginwindow.plist PowerOffDisabled`
        if [ $status == 1 ]; then echo "Login Window Sleep-Restart-Shutdown buttons hidden"
        else
        echo "Login Window Sleep-Restart-Shutdown buttons not hidden"
        fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "hiding login window sleep-restart-shutdown buttons";
        status=`$def_w.loginwindow.plist PowerOffDisabled -bool true`
        ;;
        "soho")
        echo "showing login window sleep-restart-shutdown buttons";
        if [ `$def_r.loginwindow.plist |
              grep PowerOffDisabled | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist PowerOffDisabled`
        fi
        ;;
        "sslf")
        echo "hiding login window sleep-restart-shutdown buttons";
        status=`$def_w.loginwindow.plist PowerOffDisabled -bool true`
        ;;
        "oem")
        echo "showing login window sleep-restart-shutdown buttons";
        if [ `$def_r.loginwindow.plist |
              grep PowerOffDisabled | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist PowerOffDisabled`
        fi
        ;;
    esac
    fi

# OS X 10.10 testing
# Worked immediately upon logging out.
}

######################################################################
CCE_79671_4_restart_button () {
    local doc="CCE_79671_4_restart_button                  (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep RestartDisabled | wc -l`
    if [ $exists == "0" ];then
        echo "Login Window Restart button not hidden";
    else
        status=`$def_r.loginwindow.plist RestartDisabled`
        if [ $status == 1 ]; then echo "Login Window Restart button hidden"
        else
        echo "Login Window Restart button not hidden"
        fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "disabling login window restart button";
        status=`$def_w.loginwindow.plist RestartDisabled -bool true`
        ;;
        "soho")
        echo "enabling login window restart button";
        if [ `$def_r.loginwindow.plist |
              grep RestartDisabled | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist RestartDisabled`
        fi
        ;;
        "sslf")
        echo "disabling login window restart button";
        status=`$def_w.loginwindow.plist RestartDisabled -bool true`
        ;;
        "oem")
        echo "enabling login window restart button";
        if [ `$def_r.loginwindow.plist |
              grep RestartDisabled | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist RestartDisabled`
        fi
        ;;
    esac
    fi

# Note: If the PowerOffDisabled key-which controls all 3 login window power options-is
# enabled and this key is set to disabled, this button will still appear. If this key is
# not present, then the PowerOffDisabled key's value is used. 

# OS X 10.10 testing
# Worked immediately upon logging out.
}

######################################################################
CCE_79672_2_users_list_on_login () {
    local doc="CCE_79672_2_users_list_on_login             (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep SHOWFULLNAME | wc -l`
    if [ $exists == "0" ];then
        echo "All Users Listed";
    else
        #status=`$def_r.loginwindow.plist RestartDisabled`
        status=`$def_r.loginwindow.plist SHOWFULLNAME`
        if [ $status == 1 ]; then echo "Users Not Listed"
        else
        echo "All Users Listed"
        fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "displaying login as name-and-password";
        status=`$def_w.loginwindow.plist SHOWFULLNAME -bool true`
        ;;
        "soho")
        echo "displaying login as name-and-password";
        status=`$def_w.loginwindow.plist SHOWFULLNAME -bool true`
        ;;
        "sslf")
        echo "displaying login as name-and-password";
        status=`$def_w.loginwindow.plist SHOWFULLNAME -bool true`
        ;;
        "oem")
        echo "displaying login as list of users";
        if [ `$def_r.loginwindow.plist |
              grep SHOWFULLNAME | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist SHOWFULLNAME`
        fi
        ;;
    esac
    fi
    
# 10.10 testing
# Works immediately after logging out.
}

######################################################################
CCE_79673_0_other_users_list_on_login () {
    local doc="CCE_79673_0_other_users_list_on_login     (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep SHOWOTHERUSERS_MANAGED | wc -l`
    if [ $exists == "0" ];then
        echo "Other Users Listed";
    else
        #status=`$def_r.loginwindow.plist RestartDisabled`
        status=`$def_r.loginwindow.plist SHOWOTHERUSERS_MANAGED`
        if [ $status == 1 ]; then echo "Other users Not Listed"
        else
        echo "Other Users Listed"
        fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "disabling listing of other users";
        status=`$def_w.loginwindow.plist SHOWOTHERUSERS_MANAGED \
            -bool false`
        ;;
        "soho")
        echo "disabling listing of other users";
        status=`$def_w.loginwindow.plist SHOWOTHERUSERS_MANAGED \
            -bool false`
        ;;
        "sslf")
        echo "disabling listing of other users";
        status=`$def_w.loginwindow.plist SHOWOTHERUSERS_MANAGED \
            -bool false`
        ;;
        "oem")
        echo "enabling listing of other users";
        if [ `$def_r.loginwindow.plist |
              grep SHOWOTHERUSERS_MANAGED | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist SHOWOTHERUSERS_MANAGED`
        fi
        ;;
    esac
    fi
    
# 10.10 testing
# Created hidden users, which caused the "Other..." option to appear on the 
# login menu. Works immediately after logging out.
}

######################################################################
CCE_79674_8_shutdown_button () {
    local doc="CCE_79674_8_shutdown_button                 (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep ShutDownDisabled | wc -l`
    if [ $exists == "0" ];then
        echo "Login Window Shutdown Button not hidden"
    else
        status=`$def_r.loginwindow.plist ShutDownDisabled`
        if [ $status == 1 ]; then echo "Login Window Shutdown Button hidden"
        else
            echo "Login Window Shutdown Button not hidden"
        fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "disabling login window shutdown button"
        status=`$def_w.loginwindow.plist ShutDownDisabled -bool true`
        ;;
        "soho")
        echo "enabling login window shutdown button"
        if [ `$def_r.loginwindow.plist |
              grep ShutDownDisabled | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist ShutDownDisabled`
        fi
        ;;
        "sslf")
        echo "disabling login window shutdown button"
        status=`$def_w.loginwindow.plist ShutDownDisabled -bool true`
        ;;
        "oem")
        echo "enabling login window shutdown button"
        if [ `$def_r.loginwindow.plist |
              grep ShutDownDisabled | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist ShutDownDisabled`
        fi
        ;;
    esac
    fi

# Note: If the PowerOffDisabled key-which controls all 3 login window power options-is
# enabled and this key is set to disabled, this button will still appear. If this key is
# not present, then the PowerOffDisabled key's value is used. 

# OS X 10.10 testing
# Worked immediately upon logging out.
}

######################################################################
CCE_79675_5_sleep_button () {
    local doc="CCE_79675_5_sleep_button                    (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep SleepDisabled | wc -l`
    if [ $exists == "0" ];then
        echo "Login Window Sleep Button not hidden";
    else
        status=`$def_r.loginwindow.plist SleepDisabled`
        if [ $status == 1 ]; then echo "Login Window Sleep Button hidden"
        else
        echo "Login Window Sleep Button not hidden"
        fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "disabling login window sleep button";
        status=`$def_w.loginwindow.plist SleepDisabled -bool true`
        ;;
        "soho")
        echo "enabling login window sleep button";
        if [ `$def_r.loginwindow.plist |
              grep SleepDisabled | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist SleepDisabled`
        fi
        ;;
        "sslf")
        echo "disabling login window sleep button";
        status=`$def_w.loginwindow.plist SleepDisabled -bool true`
        ;;
        "oem")
        echo "enabling login window sleep button";
        if [ `$def_r.loginwindow.plist |
              grep SleepDisabled | wc -l` != "0" ]; then
            status=`$def_d.loginwindow.plist SleepDisabled`
        fi
        ;;
    esac
    fi

# Note: If the PowerOffDisabled key-which controls all 3 login window power options-is
# enabled and this key is set to disabled, this button will still appear. If this key is
# not present, then the PowerOffDisabled key's value is used. 

# OS X 10.10 testing
# Worked immediately upon logging out.
}

######################################################################
CCE_79676_3_retries_until_hint () {
    local doc="CCE_79676_3_retries_until_hint              (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_r.loginwindow.plist | grep RetriesUntilHint | wc -l`
    if [ $exists == "0" ];then
        echo "Password Retries-until-hint disabled";
    else
        status=`$def_r.loginwindow.plist RetriesUntilHint`
        if [ "$status" == "0" ] ; then
        echo "Password Retries-until-hint disabled"
        else
        echo "Password Retries-until-hint: $status"
        fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "disabling password retries-until-hint";
        status=`$def_w.loginwindow.plist RetriesUntilHint -int 0`
        ;;
        "soho")
        echo "disabling password retries-until-hint";
        status=`$def_w.loginwindow.plist RetriesUntilHint -int 0`
        ;;
        "sslf")
        echo "disabling password retries-until-hint";
        status=`$def_w.loginwindow.plist RetriesUntilHint -int 0`
        ;;
        "oem")
        echo "setting password retries-until-hint to 3";
        status=`$def_w.loginwindow.plist RetriesUntilHint -int 3`
        ;;
    esac
    fi

# OS X 10.10 testing
# Tested manually; hints enabled or disabled both in preferences and
# on login.  Preferences subpane needs to be closed and reopened to
# refresh the setting state.
}

######################################################################
CCE_79677_1_inactivity_logout () {
    local doc="CCE_79677_1_inactivity_logout               (OEM=ENT=SOHO=SSLF)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_gr | grep AutoLogOutDelay | wc -l`
    if [ $exists == "0" ];then
        echo "Inactivity-logout Disabled";
    else
        status=`$def_gr com.apple.autologout.AutoLogOutDelay`
        if [ "$status" == "0" ]; then 
            echo "Inactivity-logout Disabled";
        else
            echo "Inactivity-logout: $status (seconds)"
        fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "disabling inactivity logout";
        if [ `$def_gr | grep AutoLogOutDelay | wc -l` != "0" ]; then
            status=`$def_gw com.apple.autologout.AutoLogOutDelay -int 0`
        fi
        ;;
        "soho")
        echo "disabling inactivity logout";
        if [ `$def_gr | grep AutoLogOutDelay | wc -l` != "0" ]; then
            status=`$def_gd com.apple.autologout.AutoLogOutDelay`
        fi
        ;;
        "sslf")
        echo "disabling inactivity logout";
        if [ `$def_gr | grep AutoLogOutDelay | wc -l` != "0" ]; then
            status=`$def_gd com.apple.autologout.AutoLogOutDelay`
        fi
        ;;
        "oem")
        echo "disabling inactivity logout";
        if [ `$def_gr | grep AutoLogOutDelay | wc -l` != "0" ]; then
            status=`$def_gd com.apple.autologout.AutoLogOutDelay`
        fi
        ;;
    esac
    fi
}

######################################################################
CCE_79678_9_fast_user_switching () {
    local doc="CCE_79678_9_fast_user_switching             (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
    exists=`$def_gr MultipleSessionEnabled | wc -l 2> /dev/null`
    if [ $exists == "0" ];then
        echo "Fast User Switching Disabled";
    else
        status=`$def_gr MultipleSessionEnabled`
        if [ $status == 1 ]; then echo "Fast User Switching Enabled"
        else
        echo "Fast User Switching Disabled"
        fi
    fi
    fi
    if [ "$set_flag" != "" ]; then
    local status
    case $profile_flag in
        "ent")
        echo "disabling fast user switching";
        status=`$def_gw MultipleSessionEnabled -bool false`
        ;;
        "soho")
        echo "disabling fast user switching";
        status=`$def_gw MultipleSessionEnabled -bool false`
        ;;
        "sslf")
        echo "disabling fast user switching";
        status=`$def_gw MultipleSessionEnabled -bool false`
        ;;
        "oem")
        echo "enabling fast user switching";
        status=`$def_gw MultipleSessionEnabled -bool true`
        ;;
    esac
    fi
# OS X 10.10    
# Tested manually.  Have to login again or switch users for the new
# setting to take effect.
}

######################################################################
#
# Displays file attributes (owner, group, permissions, setuid), and sets
# them for the four possible profiles (oem, sslf, soho, enterprise).
#
# A CCE will specify a single attribute but may be multiple file paths.
# Conversely, a simple operation on a file (e.g., chmod) may represent multiple
# CCEs.
#
# This function groups CCEs and paths together to concisely display and set
# multiple paths + attributes + profiles.
#
# In comments, function names, and output statements, we keep track of
# which CCEs are represented by the various printing and setting
# functions.  This is extremely verbose but seems needed for us to
# keep track of what the script is doing on a per-CCE basis.  I.e., we
# want to be able to search the script using a CCE id and find every
# action taken on behalf of that CCE.
#
# This function is designed to grow substantially as we add more file CCEs.
#
file_attribute_CCEs () {
    local doc="file_attribute_CCEs                    (manual-test-PASSED)"
    
    if [ "$v_flag" != "" -a "$list_flag" != "" ]; then
    echo "      CCE_79698_7_ipcs_owner
      CCE_79699_5_ipcs_group
      CCE_79700_1_ipcs_permissions
      CCE_79701_9_rcp_owner
      CCE_79702_7_rcp_group
      CCE_79703_5_rcp_permissions
      CCE_79704_3_rlogin_owner
      CCE_79705_0_rlogin_group
      CCE_79706_8_rlogin_permissions
      CCE_79707_6_rsh_owner
      CCE_79708_4_rsh_group
      CCE_79709_2_rsh_permissions
      CCE_79685_4_bash_init_files_owner
      CCE_79686_2_bash_init_files_group
      CCE_79687_0_bash_init_files_permissions
      CCE_79688_8_csh_init_files_owner
      CCE_79689_6_csh_init_files_group
      CCE_79690_4_csh_init_files_permissions
      CCE_79721_7_services_owner
      CCE_79722_5_services_group
      CCE_79723_3_services_permissions
      CCE_79724_1_syslog_conf_owner
      CCE_79725_8_syslog_conf_group
      CCE_79726_6_audit_logs_owner
      CCE_79727_4_audit_logs_group
      CCE_79728_2_audit_logs_permissions
      CCE_79730_8_audit_config_permissions
      CCE_79877_7_library_files_permissions
      CCE_79878_5_system_log_files_permissions
      CCE_79881_9_etc_shells_permissions
      CCE_79882_7_etc_shells_owner
      CCE_79883_5_etc_group_file_permissions
      CCE_79884_3_etc_group_file_owner
      CCE_79885_0_etc_group_file_group
      CCE_79886_8_etc_hosts_permissions
      CCE_79887_6_etc_hosts_owner
      CCE_79888_4_etc_hosts_group
      CCE_79890_0_var_run_resolv_conf_permissions
      CCE_79891_8_var_run_resolv_conf_owner
      CCE_79892_6_var_run_resolv_conf_group
      CCE_79894_2_etc_openldap_ldap_conf_permissions
      CCE_79895_9_etc_openldap_ldap_conf_owner
      CCE_79896_7_etc_openldap_ldap_conf_group
      CCE_79897_5_etc_passwd_permissions
      CCE_79898_3_etc_passwd_owner
      CCE_79899_1_etc_passwd_group
      CCE_79900_7_usr_sbin_traceroute_permissions
      CCE_79901_5_usr_sbin_traceroute_owner
      CCE_79902_3_usr_sbin_traceroute_group
      CCE_79903_1_etc_motd_permissions
      CCE_79904_9_etc_motd_owner
      CCE_79905_6_etc_motd_group
      CCE_79907_2_var_at_at_deny_owner
      CCE_79909_8_var_at_permissions
      CCE_79913_0_private_var_at_cron_allow_group
      CCE_79916_3_private_var_at_cron_deny_group
      CCE_79917_1_global_preferences_plist_permissions
      CCE_79918_9_system_command_files_permissions
      CCE_79919_7_etc_aliases_group
      CCE_79920_5_usr_lib_sa_sadc_permissions
      CCE_79921_3_sbin_route_no_setid_bits
      CCE_79923_9_usr_libexec_dumpemacs_no_setid_bits
      CCE_79924_7_usr_libexec_rexecd_no_setid_bits
      CCE_79925_4_usr_sbin_vpnd_no_setid_bits
      CCE_79926_2_preferences_install_assistant_no_setid_bits
      CCE_79927_0_iodbcadmintool_no_setid_bits
      CCE_79928_8_extensions_webdav_fs_no_setid_bits
      CCE_79929_6_appleshare_afpLoad_no_setid_bits
      CCE_79930_4_appleshare_check_afp_no_setid_bits
      CCE_79931_2_user_home_directories_permissions
      CCE_79933_8_remote_management_ARD_agent_permissions"


    elif [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$skip_flag" != "" ]; then
        echo "Skip flag enabled. Skipping file permission checking, due to potentially lengthy run time."
        return;
    fi

    if [ "$print_flag" != "" ]; then
        echo "File Permissions Print (use -v to see)"

        #already printed by CCE_79918_9_system_command_files_permissions
        #print_file_permission "/usr/bin/ipcs"
        #print_file_permission "/bin/rcp"
        #print_file_permission "/usr/bin/rlogin"
        #print_file_permission "/usr/bin/rsh"

        # CCE_79685_4_bash_init_files_owner
        # CCE_79686_2_bash_init_files_group
        # CCE_79687_0_bash_init_files_permissions
        print_file_permission "/etc/bashrc"
        print_file_permission "/etc/profile"

        # CCE_79688_8_csh_init_files_owner
        # CCE_79689_6_csh_init_files_group
        # CCE_79690_4_csh_init_files_permissions
        print_file_permission "/etc/csh.cshrc"
        print_file_permission "/etc/csh.login"
        print_file_permission "/etc/csh.logout"

        # CCE_79721_7_services_owner
        # CCE_79722_5_services_group
        # CCE_79723_3_services_permissions
        print_file_permission "/etc/services"

        # CCE_79724_1_syslog_conf_owner
        # CCE_79725_8_syslog_conf_group
        print_file_permission "/etc/syslog.conf"


        # CCE_79726_6_audit_logs_owner
        # CCE_79727_4_audit_logs_group
        # CCE_79728_2_audit_logs_permissions
        r_print_file_permission "$audit_log_path"


        # CCE_79730_8_audit_config_permissions
        print_file_permission "/etc/security/audit_class"
        print_file_permission "/etc/security/audit_control"
        print_file_permission "/etc/security/audit_event"
        print_file_permission "/etc/security/audit_warn"
        print_file_permission "/etc/security/audit_user"


        #CCE_79877_7_library_files_permissions
        local lib_file_list=`find $lib_files -type f -perm +4022 2> /dev/null`
        for lib_file in $lib_file_list; do
            print_file_permission "$lib_file"
        done
        
        #CCE_79878_5_system_log_files_permissions
        r_print_file_permission "/var/log"
        r_print_file_permission "$audit_log_path"
        r_print_file_permission "/Library/Logs"


        #CCE_79881_9_etc_shells_permissions
        #CCE_79882_7_etc_shells_owner
        local shells=`cat /etc/shells | grep -v "^#" | grep -v "^$"`
        for shell_file in $shells; do
            #print for each file path found in the /etc/shells file
            print_file_permission "$shell_file"
        done

        #CCE_79883_5_etc_group_file_permissions
        #CCE_79884_3_etc_group_file_owner
        #CCE_79885_0_etc_group_file_group
        print_file_permission "/etc/group"

        #CCE_79886_8_etc_hosts_permissions
        #CCE_79887_6_etc_hosts_owner
        #CCE_79888_4_etc_hosts_group
        print_file_permission "/etc/hosts"

        #CCE_79890_0_var_run_resolv_conf_permissions
        #CCE_79891_8_var_run_resolv_conf_owner
        #CCE_79892_6_var_run_resolv_conf_group
        print_file_permission "/var/run/resolv.conf"

        #CCE_79894_2_etc_openldap_ldap_conf_permissions
        #CCE_79895_9_etc_openldap_ldap_conf_owner
        #CCE_79896_7_etc_openldap_ldap_conf_group
        print_file_permission "/etc/openldap/ldap.conf"

        #CCE_79897_5_etc_passwd_permissions
        #CCE_79898_3_etc_passwd_owner
        #CCE_79899_1_etc_passwd_group
        print_file_permission "/etc/passwd"

        #CCE_79900_7_usr_sbin_traceroute_permissions
        #CCE_79901_5_usr_sbin_traceroute_owner
        #CCE_79902_3_usr_sbin_traceroute_group
        #print_file_permission "/usr/sbin/traceroute" # covered by a larger CCE

        #CCE_79903_1_etc_motd_permissions
        #CCE_79904_9_etc_motd_owner
        #CCE_79905_6_etc_motd_group
        print_file_permission "/etc/motd"



        #CCE_79907_2_var_at_at_deny_owner
        print_file_permission "/var/at/at.deny"

        #CCE_79909_8_var_at_permissions
        print_file_permission "/var/at"

        #CCE_79913_0_private_var_at_cron_allow_group
        print_file_permission "/private/var/at/cron.allow"

        #CCE_79916_3_private_var_at_cron_deny_group
        print_file_permission "/private/var/at/cron.deny"


        #CCE_79917_1_global_preferences_plist_permissions
        print_file_permission "/Library/Preferences/.GlobalPreferences.plist"

        #CCE_79918_9_system_command_files_permissions
        # CCE_79698_7_ipcs_owner
        # CCE_79699_5_ipcs_group
        # CCE_79700_1_ipcs_permissions
        # CCE_79701_9_rcp_owner
        # CCE_79702_7_rcp_group
        # CCE_79703_5_rcp_permissions
        # CCE_79704_3_rlogin_owner
        # CCE_79705_0_rlogin_group
        # CCE_79706_8_rlogin_permissions
        # CCE_79707_6_rsh_owner
        # CCE_79708_4_rsh_group
        # CCE_79709_2_rsh_permissions
        #CCE_79900_7_usr_sbin_traceroute_permissions
        #CCE_79901_5_usr_sbin_traceroute_owner
        #CCE_79902_3_usr_sbin_traceroute_group
        #CCE_79921_3_sbin_route_no_setid_bits
        r_print_file_permission "/bin"
        r_print_file_permission "/sbin"
        r_print_file_permission "/usr/bin"
        r_print_file_permission "/usr/sbin"

        #CCE_79919_7_etc_aliases_group
        print_file_permission "/etc/aliases"
        print_link_file_permission "/etc/aliases"


        #CCE_79920_5_usr_lib_sa_sadc_permissions
        print_file_permission "/usr/lib/sa/sadc"

        #CCE_79923_9_usr_libexec_dumpemacs_no_setid_bits
        print_setuid_bits "/usr/libexec/dumpemacs"

        #CCE_79924_7_usr_libexec_rexecd_no_setid_bits
        print_setuid_bits "/usr/libexec/rexecd"

        #CCE_79925_4_usr_sbin_vpnd_no_setid_bits
        print_setuid_bits "/usr/sbin/vpnd"

        #CCE_79926_2_preferences_install_assistant_no_setid_bits
        print_setuid_bits "/Applications/System Preferences.app/Contents/Resources/installAssistant"

        #CCE_79927_0_iodbcadmintool_no_setid_bits
        print_setuid_bits "/Applications/Utilities/ODBCAdministrator.app/Contents/Resources/iodbcadmintool"

        #CCE_79928_8_extensions_webdav_fs_no_setid_bits
        print_setuid_bits "/System/Library/Extensions/webdav_fs.kext/Contents/Resources/load_webdav"

        #CCE_79929_6_appleshare_afpLoad_no_setid_bits
        print_setuid_bits "/System/Library/Filesystems/AppleShare/afpLoad"

        #CCE_79930_4_appleshare_check_afp_no_setid_bits
        print_setuid_bits "/System/Library/Filesystems/AppleShare/check_afp.app/Contents/MacOS/check_afp"

        #CCE_79931_2_user_home_directories_permissions
        for user in $user_list; do
            print_file_permission "/Users/$user/"
        done

        #CCE_79933_8_remote_management_ARD_agent_permissions
        print_file_permission "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent"
    fi


    if [ "$set_flag" != "" ]; then
    case $profile_flag in
        "ent")
        echo "setting enterprise file permissions";

            # CCE_79698_7_ipcs_owner
            # CCE_79699_5_ipcs_group
            # CCE_79700_1_ipcs_permissions
            set_max_file_permission "/usr/bin/ipcs" "root" "wheel" "0511"

            # CCE_79701_9_rcp_owner
            # CCE_79702_7_rcp_group
            # CCE_79703_5_rcp_permissions
            set_max_file_permission "/bin/rcp" "root" "wheel" "0555"

            # CCE_79704_3_rlogin_owner
            # CCE_79705_0_rlogin_group
            # CCE_79706_8_rlogin_permissions
            set_max_file_permission "/usr/bin/rlogin" "root" "wheel" "0555"

            # CCE_79707_6_rsh_owner
            # CCE_79708_4_rsh_group
            # CCE_79709_2_rsh_permissions
            set_max_file_permission "/usr/bin/rsh" "root" "wheel" "0555"

            # CCE_79721_7_services_owner
            # CCE_79722_5_services_group
            # CCE_79723_3_services_permissions
            set_max_file_permission "/etc/services" "root" "wheel" "0644"

            # CCE_79724_1_syslog_conf_owner
            # CCE_79725_8_syslog_conf_group
            set_max_file_permission "/etc/syslog.conf" "root" "wheel" "0644"

                
            #Covered by CCE_79878_5_system_log_files_permissions
            # CCE_79726_6_audit_logs_owner
            # CCE_79727_4_audit_logs_group
            # CCE_79728_2_audit_logs_permissions
            #r_set_max_file_permission "$audit_log_path" "root" "wheel" "0640"

            # CCE_79730_8_audit_config_permissions
            set_max_file_permission "/etc/security/audit_class" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_control" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_event" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_warn" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_user" "root" "wheel" "0555"

            # CCE_79685_4_bash_init_files_owner
            # CCE_79686_2_bash_init_files_group
            # CCE_79687_0_bash_init_files_permissions
            set_max_file_permission "/etc/bashrc" "root" "wheel" "0444"
            set_max_file_permission "/etc/profile" "root" "wheel" "0444"

            # CCE_79688_8_csh_init_files_owner
            # CCE_79689_6_csh_init_files_group
            # CCE_79690_4_csh_init_files_permissions
            set_max_file_permission "/etc/csh.cshrc" "root" "wheel" "0644"
            set_max_file_permission "/etc/csh.login" "root" "wheel" "0644"
            set_max_file_permission "/etc/csh.logout" "root" "wheel" "0644"


            #CCE_79877_7_library_files_permissions
            local file_list=`find $lib_files -type f -perm +4022 2> /dev/null`
            for lib_file in $file_list; do
                set_max_file_permission "$lib_file" "" "" "0755"
            done

            #CCE_79878_5_system_log_files_permissions
            # CCE_79726_6_audit_logs_owner
            # CCE_79727_4_audit_logs_group
            # CCE_79728_2_audit_logs_permissions
            r_set_max_file_permission "/var/log" "" "" "0644"
            r_set_max_file_permission "$audit_log_path" "" "" "0640"
            r_set_max_file_permission "/Library/Logs" "" "" "0644"

            #CCE_79881_9_etc_shells_permissions
            #CCE_79882_7_etc_shells_owner
            local shells=`cat /etc/shells | grep -v "^#" | grep -v "^$"`
            for shell_file in $shells; do
                set_max_file_permission "$shell_file" "root" "" "0755"
            done

            #CCE_79883_5_etc_group_file_permissions
            #CCE_79884_3_etc_group_file_owner
            #CCE_79885_0_etc_group_file_group
            set_max_file_permission "/etc/group" "root" "wheel" "0644"

            #CCE_79886_8_etc_hosts_permissions
            #CCE_79887_6_etc_hosts_owner
            #CCE_79888_4_etc_hosts_group
            set_max_file_permission "/etc/hosts" "root" "wheel" "0644"

            #CCE_79890_0_var_run_resolv_conf_permissions
            #CCE_79891_8_var_run_resolv_conf_owner
            #CCE_79892_6_var_run_resolv_conf_group
            set_max_file_permission "/var/run/resolv.conf" "root" "daemon" "0644"

            #CCE_79894_2_etc_openldap_ldap_conf_permissions
            #CCE_79895_9_etc_openldap_ldap_conf_owner
            #CCE_79896_7_etc_openldap_ldap_conf_group
            set_max_file_permission "/etc/openldap/ldap.conf" "root" "wheel" "0644"

            #CCE_79897_5_etc_passwd_permissions
            #CCE_79898_3_etc_passwd_owner
            #CCE_79899_1_etc_passwd_group
            set_max_file_permission "/etc/passwd" "root" "wheel" "0644"

            #CCE_79900_7_usr_sbin_traceroute_permissions
            #CCE_79901_5_usr_sbin_traceroute_owner
            #CCE_79902_3_usr_sbin_traceroute_group
            set_max_file_permission "/usr/sbin/traceroute" "root" "wheel" "4511" #default is 4555

            #CCE_79903_1_etc_motd_permissions
            #CCE_79904_9_etc_motd_owner
            #CCE_79905_6_etc_motd_group
            set_max_file_permission "/etc/motd" "root" "wheel" "0644"

            #CCE_79907_2_var_at_at_deny_owner
            set_max_file_permission "/var/at/at.deny" "root" "" ""

            #CCE_79909_8_var_at_permissions
            set_max_file_permission "/var/at" "" "" "0755"

            #CCE_79913_0_private_var_at_cron_allow_group
            set_max_file_permission "/private/var/at/cron.allow" "" "wheel" ""

            #CCE_79916_3_private_var_at_cron_deny_group
            set_max_file_permission "/private/var/at/cron.deny" "" "wheel" ""

            #CCE_79917_1_global_preferences_plist_permissions
            set_max_file_permission "/Library/Preferences/.GlobalPreferences.plist" "" "" "0644"

            #CCE_79918_9_system_command_files_permissions
            #CCE_79921_3_sbin_route_no_setid_bits
            r_set_max_file_permission "/bin" "" "" "0755"
            r_set_max_file_permission "/sbin" "" "" "0755"
            r_set_max_file_permission "/usr/bin" "" "" "755"
            r_set_max_file_permission "/usr/sbin" "" "" "755"
            set_setuid_bits "/usr/bin/at" "" ""
            set_setuid_bits "/usr/bin/atq" "" ""
            set_setuid_bits "/usr/bin/atrm" "" ""
            set_setuid_bits "/usr/bin/batch" "" ""
            set_setuid_bits "/usr/bin/crontab" "" ""
            set_setuid_bits "/usr/bin/quota" "" ""
            set_setuid_bits "/usr/bin/lockfile" "" ""
            set_setuid_bits "/usr/bin/procmail" "" ""
            set_setuid_bits "/usr/bin/wall" "" ""
            set_setuid_bits "/usr/bin/write" "" ""
            set_setuid_bits "/usr/sbin/postdrop" "" ""
            set_setuid_bits "/usr/sbin/postqueue" "" ""
            set_setuid_bits "/bin/ps" "" ""
            set_setuid_bits "/sbin/route" "" ""


            #CCE_79919_7_etc_aliases_group
            set_max_file_permission  "/etc/aliases" "" "wheel" ""

            #CCE_79920_5_usr_lib_sa_sadc_permissions
            set_max_file_permission "/usr/lib/sa/sadc" "" "" "0555"

            #CCE_79923_9_usr_libexec_dumpemacs_no_setid_bits
            set_setuid_bits "/usr/libexec/dumpemacs" "" ""

            #CCE_79924_7_usr_libexec_rexecd_no_setid_bits
            set_setuid_bits "/usr/libexec/rexecd" "" ""

            #CCE_79925_4_usr_sbin_vpnd_no_setid_bits
            set_setuid_bits "/usr/sbin/vpnd" "" ""

            #CCE_79926_2_preferences_install_assistant_no_setid_bits
            set_setuid_bits "/Applications/System Preferences.app/Contents/Resources/installAssistant" "" ""

            #CCE_79927_0_iodbcadmintool_no_setid_bits
            set_setuid_bits "/Applications/Utilities/ODBCAdministrator.app/Contents/Resources/iodbadmintool" "" ""

            #CCE_79928_8_extensions_webdav_fs_no_setid_bits
            set_setuid_bits "/System/Library/Extensions/webdav_fs.kext/Contents/Resources/load_webdav" "" ""

            #CCE_79929_6_appleshare_afpLoad_no_setid_bits
            set_setuid_bits "/System/Library/Filesystems/AppleShare/afpLoad" "" ""

            #CCE_79930_4_appleshare_check_afp_no_setid_bits
            set_setuid_bits "/System/Library/Filesystems/AppleShare/check_afp.app/Contents/MacOS/check_afp" "" ""


            #CCE_79931_2_user_home_directories_permissions
            for user in $user_list; do
                set_max_file_permission "/Users/$user/" "" "" "700"
            done


            #CCE_79933_8_remote_management_ARD_agent_permissions
            set_max_file_permission "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent" "" "" "0755"
            ;;

        "soho")
            echo "setting soho file permissions";

            # CCE_79698_7_ipcs_owner
            # CCE_79699_5_ipcs_group
            # CCE_79700_1_ipcs_permissions
            set_max_file_permission "/usr/bin/ipcs" "root" "wheel" "0511"

            # CCE_79701_9_rcp_owner
            # CCE_79702_7_rcp_group
            # CCE_79703_5_rcp_permissions
            set_max_file_permission "/bin/rcp" "root" "wheel" "0555"

            # CCE_79704_3_rlogin_owner
            # CCE_79705_0_rlogin_group
            # CCE_79706_8_rlogin_permissions
            set_max_file_permission "/usr/bin/rlogin" "root" "wheel" "0555"

            # CCE_79707_6_rsh_owner
            # CCE_79708_4_rsh_group
            # CCE_79709_2_rsh_permissions
            set_max_file_permission "/usr/bin/rsh" "root" "wheel" "0555"

            # CCE_79721_7_services_owner
            # CCE_79722_5_services_group
            # CCE_79723_3_services_permissions
            set_max_file_permission "/etc/services" "root" "wheel" "0644"

            # CCE_79724_1_syslog_conf_owner
            # CCE_79725_8_syslog_conf_group
            set_max_file_permission "/etc/syslog.conf" "root" "wheel" "0644"

                
            #Covered by CCE_79878_5_system_log_files_permissions
            # CCE_79726_6_audit_logs_owner
            # CCE_79727_4_audit_logs_group
            # CCE_79728_2_audit_logs_permissions
            #r_set_max_file_permission "$audit_log_path" "root" "wheel" "0640"

                # CCE_79730_8_audit_config_permissions
            set_max_file_permission "/etc/security/audit_class" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_control" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_event" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_warn" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_user" "root" "wheel" "0555"

            # CCE_79685_4_bash_init_files_owner
            # CCE_79686_2_bash_init_files_group
            # CCE_79687_0_bash_init_files_permissions
            set_max_file_permission "/etc/bashrc" "root" "wheel" "0444"
            set_max_file_permission "/etc/profile" "root" "wheel" "0444"

            # CCE_79688_8_csh_init_files_owner
            # CCE_79689_6_csh_init_files_group
            # CCE_79690_4_csh_init_files_permissions
            set_max_file_permission "/etc/csh.cshrc" "root" "wheel" "0644"
            set_max_file_permission "/etc/csh.login" "root" "wheel" "0644"
            set_max_file_permission "/etc/csh.logout" "root" "wheel" "0644"


            #CCE_79877_7_library_files_permissions
            local file_list=`find $lib_files -type f -perm +4022 2> /dev/null`
            for lib_file in $file_list; do
                set_max_file_permission "$lib_file" "" "" "0755"
            done

            #CCE_79878_5_system_log_files_permissions
            # CCE_79726_6_audit_logs_owner
            # CCE_79727_4_audit_logs_group
            # CCE_79728_2_audit_logs_permissions
            r_set_max_file_permission "/var/log" "" "" "0644"
            r_set_max_file_permission "$audit_log_path" "" "" "0640"
            r_set_max_file_permission "/Library/Logs" "" "" "0644"

            #CCE_79881_9_etc_shells_permissions
            #CCE_79882_7_etc_shells_owner
            local shells=`cat /etc/shells | grep -v "^#" | grep -v "^$"`
            for shell_file in $shells; do
                set_max_file_permission "$shell_file" "root" "" "0755"
            done

            #CCE_79883_5_etc_group_file_permissions
            #CCE_79884_3_etc_group_file_owner
            #CCE_79885_0_etc_group_file_group
            set_max_file_permission "/etc/group" "root" "wheel" "0644"

            #CCE_79886_8_etc_hosts_permissions
            #CCE_79887_6_etc_hosts_owner
            #CCE_79888_4_etc_hosts_group
            set_max_file_permission "/etc/hosts" "root" "wheel" "0644"

            #CCE_79890_0_var_run_resolv_conf_permissions
            #CCE_79891_8_var_run_resolv_conf_owner
            #CCE_79892_6_var_run_resolv_conf_group
            set_max_file_permission "/var/run/resolv.conf" "root" "daemon" "0644"

            #CCE_79894_2_etc_openldap_ldap_conf_permissions
            #CCE_79895_9_etc_openldap_ldap_conf_owner
            #CCE_79896_7_etc_openldap_ldap_conf_group
            set_max_file_permission "/etc/openldap/ldap.conf" "root" "wheel" "0644"

            #CCE_79897_5_etc_passwd_permissions
            #CCE_79898_3_etc_passwd_owner
            #CCE_79899_1_etc_passwd_group
            set_max_file_permission "/etc/passwd" "root" "wheel" "0644"

            #CCE_79900_7_usr_sbin_traceroute_permissions
            #CCE_79901_5_usr_sbin_traceroute_owner
            #CCE_79902_3_usr_sbin_traceroute_group
            set_max_file_permission "/usr/sbin/traceroute" "root" "wheel" "4511" #default is 4555

            #CCE_79903_1_etc_motd_permissions
            #CCE_79904_9_etc_motd_owner
            #CCE_79905_6_etc_motd_group
            set_max_file_permission "/etc/motd" "root" "wheel" "0644"

            #CCE_79907_2_var_at_at_deny_owner
            set_max_file_permission "/var/at/at.deny" "root" "" ""

            #CCE_79909_8_var_at_permissions
            set_max_file_permission "/var/at" "" "" "0755"

            #CCE_79913_0_private_var_at_cron_allow_group
            set_max_file_permission "/private/var/at/cron.allow" "" "wheel" ""

            #CCE_79916_3_private_var_at_cron_deny_group
            set_max_file_permission "/private/var/at/cron.deny" "" "wheel" ""

            #CCE_79917_1_global_preferences_plist_permissions
            set_max_file_permission "/Library/Preferences/.GlobalPreferences.plist" "" "" "0644"

            #CCE_79918_9_system_command_files_permissions
            #CCE_79921_3_sbin_route_no_setid_bits
            r_set_max_file_permission "/bin" "" "" "0755"
            r_set_max_file_permission "/sbin" "" "" "0755"
            r_set_max_file_permission "/usr/bin" "" "" "755"
            r_set_max_file_permission "/usr/sbin" "" "" "755"
            set_setuid_bits "/usr/bin/at" "" ""
            set_setuid_bits "/usr/bin/atq" "" ""
            set_setuid_bits "/usr/bin/atrm" "" ""
            set_setuid_bits "/usr/bin/batch" "" ""
            set_setuid_bits "/usr/bin/crontab" "" ""
            set_setuid_bits "/usr/bin/quota" "" ""
            set_setuid_bits "/usr/bin/lockfile" "" ""
            set_setuid_bits "/usr/bin/procmail" "" ""
            set_setuid_bits "/usr/bin/wall" "" ""
            set_setuid_bits "/usr/bin/write" "" ""
            set_setuid_bits "/usr/sbin/postdrop" "" ""
            set_setuid_bits "/usr/sbin/postqueue" "" ""
            set_setuid_bits "/bin/ps" "" ""
            set_setuid_bits "/sbin/route" "" ""


            #CCE_79919_7_etc_aliases_group
            set_max_file_permission  "/etc/aliases" "" "wheel" ""

            #CCE_79920_5_usr_lib_sa_sadc_permissions
            set_max_file_permission "/usr/lib/sa/sadc" "" "" "0555"

            #CCE_79923_9_usr_libexec_dumpemacs_no_setid_bits
            set_setuid_bits "/usr/libexec/dumpemacs" "" ""

            #CCE_79924_7_usr_libexec_rexecd_no_setid_bits
            set_setuid_bits "/usr/libexec/rexecd" "" ""

            #CCE_79925_4_usr_sbin_vpnd_no_setid_bits
            set_setuid_bits "/usr/sbin/vpnd" "" ""

            #CCE_79926_2_preferences_install_assistant_no_setid_bits
            set_setuid_bits "/Applications/System Preferences.app/Contents/Resources/installAssistant" "" ""

            #CCE_79927_0_iodbcadmintool_no_setid_bits
            set_setuid_bits "/Applications/Utilities/ODBCAdministrator.app/Contents/Resources/iodbadmintool" "" ""

            #CCE_79928_8_extensions_webdav_fs_no_setid_bits
            set_setuid_bits "/System/Library/Extensions/webdav_fs.kext/Contents/Resources/load_webdav" "" ""

            #CCE_79929_6_appleshare_afpLoad_no_setid_bits
            set_setuid_bits "/System/Library/Filesystems/AppleShare/afpLoad" "" ""

            #CCE_79930_4_appleshare_check_afp_no_setid_bits
            set_setuid_bits "/System/Library/Filesystems/AppleShare/check_afp.app/Contents/MacOS/check_afp" "" ""


            #CCE_79931_2_user_home_directories_permissions
            for user in $user_list; do
                set_max_file_permission "/Users/$user/" "" "" "700"
            done


            #CCE_79933_8_remote_management_ARD_agent_permissions
            set_max_file_permission "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent" "" "" "0755"
            ;;

        "sslf")
            echo "setting sslf file permissions";

            # CCE_79698_7_ipcs_owner
            # CCE_79699_5_ipcs_group
            # CCE_79700_1_ipcs_permissions
            set_max_file_permission "/usr/bin/ipcs" "root" "wheel" "0511"

            # CCE_79701_9_rcp_owner
            # CCE_79702_7_rcp_group
            # CCE_79703_5_rcp_permissions
            set_max_file_permission "/bin/rcp" "root" "wheel" "0555"

            # CCE_79704_3_rlogin_owner
            # CCE_79705_0_rlogin_group
            # CCE_79706_8_rlogin_permissions
            set_max_file_permission "/usr/bin/rlogin" "root" "wheel" "0555"

            # CCE_79707_6_rsh_owner
            # CCE_79708_4_rsh_group
            # CCE_79709_2_rsh_permissions
            set_max_file_permission "/usr/bin/rsh" "root" "wheel" "0555"

            # CCE_79721_7_services_owner
            # CCE_79722_5_services_group
            # CCE_79723_3_services_permissions
            set_max_file_permission "/etc/services" "root" "wheel" "0644"

            # CCE_79724_1_syslog_conf_owner
            # CCE_79725_8_syslog_conf_group
            set_max_file_permission "/etc/syslog.conf" "root" "wheel" "0644"

                
            #Covered by CCE_79878_5_system_log_files_permissions
            # CCE_79726_6_audit_logs_owner
            # CCE_79727_4_audit_logs_group
            # CCE_79728_2_audit_logs_permissions
            #r_set_max_file_permission "$audit_log_path" "root" "wheel" "0640"

            # CCE_79730_8_audit_config_permissions
            set_max_file_permission "/etc/security/audit_class" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_control" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_event" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_warn" "root" "wheel" "0555"
            set_max_file_permission "/etc/security/audit_user" "root" "wheel" "0555"

            # CCE_79685_4_bash_init_files_owner
            # CCE_79686_2_bash_init_files_group
            # CCE_79687_0_bash_init_files_permissions
            set_max_file_permission "/etc/bashrc" "root" "wheel" "0444"
            set_max_file_permission "/etc/profile" "root" "wheel" "0444"

            # CCE_79688_8_csh_init_files_owner
            # CCE_79689_6_csh_init_files_group
            # CCE_79690_4_csh_init_files_permissions
            set_max_file_permission "/etc/csh.cshrc" "root" "wheel" "0644"
            set_max_file_permission "/etc/csh.login" "root" "wheel" "0644"
            set_max_file_permission "/etc/csh.logout" "root" "wheel" "0644"


            #CCE_79877_7_library_files_permissions
            local file_list=`find $lib_files -type f -perm +4022 2> /dev/null`
            for lib_file in $file_list; do
                set_max_file_permission "$lib_file" "" "" "0755"
            done

            #CCE_79878_5_system_log_files_permissions
            # CCE_79726_6_audit_logs_owner
            # CCE_79727_4_audit_logs_group
            # CCE_79728_2_audit_logs_permissions
            r_set_max_file_permission "/var/log" "" "" "0644"
            r_set_max_file_permission "$audit_log_path" "" "" "0640"
            r_set_max_file_permission "/Library/Logs" "" "" "0644"

            #CCE_79881_9_etc_shells_permissions
            #CCE_79882_7_etc_shells_owner
            local shells=`cat /etc/shells | grep -v "^#" | grep -v "^$"`
            for shell_file in $shells; do
                set_max_file_permission "$shell_file" "root" "" "0755"
            done

            #CCE_79883_5_etc_group_file_permissions
            #CCE_79884_3_etc_group_file_owner
            #CCE_79885_0_etc_group_file_group
            set_max_file_permission "/etc/group" "root" "wheel" "0644"

            #CCE_79886_8_etc_hosts_permissions
            #CCE_79887_6_etc_hosts_owner
            #CCE_79888_4_etc_hosts_group
            set_max_file_permission "/etc/hosts" "root" "wheel" "0644"

            #CCE_79890_0_var_run_resolv_conf_permissions
            #CCE_79891_8_var_run_resolv_conf_owner
            #CCE_79892_6_var_run_resolv_conf_group
            set_max_file_permission "/var/run/resolv.conf" "root" "daemon" "0644"

            #CCE_79894_2_etc_openldap_ldap_conf_permissions
            #CCE_79895_9_etc_openldap_ldap_conf_owner
            #CCE_79896_7_etc_openldap_ldap_conf_group
            set_max_file_permission "/etc/openldap/ldap.conf" "root" "wheel" "0644"

            #CCE_79897_5_etc_passwd_permissions
            #CCE_79898_3_etc_passwd_owner
            #CCE_79899_1_etc_passwd_group
            set_max_file_permission "/etc/passwd" "root" "wheel" "0644"

            #CCE_79900_7_usr_sbin_traceroute_permissions
            #CCE_79901_5_usr_sbin_traceroute_owner
            #CCE_79902_3_usr_sbin_traceroute_group
            set_max_file_permission "/usr/sbin/traceroute" "root" "wheel" "4511" #default is 4555

            #CCE_79903_1_etc_motd_permissions
            #CCE_79904_9_etc_motd_owner
            #CCE_79905_6_etc_motd_group
            set_max_file_permission "/etc/motd" "root" "wheel" "0644"

            #CCE_79907_2_var_at_at_deny_owner
            set_max_file_permission "/var/at/at.deny" "root" "" ""

            #CCE_79909_8_var_at_permissions
            set_max_file_permission "/var/at" "" "" "0755"

            #CCE_79913_0_private_var_at_cron_allow_group
            set_max_file_permission "/private/var/at/cron.allow" "" "wheel" ""

            #CCE_79916_3_private_var_at_cron_deny_group
            set_max_file_permission "/private/var/at/cron.deny" "" "wheel" ""

            #CCE_79917_1_global_preferences_plist_permissions
            set_max_file_permission "/Library/Preferences/.GlobalPreferences.plist" "" "" "0644"

            #CCE_79918_9_system_command_files_permissions
            #CCE_79921_3_sbin_route_no_setid_bits
            r_set_max_file_permission "/bin" "" "" "0755"
            r_set_max_file_permission "/sbin" "" "" "0755"
            r_set_max_file_permission "/usr/bin" "" "" "755"
            r_set_max_file_permission "/usr/sbin" "" "" "755"
            set_setuid_bits "/usr/bin/at" "" ""
            set_setuid_bits "/usr/bin/atq" "" ""
            set_setuid_bits "/usr/bin/atrm" "" ""
            set_setuid_bits "/usr/bin/batch" "" ""
            set_setuid_bits "/usr/bin/crontab" "" ""
            set_setuid_bits "/usr/bin/quota" "" ""
            set_setuid_bits "/usr/bin/lockfile" "" ""
            set_setuid_bits "/usr/bin/procmail" "" ""
            set_setuid_bits "/usr/bin/wall" "" ""
            set_setuid_bits "/usr/bin/write" "" ""
            set_setuid_bits "/usr/sbin/postdrop" "" ""
            set_setuid_bits "/usr/sbin/postqueue" "" ""
            set_setuid_bits "/bin/ps" "" ""
            set_setuid_bits "/sbin/route" "" ""


            #CCE_79919_7_etc_aliases_group
            set_max_file_permission  "/etc/aliases" "" "wheel" ""

            #CCE_79920_5_usr_lib_sa_sadc_permissions
            set_max_file_permission "/usr/lib/sa/sadc" "" "" "0555"

            #CCE_79923_9_usr_libexec_dumpemacs_no_setid_bits
            set_setuid_bits "/usr/libexec/dumpemacs" "" ""

            #CCE_79924_7_usr_libexec_rexecd_no_setid_bits
            set_setuid_bits "/usr/libexec/rexecd" "" ""

            #CCE_79925_4_usr_sbin_vpnd_no_setid_bits
            set_setuid_bits "/usr/sbin/vpnd" "" ""

            #CCE_79926_2_preferences_install_assistant_no_setid_bits
            set_setuid_bits "/Applications/System Preferences.app/Contents/Resources/installAssistant" "" ""

            #CCE_79927_0_iodbcadmintool_no_setid_bits
            set_setuid_bits "/Applications/Utilities/ODBCAdministrator.app/Contents/Resources/iodbadmintool" "" ""

            #CCE_79928_8_extensions_webdav_fs_no_setid_bits
            set_setuid_bits "/System/Library/Extensions/webdav_fs.kext/Contents/Resources/load_webdav" "" ""

            #CCE_79929_6_appleshare_afpLoad_no_setid_bits
            set_setuid_bits "/System/Library/Filesystems/AppleShare/afpLoad" "" ""

            #CCE_79930_4_appleshare_check_afp_no_setid_bits
            set_setuid_bits "/System/Library/Filesystems/AppleShare/check_afp.app/Contents/MacOS/check_afp" "" ""


            #CCE_79931_2_user_home_directories_permissions
            for user in $user_list; do
                set_max_file_permission "/Users/$user/" "" "" "700"
            done


            #CCE_79933_8_remote_management_ARD_agent_permissions
            set_max_file_permission "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent" "" "" "0755"
            ;;

        "oem")
            diskutil repairPermissions
            ;;
    esac
    fi
}


#
# This function is used for symbolic links
# $1 : file path
#
print_link_file_permission () {
    if [ "$v_flag" != "" ]; then
        if [ -a "$1" ]; then
            # add symlink tag to the front of the path, since it is a symbolic link
            # shorten long paths and then print, along with UNIX mode bits
            ls -ld "$1" |
                awk -v file_path="$1" '{
                    if (length(file_path) >30) {
                        line_buf=sprintf("%s ... %s", substr(file_path, 1, 10),
                                              substr(file_path, length(file_path)-19, 20))
                        printf("%s\t%-40s%s", "(sLink)", line_buf, $1);
                        printf("\t%-10s\t%s\n", $3, $4) #show owner and group as well
                    }
                    else {

                        printf("%s\t%-40s%s", "(sLink)", file_path, $1)
                        printf("\t%-10s\t%s\n", $3, $4) #show owner and group as well
                        }
                    }'
        else
            echo "NOT FOUND($1)" >&2
        fi
    fi
}


#
# $1 : file path
#
print_file_permission () {
    if [ "$v_flag" != "" ]; then
    if [ -a "$1" ]; then
        # shorten long paths and then print, along with UNIX mode bits
        ls -lLd "$1" |
            awk -v file_path="$1" '{
                if (length(file_path) >30) {
                    line_buf=sprintf("%s ... %s", substr(file_path, 1, 10),
                                          substr(file_path, length(file_path)-19, 20))
                    #printf("\t%-40s%s\n", line_buf, $1);
                    printf("\t%-40s%s", line_buf, $1);
                    printf("\t%-10s\t%s\n", $3, $4) #show owner and group as well
                }
                else {
                    #printf("\t%-40s%s\n", $9, $1)
                    printf("\t%-40s%s", file_path, $1)
                    printf("\t%-10s\t%s\n", $3, $4) #show owner and group as well
                    }
                }'
    else
        echo "NOT FOUND($1)" >&2
    fi
    fi
}

#
# Recursively prints the permissions for all the files below the passed path.
#
# $1 : file path
#
r_print_file_permission () {
    
    #for x in `find $1 -name \* -print`; do
    while IFS= read -r x ; do
        print_file_permission "$x"
    done <<< "`find $1 -name \* -print`"
}

#
# $1 : file path
# $2 : owner to set
# $3 : group to set
# $4 : UNIX mode bits to set (including sticky/setuid)
#
set_file_permission () {
    if [ -a "$1" ]; then

        #Don't try to modify a property if it is blank
        if [ "$2" != "" ]; then
            chown $2 $1        # set the user
        fi

        if [ "$3" != "" ]; then
            chgrp $3 $1        # set the group
        fi

        if [ "$4" != "" ]; then
            chmod $4 $1        # set the mode bits
        fi

    else
        if [ "$v_flag" != "" ]; then
            echo "NOT FOUND($1)" >&2
        fi
    fi
}

#
# Set file permissions only if the existing permissions exceed the permission arguments
#
# $1 : file path
# $2 : owner to set
# $3 : group to set
# $4 : UNIX mode bits to set (including sticky/setuid)
#
set_max_file_permission () {
    if [ -e "$1" ]; then
        if [ "$4" != "" ]; then
            local u_bits=`echo $4 | cut -c1`
            local g_bits=`echo $4 | cut -c2`
            local o_bits=`echo $4 | cut -c3`

            local u_subtract=""
            local g_subtract=""
            local o_subtract=""

            #only change the set id permissions if it is included in the parameter (if $4
            #is 4 characters long)
            if [ "${#4}" -eq "4" ]; then
                local id_bits=`echo $4 | cut -c1`
                u_bits=`echo $4 | cut -c2`
                g_bits=`echo $4 | cut -c3`
                o_bits=`echo $4 | cut -c4`

                #set id permissions
                if [ "$id_bits" -lt "4" ]; then
                    u_subtract="s"
                #subtract 4 so that we can check for set gid on execute(2) permission
                else
                    id_bits=$(( $id_bits - 4 ))
                fi

                if [ "$id_bits" -lt "2" ]; then
                    g_subtract="s"
                fi
            fi

            #user permissions
            if [ "$u_bits" -lt "4" ]; then
                u_subtract="${u_subtract}r"
            #subtract 4 so that we can check for write(2) and execute(1) permissions
            else
                u_bits=$(( $u_bits - 4 ))
            fi

            if [ "$u_bits" -lt "2" ]; then
                u_subtract="${u_subtract}w"
            else
                u_bits=$(( $u_bits - 2 ))
            fi

            if [ "$u_bits" -lt "1" ]; then
                u_subtract="${u_subtract}x"
            fi


            #group permissions
            if [ "$g_bits" -lt "4" ]; then
                g_subtract="${g_subtract}r"
            else
                g_bits=$(( $g_bits - 4 ))
            fi

            if [ "$g_bits" -lt "2" ]; then
                g_subtract="${g_subtract}w"
            else
                g_bits=$(( $g_bits - 2 ))
            fi

            if [ "$g_bits" -lt "1" ]; then
                g_subtract="${g_subtract}x"
            fi

            #other permissions
            if [ "$o_bits" -lt "4" ]; then
                o_subtract="${o_subtract}r"
            else
                o_bits=$(( $o_bits - 4 ))
            fi

            if [ "$o_bits" -lt "2" ]; then
                o_subtract="${o_subtract}w"
            else
                o_bits=$(( $o_bits - 2 ))
            fi

            if [ "$o_bits" -lt "1" ]; then
                o_subtract="${o_subtract}x"
            fi

            chmod u-${u_subtract} "$1"
            chmod g-${g_subtract} "$1"
            chmod o-${o_subtract} "$1"
        fi

        if [ "$2" != "" ];  then
            chown "$2" "$1"
        fi

        if [ "$3" != "" ]; then
            chgrp "$3" "$1"
        fi

    else
        if [ "$v_flag" != "" ]; then
            echo "NOT FOUND($1)" >&2
        fi
    fi
}

#
# Recursively sets attributes for all the files below the passed path using a max
# permission value.
#
# $1 : file path
# $2 : owner to set
# $3 : group to set
# $4 : UNIX mode bits to set (including sticky/setuid)
#
r_set_max_file_permission () {
    
    while IFS= read -r file ; do

        if [ ! -d "$file" ]; then
            set_max_file_permission "$file" "$2" "$3" "$4"
        #prevent infinite recursion by checking if the file/directory
    #found is the directory we started in
    elif [ $file != $1 ]; then
        
            r_set_max_file_permission "$file" "$2" "$3" "$4"
        fi
    done <<< "`find $1 -name \* -print`"
        
}

#
# Recursively sets attributes for all the directories below the passed path using a max
# permission value.
#
# $1 : directory path
# $2 : owner to set
# $3 : group to set
# $4 : UNIX mode bits to set (including sticky/setuid)
#
r_set_max_directory_permission () {
    
    #for file in `find $1 -name \* -print`; do
    while IFS= read -r file ; do
        if [ -d "$file" ]; then
            set_max_file_permission "$file" "$2" "$3" "$4"
        fi
    done <<< "`find $1 -name \* -print`"
}

#
# Recursively sets attributes for all the files below the passed path.
#
# $1 : file path
# $2 : owner to set
# $3 : group to set
# $4 : UNIX mode bits to set (including sticky/setuid)
#
r_set_file_permission () {
    while IFS= read -r x ; do 
        set_file_permission "$x" "$2" "$3" "$4"
    done <<< "`find $1 -name \* -print`"
}


# If the file with an ACL is a link, print the link, not the actual file
#
# $1 : file path
print_extended_acl () {
    if [ -a "$1" ]; then
        #exists=`find $1 -name \* -type f -acl | grep -c \'\^$1\$\'`
        #if [ $exists != "1" ];then
        #local actual_file="$1"
        local file_ls=`ls -lde "$1"`
        
        #problematic for some links (/var/audit and Trash files)
        #if [ `echo "$file_ls" | grep -c "^l"` -ge "1" ]; then
        #

        #  actual_file=`readlink -n "$1"`
        #	actual_file=`dirname "$1"`"/$actual_file"
            
        #fi
            
        #file_ls=`ls -lde "$actual_file"`
            
        if [ `echo "$file_ls" | wc -l` -gt "1" ]; then
            if [ "$v_flag" != "" ]; then
                # left justify the path, fill 40, and add the path
                printf "%-40s Extended ACL\n" "$1"
            fi
            acl_files=$[ acl_files + 1 ]
        else
            non_acl_files=$[ non_acl_files + 1 ]
            #printf "%-40s NO extended ACL\n" $1
        fi
    fi
}

#
# Recursively prints the extended ACLs for all the files below the passed path.
#
# $1 : file path
#
r_print_extended_acl () {
    while IFS= read -r x ; do
        print_extended_acl "$x"
    done <<< "`find $1 -name \* -print`"

}


#
# Recursively prints the extended ACLs for all the executable files below the passed path.
#
# $1 : file path
#
r_print_extended_acl_for_executables () {
    local files=`find "$1" -name \* -perm +0111 -type f`
    local num_files=`echo "$files" | wc -l`
    
    while IFS= read -r x ; do
        if [ "$x" != "" ]; then
            print_extended_acl "$x"
        fi
    done <<< "$files"
}

remove_extended_acl () {
    if [ -a "$1" ]; then
        chmod -N "$1"
    elif [ "$v_flag" != "" ] ; then
        echo "NOT FOUND($1)" >&2
    fi
}

#
# Recursively removes the extended ACLs for all the files below the passed
# path.
#
# $1 : file path
#
r_remove_extended_acl () {
    #find all files below the passed path, and execute chmod with as many files at a time
    #as possible; the '{}' means path and name of current file
    #use -acl to only find acl files
    find "$1" -name \* -acl -exec chmod -N '{}' +
    #for x in `find "$1" -name \* -print`
    #do
    #remove_extended_acl "$x"
    #done
}


#
# Recursively removes the extended ACLs for all the executable files below the passed
# path.
#
# $1 : file path
#
r_remove_extended_acl_for_executables () {
    while IFS= read -r x ; do 
        if [ "$x" != "" ]; then
            remove_extended_acl "$x"
        fi
    done <<< "`find $1 -name \* -perm +0111 -type f -acl`"
}


#
# At this point, oem = ent = soho = sslf, so say it just once.
#
set_same_extended_acl() {
    #CCE_79710_0_aliases_acl
    #CCE_79711_8_group_acl
    #CCE_79712_6_hosts_acl
    #CCE_79713_4_ldap_conf_acl
    #CCE_79714_2_passwd_acl
    #CCE_79715_9_services_acl
    #CCE_79716_7_syslog_conf_acl
    #CCE_79717_5_cron_allow_acl
    #CCE_79718_3_cron_deny_acl
    #CCE_79720_9_resolve_conf_acl
    remove_extended_acl "/etc/aliases"
    remove_extended_acl "/etc/group"
    remove_extended_acl "/etc/hosts"
    remove_extended_acl "/etc/openldap/ldap.conf"
    remove_extended_acl "/etc/passwd"
    remove_extended_acl "/etc/services"
    remove_extended_acl "/etc/syslog.conf"
    remove_extended_acl "/private/var/at/cron.allow"
    remove_extended_acl "/private/var/at/cron.deny"
    remove_extended_acl "/etc/resolv.conf"
    
    #CCE_79729_0_audit_logs_acl
    r_remove_extended_acl "$audit_log_path"


#
#these already checked by CCE_79861_1_no_acls_system_command_executables
#
:<<'COMMENT_BLOCK'
    #CCE_79719_1_traceroute_acl
    remove_extended_acl "/usr/sbin/traceroute"

    #CCE_79731_6_audit_tool_executables_acl
    remove_extended_acl "/usr/sbin/auditd"
    remove_extended_acl "/usr/sbin/audit"
    remove_extended_acl "/usr/sbin/auditreduce"
    remove_extended_acl "/usr/sbin/praudit"

    #CCE_79867_8_crontab_files_no_acls
    remove_extended_acl "/usr/sbin/cron"
    remove_extended_acl "/usr/bin/crontab"


COMMENT_BLOCK
    ###########################################
    
    #CCE_79869_4_etc_shells_no_ACLs - checked by CCE_79861_1_no_acls_system_command_executables
    #Default location of these files are in /bin/, but they could be elsewhere.
    #Because of this, these files may be reported more than once.
    #CCE_79869_4_etc_shells_no_acls
    local shells=`grep -v "^#" /etc/shells | grep -ve "^$"`
    for shell_file in $shells; do
        remove_extended_acl $shell_file
    done
    
#:<<'COMMENT_BLOCK'
    #Added
    #CCE_79861_1_no_acls_system_command_executables- this also covers the following CCEs:
    #CCE_79869_4_etc_shells_no_acls
    #CCE_79731_6_audit_tool_executables_acl
    r_remove_extended_acl_for_executables "/bin"
    r_remove_extended_acl_for_executables "/sbin"
    r_remove_extended_acl_for_executables "/usr/bin"
    r_remove_extended_acl_for_executables "/usr/sbin"

    #CCE_79867_8_crontab_files_no_acls
    remove_extended_acl "/usr/lib/cron"

    #CCE_79879_3_files_in_user_home_directories_no_ACLs
    #CCE_79880_1_user_home_directories_no_ACLs
    #r_remove_extended_acl "/Users"
    for user in $user_list; do
        r_remove_extended_acl "/Users/$user/"
    done


    #CCE_79911_4_library_files_no_acls
    local file_list=`find $lib_files -type f -acl 2> /dev/null`
    for lib_file in $file_list; do
        remove_extended_acl "$lib_file"
    done
    
#COMMENT_BLOCK
}


######################################################################
#Read ACLs for files
extended_acls_CCEs () {
    local doc="extended_acls                      (manual-test-PASSED)"
    
    if  [ "$v_flag" != "" -a "$list_flag" != "" ]; then
    echo "      CCE_79710_0_aliases_acl
      CCE_79711_8_group_acl
      CCE_79712_6_hosts_acl
      CCE_79713_4_ldap_conf_acl
      CCE_79714_2_passwd_acl
      CCE_79715_9_services_acl
      CCE_79716_7_syslog_conf_acl
      CCE_79717_5_cron_allow_acl
      CCE_79718_3_cron_deny_acl
      CCE_79719_1_traceroute_acl
      CCE_79720_9_resolve_conf_acl
      CCE_79729_0_audit_logs_acl
      CCE_79731_6_audit_tool_executables_acl
      CCE_79861_1_no_acls_system_command_executables
      CCE_79867_8_crontab_files_no_acls
      CCE_79869_4_etc_shells_no_ACLs
      CCE_79879_3_files_in_user_home_directories_no_ACLs
      CCE_79880_1_user_home_directories_no_ACLs
      CCE_79911_4_library_files_no_acls"

    elif [ "$list_flag" != "" ]; then echo "$doc";
    fi
      
    if [ "$skip_flag" != "" ]; then
        echo "Skip flag enabled. Skipping file ACLs checking, due to potentially lengthy run time."
        return;
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$v_flag" == "" ]; then
            echo "Extended ACLs (use -v to see)"
        else
            echo "Checking for extended ACLs"
        fi
        
#:<<'COMMENT_BLOCK'
        # CCE_79710_0_aliases_acl
        print_extended_acl "/etc/aliases"

        # CCE_79711_8_group_acl
        print_extended_acl "/etc/group"

        # CCE_79712_6_hosts_acl
        print_extended_acl "/etc/hosts"

        # CCE_79713_4_ldap_conf_acl
        print_extended_acl "/etc/openldap/ldap.conf"

        # CCE_79714_2_passwd_acl
        print_extended_acl "/etc/passwd"

        # CCE_79715_9_services_acl
        print_extended_acl "/etc/services"

        # CCE_79716_7_syslog_conf_acl
        print_extended_acl "/etc/syslog.conf"

        # CCE_79717_5_cron_allow_acl
        print_extended_acl "/private/var/at/cron.allow"

        # CCE_79867_8_crontab_files_no_acls
        # CCE_79718_3_cron_deny_acl
        print_extended_acl "/private/var/at/cron.deny"

        # CCE_79719_1_traceroute_acl
        print_extended_acl "/usr/sbin/traceroute"

        # CCE_79720_9_resolve_conf_acl
        print_extended_acl "/etc/resolv.conf"

        # CCE_79729_0_audit_logs_acl
        r_print_extended_acl "$audit_log_path"
#COMMENT_BLOCK

        

#:<<'COMMENT_BLOCK'
        #############NEW

        # CCE_79731_6_audit_tool_executables_acl - checked by 
        # CCE_79861_1_no_acls_system_command_executables
        #print_extended_acl "/usr/sbin/auditd"
        #print_extended_acl "/usr/sbin/audit"
        #print_extended_acl "/usr/sbin/auditreduce"
        #print_extended_acl "/usr/sbin/praudit"

        #CCE_79861_1_no_acls_system_command_executables
        #command to find executables only (end with *) on a single line: ls -1F
        r_print_extended_acl_for_executables "/bin"
        r_print_extended_acl_for_executables "/sbin"
        r_print_extended_acl_for_executables "/usr/bin"
        r_print_extended_acl_for_executables "/usr/sbin"


        #CCE_79867_8_crontab_files_no_acls
        #print_extended_acl "/usr/sbin/cron"
        print_extended_acl "/usr/lib/cron"
        #print_extended_acl "/usr/bin/crontab"
        #print_extended_acl "/private/var/at/cron.deny"


        #CCE_79869_4_etc_shells_no_ACLs - may be checked by CCE_79861_1_no_acls_system_command_executables
        #Default location of these files are in /bin/, but they could be elsewhere.
        #Because of this, these files may be reported more than once.
        local shells=`cat /etc/shells | grep -v "^#" | grep -ve "^$"`
        for shell_file in $shells; do
            print_extended_acl $shell_file
        done

        #CCE_79879_3_files_in_user_home_directories_no_ACLs
        #CCE_79880_1_user_home_directories_no_ACLs
        for user in $user_list; do
            r_print_extended_acl "/Users/$user/"
        done

        #CCE_79911_4_library_files_no_acls
        for lib_file in $lib_files; do
            print_extended_acl "$lib_file"
        done


#COMMENT_BLOCK

        if [ "$acl_files" == "0" ]; then
            echo "No extended ACL files found ($non_acl_files checked)."
        else
            echo "$acl_files extended ACL files found ($[ $non_acl_files + $acl_files ] checked)."
        fi

    fi

    if [ "$set_flag" != "" ]; then
    case $profile_flag in
        "ent")
        echo "setting enterprise acl configs (no-ACLs)";
        set_same_extended_acl
        ;;
        "soho")
        echo "setting soho acl configs (no-ACLs)";
        set_same_extended_acl
        ;;
        "sslf")
        echo "setting sslf acl configs (no-ACLs)";
        set_same_extended_acl
        ;;
        "oem")
        echo "setting oem acl configs (no-ACLs)";
        set_same_extended_acl
        ;;
    esac
    fi
    
# ACLs were successfully removed from the files that had them.
}

print_root_ownership () {
    if [ "$v_flag" != "" ]; then
    if [ -a $1 ]; then
        # shorten long paths and then print, along with UNIX mode bits
        ls -ld $1 |
            awk '{
                if (length($9) >30) {
                    line_buf=sprintf("%s ... %s", substr($9, 1, 10),
                                          substr($9, length($9)-19, 20))
                    printf("\t%-40s%s\n", line_buf, $3);
                }
                else
                    printf("\t%-40s%s\n", $9, $3)
                }'
    else
        echo "NOT FOUND($1)" >&2
    fi
    fi
}

set_root_ownership () {
    if [ -a $1 ]; then
    chown root $1
    else
    if [ "$v_flag" != "" ] ; then
        echo "NOT FOUND($1)" >&2
    fi
    fi
}


print_setuid_bits () {
    if [ "$v_flag" != "" ]; then
        if [ -a "$1" ]; then
        local ls_output=`ls -ld "$1"`
        local file_name=`echo $ls_output | egrep -o '/.*$'`

            # shorten long paths and then print, along with setuid/setgid bits
            echo $ls_output |
            awk -v file_path="$1" '{

                setuid_bit = substr($0, 4, 1);
                setgid_bit = substr($0, 7, 1);
                u_choice = "not-setuid"
                g_choice = "not-setgid"

                if (setuid_bit == "s") u_choice = "SETUID";
                if (setuid_bit == "S") u_choice = "SETUID";
                if (setgid_bit == "s") g_choice = "SETGID";
                if (setgid_bit == "S") g_choice = "SETGID";

                if (length(file_path) >30) {
                    line_buf=sprintf("%s ... %s", substr(file_path, 1, 10),
                                          substr(file_path, length(file_path)-19, 20))
                    printf("\t%-40s%s\t%s\n", line_buf, u_choice, g_choice);
                }
                else
                    printf("\t%-40s%s\t%s\n", file_path, u_choice, g_choice);
            }'
        else
            echo "NOT FOUND($1)" >&2
        fi
    fi

}

#
# $1 : file path
# $2 : user setuid bit to set, either "" for none, or "u"
# $3 : group setgid bit to set, either "" for none, or "g"
#
set_setuid_bits () {
    if [ -a "$1" ]; then
    if [ "$2" == "u" ]; then
        chmod u+s "$1"   #set the bit
    else
        chmod u-s "$1"   #clear the bit
    fi
    if [ "$3" == "g" ]; then
        chmod g+s "$1"   #set the bit
    else
        chmod g-s "$1"   #clear the bit
    fi
    else
    if [ "$v_flag" != "" ] ; then
        echo "NOT FOUND($1)" >&2
    fi
    fi
}

print_group_ownership () {
    if [ "$v_flag" != "" ]; then
    if [ -a $1 ]; then
        # shorten long paths and then print
        ls -ld $1 |
            awk '{
                if (length($9) >30) {
                    line_buf=sprintf("%s ... %s", substr($9, 1, 10),
                                          substr($9, length($9)-19, 20))
                    printf("\t%-40s%s\n", line_buf, $4);
                }
                else
                    printf("\t%-40s%s\n", $9, $4)
                }'
    else
        echo "NOT FOUND($1)" >&2
    fi
    fi
}

set_group_ownership () {
    if [ -a $1 ]; then
    chgrp wheel $1
    else
    if [ "$v_flag" != "" ] ; then
        echo "NOT FOUND($1)" >&2
    fi
    fi
}


######################################################################
CCE_79737_3_require_password_after_screensaver () {
    local doc="CCE_79737_3_require_password_after_screensaver        (manual-test-PASSED)"

    local file=$home_path/Library/Preferences/ByHost/com.apple.screensaver.$hw_uuid.plist
    local file2=$home_path/Library/Preferences/com.apple.screensaver.plist

    local friendly_name="require password after screensaver"
    local status="0" # default value is password not required
    local setting_name=askForPassword

    # if the ByHost file exists, then first try to access it
    if [ -e $file ]; then

        local key_exists=`defaults read $file | grep -w "$setting_name" | wc -l`
        if [ $key_exists == 1 ]; then
            status=`defaults read $file $setting_name`
        # if the key is not present, then try to read file2
        else
            if [ -e $file2 ]; then
                key_exists=`defaults read $file2 | grep -w "$setting_name" | wc -l`
                if [ $key_exists == 1 ]; then
                    status=`defaults read $file2 $setting_name`
                    file=$file2  # since $file2 has the key, change that one
                fi

            fi
        fi
    #if ByHost file doesn't exist, try to access file2
    elif [ -e $file2 ]; then
        key_exists=`defaults read $file2 | grep -w "$setting_name" | wc -l`
        if [ $key_exists == 1 ]; then
            status=`defaults read $file2 $setting_name`
            file=$file2  # since $file2 has the key, change that one
        fi
    # else do nothing, since neither file exists, and the default value will be used
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $status == "1" ]; then
            echo "$friendly_name is enabled";
        else
            echo "$friendly_name is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then

        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ $status != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -int 1
                
                    add_processes_to_kill_list Dock cfprefsd
                
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ $status != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -int 1
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ $status != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -int 1
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $status != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -int 0
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi


# 10.10
# Restart required to take effect.

# Note:
# This file exists in both Preferences and Preferences/ByHost
# If the key/value pair is not present in the ByHost .plist file, then the other one
# is checked. The entry in the ByHost file takes precedence if it exists. If the setting
# is changed in the GUI, the entry is removed from the ByHost file.
# File owner/group changed to root wheel.
}



######################################################################
CCE_79736_5_screensaver_grace_period () {
    local doc="CCE_79736_5_screensaver_grace_period                 (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/ByHost/com.apple.screensaver.$hw_uuid.plist
    local file2=$home_path/Library/Preferences/com.apple.screensaver.plist

    local friendly_name="screensaver grace period"
    local delay="0" # default value is does not exist
    local target_delay=5 # number of seconds to set grace period to

    local setting_name=askForPasswordDelay

    # if the ByHost file exists, then first try to access it
    if [ -e $file ]; then
        local key_exists=`defaults read $file | grep "$setting_name" | wc -l`

        if [ $key_exists == 1 ]; then
            delay=`defaults read $file $setting_name`
        # if the key is not present, then try to read file2
        else
            if [ -e $file2 ]; then
                key_exists=`defaults read $file2 | grep "$setting_name" | wc -l`
                if [ $key_exists == 1 ]; then
                    delay=`defaults read $file2 $setting_name`
                    file=$file2  # since $file2 has the key, change that one
                fi

            fi
        fi
    #if ByHost file doesn't exist, try to access file2
    elif [ -e $file2 ]; then
        key_exists=`defaults read $file2 | grep "$setting_name" | wc -l`
        if [ $key_exists == 1 ]; then
            delay=`defaults read $file2 $setting_name`
            file=$file2  # since $file2 has the key, change that one
        fi
    # else do nothing, since neither file exists, and the default value will be used
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $delay != "0" ]; then
            echo "$delay seconds $friendly_name";
        else
            echo "$friendly_name is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $delay != "$target_delay" ]; then
                    echo "setting screensaver grace period to $target_delay seconds";
                    defaults write $file $setting_name -int $target_delay
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already set to $target_delay seconds"
                fi
                ;;
            "soho")
                if [ $delay != "$target_delay" ]; then
                    echo "setting screensaver grace period to $target_delay seconds";
                    defaults write $file $setting_name -int $target_delay
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already set to $target_delay seconds"
                fi
                ;;
            "sslf")
                if [ $delay != "$target_delay" ]; then
                    echo "setting screensaver grace period to $target_delay seconds";
                    defaults write $file $setting_name -int $target_delay
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already set to $target_delay seconds"
                fi
                ;;
            "oem")
                if [ $delay != "0" ]; then
                    echo "setting screensaver grace period to 0 seconds";
                    defaults write $file $setting_name -int 0
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

# OS X 10.10 - tested
# Setting does not apply even after user is logged out and back in. The GUI doesn't
# reflect the changed setting and it does not use the new grace period value.
# After restarting the VM, the setting appears in the GUI and works with manual testing.
}



######################################################################
CCE_79738_1_start_screen_saver_hot_corner () {
    local doc="CCE_79738_1_start_screen_saver_hot_corner      (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.dock.plist

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local active=0

    # suppress error message in case the domain/default pair doesn't exist
    local btm_left=`defaults read $file wvous-bl-corner 2> /dev/null`
    local btm_right=`defaults read $file wvous-br-corner 2> /dev/null`
    local top_left=`defaults read $file wvous-tl-corner 2> /dev/null`
    local top_right=`defaults read $file wvous-tr-corner 2> /dev/null`

    # 5 represents start screen saver
    if [ "$btm_left" == "5" ] || [ "$btm_right" == "5" ] || [ "$top_left" == "5" ] ||
       [ "$top_right" == "5" ]; then
        active=1
    fi


    if [ "$print_flag" != "" ]; then
        if [ $active == "0" ]; then
            echo "no screen saver hot corners are active";
        else
            echo "at least one screen saver hot corner is active"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $active == 0 ]; then
                    echo "setting start screen saver to bottom-left hot corner";
                    defaults write $file wvous-bl-corner -int 5
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "start screen saver hot corner is already set"
                fi
                ;;
            "soho")
                if [ $active == 0 ]; then
                    echo "setting start screen saver to bottom-left hot corner";
                    defaults write $file wvous-bl-corner -int 5
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "start screen saver hot corner is already set"
                fi
                ;;
            "sslf")
                if [ $active == 0 ]; then
                    echo "setting start screen saver to bottom-left hot corner";
                    defaults write $file wvous-bl-corner -int 5
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "start screen saver hot corner is already set"
                fi
                ;;
            "oem")
                if [ "$btm_left" == "5" ]; then
                    echo "removing action from bottom-left hot corner";
                    defaults write $file wvous-bl-corner -int 1
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "start screen saver bottom-left hot corner is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

# OS X 10.10
# Requires restart to take effect. If this value is set through the script and the
# user only logs out and back in, the setting goes back to its original value before 
# making the change. No command key modifiers were applied when enabling this.
}


# if any corners are set to display sleep, set them to perform no action instead
disable_display_sleep_corners () {

    local btm_left=$1
    local btm_right=$2
    local top_left=$3
    local top_right=$4

    if [ "$btm_left" == "10" ]; then
        defaults write $file wvous-bl-corner -int 1
        echo "disabling bottom-left display sleep corner.";
    fi

    if [ "$btm_right" == "10" ]; then
        defaults write $file wvous-br-corner -int 1
        echo "disabling bottom-right display sleep corner.";
    fi

    if [ "$top_left" == "10" ]; then
        defaults write $file wvous-tl-corner -int 1
        echo "disabling top-left display sleep corner.";
    fi

    if [ "$top_right" == "10" ]; then
        defaults write $file wvous-tr-corner -int 1
        echo "disabling top-right display sleep corner.";
    fi
}


######################################################################
CCE_79739_9_no_put_to_sleep_corner () {
    local doc="CCE_79739_9_no_put_to_sleep_corner      (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.dock.plist

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local active=0

    # default value is 1, meaning no action
    local btm_left=1
    local btm_right=1
    local top_left=1
    local top_right=1

    if [ -e $file ]; then
    # suppress error message in case the domain/default pair doesn't exist
        btm_left=`defaults read $file wvous-bl-corner 2> /dev/null`
        btm_right=`defaults read $file wvous-br-corner 2> /dev/null`
        top_left=`defaults read $file wvous-tl-corner 2> /dev/null`
        top_right=`defaults read $file wvous-tr-corner 2> /dev/null`
    fi

    # 10 represents start display sleep
    if [ "$btm_left" == "10" ] || [ "$btm_right" == "10" ] || [ "$top_left" == "10" ] ||
       [ "$top_right" == "10" ]; then
        active=1
    fi


    if [ "$print_flag" != "" ]; then
        if [ $active == "0" ];then echo "no display sleep hot corners are active";
            else
            echo "at least one display sleep hot corner is active"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        if [ $active == 0 ]; then
            echo "no display sleep hot corners are active"
        else
            # All profiles have sleep corner disabled
            case $profile_flag in
                "ent")
                    disable_display_sleep_corners "$btm_left" "$btm_right" "$top_left" "$top_right"
                    add_processes_to_kill_list Dock cfprefsd
                    ;;
                "soho")
                    disable_display_sleep_corners "$btm_left" "$btm_right" "$top_left" "$top_right"
                    add_processes_to_kill_list Dock cfprefsd
                    ;;
                "sslf")
                    disable_display_sleep_corners "$btm_left" "$btm_right" "$top_left" "$top_right"
                    add_processes_to_kill_list Dock cfprefsd
                    ;;
                "oem")
                    disable_display_sleep_corners "$btm_left" "$btm_right" "$top_left" "$top_right"
                    add_processes_to_kill_list Dock cfprefsd
                    ;;
            esac

            if [ -e "$file" ]; then
                chown $owner:$group $file #restore original owner/group
            fi
        fi
    fi

# NEEDS_REAL_HARDWARE

# Tested on OS X 10.10 and worked as expected. When killing the processes, it
# applied immediately.
}


# if any modifier keys exist for a screen saver hot corner, set the modifier to none
disable_screen_saver_modifier_keys () {
    local file=$home_path/Library/Preferences/com.apple.dock.plist
    local bl_disable=$1
    local br_disable=$2
    local tl_disable=$3
    local tr_disable=$4
    local active_corner=$5

    # check each corner and remove modifier key if necessary
    if [ $bl_disable == "1" ]; then
        defaults write $file wvous-bl-modifier -int 0
    fi

    if [ $br_disable == "1" ]; then
        defaults write $file wvous-br-modifier -int 0
    fi

    if [ $tl_disable == "1" ]; then
        defaults write $file wvous-tl-modifier -int 0
    fi

    if [ $tr_disable == "1" ]; then
        defaults write $file wvous-tr-modifier -int 0
    fi

    # display message if any screen saver corner had a modifier key removed
    if [ $active == 1 ]; then
        echo "Disabling all hot corner start screen saver modifier keys."
    fi
}


######################################################################
CCE_79740_7_no_modifier_keys_for_screen_saver_start () {

    local doc="CCE_79740_7_no_modifier_keys_for_screen_saver_start      (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.dock.plist

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local active=0

    # default value is 1
    local btm_left=1
    local btm_right=1
    local top_left=1
    local top_right=1

    # default value is 0
    local btm_left_modifier=0
    local btm_right_modifier=0
    local top_left_modifier=0
    local top_right_modifier=0

    if [ -e $file ]; then
        # suppress error message in case the domain/default pair doesn't exist
        btm_left=`defaults read $file wvous-bl-corner 2> /dev/null`
        btm_right=`defaults read $file wvous-br-corner 2> /dev/null`
        top_left=`defaults read $file wvous-tl-corner 2> /dev/null`
        top_right=`defaults read $file wvous-tr-corner 2> /dev/null`

        btm_left_modifier=`defaults read $file wvous-bl-modifier 2> /dev/null`
        btm_right_modifier=`defaults read $file wvous-br-modifier 2> /dev/null`
        top_left_modifier=`defaults read $file wvous-tl-modifier 2> /dev/null`
        top_right_modifier=`defaults read $file wvous-tr-modifier 2> /dev/null`
    fi

    # used for determining if a modifier needs to be disabled
    local btm_left_disable=0
    local btm_right_disable=0
    local top_left_disable=0
    local top_right_disable=0

    # 5 represents start screen saver
    # make sure the modifier is not "0" or ""
    if [ "$btm_left" == "5" ] && [ "$btm_left_modifier" != "0" ] &&
       [ "$btm_left_modifier" != "" ]; then
        btm_left_disable=1
    fi

    if [ "$btm_right" == "5" ] && [ "$btm_right_modifier" != "0" ] &&
       [ "$btm_right_modifier" != "" ]; then
        btm_right_disable=1
    fi

    if [ "$top_left" == "5" ] && [ "$top_left_modifier" != "0" ] &&
       [ "$top_left_modifier" != "" ]; then
        top_left_disable=1
    fi

    if [ "$top_right" == "5" ] && [ "$top_right_modifier" != "0" ] &&
       [ "$top_right_modifier" != "" ]; then
        top_right_disable=1
    fi

    #set active if any modifiers are found on screen saver hot corners
    if [ $btm_left_disable == 1 ] || [ $btm_right_disable == 1 ] ||
       [ $top_left_disable == 1 ] || [ $top_right_disable == 1 ]; then
        active=1
    fi


    if [ "$print_flag" != "" ]; then
        if [ $active == "0" ]; then
            echo "no modifier keys for screen saver hot corners are active";
        else
            echo "at least one screen saver hot corner modifier key is active"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        if [ $active == 0 ]; then
            echo "no modifier keys for screen saver hot corners are active";
        else
            # All profiles have sleep corner disabled
            case $profile_flag in
                "ent")
                    disable_screen_saver_modifier_keys "$btm_left_disable" "$btm_right_disable" "$top_left_disable" "$top_right_disable" "$active"

                    add_processes_to_kill_list Dock cfprefsd
                    ;;
                "soho")
                    disable_screen_saver_modifier_keys "$btm_left_disable" "$btm_right_disable" "$top_left_disable" "$top_right_disable" "$active"

                    add_processes_to_kill_list Dock cfprefsd
                    ;;
                "sslf")
                    disable_screen_saver_modifier_keys "$btm_left_disable" "$btm_right_disable" "$top_left_disable" "$top_right_disable" "$active"

                    add_processes_to_kill_list Dock cfprefsd
                    ;;
                "oem")
                    disable_screen_saver_modifier_keys "$btm_left_disable" "$btm_right_disable" "$top_left_disable" "$top_right_disable" "$active"

                    add_processes_to_kill_list Dock cfprefsd
                    ;;
            esac

            if [ -e "$file" ]; then
                chown $owner:$group $file #restore original owner/group
            fi
        fi
    fi

# OS X 10.10
# Works immediately; no restart or logout required with killing processes.
}


# if any disable screen saver corners exist, set the corner to perform no action
turn_off_prevent_screen_saver_corners () {

    local btm_left=$1
    local btm_right=$2
    local top_left=$3
    local top_right=$4

    local corner_changed=""
    local verbose_message=""

    if [ "$btm_left" == "6" ]; then
        defaults write $file wvous-bl-corner -int 1
        corner_changed="true"
        verbose_message="disabling bottom-left disable screen saver corner.";
    fi

    if [ "$btm_right" == "6" ]; then
        defaults write $file wvous-br-corner -int 1
        corner_changed="true"
        verbose_message="$verbose_message\ndisabling bottom-right disable screen saver corner.";
    fi

    if [ "$top_left" == "6" ]; then
        defaults write $file wvous-tl-corner -int 1
        corner_changed="true"
        verbose_message="$verbose_message\ndisabling top-left disable screen saver corner.";
    fi

    if [ "$top_right" == "6" ]; then
        defaults write $file wvous-tr-corner -int 1
        corner_changed="true"
        verbose_message="$verbose_message\ndisabling top-right disable screen saver corner.";
    fi

    if [ "$v_flag" != "" ]; then
        echo "$verbose_message"

    elif [ "$corner_changed" == "true" ]; then
        echo "disabling at least one disable screen saver corner.";

    else
        echo "no disable screen saver corners have been removed.";
    fi
}

######################################################################
CCE_79743_1_no_prevent_screensaver_corner () {
    local doc="CCE_79743_1_no_prevent_screensaver_corner      (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.dock.plist

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local active=0

    # default value is 1, meaning no action
    local btm_left=1
    local btm_right=1
    local top_left=1
    local top_right=1

    if [ -e $file ]; then
        # suppress error message in case the domain/default pair doesn't exist
        btm_left=`defaults read $file wvous-bl-corner 2> /dev/null`
        btm_right=`defaults read $file wvous-br-corner 2> /dev/null`
        top_left=`defaults read $file wvous-tl-corner 2> /dev/null`
        top_right=`defaults read $file wvous-tr-corner 2> /dev/null`
    fi


    # 6 represents prevent screen saver
    if [ "$btm_left" == "6" ] || [ "$btm_right" == "6" ] || [ "$top_left" == "6" ] ||
       [ "$top_right" == "6" ]; then
        active=1
    fi


    if [ "$print_flag" != "" ]; then
        if [ $active == "0" ];then
            echo "no disable screen saver hot corners are active";
        else
            echo "at least one disable screen saver hot corner is active"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        if [ $active == 0 ]; then
            echo "no disable screen saver hot corners are active";
        else

            # All profiles have prevent screen saver corners disabled
            case $profile_flag in
                "ent")
                    turn_off_prevent_screen_saver_corners "$btm_left" "$btm_right" "$top_left" "$top_right"

                    add_processes_to_kill_list Dock cfprefsd
                    ;;
                "soho")
                    turn_off_prevent_screen_saver_corners "$btm_left" "$btm_right" "$top_left" "$top_right"

                    add_processes_to_kill_list Dock cfprefsd
                    ;;
                "sslf")
                    turn_off_prevent_screen_saver_corners "$btm_left" "$btm_right" "$top_left" "$top_right"

                    add_processes_to_kill_list Dock cfprefsd
                    ;;
                "oem")
                    turn_off_prevent_screen_saver_corners "$btm_left" "$btm_right" "$top_left" "$top_right"

                    add_processes_to_kill_list Dock cfprefsd
                    ;;
            esac


            if [ -e "$file" ]; then
                chown $owner:$group $file #restore original owner/group
            fi
        fi
    fi

# OS X 10.10
# Works immediately; no restart or logout required with killing processes.
}



######################################################################
CCE_79754_8_desktop_idle_time () {
    local doc="CCE_79754_8_desktop_idle_time           (manual-test-PASSED)"

    local file=$home_path/Library/Preferences/ByHost/com.apple.screensaver.$hw_uuid.plist
    local file2=$home_path/Library/Preferences/com.apple.screensaver.plist

    local setting_value=1200 #assume default of 1200 if no value is found in config files
    local target_value=1200 #desired value for all profiles
    local setting_name=idleTime

    # if the ByHost file exists, then first try to access it
    if [ -e $file ]; then
        local key_exists=`defaults read $file | grep "$setting_name" | wc -l`
        if [ $key_exists == 1 ]; then
            setting_value=`defaults read $file $setting_name`
        # if the key is not present, then try to read file2
        else
            if [ -e $file2 ]; then
                key_exists=`defaults read $file2 | grep "$setting_name" | wc -l`
                if [ $key_exists == 1 ]; then
                    setting_value=`defaults read $file2 $setting_name`
                    file=$file2  # since $file2 has the key, change that one
                fi

            fi
        fi
    #if ByHost file doesn't exist, try to access file2
    elif [ -e $file2 ]; then
        key_exists=`defaults read $file2 | grep "$setting_name" | wc -l`
        if [ $key_exists == 1 ]; then
            setting_value=`defaults read $file2 $setting_name`
            file=$file2  # since $file2 has the key, change that one
        fi
    # else do nothing, since neither file exists, and the default value will be used
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then

        if [ $setting_value == 1200 ]; then
            echo "desktop idle time before screensaver is default value of 1200 seconds (20 minutes)";
        elif [ $setting_value != 0 ]; then
            echo "desktop idle time before screensaver is $setting_value seconds";
        else
            echo "screensaver is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then

        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "$setting_value" -gt "$target_value" -o "$setting_value" -eq 0 ]; then
                    echo "setting start screensaver after 20 minutes of idle time";
                    defaults write "$file" idleTime -int "$target_value"

                    add_processes_to_kill_list Dock cfprefsd
                
                else
                    echo "screensaver already starts after 20 minutes or less of idle time"
                fi
                ;;
            "soho")
                if [ "$setting_value" -gt "$target_value" -o "$setting_value" -eq 0 ]; then
                    echo "setting start screensaver after 20 minutes of idle time";
                    defaults write "$file" idleTime -int "$target_value"

                    add_processes_to_kill_list Dock cfprefsd

                else
                    echo "screensaver already starts after 20 minutes or less of idle time"
                fi
                ;;
            "sslf")
                if [ "$setting_value" -gt "$target_value" -o "$setting_value" -eq 0 ]; then
                    echo "setting start screensaver after 20 minutes of idle time";
                    defaults write "$file" idleTime -int "$target_value"

                    add_processes_to_kill_list Dock cfprefsd

                else
                    echo "screensaver already starts after 20 minutes or less of idle time"
                fi
                ;;
            "oem")
                if [ "$setting_value" != 1200 ]; then
                    echo "setting start screensaver after 20 minutes of idle time";
                    defaults write "$file" idleTime -int 1200
                    add_processes_to_kill_list Dock cfprefsd

                else
                    echo "screensaver already starts after 20 minutes of idle time"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#NOTE: If the screensaver is set to a value that is not an option through the GUI (never, 
#1, 2, 5, 10, 20, 30, 60 minutes), the value will not stay after the preferences window 
#is opened. It will change automatically to the default value of 20 minutes.

#DEPENDENT on value in CCE_79790_2_enable_display_sleep
#If the screen goes to sleep before the computer starts its screensaver and locks,
#there is a false sense of security.

#OS X 10.10
#Takes effect immediately with process killing.
}


######################################################################
CCE_79749_8_password_complex_passwords_alphabetic_char () {
    local doc="CCE_79749_8_password_complex_passwords_alphabetic_char      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="number of alphabetic characters required in passwords"
    local policy_category="policyCategoryPasswordContent"
    local policy_content="policyAttributePassword matches \'(.*[A-Za-z].*)\'"
    local policy_identifier="com.apple.policy.legacy.requiresAlpha"
    local parameter_name="minimumAlphaCharacters"
    local parameter_value="1"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists=`$plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null`
    
    local current_value=`defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//"`
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are cleared before running with set flag
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "soho")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "sslf")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "oem")
                echo "Resetting global policies to default (none)"
                ;;
        esac
        
        pwpolicy -setaccountpolicies "$temp_file" &> /dev/null
    fi    

    #Rules must be added to the policy one-by-one, and using the proper array index. If
    #it is not incremented after each rule, the rules will overwrite one another.
    pw_content_index=$(( pw_content_index + 1 ))

    #remove temp file created here
    rm "$temp_file"

#OS X 10.10
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79750_6_password_complex_passwords_numeric_char () {
    local doc="CCE_79750_6_password_complex_passwords_numeric_char       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="number of numeric characters required in passwords"
    local policy_category="policyCategoryPasswordContent"
    local policy_content="policyAttributePassword matches \'(.*[0-9].*)\'"
    local policy_identifier="com.apple.policy.legacy.requiresNumeric"
    local parameter_name="minimumNumericCharacters"
    local parameter_value="1"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists=`$plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null`
    
    local current_value=`defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//"`
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are cleared before running with set flag
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "soho")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "sslf")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "oem")
                echo "Resetting global policies to default (none)"
                ;;
        esac
        
        pwpolicy -setaccountpolicies "$temp_file" &> /dev/null
    fi    
    
    #Rules must be added to the policy one-by-one, and using the proper array index. If
    #it is not incremented after each rule, the rules will overwrite one another.
    pw_content_index=$(( pw_content_index + 1 ))

    #remove temp file created here
    rm "$temp_file"

#OS X 10.10
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79751_4_password_complex_passwords_symbolic_char () {
    local doc="CCE_79751_4_password_complex_passwords_symbolic_char       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="number of symbolic characters required in passwords"
    local policy_category="policyCategoryPasswordContent"
    local policy_content="policyAttributePassword matches \'.*[^0-9a-zA-Z].*\'"
    local policy_identifier="com.apple.policy.legacy.requiresSymbolic"
    local parameter_name="minimumSymbolicCharacters"
    local parameter_value="1"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists=`$plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null`
    
    local current_value=`defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//"`
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are cleared before running with set flag
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "soho")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "sslf")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "oem")
                echo "Resetting global policies to default (none)"
                ;;
        esac
        
        pwpolicy -setaccountpolicies "$temp_file" &> /dev/null
    fi    

    #Rules must be added to the policy one-by-one, and using the proper array index. If
    #it is not incremented after each rule, the rules will overwrite one another.
    pw_content_index=$(( pw_content_index + 1 ))

    #remove temp file created here
    rm "$temp_file"

#OS X 10.10
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79759_7_password_uppercase_and_lowercase () {
    local doc="CCE_79759_7_password_uppercase_and_lowercase       (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="number of upper and lowercase characters required in passwords"
    local policy_category="policyCategoryPasswordContent"
    local policy_content="policyAttributePassword matches \'(.*[a-z].*[A-Z].*)|(.*[A-Z].*[a-z].*)\'"
    local policy_identifier="com.apple.policy.legacy.requiresMixedCase"
    local parameter_name="minimumMixedCaseInstances"
    local parameter_value="1"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists=`$plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null`
    
    local current_value=`defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//"`
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are cleared before running with set flag
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "soho")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "sslf")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "oem")
                echo "Resetting global policies to default (none)"
                ;;
        esac
        
        pwpolicy -setaccountpolicies "$temp_file" &> /dev/null
    fi    

    #Rules must be added to the policy one-by-one, and using the proper array index. If
    #it is not incremented after each rule, the rules will overwrite one another.
    pw_content_index=$(( pw_content_index + 1 ))

    #remove temp file created here
    rm "$temp_file"
    
#OS X 10.10
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79747_2_password_enforce_password_history_restriction () {
    local doc="CCE_79747_2_password_enforce_password_history_restriction       (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"


    local friendly_name="number of remembered passwords"
    local policy_category="policyCategoryPasswordContent"
    local policy_content="none policyAttributePasswordHashes in policyAttributePasswordHistory"
    local policy_identifier="com.apple.policy.legacy.usingHistory"
    local parameter_name="policyAttributePasswordHistoryDepth"
    local parameter_value="15"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists=`$plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null`
    
    local current_value=`defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//"`
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are cleared before running with set flag
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "soho")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "sslf")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "oem")
                echo "Resetting global policies to default (none)"
                ;;
        esac
        
        pwpolicy -setaccountpolicies "$temp_file" &> /dev/null
    fi    

    #Rules must be added to the policy one-by-one, and using the proper array index. If
    #it is not incremented after each rule, the rules will overwrite one another.
    pw_content_index=$(( pw_content_index + 1 ))

    #remove temp file created here
    rm "$temp_file"

#OS X 10.10
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79761_3_password_minimum_length () {
    local doc="CCE_79761_3_password_minimum_length       (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="minimum password length"
    local policy_category="policyCategoryPasswordContent"
    local policy_content="policyAttributePassword matches \'(.){12,}\'"
    local policy_identifier="com.apple.policy.legacy.minChars"
    local parameter_name="minimumChars"
    local parameter_value="12"
    
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists=`$plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null`
    
    local current_value=`defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//"`
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are cleared before running with set flag
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "soho")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "sslf")
                echo "setting $friendly_name to $parameter_value"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_content_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "oem")
                echo "Resetting global policies to default (none)"
                ;;
        esac
        
        pwpolicy -setaccountpolicies "$temp_file" &> /dev/null
    fi    

    #Rules must be added to the policy one-by-one, and using the proper array index. If
    #it is not incremented after each rule, the rules will overwrite one another.
    pw_content_index=$(( pw_content_index + 1 ))

    #remove temp file created here
    rm "$temp_file"


#OS X 10.10
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79762_1_password_maximum_age () {
    local doc="CCE_79762_1_password_maximum_age       (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="maximum password age"
    local timeUnit="days"
    local policy_category="policyCategoryPasswordChange"
    local policy_content="policyAttributeCurrentTime > policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)"
    local policy_identifier="com.apple.policy.legacy.maxMinutesUntilChangePassword"
    local parameter_name="policyAttributeExpiresEveryNDays"
    local parameter_value="60"
    
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists=`$plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null`
    
    local current_value=`defaults read "$temp_file" 2> /dev/null | egrep "^( *$parameter_name)" |  sed -E "s/ *$parameter_name *= *//" | sed "s/;//"`
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value $timeUnit"
        fi
    fi

    #global policies are cleared before running with set flag
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "setting $friendly_name to $parameter_value $timeUnit"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "soho")
                echo "setting $friendly_name to $parameter_value $timeUnit"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "sslf")
                echo "setting $friendly_name to $parameter_value $timeUnit"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_change_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                ;;
            "oem")
                echo "Resetting global policies to default (none)"
                ;;
        esac
        
        pwpolicy -setaccountpolicies "$temp_file" &> /dev/null
    fi    

    #Rules must be added to the policy one-by-one, and using the proper array index. If
    #it is not incremented after each rule, the rules will overwrite one another.
    pw_change_index=$(( pw_change_index + 1 ))

    #remove temp file created here
    rm "$temp_file"

#OS X 10.10
#User is forced to change their password after the specified period.
}


######################################################################
CCE_79767_0_disable_guest_user () {
    local doc="CCE_79767_0_disable_guest_user       (manual-test-PASSED)"

    local file=/Library/Preferences/com.apple.loginwindow.plist

    local status=`defaults read $file | grep GuestEnabled | wc -l`
    local is_guest_enabled=0

    if [ $status != "0" ]; then
        is_guest_enabled=`defaults read $file GuestEnabled`
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
        # GuestEnabled can be either 0 or false
        if [ $is_guest_enabled == "false" ] || [ $is_guest_enabled == "0" ]; then
            echo "guest account is disabled.";
            is_guest_enabled=0

        else
            echo "guest account is enabled.";
        fi
    fi

    if [ "$set_flag" != "" ]; then

    case $profile_flag in
        "ent")
        echo "disabling guest user account";
                dscl . -create /Users/Guest AuthenticationAuthority ";basic;"
                dscl . -create /Users/Guest passwd "*"
                dscl . -create /Users/Guest UserShell "/sbin/nologin"
        defaults write $file GuestEnabled -int 0
        ;;
        "soho")
        echo "disabling guest user account";
        dscl . -create /Users/Guest AuthenticationAuthority ";basic;"
                dscl . -create /Users/Guest passwd "*"
                dscl . -create /Users/Guest UserShell "/sbin/nologin"
        defaults write $file GuestEnabled -int 0
        ;;
        "sslf")
        echo "disabling guest user account";
        dscl . -create /Users/Guest AuthenticationAuthority ";basic;"
                dscl . -create /Users/Guest passwd "*"
                dscl . -create /Users/Guest UserShell "/sbin/nologin"
        defaults write $file GuestEnabled -int 0
        ;;
        "oem")
        echo "disabling guest user account";
        dscl . -create /Users/Guest AuthenticationAuthority ";basic;"
                dscl . -create /Users/Guest passwd "*"
                dscl . -create /Users/Guest UserShell "/sbin/nologin"
        defaults write $file GuestEnabled -int 0
        ;;
    esac
    fi



# 10.10 testing
# After disabling with dscl, account was still selectable before restart, but could not
# be accessed. After restart, the guest account was no longer visible.

# Actual process:
# Enable guest user through GUI, restart, run dscl commands.

# Result:
# Guest user was still showing disabled in GUI, but guest user was available to
# be logged into even after restarting. However, the plist file correctly reported that
# the guest user account was enabled.
# After running dscl commands and before restarting, the guest user still shows up, but
# prompts for a password when trying to login. After restarting, the guest account is no
# longer selectable.

}



######################################################################
CCE_79770_4_require_admin_password_for_system_prefs () {
    local doc="CCE_79770_4_require_admin_password_for_system_prefs     (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local script_dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
    
    
    local setting_value=""
    local temp_file="${script_dir}/tmpsysprefs.plist"
    local db_table="system.preferences"
    local friendly_name="admin password required for system preferences"
    
    # get the contents of the table containing the shared key
    security authorizationdb read "$db_table" > "$temp_file" 2> /dev/null
    
    # get the value of the shared key
    setting_value=`defaults read "$temp_file" shared`
    
    if [ "$print_flag" != "" ]; then
        # if shared is true, settings can be accessed by all users because
        # no password is required
        if [ "$setting_value" == "false" -o "$setting_value" == "0" ]; then
            echo "$friendly_name is enabled.";

        else
            echo "$friendly_name is disabled.";
        fi
    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$setting_value" == "true" -o "$setting_value" == "1" ]; then
                    echo "enabling $friendly_name";
                
                    # write the new value to the temp plist and then write the plist
                    # to the system.preferences table
                    defaults write "$temp_file" shared -bool false
                    security authorizationdb write "$db_table" < "$temp_file" 2> /dev/null
                
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ "$setting_value" == "true" -o "$setting_value" == "1" ]; then
                    echo "enabling $friendly_name";
                
                    # write the new value to the temp plist and then write the plist
                    # to the system.preferences table
                    defaults write "$temp_file" shared -bool false
                    security authorizationdb write "$db_table" < "$temp_file" 2> /dev/null
                
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ "$setting_value" == "true" -o "$setting_value" == "1" ]; then
                    echo "enabling $friendly_name";
                
                    # write the new value to the temp plist and then write the plist
                    # to the system.preferences table
                    defaults write "$temp_file" shared -bool false
                    security authorizationdb write "$db_table" < "$temp_file" 2> /dev/null
                
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ "$setting_value" == "true" -o "$setting_value" == "1" ]; then
                    echo "enabling $friendly_name";
                
                    # write the new value to the temp plist and then write the plist
                    # to the system.preferences table
                    defaults write "$temp_file" shared -bool false
                    security authorizationdb write "$db_table" < "$temp_file" 2> /dev/null
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac
    fi

    rm -f "$temp_file"


# Affected settings pages:
# Sharing
# Energy Saver
# Print & Scan
# Date & Time
# Time Machine
# Startup disk

# Testing - OS X 10.10
# Using the "security" program, changes to this setting can be made using the 
# system.preferences key. No restart is required, and setting takes effect immediately.
}


######################################################################
CCE_79771_2_no_guest_access_to_shared_folders () {
    local doc="CCE_79771_2_no_guest_access_to_shared_folders	    (manual-test-PASSED)"

    # two settings exist for file file sharing: AFP and SMB file sharing
    # these are used for the AFP file sharing setting
    local afp_file="/Library/Preferences/com.apple.AppleFileServer.plist"
    local afp_setting_value="0" # default 10.10 value is guest sharing disabled

    local afp_setting_name="guestAccess"
    local afp_exists=""

    # setting for SMB file sharing
    local smb_file="/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist"
    local smb_setting_value="0" # default 10.10 value is guest sharing disabled

    local smb_setting_name="AllowGuestAccess"
    local smb_exists=""

    if [ -e $afp_file ]; then
        afp_exists=`defaults read $afp_file | grep "$afp_setting_name" | wc -l`
        if [ $afp_exists == 1 ]; then
            afp_setting_value=`defaults read $afp_file $afp_setting_name`
        fi
    fi

    if [ -e $smb_file ]; then
        smb_exists=`defaults read $smb_file | grep "$smb_setting_name" | wc -l`
        if [ $smb_exists == 1 ]; then
            smb_setting_value=`defaults read $smb_file $smb_setting_name`
        fi
    fi


    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then

        if [ $afp_setting_value == 0 ] && [ $smb_setting_value == 0 ]; then
            echo "guest folder sharing is disabled.";

        else
            echo "guest folder sharing is enabled.";
        fi
    fi

    if [ "$set_flag" != "" ]; then

        case $profile_flag in
            "ent")
                echo "disabling guest access to shared folders";
                if [ $afp_setting_value == "1" ]; then
                    defaults write $afp_file $afp_setting_name -bool false
                    if [ "$v_flag" != "" ]; then
                        echo "disabling guest AFP file sharing"
                    fi
                    chown $owner:$group $afp_file #restore original owner/group
                fi

                if [ $smb_setting_value == "1" ]; then
                    defaults write $smb_file $smb_setting_name -bool false
                    if [ "$v_flag" != "" ]; then
                        echo "disabling guest SMB file sharing"
                    fi
                    chown $owner:$group $smb_file #restore original owner/group
                fi
                ;;
            "soho")
                echo "disabling guest access to shared folders";
                if [ $afp_setting_value == "1" ]; then
                    defaults write $afp_file $afp_setting_name -bool false
                    if [ "$v_flag" != "" ]; then
                        echo "disabling guest AFP file sharing"
                    fi
                    chown $owner:$group $afp_file #restore original owner/group
                fi

                if [ $smb_setting_value == "1" ]; then
                    defaults write $smb_file $smb_setting_name -bool false
                    if [ "$v_flag" != "" ]; then
                        echo "disabling guest SMB file sharing"
                    fi
                    chown $owner:$group $smb_file #restore original owner/group
                fi
                ;;
            "sslf")
                echo "disabling guest access to shared folders";
                if [ $afp_setting_value == "1" ]; then
                    defaults write $afp_file $afp_setting_name -bool false
                    if [ "$v_flag" != "" ]; then
                        echo "disabling guest AFP file sharing"
                    fi
                    chown $owner:$group $afp_file #restore original owner/group
                fi

                if [ $smb_setting_value == "1" ]; then
                    defaults write $smb_file $smb_setting_name -bool false
                    if [ "$v_flag" != "" ]; then
                        echo "disabling guest SMB file sharing"
                    fi
                    chown $owner:$group $smb_file #restore original owner/group
                fi
                ;;
            "oem")
                local bool_value="false"
                local int_value="0"


                echo "disabling guest access to shared folders";
                if [ $afp_setting_value == "$int_value" ]; then
                    defaults write $afp_file $afp_setting_name -bool "$bool_value"
                    if [ "$v_flag" != "" ]; then
                        echo "disabling guest AFP file sharing"
                    fi
                    chown $owner:$group $afp_file #restore original owner/group
                elif [ "$v_flag" != "" ]; then
                    echo "AFP file sharing is already disabled"
                fi

                if [ $smb_setting_value == "$int_value" ]; then
                    defaults write $smb_file $smb_setting_name -bool "$bool_value"
                    if [ "$v_flag" != "" ]; then
                        echo "disabling guest SMB file sharing"
                    fi
                    chown $owner:$group $smb_file #restore original owner/group
                elif [ "$v_flag" != "" ]; then
                    echo "SMB file sharing is already disabled"
                fi
                ;;
        esac
    fi


# Testing - OS X 10.10
# After running the script and disabling remote guest sharing, the remote user could no
# longer connect as a guest, and access to shared folders was denied.
# Guest folder sharing is not enabled by default. Restart is required to take effect.
}


######################################################################
CCE_79773_8_login_window_disable_input_menu () {
    local doc="CCE_79773_8_login_window_disable_input_menu      (manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.loginwindow.plist"

    local friendly_name="keyboard input menu on the login window"
    local setting_name=showInputMenu
    local setting_value="0"
    local key_exists="0"

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$setting_name" | wc -l`
    fi

    if [ $key_exists == "1" ]; then
        setting_value=`defaults read $file $setting_name`
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then

    if [ $setting_value == "1" ]; then
        echo "$friendly_name is enabled";
    else
        echo "$friendly_name is disabled";
    fi

    fi

    if [ "$set_flag" != "" ]; then

        # only enable the setting if it is not already set
    case $profile_flag in
        "ent")
                if [ $setting_value != 0 ]; then
            echo "disabling $friendly_name";
            defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
        ;;
        "soho")
                if [ $setting_value != 0 ]; then
            echo "disabling $friendly_name";
            defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
        ;;
        "sslf")
                if [ $setting_value != 0 ]; then
            echo "disabling $friendly_name";
            defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
        ;;
        "oem")
                if [ $setting_value != 0 ]; then
            echo "disabling $friendly_name";
            defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
        ;;
    esac
    fi

# Testing - OS X 10.10
# Restart not required for setting to take effect.
}



######################################################################
CCE_79774_6_login_window_disable_voiceover () {
    local doc="CCE_79774_6_login_window_disable_voiceover      (manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.loginwindow.plist"

    local friendly_name="VoiceOver on the login window"
    local setting_name=UseVoiceOverAtLoginwindow
    local setting_value="0"
    local key_exists="0"

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$setting_name" | wc -l`
    fi

    if [ $key_exists == "1" ]; then
        setting_value=`defaults read $file $setting_name`
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then

    if [ $setting_value == "1" ]; then
        echo "$friendly_name is enabled";
    else
        echo "$friendly_name is disabled";
    fi
    fi

    if [ "$set_flag" != "" ]; then

        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                echo "$friendly_name is unchanged"
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac
    fi

# Testing OS X 10.10
# Setting was applied without restart.
}


######################################################################
CCE_79776_1_updates_download_in_background () {
    local doc="CCE_79776_1_updates_download_in_background      (manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.SoftwareUpdate.plist"

    local friendly_name="download software updates in background"
    local setting_name=AutomaticDownload
    local setting_value="1"
    local key_exists="0"

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$setting_name" | wc -l`
    fi

    if [ $key_exists == "1" ]; then
        setting_value=`defaults read $file $setting_name`
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $setting_value == "1" ]; then
            echo "$friendly_name is enabled";
        else
            echo "$friendly_name is disabled";
        fi
    fi


    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ $setting_value != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ $setting_value != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ $setting_value != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $setting_value != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac
    fi

# Testing - OS X 10.10
# Setting shows up immediately as enabled in GUI.
}



######################################################################
CCE_79777_9_install_system_data_updates () {
    local doc="CCE_79777_9_install_system_data_updates      (manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.SoftwareUpdate.plist"

    local setting_name=ConfigDataInstall
    local friendly_name="install system data updates"
    local setting_value="1"
    local key_exists="0"

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$setting_name" | wc -l`
    fi

    if [ $key_exists == "1" ]; then
        setting_value=`defaults read $file $setting_name`
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then

    if [ $setting_value == "1" ]; then
        echo "$friendly_name is enabled";
    else
        echo "$friendly_name is disabled";
    fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ $setting_value != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ $setting_value != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ $setting_value != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $setting_value != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac
    fi

# Testing - OS X 10.10
# When this setting is disabled, the "Install system data files and security updates"
# setting in the GUI is unchecked immediately. Both this setting and
# CCE_79778_7_install_security_updates must be enabled for the box to be checked
# off in the GUI. Effectiveness of the setting not verified.
}



######################################################################
CCE_79778_7_install_security_updates () {
    local doc="CCE_79778_7_install_security_updates      (manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.SoftwareUpdate.plist"

    local setting_name=CriticalUpdateInstall
    local friendly_name="install security updates"
    local setting_value="1"
    local key_exists="0"


    if [ -s $file ]; then
        key_exists=`defaults read $file | grep "$setting_name" | wc -l`
    fi

    if [ $key_exists == "1" ]; then
        setting_value=`defaults read $file $setting_name`
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then

    if [ $setting_value == "1" ]; then
        echo "$friendly_name is enabled";
    else
        echo "$friendly_name is disabled";
    fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
    case $profile_flag in
        "ent")
            if [ $setting_value != 1 ]; then
                echo "enabling $friendly_name";
                defaults write $file $setting_name -bool true
            else
                echo "$friendly_name is already enabled"
            fi
            ;;
        "soho")
            if [ $setting_value != 1 ]; then
                echo "enabling $friendly_name";
                defaults write $file $setting_name -bool true
            else
                echo "$friendly_name is already enabled"
            fi
            ;;
        "sslf")
            if [ $setting_value != 1 ]; then
                echo "enabling $friendly_name";
                defaults write $file $setting_name -bool true
            else
                echo "$friendly_name is already enabled"
            fi
            ;;
        "oem")
            if [ $setting_value != 1 ]; then
                echo "enabling $friendly_name";
                defaults write $file $setting_name -bool true
            else
                echo "$friendly_name is already enabled"
            fi
            ;;
    esac
    fi

# Testing - OS X 10.10
# When this setting is disabled, the "Install system data files and security updates"
# setting in the GUI is unchecked immediately. Both this setting and
# CCE_79777_9_install_system_data_updates must be enabled for the box to be checked
# off in the GUI. Effectiveness of the setting not verified.
}




######################################################################
CCE_79779_5_all_files_in_a_users_home_dir_are_owned_by_that_user () {
    local doc="CCE_79779_5_all_files_in_a_users_home_dir_are_owned_by_that_user     (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    #since this can be a lengthy operation, only search if running in print or set mode
    if [ "$print_flag" != "" -o "$set_flag" != "" ]; then
        local file_list=`find $home_path ! -user $owner -print`
        local file_count=`echo "$file_list" | grep -c "^/"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$v_flag" == "" ]; then
            echo "number of files in $owner's home with wrong owner: $file_count";
        else
            for file in $file_list; do
                echo "$file is not owned by $owner";
            done

            if [ $file_count == "0" ]; then
                echo "all files in $owner's home directory belong to $owner";
            fi
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
    case $profile_flag in
        "ent")
            while read -r file; do
                if [ "$v_flag" != "" ]; then
                    echo "changing owner of $file to $owner";
                fi
                chown "$owner" "$file"
            done <<< "$file_list"
            echo "$file_count files have had the owner changed";
            ;;
        "soho")
            while read -r file; do
                if [ "$v_flag" != "" ]; then
                    echo "changing owner of $file to $owner";
                fi
                chown "$owner" "$file"
            done <<< "$file_list"
            echo "$file_count files have had the owner changed";
            ;;
        "sslf")
            while read -r file; do
                if [ "$v_flag" != "" ]; then
                    echo "changing owner of $file to $owner";
                fi
                chown "$owner" "$file"
            done <<< "$file_list"
            echo "$file_count files have had the owner changed";
            ;;
        "oem")
            # do not change ownership
            echo "file ownership is unchanged";
            ;;
    esac
    fi


# Testing OS X 10.10
# Verified changed ownership in home directory and all subdirectories
}


######################################################################
CCE_79780_3_files_in_home_dir_group_owned_by_owners_group () {
    local doc="CCE_79780_3_files_in_home_dir_group_owned_by_owners_group      (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #since these can be lengthy operations, only search if running in print or set mode
    if [ "$print_flag" != "" -o "$set_flag" != "" ]; then
    
        # gets all groups the specified user is part of
        local groups=`groups $owner`

        # format groups output for use by find
        local groups_cmd=`echo "$groups" | sed 's/ / -a ! -group /g'`

        local file_list=`find $home_path ! -group $groups_cmd -print`
        local file_count=`echo "$file_list" | grep -c "^/"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$v_flag" == "" ]; then
            echo "number of files in $owner's home with wrong group: $file_count";
        else
            for file in $file_list; do
                echo "$file does not belong to one of $owner's groups";
            done

            if [ $file_count == "0" ]; then
                echo "all files in $owner's home belong to an appropriate group";
            fi
        fi

    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
    case $profile_flag in
        "ent")
                for file in $file_list; do
                    if [ "$v_flag" != "" ]; then
                        echo "changing group of $file to $group";
                    fi
                    chgrp $group $file
                done
                echo "$file_count files have had the group changed";
        ;;
        "soho")
                for file in $file_list; do
                    if [ "$v_flag" != "" ]; then
                        echo "changing group of $file to $group";
                    fi
                    chgrp $group $file
                done
                echo "$file_count files have had the group changed";
        ;;
        "sslf")
                for file in $file_list; do
                    if [ "$v_flag" != "" ]; then
                        echo "changing group of $file to $group";
                    fi
                    chgrp $group $file
                done
                echo "$file_count files have had the group changed";
        ;;
        "oem")
                # do not change group ownership
                echo "group ownership for files is unmodified";
        ;;
    esac
    fi


# Testing OS X 10.10
# Verified changed group ownership in home directory and all subdirectories
}


######################################################################
CCE_79781_1_use_network_time_protocol () {
    local doc="CCE_79781_1_use_network_time_protocol      (manual-test-PASSED)"

    local setting_name=networktimeserver
    local setting2_name=usingnetworktime #used to enable automatic time syncing
    local friendly_name="use network time protocol for system time"
    local setting_value="time.apple.com"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
        echo "`systemsetup -get$setting2_name`";
    echo "`systemsetup -get$setting_name`";
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                echo "enabling $friendly_name";
                systemsetup -set$setting_name $setting_value > /dev/null
                systemsetup -set$setting2_name on > /dev/null
                ;;
            "soho")
                echo "enabling $friendly_name";
                systemsetup -set$setting_name $setting_value > /dev/null
                systemsetup -set$setting2_name on > /dev/null
                ;;
            "sslf")
                echo "enabling $friendly_name";
                systemsetup -set$setting_name $setting_value > /dev/null
                systemsetup -set$setting2_name on > /dev/null
                ;;
            "oem")
                echo "enabling $friendly_name";
                systemsetup -set$setting_name $setting_value > /dev/null
                systemsetup -set$setting2_name on > /dev/null
                ;;
        esac
    fi

# Testing OS X 10.10
# Manually tested and works as expected.
# Setting the value took effect immediately.
}


######################################################################
CCE_79782_9_park_disk_heads_on_sudden_motion () {
    local doc="CCE_79782_9_park_disk_heads_on_sudden_motion    (effects-test-indeterminate)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local setting_name=sms
    local setting_value=1 #default is enabled on equipped systems
    local friendly_name="park disk heads on sudden motion"
    local key_exists=0

    if [ -e $file ]; then
        local setting_line=`pmset -g | grep " $setting_name "`
        key_exists=`echo "$setting_line" | grep -c "$setting_name"`

        if [ $key_exists == "1" ]; then
            setting_value=`echo "$setting_line" | egrep -o "0|1"`
        fi
    fi


    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "1" ]; then
        if [ $setting_value == "1" ]; then
            echo "$friendly_name enabled";
        else
            echo "$friendly_name disabled";
        fi
        else
            echo "this system is not equipped with sudden motion sensor";
        fi

    fi


    if [ "$set_flag" != "" ]; then
    case $profile_flag in
        "ent")
                if [ $key_exists == 1 ]; then
                    if [ $setting_value == 1 ]; then
                        echo "$friendly_name is already enabled"
                    else
                        echo "enabling $friendly_name"
                        pmset -a sms 1
                    fi
                else
            echo "this system is not equipped with sudden motion sensor";
                fi
        ;;
        "soho")
        if [ $key_exists == 1 ]; then
                    if [ $setting_value == 1 ]; then
                        echo "$friendly_name is already enabled"
                    else
                        echo "enabling $friendly_name"
                        pmset -a sms 1
                    fi
                else
            echo "this system is not equipped with sudden motion sensor";
                fi
        ;;
        "sslf")
        if [ $key_exists == 1 ]; then
                    if [ $setting_value == 1 ]; then
                        echo "$friendly_name is already enabled"
                    else
                        echo "enabling $friendly_name"
                        pmset -a sms 1
                    fi
                else
            echo "this system is not equipped with sudden motion sensor";
                fi
        ;;
        "oem")
        if [ $key_exists == 1 ]; then
                    if [ $setting_value == 1 ]; then
                        echo "$friendly_name is already enabled"
                    else
                        echo "enabling $friendly_name"
                        pmset -a sms 1
                    fi
                else
            echo "this system is not equipped with sudden motion sensor";
                fi
        ;;
    esac
    fi

# NEEDS_REAL_HARDWARE

# OS X 10.10 real hardware test
# The value successfully changed in the `pmset -g` report immediately. It is not
# practical to manually test the effectiveness on real hardware.
}


######################################################################
CCE_79783_7_display_file_extensions () {
    local doc="CCE_79783_7_display_file_extensions               (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/.GlobalPreferences.plist
    local setting_name=AppleShowAllExtensions
    local friendly_name="show all file extensions"
    local value=0

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep $setting_name | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true

                    # Finder must be restarted before system restart to take effect
                    # operating system automatically restarts the processes
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true

                    # Finder must be restarted before system restart to take effect
                    # operating system automatically restarts the processes
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true

                    # Finder must be restarted before system restart to take effect
                    # operating system automatically restarts the processes
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

# Note: The "All My Files" shortcut in Finder ignores the setting and hides extensions
# on a per file basis.

# Testing - OS X 10.10
# Successfully takes effect immediately.
}


######################################################################
CCE_79784_5_show_hidden_files () {
    local doc="CCE_79784_5_show_hidden_files               (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.finder.plist
    local setting_name=AppleShowAllFiles
    local friendly_name="show hidden files"
    local value=0

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep $setting_name | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        #only change values that aren't already set for that profile
        case $profile_flag in
            "ent")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi


#OS X 10.10
#The setting will not take effect, even after restarting, if cfprefsd is not killed.
#Works without restart
}


######################################################################
CCE_79802_5_secure_erase_trash () {
    local doc="CCE_79802_5_secure_erase_trash          (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.finder.plist

    local setting_name=EmptyTrashSecurely
    local friendly_name="empty Trash securely"
    local setting_value=0

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep $setting_name | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            setting_value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$print_flag" != "" ]; then
        if [ $setting_value == "1" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                # take no action for this profile
                echo "$friendly_name has not been changed"
                ;;
            "soho")
                # take no action for this profile
                echo "$friendly_name has not been changed"
                ;;
            "sslf")
                if [ $setting_value != "1" ]; then
                    echo "enabling $friendly_name"
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $setting_value != "0" ]; then
                    echo "disabling securely erase Trash"
                    defaults write $file $setting_name -bool false
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

# OS X 10.10
# Unless the `killall Finder` and `killall cfprefsd` commands are run, the setting
# does not appear to take effect (cached settings overwriting changes?).
# Works without restart.
}


######################################################################
CCE_79803_3_search_scope_search_this_mac () {
    local doc="CCE_79803_3_search_scope_search_this_mac          (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.finder.plist

    local setting_name=FXDefaultSearchScope
    local friendly_name="Search scope: search this Mac"
    local setting_value="SCev"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep $setting_name | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            setting_value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" == "SCcf" ]; then
            echo "current search scope: search current folder"
        elif [ "$setting_value" == "SCsp" ]; then
            echo "current search scope: use previous search scope"
        else
            echo "$friendly_name is enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ $setting_value != "SCev" ]; then
                    echo "enabling $friendly_name"
                    defaults write $file $setting_name -string "SCev"
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ $setting_value != "SCev" ]; then
                    echo "enabling $friendly_name"
                    defaults write $file $setting_name -string "SCev"
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ $setting_value != "SCev" ]; then
                    echo "enabling $friendly_name"
                    defaults write $file $setting_name -string "SCev"
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $setting_value != "SCev" ]; then
                    echo "enabling $friendly_name"
                    defaults write $file $setting_name -string "SCev"
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

# OS X 10.10 testing 
# If the `killall Finder` and `killall cfprefsd` commands are run, a logout isn't required
# Successfully enabled search this Mac in the GUI when running the function. Changing
# the setting more than once in succession may cause the newest value to not be applied.

}

######################################################################
CCE_79804_1_warn_before_changing_extension () {
    local doc="CCE_79804_1_warn_before_changing_extension          (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.finder.plist

    local setting_name=FXEnableExtensionChangeWarning
    local friendly_name="warn before changing file extensions"
    local value="1"

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep $setting_name | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#OS X 10.10
#Setting takes effect without restart.
}


######################################################################
CCE_79809_0_warn_before_emptying_trash () {
    local doc="CCE_79809_0_warn_before_emptying_trash          (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.finder.plist

    local setting_name=WarnOnEmptyTrash
    local friendly_name="warn before emptying trash"
    local value="1"

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep $setting_name | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "0" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#OS X 10.10
#Takes effect immediately, but will not work if the setting is changed multiple times in
#quick succession

}


######################################################################
CCE_79810_8_windows_not_saved_when_quitting_app () {
    local doc="CCE_79810_8_windows_not_saved_when_quitting_app      (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/.GlobalPreferences.plist"

    local setting_name=NSQuitAlwaysKeepsWindows
    local friendly_name="windows save when quitting apps"
    local value="0"

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep $setting_name | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "0" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi



#OS X 10.10
#Tested using TextEdit and Dictionary apps. TextEdit consistently worked, but
#Dictionary seems to ignore the setting.
#Windows will not be saved after the next time an app starts up; if the windows
#were being saved, they will appear the next time an app starts, but they will
#no longer be saved afterwards.

}


######################################################################
CCE_79811_6_dock_enable_autohide () {
    local doc="CCE_79811_6_dock_enable_autohide         (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/com.apple.dock.plist"

    local setting_name=autohide
    local friendly_name="dock autohide"
    local value="0"

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep $setting_name | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
                if [ $value != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#OS X 10.10
#Must kill cfprefsd for setting to take effect. If not terminating the Dock process,
#it will apply after restart.
}


######################################################################
CCE_79813_2_disable_dictation () {
    local doc="CCE_79813_2_disable_dictation         (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/com.apple.speech.recognition.AppleSpeechRecognition.prefs.plist"

    local setting_name="DictationIMMasterDictationEnabled"
    local friendly_name="dictation feature"
    local dictation_pid=`ps -caxo pid,comm | grep "DictationIM" | grep -v "grep" | sed 's/DictationIM//' | sed 's/ //g'`
    local value="0"
    

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep "$setting_name" | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file "$setting_name"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "$friendly_name is unchanged"
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file "$setting_name" -bool false

                    #kill Dictation if it is running; no other functions need to kill it
                    if [ "$dictation_pid" != "" ]; then
                        kill -9 "$dictation_pid"
                    fi

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file "$setting_name" -bool false

                    #kill Dictation if it is running; no other functions need to kill it
                    if [ "$dictation_pid" != "" ]; then
                        kill -9 "$dictation_pid"
                    fi

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

# Note: The Dictation process name is DictationIM

#10.10 
#Works without restart.
}


######################################################################
CCE_79814_0_disable_voiceover () {
    local doc="CCE_79814_0_disable_voiceover         (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/com.apple.universalaccess.plist"

    local setting_name="voiceOverOnOffKey"
    local friendly_name="VoiceOver"
    local value="0"

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep "$setting_name" | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file "$setting_name"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "$friendly_name is unchanged"
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file "$setting_name" -bool false

                    add_processes_to_kill_list VoiceOver cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file "$setting_name" -bool false

                    add_processes_to_kill_list VoiceOver cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi


# Notes
# If the VoiceOver process is not killed, a restart is required. If cfprefsd is not killed
# in addition to VoiceOver, the setting may be re-enabled when logging out and back in.

# OS X 10.10
# Works after logout.
}


######################################################################
CCE_79815_7_no_announce_when_alerts_displayed () {
    local doc="CCE_79815_7_no_announce_when_alerts_displayed        (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/com.apple.speech.synthesis.general.prefs.plist"

    local setting_name="TalkingAlertsSpeakTextFlag"
    local friendly_name="announce alerts dictation setting"
    local value="0"

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep "$setting_name" | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file "$setting_name"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "$friendly_name is unchanged"
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file "$setting_name" -bool false

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file "$setting_name" -bool false

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

# Notes
# Does not require restart or logout to take effect immediately. If cfprefsd is not ended,
# the setting takes effect after system restart.

# OS X 10.10 
# Restart required.
# The setting CCE_79812_4_no_announcement_when_app_wants_attention was merged into this
# one starting at OS X 10.10.
}



######################################################################
CCE_79816_5_do_not_speak_selected_text () {
    local doc="CCE_79816_5_do_not_speak_selected_text        (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/com.apple.speech.synthesis.general.prefs.plist"

    local setting_name="SpokenUIUseSpeakingHotKeyFlag"
    local friendly_name="announce selected text on key press"
    local value="0"

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep "$setting_name" | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file "$setting_name"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "$friendly_name is unchanged"
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file "$setting_name" -bool false

                    add_processes_to_kill_list SpeechSynthesisServer cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $value != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write $file "$setting_name" -bool false

                    add_processes_to_kill_list SpeechSynthesisServer cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

# OS X 10.10
# If no processes are killed, a system restart is required. When killing
# SpeechSynthesisServer, the setting takes effect immediately. However, logging out and
# back in without a system restart causes the setting to be re-enabled; a system restart
# fixes this problem and causes the setting to once again be disabled.
# If cfprefsd is killed, the problem explained above does not occur; the system can
# be restarted or logged out in any order, and the setting still stays off.
}


######################################################################
CCE_79817_3_ssh_login_grace_period () {
    local doc="CCE_79817_3_ssh_login_grace_period               (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="LoginGraceTime"
    local friendly_name="SSH login grace time"
    local current_string=""
    local file_contents=`cat $file 2> /dev/null`
    local new_file_contents=""
    local current_value=""

    local oem_value="2m" # confirmed value through testing
    local oem_string="#$setting_name $oem_value"

    local required_value="30"
    local required_string="$setting_name $required_value"

    if [ -e "$file" ]; then
        current_string=`echo "$file_contents" | grep "$setting_name"`
        if [ `echo $current_string | grep -c "^#"` -gt 0 ]; then
            current_value=""
        else
            current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        #no value indicates oem value
        if [ "$current_value" == "" ]; then
            echo "$friendly_name is $oem_value"
        else
            #if time is expressed in minutes
            if [ `echo "$current_value" | grep -c "m$"` -gt 0 ]; then
                echo "$friendly_name is set to $current_value";
            else
                echo "$friendly_name is set to $current_value seconds";
            fi
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_string" != "$required_string" ]; then
                    echo "setting $friendly_name to $required_value seconds"

                    # if the setting exists in the file, overwrite it
                    if [ "$current_string" != "" ]; then
                        new_file_contents=`echo "$file_contents" | sed -E "s/^#?LoginGraceTime .+/$required_string/"`

                        echo "$new_file_contents" > "$file"
                    # otherwise, append
                    else
                        echo "$required_string" >> "$file"
                    fi

                else
                    #if time is expressed in minutes
                    if [ `echo "$required_value" | grep -c "m$"` -gt 0 ]; then
                        echo "$friendly_name is already set to $required_value";
                    else
                        echo "$friendly_name is already set to $required_value seconds";
                    fi
                fi
                ;;
            "soho")
                if [ "$current_string" != "$required_string" ]; then
                    echo "setting $friendly_name to $required_value seconds"

                    # if the setting exists in the file, overwrite it
                    if [ "$current_string" != "" ]; then
                        new_file_contents=`echo "$file_contents" | sed -E "s/^#?LoginGraceTime .+/$required_string/"`

                        echo "$new_file_contents" > "$file"
                    # otherwise, append
                    else
                        echo "$required_string" >> "$file"
                    fi

                else
                    #if time is expressed in minutes
                    if [ `echo "$required_value" | grep -c "m$"` -gt 0 ]; then
                        echo "$friendly_name is already set to $required_value";
                    else
                        echo "$friendly_name is already set to $required_value seconds";
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_string" != "$required_string" ]; then
                    echo "setting $friendly_name to $required_value seconds"

                    # if the setting exists in the file, overwrite it
                    if [ "$current_string" != "" ]; then
                        new_file_contents=`echo "$file_contents" | sed -E "s/^#?LoginGraceTime .+/$required_string/"`

                        echo "$new_file_contents" > "$file"
                    # otherwise, append
                    else
                        echo "$required_string" >> "$file"
                    fi

                else
                    #if time is expressed in minutes
                    if [ `echo "$required_value" | grep -c "m$"` -gt 0 ]; then
                        echo "$friendly_name is already set to $required_value";
                    else
                        echo "$friendly_name is already set to $required_value seconds";
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    if [ "$current_string" != "" ]; then
                        new_file_contents=`echo "$file_contents" | sed -E "s/^#?LoginGraceTime .+/$oem_string/"`
                        echo "$new_file_contents" > "$file"
                    else
                        echo "$oem_string" >> "$file"
                    fi
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

# Testing Process
# Connected to machine with `ssh username@host` then waited a few seconds before
# and after the designated time to enter the password. For example, when testing 2
# minutes grace time, password was entered at 1m 55s, and 2m 5s to make sure the
# setting agreed with the expected behavior. When the grace period is exceeded, the
# connection is closed by the remote machine after submitting the password, regardless
# of whether the password is correct. Note that failed password attempts do not
# reset the grace timer.

# OS X 10.10 Testing
# Setting applies immediately without restart.

}



######################################################################
CCE_79818_1_ssh_remove_non_fips_140_2_ciphers () {
    local doc="CCE_79818_1_ssh_remove_non_fips_140_2_ciphers        (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="Ciphers"
    local friendly_name="non FIPS 140-2 compliant SSH ciphers"
    local oem_value="3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,cast128-cbc,arcfour,arcfour128,arcfour256,blowfish-cbc"


    local current_string=""
    local current_value="" #holds a list of ciphers separated by commas
    local file_contents=`cat $file 2> /dev/null | sed 's/^ciphers/Ciphers/'` #normalize case
    local new_file_contents=""


    if [ -e "$file" ]; then
        current_string=`echo "$file_contents" | grep -i "^$setting_name"`
        current_value=`echo "$current_string" | sed -E "s/$setting_name //"`

        #if the word ciphers is present, but there are no values, oem values are used
        if [ "$current_value" == "" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    # create a list of existing ciphers, with one per line
    local cipher_list=`echo "$current_value" | sed -E 's/, ?/\\
/g'`
    # separate ciphers into lists based on FIPS compliance
    local bad_ciphers=`echo "$cipher_list" | egrep -v "^[\"]*(aes)|(3des)"`
    local good_ciphers=`echo "$cipher_list" | egrep "^[\"]*(aes)|(3des)"`

    #format for sshd_config file
    good_ciphers=`echo $good_ciphers | sed 's/ /,/g'`

    # print the list of non-compliant ciphers if v-flag present
    if [ "$print_flag" != "" ]; then
        if [ "$bad_ciphers" == "" ]; then
            echo "$friendly_name are not present"
        elif [ "$v_flag" != "" ]; then
            echo "the following $friendly_name are present:" $bad_ciphers
        else
            echo "$friendly_name are present"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$bad_ciphers" == "" ]; then
                    echo "$friendly_name are not present"
                else
                    echo "removing $friendly_name"
                    if [ "$current_string" != "" ]; then
                        #replace list of ciphers
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/Ciphers $good_ciphers/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of ciphers
                        echo "Ciphers $good_ciphers" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$bad_ciphers" == "" ]; then
                    echo "$friendly_name are not present"
                else
                    echo "removing $friendly_name"
                    if [ "$current_string" != "" ]; then
                        #replace list of ciphers
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/Ciphers $good_ciphers/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of ciphers
                        echo "Ciphers $good_ciphers" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$bad_ciphers" == "" ]; then
                    echo "$friendly_name are not present"
                else
                    echo "removing $friendly_name"
                    if [ "$current_string" != "" ]; then
                        #replace list of ciphers
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/Ciphers $good_ciphers/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of ciphers
                        echo "Ciphers $good_ciphers" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "" ]; then
                    #remove list of ciphers from file
                    echo "reverting to default SSH ciphers"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string//"`
                    echo "$new_file_contents" > $file
                else
                    echo "default SSH ciphers are already being used"
                fi
                ;;
        esac
    fi

# Note: An incorrect format for the Ciphers line seems to cause SSH connections to be
# rejected entirely, regardless of the cipher specified when connecting. We noticed this
# problem with spaces separating the ciphers.
# FIPS 140-2 compliant ciphers begin with "3des" or "aes"

# Known default ciphers when no values specified in /etc/sshd_config:
#	"3des-cbc", "aes128-ctr", "aes192-ctr", "aes256-ctr", "arcfour256", "arcfour128",
#	"aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour"


# Testing Process
# Verified accepted sshd ciphers by using ssh with -c option to specify a cipher.

# OS X 10.10 Testing
# When specifying an accepted cipher, the ssh connection was successful; otherwise, it
# was terminated. The change in acceptable ciphers took effect immediately.
}



######################################################################
CCE_79819_9_ssh_remove_cbc_ciphers () {
    local doc="CCE_79819_9_ssh_remove_cbc_ciphers           (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="Ciphers"
    local friendly_name="CBC SSH ciphers"
    local oem_value="3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,cast128-cbc,arcfour,arcfour128,arcfour256,blowfish-cbc"

    local current_string=""
    local current_value="" #holds a list of ciphers separated by commas
    local file_contents=`cat $file 2> /dev/null | sed 's/^ciphers/Ciphers/'` #normalize case
    local new_file_contents=""


    if [ -e "$file" ]; then
        current_string=`echo "$file_contents" | grep -i "^$setting_name"`
        current_value=`echo "$current_string" | sed -E "s/$setting_name //"`

        #if the word ciphers is present, but there are no values, oem values are used
        if [ "$current_value" == "" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    # create a list of existing ciphers, with one per line
    local cipher_list=`echo "$current_value" | sed -E 's/, ?/\\
/g'`
    # separate ciphers into lists based on CBC
    local bad_ciphers=`echo "$cipher_list" | egrep "(cbc)[\"]*$"`
    local good_ciphers=`echo "$cipher_list" | egrep -v "(cbc)[\"]*$"`

    #format for sshd_config file
    good_ciphers=`echo $good_ciphers | sed 's/ /,/g'`

    # print the list of non-compliant ciphers if v-flag present
    if [ "$print_flag" != "" ]; then
        if [ "$bad_ciphers" == "" ]; then
            echo "$friendly_name are not present"
        elif [ "$v_flag" != "" ]; then
            echo "the following $friendly_name are present:" $bad_ciphers
        else
            echo "$friendly_name are present"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$bad_ciphers" == "" ]; then
                    echo "$friendly_name are not present"
                else
                    echo "removing $friendly_name"
                    if [ "$current_string" != "" ]; then
                        #replace list of ciphers
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/Ciphers $good_ciphers/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of ciphers
                        echo "Ciphers $good_ciphers" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$bad_ciphers" == "" ]; then
                    echo "$friendly_name are not present"
                else
                    echo "removing $friendly_name"
                    if [ "$current_string" != "" ]; then
                        #replace list of ciphers
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/Ciphers $good_ciphers/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of ciphers
                        echo "Ciphers $good_ciphers" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$bad_ciphers" == "" ]; then
                    echo "$friendly_name are not present"
                else
                    echo "removing $friendly_name"
                    if [ "$current_string" != "" ]; then
                        #replace list of ciphers
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/Ciphers $good_ciphers/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of ciphers
                        echo "Ciphers $good_ciphers" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "" ]; then
                    #remove list of ciphers from file
                    echo "reverting to default SSH ciphers"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string//"`
                    echo "$new_file_contents" > $file
                else
                    echo "default SSH ciphers are already being used"
                fi
                ;;
        esac
    fi


# Note: An incorrect format for the Ciphers line seems to cause SSH connections to be
# rejected entirely, regardless of the cipher specified when connecting. We noticed this
# problem with spaces separating the ciphers.

# Known default ciphers when no values specified in /etc/sshd_config:
#	"3des-cbc", "aes128-ctr", "aes192-ctr", "aes256-ctr", "arcfour256", "arcfour128",
#	"aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour"


# Testing Process
# Verified accepted sshd ciphers by using ssh with -c option to specify a cipher.

# OS X 10.10 Testing
# When specifying an accepted cipher, the ssh connection was successful; otherwise, it
# was terminated. The change in acceptable ciphers took effect immediately.
}



######################################################################
CCE_79820_7_ssh_remove_non_fips_140_2_macs () {
    local doc="CCE_79820_7_ssh_remove_non_fips_140_2_macs           (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="MACs"
    local friendly_name="non FIPS 140-2 SSH MACs"

    local oem_value="hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96,hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,umac-128@openssh.com"


    local allowed_mac="hmac-sha1"
    local current_string=""
    local current_value="" #holds a list of MACs separated by commas
    local file_contents=`cat $file 2> /dev/null | sed 's/^macs/MACs/'` #normalize case
    local new_file_contents=""


    if [ -e "$file" ]; then
        current_string=`echo "$file_contents" | grep -i "^$setting_name"`
        current_value=`echo "$current_string" | sed -E "s/$setting_name //"`

        #if the word MACs is present, but there are no values, oem values are used
        if [ "$current_value" == "" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    # create a list of existing MACs, with one per line
    local mac_list=`echo "$current_value" | sed -E 's/, ?/\\
/g'`
    # separate MACs into lists based on FIPS compliance
    local bad_macs=`echo "$mac_list" | egrep -v "^[\"]*(${allowed_mac})[\"]*$"`
    local good_macs=`echo "$mac_list" | egrep "^[\"]*(${allowed_mac})[\"]*$"`

    #format for sshd_config file
    good_macs=`echo $good_macs | sed 's/ /,/g'`

    # print the list of non-compliant macs if v-flag present
    if [ "$print_flag" != "" ]; then
        if [ "$bad_macs" == "" ]; then
            echo "$friendly_name are not present"
        elif [ "$v_flag" != "" ]; then
            echo "the following $friendly_name are present:" $bad_macs
        else
            echo "$friendly_name are present"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$bad_macs" == "" ]; then
                    echo "$friendly_name are not present"
                else
                    echo "removing $friendly_name"
                    if [ "$current_string" != "" ]; then
                        #replace list of MACs
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/MACs $good_macs/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of MACs
                        echo "MACs $good_macs" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$bad_macs" == "" ]; then
                    echo "$friendly_name are not present"
                else
                    echo "removing $friendly_name"
                    if [ "$current_string" != "" ]; then
                        #replace list of MACs
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/MACs $good_macs/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of MACs
                        echo "MACs $good_macs" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$bad_macs" == "" ]; then
                    echo "$friendly_name are not present"
                else
                    echo "removing $friendly_name"
                    if [ "$current_string" != "" ]; then
                        #replace list of MACs
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/MACs $good_macs/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of MACs
                        echo "MACs $good_macs" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "" ]; then
                    #remove list of ciphers from file
                    echo "reverting to default SSH MACs"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string//"`
                    echo "$new_file_contents" > $file
                else
                    echo "default SSH MACs are already being used"
                fi
                ;;
        esac
    fi


# Note: An incorrect format for the MACs line seems to cause SSH connections to be
# rejected entirely, regardless of the MAC specified when connecting. We noticed this
# problem with spaces separating the MACs.

# Known default MACs when no values specified in /etc/sshd_config:
#	"hmac-md5", "hmac-sha1", "umac-64@openssh.com", "hmac-sha2-256", "hmac-sha2-512", 
#	"hmac-ripemd160", "hmac-ripemd160@openssh.com", "hmac-sha1-96", "hmac-md5-96",
#	"hmac-md5-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64-etm@openssh.com",
#	"umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
#	"hmac-sha2-512-etm@openssh.com", "hmac-ripemd160-etm@openssh.com",
#	"hmac-sha1-96-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "umac-128@openssh.com"

# Testing Process
# Verified accepted sshd MACs by using ssh with -m option to specify a MAC.

# OS X 10.10 Testing
# When specifying an accepted MAC, the ssh connection was successful; otherwise, it
# was terminated. The change in acceptable MACs took effect immediately.
}


######################################################################
CCE_79821_5_ssh_challenge_response_authentication_disallowed () {
    local doc="CCE_79821_5_ssh_challenge_response_authentication_disallowed           (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="ChallengeResponseAuthentication"
    local friendly_name="allow SSH challenge-response authentication"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="no"
    local soho_value="no"
    local sslf_value="no"
    local oem_value="yes"

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""


    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" != "no" ]; then
            echo "$friendly_name is true"
        else
            echo "$friendly_name is false"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name is already set to $ent_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" == "$soho_value" ]; then
                    echo "$friendly_name is already set to $soho_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$sslf_value" ]; then
                    echo "$friendly_name is already set to $sslf_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

#Note: In order to see this setting work, change the "PasswordAuthentication" entry to yes

# OS X 10.10 testing
# The setting change applied immediately. This setting disables login using
# a password through PAM. PAM's password authentication mechanism takes precedence
# over sshd's password authentication; if both are enabled, PAM is used.

}


######################################################################
CCE_79826_4_ssh_enable_password_authentication () {
    local doc="CCE_79826_4_ssh_enable_password_authentication   (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="PasswordAuthentication"
    local friendly_name="allow SSH password authentication"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="yes"
    local soho_value="yes"
    local sslf_value="yes"
    local oem_value="no"

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" != "no" ]; then
            echo "$friendly_name is true"
        else
            echo "$friendly_name is false"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name is already set to $ent_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" == "$soho_value" ]; then
                    echo "$friendly_name is already set to $soho_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$sslf_value" ]; then
                    echo "$friendly_name is already set to $sslf_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

# OS X 10.10 testing
# The setting applies immediately. This setting causes sshd to perform user password
# authentication only if PAM authentication is disabled.

}


######################################################################
CCE_79827_2_ssh_disable_pub_key_authentication () {
    local doc="CCE_79827_2_ssh_disable_pub_key_authentication   (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="PubkeyAuthentication"
    local friendly_name="allow SSH public key authentication"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="no"
    local soho_value="no"
    local sslf_value="no"
    local oem_value="yes"

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" != "no" ]; then
            echo "$friendly_name is true"
        else
            echo "$friendly_name is false"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name is already set to $ent_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" == "$soho_value" ]; then
                    echo "$friendly_name is already set to $soho_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$sslf_value" ]; then
                    echo "$friendly_name is already set to $sslf_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

#Notes: Use the method described in the link to set up public key authorization for ssh
#to see the effectiveness of the setting: https://support.apple.com/kb/PH15747?locale=en_US

# OS X 10.10 testing
# The setting applies immediately. If enabled, takes precedence over other authentication
# means.

}


######################################################################
CCE_79828_0_ssh_restrict_users () {
    local doc="CCE_79828_0_ssh_restrict_users                    (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="DenyUsers" #use "DenyGroups" to instead deny group access to SSH
    local friendly_name="SSH limited user access"
    local file_contents=`cat $file 2> /dev/null`

    #profile values - all users specified means no users allowed
    local ent_value='*'
    local soho_value='*'
    local sslf_value='*'

    #default value allows all users
    local oem_value="" # value not specified in file by default

    #default to oem value in case file does not exist
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" != "" ]; then
            if [ "$v_flag" != "" ]; then
                echo "SSH remote access limited to the following users: $current_value"
            else
                echo "$friendly_name is enabled"
            fi
        else
            echo "$friendly_name is disabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_string" != "" -a "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name is already set to no users allowed"
                else
                    echo "setting $friendly_name to no users allowed"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "${file_contents/"$current_string"/$setting_name $ent_value}"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" == "$soho_value" ]; then
                    echo "$friendly_name is already set to no users allowed"
                else
                    echo "setting $friendly_name to no users allowed"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "${file_contents/"$current_string"/$setting_name $soho_value}"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$sslf_value" ]; then
                    echo "$friendly_name is already set to no users allowed"
                else
                    echo "setting $friendly_name to no users allowed"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "${file_contents/"$current_string"/$setting_name $sslf_value}"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_value" ]; then
                    echo "disabling $friendly_name"
                    # replace existing value with oem value
                    new_file_contents=`echo "${file_contents/"$current_string"/$oem_value}"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac
    fi

# Notes: When using AllowUser, all users on the allowed list were properly
# permitted to connect, and users not specified were properly denied access.

# OS X 10.10 testing
# The setting takes effect immediately; all users are denied SSH access.
}


######################################################################
CCE_79829_8_disable_mission_control_dashboard () {
    local doc="CCE_79829_8_disable_mission_control_dashboard    (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/com.apple.dashboard.plist"

    local setting_name="mcx-disabled"
    local friendly_name="Mission Control dashboard"
    local value="0"

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep $setting_name | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value == "0" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled";
        fi
    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "$friendly_name has not been changed"
                ;;
            "soho")
                echo "$friendly_name has not been changed"
                ;;
            "sslf")
                if [ "$value" != "1" ]; then
                    echo "disabling $friendly_name"
                    defaults write "$file" "$setting_name" -bool true

                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ "$value" != "1" ]; then
                    echo "disabling $friendly_name"
                    defaults write "$file" "$setting_name" -bool true

                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#Note: If only widget updating was disabled, this could be applied to all profiles.
#However, this currently disables Dashboard, and is too strict for all profiles.

#OS X 10.10 Testing
#Dashboard is disabled by default. Works immediately.
}



######################################################################
CCE_79830_6_ssh_set_client_alive_300_seconds () {
    local doc="CCE_79830_6_ssh_set_client_alive_300_seconds        (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="ClientAliveInterval"
    local friendly_name="SSH client alive interval"
    local file_contents=`cat $file 2> /dev/null`

    #profile values - actual values may be less than these specified values (more strict)
    local ent_value="300"
    local soho_value="300"
    local sslf_value="300"
    local oem_value="0" #Confirmed default value

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" != "0" ]; then
            echo "$friendly_name is set to $current_value"
        else
            echo "$friendly_name is disabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                # setting must be less than or equal to the required interval
                if [ "$current_value" -gt "0" -a "$current_value" -le "$ent_value" ]; then
                    echo "$friendly_name is already set to $current_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                # setting must be less than or equal to the required interval
                if [ "$current_value" -gt "0" -a "$current_value" -le "$soho_value" ]; then
                    echo "$friendly_name is already set to $current_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                # setting must be less than or equal to the required interval
                if [ "$current_value" -gt "0" -a "$current_value" -le "$sslf_value" ]; then
                    echo "$friendly_name is already set to $current_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

# Notes on functionality:
# The server sends an alive status query to the client every ClientAliveInterval seconds.
# The connection is dropped if the server does not receive a response after approximately
# (ClientAliveCountMax - 1) queries (3 by default) * ClientAliveInterval. No queries are
# sent if ClientAliveInterval is 0.

# Testing methodology
# Initiated an SSH connection to the VM, then disabled the VM's network connection.
# Used `netstat -f inet` to watch the ssh connection's send-q increase in size each
# interval of ClientAliveInterval seconds.

# OS X 10.10 testing
# Restart required to ensure the setting takes effect.
}


######################################################################
CCE_79831_4_ssh_max_auth_tries_4_or_less () {
    local doc="CCE_79831_4_ssh_max_auth_tries_4_or_less        (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="maxAuthTries"
    local friendly_name="SSH authentication attempts limit"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="4"
    local soho_value="4"
    local sslf_value="4"
    local oem_value="6" #Confirmed from testing

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" != "0" ]; then
            echo "$friendly_name is set to $current_value"
        else
            echo "$friendly_name is disabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" -le "$ent_value" ]; then
                    echo "$friendly_name is already set to $current_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" -le "$soho_value" ]; then
                    echo "$friendly_name is already set to $current_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" -le "$sslf_value" ]; then
                    echo "$friendly_name is already set to $current_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

# Notes on functionality:
# This does not affect the number of password prompts produced by the client. By
# default, the client only prompts for a password 3 times before terminating the
# connection. To see this setting work, the server's MaxAuthTries must be less than
# the client's NumberOfPasswordPrompts.

# OS X 10.10 testing
# Setting applied immediately.
}


######################################################################
CCE_79833_0_encrypt_system_swap_file () {
    local doc="CCE_79833_0_encrypt_system_swap_file      (manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.virtualMemory.plist"

    local friendly_name="encrypted swap file"
    local setting_name="DisableEncryptedSwap"
    local setting_value="0"
    local key_exists="0"

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$setting_name" | wc -l`
    fi

    if [ $key_exists == "1" ]; then
        setting_value=`defaults read $file $setting_name`
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        # if the Disabled value is 0, then the encrypted swap file is enabled
        if [ $setting_value == "0" ]; then
            echo "$friendly_name is enabled";
        else
            echo "$friendly_name is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then

        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ $setting_value != 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ $setting_value != 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ $setting_value != 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ $setting_value != 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac
    fi


# OS X 10.10 Testing
# The setting is not present by default, meaning that the swap file is encrypted.
# However, when disabling the encryption with "DisableEncryptedSwap=1", the file doesn't
# seem to be unencrypted even after restart. The value can be changed, but the setting
# seems to have no effect.
}


######################################################################
CCE_79834_8_disable_location_services () {
    local doc="CCE_79834_8_disable_location_services      (manual-test-PASSED)"
    local defaults_file="/private/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.$hw_uuid.plist"
    local daemon_file="/System/Library/LaunchDaemons/com.apple.locationd.plist"
    local process_name="locationd"

    local friendly_name="location services"
    local setting_name="LocationServicesEnabled"
    local setting_value="0"
    local key_exists="0"

    if [ -e $defaults_file ]; then
        key_exists=`defaults read $defaults_file | grep "$setting_name" | wc -l`
        if [ $key_exists == "1" ]; then
            setting_value=`defaults read $defaults_file $setting_name`
        fi
    fi

    local process_running=`ps -ax | fgrep "$process_name" | fgrep -v "fgrep" -c`

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then

        if [ $setting_value == "1" ]; then
            echo "$friendly_name are enabled";
        else
            echo "$friendly_name are disabled";
        fi

        if [ "$v_flag" != "" ]; then
            if [ "$process_running" -gt 0 ]; then
                echo "$friendly_name process $process_name is running"
            else
                echo "$friendly_name process $process_name is not running"
            fi
        fi
    fi

    if [ "$set_flag" != "" ]; then

        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $defaults_file $setting_name -bool false

                    if [ "$process_running" -gt 0 ]; then
                        add_processes_to_kill_list "$process_name"
                        if [ "$v_flag" != "" ]; then
                            echo "stopping the $friendly_name process $process_name"
                        fi
                    fi
                elif [ "$process_running" -gt 0 ]; then
                    echo "$friendly_name is already disabled; stopping the $process_name process";
                    add_processes_to_kill_list "$process_name"
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $defaults_file $setting_name -bool false
                
                    if [ "$process_running" -gt 0 ]; then
                        add_processes_to_kill_list "$process_name"
                        if [ "$v_flag" != "" ]; then
                            echo "stopping the $friendly_name process $process_name"
                        fi
                    fi
                elif [ "$process_running" -gt 0 ]; then
                    echo "$friendly_name is already disabled; stopping the $process_name process";
                    add_processes_to_kill_list "$process_name"
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $defaults_file $setting_name -bool false
                
                    if [ "$process_running" -gt 0 ]; then
                        add_processes_to_kill_list "$process_name"
                        if [ "$v_flag" != "" ]; then
                            echo "stopping the $friendly_name process $process_name"
                        fi
                    fi
                elif [ "$process_running" -gt 0 ]; then
                    echo "$friendly_name is already disabled; stopping the $process_name process";
                    add_processes_to_kill_list "$process_name"
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $defaults_file $setting_name -bool false
                
                    if [ "$process_running" -gt 0 ]; then
                        add_processes_to_kill_list "$process_name"
                        if [ "$v_flag" != "" ]; then
                            echo "stopping the $friendly_name process $process_name"
                        fi
                    fi
                elif [ "$process_running" -gt 0 ]; then
                    echo "$friendly_name is already disabled; stopping the $process_name process";
                    add_processes_to_kill_list "$process_name"
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        #restore original owner:group of _locationd
        if [ -e "$defaults_file" ]; then
            chown "_locationd":"_locationd" "$defaults_file"
        fi
    fi

# Testing OS X 10.10
# Setting takes effect without restart after a brief delay. The process also stops
# running. The process may restart on its own, but the services remain disabled.
}


# parameters:
# $1 - the numeric setting value that corresponds to an action
# $2 - human readable setting name
cd_dvd_insert_action () {
    # possible values for setting_value are:
    # action 1 = "Ignore"
    # action 2 = "Ask what to do"
    # action 5 = "Open other application"
    # action 6 = "Run script"
    # action 100 = "Open Finder"
    # action 101 = "Open iTunes"
    # action 102 = "Open Disk Utility"
    # action 105 = "Open DVD Player"
    # action 106 = "Open iDVD"
    # action 107 = "Open iPhoto"
    # action 109 = "Open Front Row"
    local setting_value="$1"
    local friendly_name="$2"

    if [ $setting_value == "1" ]; then
        echo "$friendly_name is set to \"Ignore\"";
    elif [ $setting_value == "5" ]; then
        echo "$friendly_name is set to \"Open other application\"";
    elif [ $setting_value == "6" ]; then
        echo "$friendly_name is set to \"Run script\"";
    elif [ $setting_value == "100" ]; then
        echo "$friendly_name is set to \"Open Finder\"";
    elif [ $setting_value == "101" ]; then
        echo "$friendly_name is set to \"Open iTunes\"";
    elif [ $setting_value == "102" ]; then
        echo "$friendly_name is set to \"Open Disk Utility\"";
    elif [ $setting_value == "105" ]; then
        echo "$friendly_name is set to \"Open DVD Player\"";
    elif [ $setting_value == "106" ]; then
        echo "$friendly_name is set to \"Open iDVD\"";
    elif [ $setting_value == "107" ]; then
        echo "$friendly_name is set to \"Open iPhoto\"";
    elif [ $setting_value == "109" ]; then
        echo "$friendly_name is set to \"Open Front Row\"";
    # if the key doesn't exist or is 2, the setting is "Ask what to do"
    else
        echo "$friendly_name is set to \"Ask what to do\"";
    fi
}


######################################################################
CCE_79835_5_disable_auto_actions_on_blank_CD_insertion () {
    local doc="CCE_79835_5_disable_auto_actions_on_blank_CD_insertion     (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/com.apple.digihub.plist"

    local setting_name="action"
    local dictionary_name="com.apple.digihub.blank.cd.appeared"

    local friendly_name="blank CD insertion action"
    local setting_value="2" # default value is "Ask what to do"
    local required_value="1"
    local friendly_string="\"Ignore\""

    if [ -e $file ]; then
        local dict_exists=`defaults read $file | grep -c "$dictionary_name"`

        if [ $dict_exists == 1 ]; then
            local key_exists=`defaults read $file $dictionary_name | grep -c "$setting_name"`
            if [ $key_exists == 1 ]; then
                setting_value=`defaults read $file $dictionary_name | grep "$setting_name" | egrep -o " [0-9]+;$" | egrep -o "[0-9]+"`
            fi
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    # display the corresponding action to the setting's value
    if [ "$print_flag" != "" ]; then
        cd_dvd_insert_action "$setting_value" "$friendly_name"

    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "soho")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "sslf")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "oem")
                if [ $setting_value != "2" ]; then
                    echo "setting $friendly_name to \"Ask what to do\"";
                    defaults write $file $dictionary_name -dict $setting_name -int 2

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to \"Ask what to do\""
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

# OS X 10.10 testing
# Applied after a brief delay without restart.
# Both cfprefsd and SystemUIServer must be killed in order for the setting to apply
# and be accurately reflected in the GUI without a system restart.
}


######################################################################
CCE_79836_3_disable_auto_actions_on_blank_DVD_insertion () {
    local doc="CCE_79836_3_disable_auto_actions_on_blank_DVD_insertion     (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/com.apple.digihub.plist"

    local setting_name="action"
    local dictionary_name="com.apple.digihub.blank.dvd.appeared"

    local friendly_name="blank DVD insertion action"
    local setting_value="2" # default value is "Ask what to do"
    local required_value="1"
    local friendly_string="\"Ignore\""

    if [ -e $file ]; then
        local dict_exists=`defaults read $file | grep -c "$dictionary_name"`

        if [ $dict_exists == 1 ]; then
            local key_exists=`defaults read $file $dictionary_name | grep -c "$setting_name"`
            if [ $key_exists == 1 ]; then
                setting_value=`defaults read $file $dictionary_name | grep "$setting_name" | egrep -o " [0-9]+;$" | egrep -o "[0-9]+"`
            fi
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    # display the corresponding action to the setting's value
    if [ "$print_flag" != "" ]; then
        cd_dvd_insert_action "$setting_value" "$friendly_name"

    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "soho")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "sslf")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "oem")
                if [ $setting_value != "2" ]; then
                    echo "setting $friendly_name to \"Ask what to do\"";
                    defaults write $file $dictionary_name -dict $setting_name -int 2

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to \"Ask what to do\""
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi


# OS X 10.10 testing
# Applied after a brief delay without restart. Both cfprefsd and SystemUIServer must be
# killed in order for the setting to apply and be accurately reflected in the GUI
# without a system restart.

}


######################################################################
CCE_79837_1_disable_auto_music_CD_play () {
    local doc="CCE_79837_1_disable_auto_music_CD_play        (manual-test-PASSED)"

    local file="$home_path/Library/Preferences/com.apple.digihub.plist"

    local setting_name="action"
    local dictionary_name="com.apple.digihub.cd.music.appeared"

    local friendly_name="music CD insertion action"
    local setting_value="101" # default value is "Open iTunes"
    local required_value="1"
    local friendly_string="\"Ignore\""


    if [ -e $file ]; then
        local dict_exists=`defaults read $file | grep -c "$dictionary_name"`

        if [ $dict_exists == 1 ]; then
            local key_exists=`defaults read $file $dictionary_name | grep -c "$setting_name"`
            if [ $key_exists == 1 ]; then
                setting_value=`defaults read $file $dictionary_name | grep "$setting_name" | egrep -o " [0-9]+;$" | egrep -o "[0-9]+"`
            fi
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    # display the corresponding action to the setting's value
    if [ "$print_flag" != "" ]; then
        cd_dvd_insert_action "$setting_value" "$friendly_name"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "soho")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "sslf")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "oem")
                if [ $setting_value != "101" ]; then
                    echo "setting $friendly_name to \"Open iTunes\"";
                    defaults write $file $dictionary_name -dict $setting_name -int 101

                    # this process must be killed to apply the
                    # setting without restarting
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to \"Open iTunes\""
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#OS X 10.10 
# Applies in GUI, but effectiveness not confirmed.
}


######################################################################
CCE_79838_9_disable_auto_picture_CD_display () {
    local doc="CCE_79838_9_disable_auto_picture_CD_display        (manual-test-indeterminate)"

    local file="$home_path/Library/Preferences/com.apple.digihub.plist"

    local setting_name="action"
    local dictionary_name="com.apple.digihub.cd.picture.appeared"

    local friendly_name="picture CD insertion action"
    local setting_value="1" # default value is "Ignore"
    local required_value="1"
    local friendly_string="\"Ignore\""

    if [ -e $file ]; then
        local dict_exists=`defaults read $file | grep -c "$dictionary_name"`

        if [ $dict_exists == 1 ]; then
            local key_exists=`defaults read $file $dictionary_name | grep -c "$setting_name"`
            if [ $key_exists == 1 ]; then
                setting_value=`defaults read $file $dictionary_name | grep "$setting_name" | egrep -o " [0-9]+;$" | egrep -o "[0-9]+"`
            fi
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    # display the corresponding action to the setting's value
    if [ "$print_flag" != "" ]; then
        cd_dvd_insert_action "$setting_value" "$friendly_name"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # SystemUIServer may need to be killed to apply the setting
                    # without restarting, based on similar settings
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "soho")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # SystemUIServer may need to be killed to apply the setting
                    # without restarting, based on similar settings
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "sslf")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value

                    # SystemUIServer may need to be killed to apply the setting
                    # without restarting, based on similar settings
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "oem")
                if [ $setting_value != "1" ]; then
                    echo "setting $friendly_name to \"Ignore\"";
                    defaults write $file $dictionary_name -dict $setting_name -int 1

                    # SystemUIServer may need to be killed to apply the setting
                    # without restarting, based on similar settings
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to \"Ignore\""
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi


#*************** Profiles Changed from OS X guidance spreadsheet  ***************
# oem: Open iPhoto -> Ignore

# iPhoto may become the default action after it is installed, but it is not installed
# by default.

# Testing methodology: Used a CD with only images burned to it, and it was not treated
# as a picture CD, or it was not compatible with Preview or Photo Booth (the programs
# capable of viewing pictures). We tried burning the CD both with OS X's built-
# in CD burner and Roxio Creator DE 10.3 on Windows 7.

# OS X 10.10
# Value was changed in the file and in the GUI, but its effectiveness could not be
# confirmed.
}


######################################################################
CCE_79839_7_disable_auto_video_DVD_play () {
    local doc="CCE_79839_7_disable_auto_video_DVD_play        (manual-test-indeterminate)"
    local file="$home_path/Library/Preferences/com.apple.digihub.plist"

    local setting_name="action"
    local dictionary_name="com.apple.digihub.dvd.video.appeared"

    local friendly_name="video DVD insertion action"
    local setting_value="105" # default value is "Open DVD Player"
    local required_value="1"
    local friendly_string="\"Ignore\""

    if [ -e $file ]; then
        local dict_exists=`defaults read $file | grep -c "$dictionary_name"`

        if [ $dict_exists == 1 ]; then
            local key_exists=`defaults read $file $dictionary_name | grep -c "$setting_name"`
            if [ $key_exists == 1 ]; then
                setting_value=`defaults read $file $dictionary_name | grep "$setting_name" | egrep -o " [0-9]+;$" | egrep -o "[0-9]+"`
            fi
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    # display the corresponding action to the setting's value
    if [ "$print_flag" != "" ]; then
        cd_dvd_insert_action "$setting_value" "$friendly_name"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value
                
                    # SystemUIServer may need to be killed to apply the setting
                    # without restarting, based on similar settings
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "soho")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value
                
                    # SystemUIServer may need to be killed to apply the setting
                    # without restarting, based on similar settings
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "sslf")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $friendly_string";
                    defaults write $file $dictionary_name -dict $setting_name -int $required_value
                
                    # SystemUIServer may need to be killed to apply the setting
                    # without restarting, based on similar settings
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to $friendly_string"
                fi
                ;;
            "oem")
                if [ $setting_value != "105" ]; then
                    echo "setting $friendly_name to \"Open DVD Player\"";
                    defaults write $file $dictionary_name -dict $setting_name -int 105

                    # SystemUIServer may need to be killed to apply the setting
                    # without restarting, based on similar settings
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already set to \"Open DVD Player\""
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

# OS X 10.10 testing
# Value was changed in the file and in the GUI, but its effectiveness could not be
# confirmed.
}


######################################################################
CCE_79843_9_enable_firewall_logging () {
    local doc="CCE_79843_9_enable_firewall_logging              (manual-test-PASSED)"

    local defaults_file="/Library/Preferences/com.apple.appfirewall.plist"
    local defaults_name="loggingenabled"

    local setting_name="--setloggingmode"
    local command_name="/usr/libexec/ApplicationFirewall/socketfilterfw"

    local friendly_name="firewall logging"
    local oem_value="on" # Confirmed as default value
    local setting_value="$oem_value"
    local required_value="on"

    if [ -e $defaults_file ]; then
        local key_exists=`defaults read "$defaults_file" | grep -c "$defaults_name"`
        if [ $key_exists == 1 ]; then
            local defaults_value=`defaults read "$defaults_file" "$defaults_name"`
            if [ "$defaults_value" != "1" ]; then
                setting_value="off"
            else
                setting_value="on"
            fi
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        echo "$friendly_name is $setting_value"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $setting_value != "on" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "soho")
                if [ $setting_value != "on" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "sslf")
                if [ $setting_value != "on" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "oem")
                if [ $setting_value != "$oem_value" ]; then
                    echo "turning $friendly_name $oem_value";
                    "$command_name" "$setting_name" "$oem_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw
                else
                    echo "$friendly_name is already $oem_value"
                fi
                ;;
        esac
    fi


#*************** Profiles Changed from OS X guidance spreadsheet  ***************
#oem: firewall logging disabled -> firewall logging enabled

# Testing process:
# Used SSH to connect from the physical machine to the VM, and the log only recorded
# entries when the logging mode was turned on.

# Note: socketfilterfw DOES NOT CHECK USER PRIVILEGES. If a regular user issues it a
# command, it will behave as if the command was successful when it actually had no effect.
 
#OS X 10.10 
#Initial testing using SSH showed that the logs were not being filled when enabled. 
#Reason is because the log name changed to appfirewall.log from alf.log. The alf.log
#file is created on 10.10 when firewall logging is enabled, but remained unused. 
#Setting applies immediately without restart.
}


######################################################################
CCE_79844_7_ssh_disable_root_login () {
    local doc="CCE_79844_7_ssh_disable_root_login           (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="PermitRootLogin"
    local friendly_name="SSH permit root login"
    local current_string=""
    local file_contents=`cat $file`
    local new_file_contents=""
    local current_value=""

    local oem_value="yes" # confirmed value through testing
    local oem_string="#$setting_name $oem_value"

    local required_value="no"
    local required_string="$setting_name $required_value"

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        #no value indicates oem value
        if [ "$current_value" == "" ]; then
            echo "$friendly_name is set to $oem_value"
        else
            echo "$friendly_name is set to $current_value";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_string" != "$required_string" ]; then
                    echo "setting $friendly_name to $required_value"

                    # if the setting exists in the file, overwrite it
                    if [ "$current_string" != "" ]; then
                        new_file_contents=`echo "$file_contents" | sed -E "s/^#?${setting_name} .+/$required_string/"`

                        echo "$new_file_contents" > "$file"
                    # otherwise, append
                    else
                        echo "$required_string" >> "$file"
                    fi

                else
                    #if time is expressed in minutes
                    if [ `echo "$required_value" | grep -c "m$"` -gt 0 ]; then
                        echo "$friendly_name is already set to $required_value";
                    else
                        echo "$friendly_name is already set to $required_value";
                    fi
                fi
                ;;
            "soho")
                if [ "$current_string" != "$required_string" ]; then
                    echo "setting $friendly_name to $required_value"

                    # if the setting exists in the file, overwrite it
                    if [ "$current_string" != "" ]; then
                        new_file_contents=`echo "$file_contents" | sed -E "s/^#?${setting_name} .+/$required_string/"`

                        echo "$new_file_contents" > "$file"
                    # otherwise, append
                    else
                        echo "$required_string" >> "$file"
                    fi

                else
                    #if time is expressed in minutes
                    if [ `echo "$required_value" | grep -c "m$"` -gt 0 ]; then
                        echo "$friendly_name is already set to $required_value";
                    else
                        echo "$friendly_name is already set to $required_value";
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_string" != "$required_string" ]; then
                    echo "setting $friendly_name to $required_value"

                    # if the setting exists in the file, overwrite it
                    if [ "$current_string" != "" ]; then
                        new_file_contents=`echo "$file_contents" | sed -E "s/^#?${setting_name} .+/$required_string/"`

                        echo "$new_file_contents" > "$file"
                    # otherwise, append
                    else
                        echo "$required_string" >> "$file"
                    fi

                else
                    #if time is expressed in minutes
                    if [ `echo "$required_value" | grep -c "m$"` -gt 0 ]; then
                        echo "$friendly_name is already set to $required_value";
                    else
                        echo "$friendly_name is already set to $required_value";
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    if [ "$current_string" != "" ]; then
                        new_file_contents=`echo "$file_contents" | sed -E "s/^#?${setting_name} .+/$oem_string/"`
                        echo "$new_file_contents" > "$file"
                    else
                        echo "$oem_string" >> "$file"
                    fi
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi


# OS X 10.10 testing
# Setting value changes in the file, and root user is properly denied direct login
# through SSH. If the root account is set up, users are still allowed to `su -` to log
# in to the root user after they have logged in with valid credentials.

}


######################################################################
CCE_79845_4_allow_signed_sw_receive_connections () {
    local doc="CCE_79845_4_allow_signed_sw_receive_connections     (manual-test-PASSED)"

    local defaults_file="/Library/Preferences/com.apple.alf.plist"
    local defaults_name="allowsignedenabled"

    local setting_name="--setallowsigned"
    local command_name="/usr/libexec/ApplicationFirewall/socketfilterfw"

    local friendly_name="allow signed software to receive connections"

    # Confirmed as default value; isn't checked off in the GUI when block all incoming
    # connections is checked off. The plist file reports that it is on, however.
    local oem_value="on"

    local setting_value="$oem_value"
    local required_value="on"
    local required_defaults_value="1"

    if [ -e $defaults_file ]; then
        local key_exists=`defaults read "$defaults_file" | grep -c "$defaults_name"`
        if [ $key_exists == 1 ]; then
            local defaults_value=`defaults read "$defaults_file" "$defaults_name"`
            if [ "$defaults_value" != "1" ]; then
                setting_value="off"
            else
                setting_value="on"
            fi
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        echo "$friendly_name is turned $setting_value"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $setting_value != "on" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "soho")
                if [ $setting_value != "on" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "sslf")
                if [ $setting_value != "on" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "oem")
                if [ $setting_value != "$oem_value" ]; then
                    echo "turning $friendly_name $oem_value";
                    "$command_name" "$setting_name" "$oem_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw
                else
                    echo "$friendly_name is already $oem_value"
                fi
                ;;
        esac
    fi

# Testing process:
# With the setting off, screen sharing (a signed service) was set to enabled. A firewall
# prompt appeared asking to allow or deny it to receive incoming connections. The entry
# was then removed from the firewall advanced options list of applications/services. This
# setting was then applied, followed by a computer restart. With the setting enabled,
# no prompt appears asking to add screen sharing to the firewall.

# When using killall -HUP socketfilterfw, a restart was not required for some services
# to use the new value for the setting toggled by this function. The effectiveness
# of the setting without a restart was difficult to determine, because a prompt would
# only appear for a service once, when toggling it on and back off, until the
# system was restarted.

# OS X 10.10 testing
# Setting will work without restart for services that have not yet been toggled since
# the last restart. System restart will ensure the setting takes effect for all
# signed applications.

}


######################################################################
CCE_79846_2_turn_on_firewall () {
    local doc="CCE_79846_2_turn_on_firewall                (manual-test-PASSED)"

    local defaults_file="/Library/Preferences/com.apple.alf.plist"
    local defaults_name="globalstate"

    local lenient_setting_name="--setglobalstate"
    local strict_setting_name="--setblockall"
    local command_name="/usr/libexec/ApplicationFirewall/socketfilterfw"

    local friendly_name="application firewall"
    local oem_value="off" #Confirmed as default
    local setting_value="$oem_value"
    local required_value="on"
    local lenient_string="on"
    local strict_string="block all incoming connections"

    if [ -e $defaults_file ]; then
        local key_exists=`defaults read "$defaults_file" | grep -c "$defaults_name"`
        if [ $key_exists == 1 ]; then
            local defaults_value=`defaults read "$defaults_file" "$defaults_name"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$defaults_value" == "2" ]; then
            echo "$friendly_name is set to allow essential services"
        elif [ "$defaults_value" == "1" ]; then
            echo "$friendly_name is set to allow specific services"
        else
            echo "$friendly_name is set to $oem_value"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $defaults_value != "2" ]; then
                    echo "setting $friendly_name to $strict_string";
                    "$command_name" "$strict_setting_name" "$required_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw

                else
                    echo "$friendly_name is already set to $strict_string"
                fi
                ;;
            "soho")
                if [ $defaults_value != "1" ]; then
                    echo "setting $friendly_name to $lenient_string";
                    "$command_name" "$lenient_setting_name" "$required_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw

                else
                    echo "$friendly_name is already set to $lenient_string"
                fi
                ;;
            "sslf")
                if [ $defaults_value != "2" ]; then
                    echo "setting $friendly_name to $strict_string";
                    "$command_name" "$strict_setting_name" "$required_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw

                else
                    echo "$friendly_name is already set to $strict_string"
                fi
                ;;
            "oem")
                if [ $defaults_value != "0" ]; then
                    echo "setting $friendly_name to $oem_value";
                    "$command_name" "$lenient_setting_name" "$oem_value" > /dev/null
                    add_processes_to_kill_list socketfilterfw

                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi


# OS X 10.10 testing
# The application firewall is enabled immediately according to the GUI and external
# testing.
# The block all connections part of the setting works immediately as well.


}


######################################################################
CCE_79847_0_enable_safari_status_bar () {
    local doc="CCE_79847_0_enable_safari_status_bar           (manual-test-PASSED)"

    local file="$home_path/Library/Preferences/com.apple.Safari.plist"

    local setting_name="ShowStatusBar"
    local friendly_name="Safari status bar"
    local value="0" #defaults to off

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep -c "$setting_name"`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file "$setting_name"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$setting_value" != "1" ]; then
                    echo "enabling $friendly_name"
                    defaults write "$file" "$setting_name" -bool true
                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ "$setting_value" != "1" ]; then
                    echo "enabling $friendly_name"
                    defaults write "$file" "$setting_name" -bool true
                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ "$setting_value" != "1" ]; then
                    echo "enabling $friendly_name"
                    defaults write "$file" "$setting_name" -bool true
                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ "$setting_value" != "0" ]; then
                    echo "disabling $friendly_name"
                    defaults write "$file" "$setting_name" -bool false
                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#OS X 10.10 testing
#Setting was not reliably applied without killing cfprefsd. When cfprefsd was killed,
#the setting was applied after (re)starting Safari.
}


######################################################################
CCE_79848_8_no_netrc_files_on_system () {
    local doc="CCE_79848_8_no_netrc_files_on_system           (manual-test-PASSED)"

    local setting_name=".netrc"
    local friendly_name=".netrc file(s)"
    local file_exists="0"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$skip_flag" == "" ]; then
        #since this is a lengthy operation, only search if running in print or set mode
        if [ "$print_flag" != "" -o "$set_flag" != "" ]; then
            # search for all .netrc files on the system
            echo "searching entire system for $friendly_name..."
            local file_list=`find / -name .netrc 2> /dev/null` #store .netrc file paths in a list
            local num_netrc_files=`echo "$file_list" | grep -c '.'`

            if [ "$print_flag" != "" ]; then
                if [ "$num_netrc_files" == "0" ]; then
                    echo "$friendly_name do not exist on the system"
                elif [ "$v_flag" == "" ]; then
                    echo "$num_netrc_files $friendly_name exist on the system"
                else
                    echo "the following $friendly_name exist on the system:"
                    echo "$file_list"
                fi
            fi
        fi


        if [ "$set_flag" != "" ]; then
            case $profile_flag in
                "ent")
                    if [ "$num_netrc_files" -gt "0" ]; then
                        if [ "$v_flag" == "" ]; then
                            echo "removing all $friendly_name from the system"
                        fi

                        # if v_flag, print all file paths being deleted
                        for netrc_file in $file_list; do
                            if [ "$v_flag" != "" ]; then
                                echo "removing $netrc_file"
                            fi
                            srm $netrc_file
                        done

                    else
                        echo "$friendly_name have already been removed"
                    fi
                    ;;
                "soho")
                    if [ "$num_netrc_files" -gt "0" ]; then
                        if [ "$v_flag" == "" ]; then
                            echo "removing all $friendly_name from the system"
                        fi

                        for netrc_file in $file_list; do
                            if [ "$v_flag" != "" ]; then
                                echo "removing $netrc_file"
                            fi
                            srm $netrc_file
                        done

                    else
                        echo "$friendly_name have already been removed"
                    fi
                    ;;
                "sslf")
                    if [ "$num_netrc_files" -gt "0" ]; then
                        if [ "$v_flag" == "" ]; then
                            echo "removing all $friendly_name from the system"
                        fi

                        for netrc_file in $file_list; do
                            if [ "$v_flag" != "" ]; then
                                echo "removing $netrc_file"
                            fi
                            srm $netrc_file
                        done

                    else
                        echo "$friendly_name have already been removed"
                    fi
                    ;;
                "oem")
                    echo "$friendly_name have not been changed on the system"
                    ;;
            esac
        fi
    else
        echo "the $friendly_name function has been skipped due to lengthy operations (performs a full system search)"
    fi

#Note: only files called .netrc will be removed, not *.netrc

#OS X 10.10 testing
#Works as expected, with all files removed.
}


######################################################################
CCE_79849_6_at_least_2_DNS_servers () {
    local doc="CCE_79849_6_at_least_2_DNS_servers           (manual-test-PASSED)"

    local setting_name="-setdnsservers"
    local setting_param="" #<networkservice>
    local friendly_name="2 DNS servers"
    local value="" #DNS1, DNS2, DNS3
    local network_services=`networksetup -listallnetworkservices | sed -n '2,$p'`
    local dns_servers=""
    local verbose_message=""
    local print_message="all network services use at least 2 DNS servers."

    #ISSUE: if a service has a space in the name, it will be listed as separate services
    for service in $network_services; do
        dns_servers=`networksetup -getdnsservers "$service"`
        local num_lines=`echo "$dns_servers" | wc -l`

        if [ "$print_flag" != "" ]; then
            if [ "$v_flag" != "" ]; then
                #check number of DNS servers, and add a message for the current service
                if [ "$num_lines" -ge "2" ]; then
                    verbose_message="$verbose_message
The network service $service uses at least 2 DNS servers."
                else
                    verbose_message="$verbose_message
The network service $service uses less than 2 DNS servers."
                fi
            #else not verbose, set message if any service uses less than 2 DNS servers
            elif [ "$num_lines" -lt "2" ]; then
                print_message="At least one network service uses less than 2 DNS servers."
            fi
        fi
    done

    #remove the first blank line
    verbose_message=`echo "$verbose_message" | sed -n '2,$p'`

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" -o "$set_flag" != "" ]; then
        if [ "$v_flag" != "" ]; then
            echo "$verbose_message"
        else
            echo "$print_message"
        fi
    fi

# cannot set location/agency specific settings in a general manner
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "DNS servers for network services unchanged"
                ;;
            "soho")
                echo "DNS servers for network services unchanged"
                ;;
            "sslf")
                echo "DNS servers for network services unchanged"
                ;;
            "oem")
                echo "DNS servers for network services unchanged"
                ;;
        esac

    fi

#OS X 10.10
#Lists DNS servers for each service.
}


######################################################################
CCE_79852_0_disable_remote_apple_events () {
    local doc="CCE_79852_0_disable_remote_apple_events       (manual-test-PASSED)"
    
    local friendly_name="Remote Apple Events"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        systemsetup -getremoteappleevents
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "disabling $friendly_name; `systemsetup -setremoteappleevents off`"
                ;;
            "soho")
                echo "disabling $friendly_name; `systemsetup -setremoteappleevents off`"
                ;;
            "sslf")
                echo "disabling $friendly_name; `systemsetup -setremoteappleevents off`"
                ;;
            "oem")
                echo "disabling $friendly_name; `systemsetup -setremoteappleevents off`"
                ;;
        esac
    fi

#Testing process
#Created a simple AppleScript that opens a folder in Finder on the remote machine. The
#script was only able to run when Remote Apple Events were enabled.

#OS X 10.10 (systemsetup tool)
#Works immediately without restart.
}


######################################################################
CCE_79857_9_unload_uninstall_isight_camera () {
    local doc="CCE_79857_9_unload_uninstall_isight_camera         (manual-test-PASSED)"
    local kext_path=/System/Library/Extensions/
    local kext_path2="${kext_path}IOUSBFamily.kext/Contents/Plugins/"
    local vdc_plugin_path="/System/Library/Frameworks/CoreMediaIO.framework/Versions/A/Resources/"
    local destination=/System/Library/UnusedExtensions/
    local friendly_name="iSight Camera"

    local file1_no_ext=Apple_iSight
    local file1=$file1_no_ext.kext
    local file1_loaded=`kextstat | grep $file1_no_ext | wc -l`
    local file1_exists=0

    local file2_no_ext=AppleUSBVideoSupport
    local file2=$file2_no_ext.kext
    local file2_loaded=`kextstat | grep $file2_no_ext | wc -l`
    local file2_exists=0

    local file3=VDC.plugin
    local file3_exists=0

    if [ -e "$kext_path$file1" ]; then file1_exists=1; fi
    if [ -e "$kext_path2$file2" ]; then file2_exists=1; fi
    if [ -e "$vdc_plugin_path$file3" ]; then file3_exists=1; fi


    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$v_flag" != "" ]; then
            if [ $file1_exists == "1" ]; then
                echo "$file1 is present in $kext_path"
            else
                echo "$file1 is not present in $kext_path"
            fi

            if [ $file2_exists == "1" ]; then
                echo "$file2 is present in $kext_path2"
            else
                echo "$file2 is not present in $kext_path2"
            fi

            if [ $file3_exists == "1" ]; then
                echo "$file3 is present in $vdc_plugin_path"
            else
                echo "$file3 is not present in $vdc_plugin_path"
            fi

        else #no v flag
            if [ $file1_exists == "1" ] || [ $file2_exists == "1" ] || [ $file3_exists == "1" ] ; then
                echo "$friendly_name kext file(s) present"
            else
                echo "$friendly_name kext files not present"
            fi
        fi
    fi

#To delete kext files rather than move them, comment out the mv and chown
#lines and uncomment the srm lines
    if [ "$set_flag" != "" ]; then
    case $profile_flag in
        "ent")
            echo "$friendly_name kext files unchanged"
            ;;

        "soho")
            echo "$friendly_name kext files unchanged"
            ;;
        "sslf")
            #create destination directory
            if [ ! -e $destination ]; then
                mkdir $destination
            fi


            if [ "$v_flag" == "" ]; then
                echo "Moving $friendly_name kext files to $destination"
                #echo "Removing $friendly_name kext files"
            fi

            if [ $file1_exists == "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file1 from $kext_path to $destination"
                    #echo "Removing $kext_path$file1"
                fi

                #if moving to $destination and not $destination$file, the
                #kext file may unpack
                mv -f $kext_path$file1 $destination$file1
                chown -R root:wheel $destination$file1/* #moving changes owner

                #srm -rf $kext_path$file1

            elif [ "$v_flag" != "" ]; then
                echo "$file1 has already been removed from $kext_path"

            fi

            if [ $file2_exists == "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file2 from $kext_path to $destination"
                    #echo "Removing $kext_path2$file2"
                fi

                #if moving to $destination and not $destination$file, the
                #kext file may unpack
                mv -f $kext_path2$file2 $destination$file2
                chown -R root:wheel $destination$file2/* #moving changes owner

                #srm -rf $kext_path2$file2

            elif [ "$v_flag" != "" ]; then
                echo "$file2 has already been removed from $kext_path"

            fi

            if [ $file3_exists == "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file3 from $vdc_plugin_path to $destination"
                    #echo "Removing $vdc_plugin_path$file3"
                fi

                mv -f $vdc_plugin_path$file3 $destination$file3
                chown -R root:wheel $destination$file3/* #moving changes owner

                #srm -rf $vdc_plugin_path$file3

            elif [ "$v_flag" != "" ]; then
                echo "$file3 has already been removed from $vdc_plugin_path"
            fi
            ;;

        "oem")
            #
            # move the files back to their original locations
            #

            if [ "$v_flag" == "" ]; then
                echo "Moving $friendly_name kext files from $destination"
            fi

            if [ $file1_exists != "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file1 from $destination to $kext_path"
                fi
                mv -f $destination$file1 $kext_path$file1
                chown root:wheel $kext_path$file1
                chown -R root:wheel $kext_path$file1/*

            elif [ "$v_flag" != "" ]; then
                echo "$file1 already present in $kext_path"
            fi

            if [ $file2_exists != "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file2 from $destination to $kext_path2"
                fi
                mv -f $destination$file2 $kext_path2$file2
                chown root:wheel $kext_path2$file2
                chown -R root:wheel $kext_path2$file2/*

            elif [ "$v_flag" != "" ]; then
                echo "$file2 already present in $kext_path"
            fi


            if [ $file3_exists != "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file3 from $destination to $vdc_plugin_path"
                fi
                mv -f $destination$file3 $vdc_plugin_path$file3
                chown root:wheel $vdc_plugin_path$file3
                chown -R root:wheel $vdc_plugin_path$file3/*

            elif [ "$v_flag" != "" ]; then
                echo "$file3 already present in $vdc_plugin_path"
            fi
            ;;
        esac
    fi

#*************** Profiles Changed from OS X guidance spreadsheet  ***************
#soho: not specified -> camera kext and plugin files allowed
#ent: not specified -> camera kext and plugin files allowed

#Testing process
#In order to verify the effectiveness, the camera was tested using the Photo Booth
#application after applying the desired setting.

#When running the following command to check for camera presence, the setting is
#called "FaceTime HD Camera (Built-in)" on 10.10.
#`system_profiler SPUSBDataType`

#OS X 10.10
#Camera was disabled after the following file was removed from the system: /System/Library/Frameworks/CoreMediaIO.framework/Versions/A/Resources/VDC.plugin
#Setting applies immediately.
}


######################################################################
CCE_79858_7_unload_uninstall_infrared_receiver () {
    local doc="CCE_79858_7_unload_uninstall_infrared_receiver     (manual-test-PASSED)"
    local kext_path=/System/Library/Extensions/
    local destination=/System/Library/UnusedExtensions/
    local friendly_name="infrared receiver software"


    local file_no_ext=AppleIRController
    local file=$file_no_ext.kext
    local file_loaded=`kextstat | grep $file_no_ext | wc -l`
    local file_exists=0

    if [ -e "$kext_path$file" ]; then file_exists=1; fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
        if [ "$v_flag" != "" ]; then
            if [ $file_exists == "1" ]; then
                echo "$file is present in $kext_path"
            else
                echo "$file is not present in $kext_path"
            fi

        else #no v flag
            if [ $file_exists == "1" ]; then
                echo "$friendly_name kext file present"
            else
                echo "$friendly_name kext file not present"
            fi
        fi
    fi

#To delete kext files rather than move them, comment out the mv and chown
#lines and uncomment the srm lines
    if [ "$set_flag" != "" ]; then
    case $profile_flag in
        "ent")
            echo "$friendly_name kext file unchanged"
            ;;

        "soho")
            echo "$friendly_name kext file unchanged"
            ;;

        "sslf")
            #create destination directory
            if [ ! -e $destination ]; then
                mkdir $destination
            fi

            if [ "$v_flag" == "" ]; then
                echo "Unloading and moving $friendly_name kext file to $destination"
                #echo "Removing $friendly_name kext file"
            fi

            if [ $file_exists == "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file from $kext_path to $destination"
                    #echo "Removing $kext_path$file"
                fi

                #if moving to $destination and not $destination$file, the
                #kext file may unpack
                mv -f $kext_path$file $destination$file
                chown -R root:wheel $destination$file/* #moving changes owner

                #srm -rf $kext_path$file1

            elif [ "$v_flag" != "" ]; then
                echo "$file has already been removed from $kext_path"
            fi

            touch /System/Library/Extensions
            ;;
        "oem")
            if [ "$v_flag" == "" ]; then
                echo "Moving $friendly_name kext file from $destination"
            fi

            if [ $file_exists != "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file from $destination to $kext_path"
                fi
                mv -f $destination$file $kext_path$file
                chown root:wheel $kext_path$file
                chown -R root:wheel $kext_path$file/*

            elif [ "$v_flag" != "" ]; then
                echo "$file already present in $kext_path"
            fi

            touch /System/Library/Extensions
            ;;
        esac
    fi


#*************** Profiles Changed from OS X guidance spreadsheet  ***************
#soho: not specified -> infrared receiver kext file allowed
#ent: not specified -> infrared receiver kext file allowed

#OS X 10.10 real hardware test
#After removing the kext files, the GUI setting for infrared remote was no longer present.
#Setting took effect after restart.
}




######################################################################
CCE_79859_5_disable_infrared_receiver () {
    local doc="CCE_79859_5_disable_infrared_receiver          (manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.driver.AppleIRController.plist"

    local friendly_name="infrared receiver"
    local setting_name="DeviceEnabled"
    local setting_value="true" #confirmed default
    local key_exists="0"

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep -c "$setting_name"`
        if [ $key_exists == "1" ]; then
            setting_value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $setting_value == "1" ]; then
            echo "$friendly_name is enabled";
        else
            echo "$friendly_name is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name"
                    defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name"
                    defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name"
                    defaults write $file $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $setting_value != 1 ]; then
                    echo "enabling $friendly_name"
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac
    fi

# Testing - OS X 10.10
# This setting applies in the GUI immediately, but requires a restart for the
# actual setting to take effect. May not always require restart.
}


######################################################################
CCE_79862_9_ssh_set_log_level_verbose () {
    local doc="CCE_79862_9_ssh_set_log_level_verbose          (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="LogLevel"
    local friendly_name="SSH log level"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="VERBOSE"
    local soho_value="VERBOSE"
    local sslf_value="VERBOSE"
    local oem_value="INFO" #confirmed as default value

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        echo "$friendly_name is set to $current_value"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name is already set to $ent_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" == "$soho_value" ]; then
                    echo "$friendly_name is already set to $soho_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$sslf_value" ]; then
                    echo "$friendly_name is already set to $sslf_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

# OS X 10.10 testing
# Applied immediately without a restart. Extra logging appropriately recorded information
# to the /var/log/system.log file.
}


######################################################################
CCE_79863_7_ssh_disallow_empty_passwords() {
    local doc="CCE_79863_7_ssh_disallow_empty_passwords          (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="PermitEmptyPasswords"
    local friendly_name="SSH permit empty passwords"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="no"
    local soho_value="no"
    local sslf_value="no"
    local oem_value="no" #confirmed as default

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        echo "$friendly_name is set to $current_value"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name is already set to $ent_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" == "$soho_value" ]; then
                    echo "$friendly_name is already set to $soho_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$sslf_value" ]; then
                    echo "$friendly_name is already set to $sslf_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

# OS X 10.10 testing
# Could not figure out how to make empty passwords work, since more than one setting
# contributes to allowing empty passwords. The setting appears to be off by default.
# The value is successfully changed in the file, though.
}


######################################################################
CCE_79864_5_ssh_turn_off_user_environment() {
    local doc="CCE_79864_5_ssh_turn_off_user_environment          (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="PermitUserEnvironment"
    local friendly_name="SSH permit user environment"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="no"
    local soho_value="no"
    local sslf_value="no"
    local oem_value="no" #confirmed as default

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        echo "$friendly_name is set to $current_value"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name is already set to $ent_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" == "$soho_value" ]; then
                    echo "$friendly_name is already set to $soho_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$sslf_value" ]; then
                    echo "$friendly_name is already set to $sslf_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

# Testing Process
# Created the file ~/.ssh/environment and added a line "test_variable=test".
# After logging in with an SSH connection, using the command `echo $test_variable`
# should produce the output "test" if the setting is enabled. Otherwise, a blank line is
# printed.

# OS X 10.10 testing
# Setting applies immediately and environment variables are no longer set after SSH
# session begins.

}


######################################################################
CCE_79865_2_ssh_use_protocol_version_2() {
    local doc="CCE_79865_2_ssh_use_protocol_version_2          (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="Protocol"
    local friendly_name="SSH protocol version"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="2"
    local soho_value="2"
    local sslf_value="2"
    local oem_value="2" #confirmed as default

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        echo "$friendly_name is set to $current_value"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name is already set to $ent_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" == "$soho_value" ]; then
                    echo "$friendly_name is already set to $soho_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$sslf_value" ]; then
                    echo "$friendly_name is already set to $sslf_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

# OS X 10.10 testing
# Setting applies immediately and connection is denied when attempting to SSH in with
# explicit use of SSH 1 protocol.
}


######################################################################
CCE_79866_0_ssh_disable_x11_forwarding() {
    local doc="CCE_79866_0_ssh_disable_x11_forwarding          (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="X11Forwarding"
    local friendly_name="SSH X11 forwarding"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="no"
    local soho_value="no"
    local sslf_value="no"
    local oem_value="no" #confirmed as default

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        echo "$friendly_name is set to $current_value"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name is already set to $ent_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" == "$soho_value" ]; then
                    echo "$friendly_name is already set to $soho_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$sslf_value" ]; then
                    echo "$friendly_name is already set to $sslf_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

# OS X 10.10 testing
# The value is changed in the file but the effectiveness has not been tested.
}



######################################################################
CCE_79868_6_disable_printer_sharing() {
    local doc="CCE_79868_6_disable_printer_sharing          (manual-test-indeterminate)"
    local file="/etc/cups/cupsd.conf"
    
    local read_setting_name="_share_printers="
    local write_setting_name="--no-share-printers"
    local required_value="0"
    local friendly_name="printer sharing"
    local setting_value=`cupsctl | grep "$read_setting_name" | sed "s/$read_setting_name//"`

    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" == "1" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$setting_value" != "$required_value" ]; then
                    echo "disabling $friendly_name"
                    cupsctl $write_setting_name
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ "$setting_value" != "$required_value" ]; then
                    echo "disabling $friendly_name"
                    cupsctl $write_setting_name
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ "$setting_value" != "$required_value" ]; then
                    echo "disabling $friendly_name"
                    cupsctl $write_setting_name
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ "$setting_value" != "$required_value" ]; then
                    echo "disabling $friendly_name"
                    cupsctl $write_setting_name
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac
    fi
# OS X 10.10 testing
# Setting applies immediately in GUI, but the effectiveness has not been confirmed.
}


######################################################################
CCE_79870_2_do_not_send_diagnostic_info_to_apple () {
    local doc="CCE_79870_2_do_not_send_diagnostic_info_to_apple        (manual-test-indeterminate)"
    local file="/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"
    local setting_name="AutoSubmit"
    local friendly_name="sending of diagnostic info to Apple"
    local setting_value="0" #confirmed as default


    if [ -e "$file" ]; then
        local exists=`defaults read "$file" | grep -c "$setting_name"`
        #if key not present, it has default value
        if [ "$exists" != "0" ]; then
            setting_value=`defaults read "$file" "$setting_name"`
        fi
    fi


    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" == "1" ]; then
            echo "$friendly_name is enabled";
        else
            echo "$friendly_name is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "$setting_value" != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write "$file" $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ "$setting_value" != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write "$file" $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ "$setting_value" != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write "$file" $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ "$setting_value" != "0" ]; then
                    echo "disabling $friendly_name";
                    defaults write "$file" $setting_name -bool false
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac
    fi

#OS X 10.10
#Changes immediately in the preferences GUI, but effectiveness not confirmed.
}


######################################################################
CCE_79875_1_restrict_screen_sharing_to_specified_users () {
    local doc="CCE_79875_1_restrict_screen_sharing_to_specified_users   (manual-test-PASSED)"

    local file="/private/var/db/dslocal/nodes/Default/groups/com.apple.access_screensharing.plist"
    local screensharing_file="/System/Library/LaunchDaemons/com.apple.screensharing.plist"
    local friendly_name="screen sharing allowed for"
    local setting_name="users"
    local nestedgroups_value=
    local setting_value=
    local required_value=""

    if [ -e "$file" ]; then
        local key_exists=`defaults read $file | grep -c "$setting_name "`
        if [ "$key_exists" -gt 0 ]; then
            setting_value=`defaults read $file $setting_name -array`
        fi

        key_exists=`defaults read $file | grep -c "nestedgroups "`
        if [ "$key_exists" -gt 0 ]; then
            nestedgroups_value=`defaults read $file nestedgroups -array`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" -a ! -e "$file" ]; then
        echo "$friendly_name all users"
    elif [ "$print_flag" != "" ]; then
        #retrieve GeneratedIDs and remove parentheses, trailing commas, and quotes
        local nested_groups=`defaults read $file nestedgroups -array 2> /dev/null | sed 's/,$//' | sed 's/[()"]//g'`
        local current_group=""
        local group_names=""
        local short_message="" #used for normal print output

        #used for verbose print output
        local users_message=""
        local groups_message=""

        #extract nestedgroups and store their actual group names
        for group_uuid in $nested_groups; do
            #retrieve group name from the group's GeneratedID
            current_group=`dscl . readall /Groups GeneratedUID | grep -A 1 $group_uuid | grep "^RecordName:" | sed 's/^RecordName: //'`
            group_names="${group_names}$current_group, "
        done

        #if user names are specified in the allowed access file
        if [ "$setting_value" != ""  -a `echo "$setting_value" | grep -c .` != 2 ]; then
            #remove parentheses from defaults array
            users_message=`echo "$friendly_name these users:" $setting_value | sed 's/( //' | sed 's/ )//'`
            short_message="$friendly_name some users"

        else
            users_message="$friendly_name no users"
        fi

        #if group GeneratedIDs are specified in the allowed access file
        if [ "$group_names" != "" -a `echo "$nested_groups" | grep -c .` -gt 0 ]; then
            groups_message="$friendly_name these groups: `echo $group_names | sed 's/,$//'`"
            short_message="$friendly_name some users"
        else
            groups_message="$friendly_name no groups"
        fi

        #normal print
        if [ "$v_flag" == "" ]; then
            if [ "$short_message" == "" ];then
                echo "$friendly_name no users"
            else
                echo "$short_message"
            fi
        else #verbose print
            echo "$users_message"
            echo "$groups_message"
        fi

    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$setting_value" != "" -o "$nestedgroups_value" != "" ]; then
                    echo "setting $friendly_name no users";

                    defaults write $file $setting_name -array $required_value

                    #in case the keys don't exist, don't show errors
                    defaults delete $file "groupmembers" 2> /dev/null
                    defaults delete $file "nestedgroups" 2> /dev/null

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name no users is already set"
                fi
                ;;
            "soho")
                if [ "$setting_value" != "" -o "$nestedgroups_value" != "" ]; then
                    echo "setting $friendly_name no users";
                    defaults write $file $setting_name -array $required_value

                    #in case the keys don't exist, don't show errors
                    defaults delete $file "groupmembers" 2> /dev/null
                    defaults delete $file "nestedgroups" 2> /dev/null

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name no users is already set"
                fi
                ;;
            "sslf")
                if [ "$setting_value" != "" -o "$nestedgroups_value" != "" ]; then
                    echo "setting $friendly_name no users";
                    defaults write $file $setting_name -array $required_value

                    #in case the keys don't exist, don't show errors
                    defaults delete $file "groupmembers" 2> /dev/null
                    defaults delete $file "nestedgroups" 2> /dev/null

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name no users is already set"
                fi
                ;;
            "oem")
                echo "setting $friendly_name Administrators group only"
                local admin_uuid=`dsmemberutil getuuid -G "BUILTIN\Administrators"`
                defaults write $file nestedgroups -array "$admin_uuid"
                defaults delete $file "$setting_name" 2> /dev/null

                add_processes_to_kill_list cfprefsd
                ;;
        esac
    fi

#Testing process
#After removing the user elements from the "users" key in $file, the users specified in
#the GUI were unchanged. The users specified in the GUI were still able to use screen
#sharing, even though the plist file key "users" was blank. After deleting the key
#"groupmembers", only Administrators showed up under "Allow access for: Only these users".
#
#However, a user that was previously on the list and in $file under "users" was able
#to connect even though their name didn't show up in the GUI or in $file.

#Removing both "groupmembers" and "nestedgroups" keys in addition to setting "users" to
#blank caused the GUI to select "Only these users" and to display no users in the box.
#The last users to have permission could still connect, however. After restart, the
#users could no longer connect.
#If the "groupmembers" key is not removed, the GUI may still show users as being allowed,
#even though they won't be allowed after system restart.

#OS X 10.10
#works after restart.
}


######################################################################
CCE_79876_9_update_apple_software () {
    local doc="CCE_79876_9_update_apple_software                (manual-test-PASSED)"
    local friendly_name="Apple software updates"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$skip_flag" == "" ]; then
        if [ "$print_flag" != "" ]; then
            echo "Checking for software updates..."
            local setting_value=`softwareupdate -l`
            local available_updates=`echo "$setting_value" | egrep "(\[recommended\])|(\[restart\])"`
            local number_of_updates=`echo "$available_updates" | grep -c "."`

            #if any updates are available, then updates will be required
            if [ "$number_of_updates" -gt "0" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "The following $friendly_name are available:"
                    echo "$available_updates"
                else
                    echo "$number_of_updates $friendly_name were found that need to be installed"
                fi
            else
                echo "all $friendly_name are installed"
            fi
        fi

        if [ "$set_flag" != "" ]; then
            case $profile_flag in
                "ent")
                    echo "installing $friendly_name..."
                    softwareupdate -ia
                    ;;
                "soho")
                    echo "installing $friendly_name..."
                    softwareupdate -ia
                    ;;
                "sslf")
                    echo "installing $friendly_name..."
                    softwareupdate -ia
                    ;;
                "oem")
                    echo "$friendly_name will not be downloaded or installed at this time"
                    ;;
            esac
        fi
    else #skip flag is enabled, so don't check for updates or install them
        echo "$friendly_name setting has been skipped. The duration required for this setting is variable depending on number of required updates and download speed."
    fi

#OS X 10.10 testing
#Successfully applied the required updates.
}


######################################################################
CCE_79889_2_disable_remote_login () {
local doc="CCE_79889_2_disable_remote_login    (manual-test-PASSED)"

    local friendly_name="remote login"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        systemsetup -getremotelogin
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "disabling $friendly_name; `systemsetup -f -setremotelogin off`"
                ;;
            "soho")
                echo "disabling $friendly_name; `systemsetup -f -setremotelogin off`"
                ;;
            "sslf")
                echo "disabling $friendly_name; `systemsetup -f -setremotelogin off`"
                ;;
            "oem")
                echo "disabling $friendly_name; `systemsetup -f -setremotelogin off`"
                ;;
        esac
    fi


#Note: The file to change may have been com.apple.sshd, but is now com.openssh.sshd.

#OS X 10.10 (systemsetup tool)
#Works immediately without restart.
}


######################################################################
CCE_79893_4_ssh_keep_alive_messages () {
    local doc="CCE_79893_4_ssh_keep_alive_messages             (manual-test-PASSED)"
    local file="/etc/sshd_config"
    local setting_name="ClientAliveCountMax"
    local friendly_name="SSH client alive count max"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="0"
    local soho_value="0"
    local sslf_value="0"
    local oem_value="3" #Confirmed default value

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not effect the setting;
        # current_value will equal current_string if the setting is commented
        current_value=`echo "$current_string" | sed -E "s/^$setting_name //"`

        # use default value if no value present or line commented
        if [ "$current_value" == "" -o "$current_value" == "$current_string" ]; then
            current_value="$oem_value"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" != "0" ]; then
            echo "$friendly_name is set to $current_value"
        else
            echo "$friendly_name is $current_value"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                # setting must be less than or equal to the required interval
                if [ "$current_value" -eq "$ent_value" ]; then
                    echo "$friendly_name is already set to $ent_value"
                else
                    echo "setting $friendly_name to $ent_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                # setting must be less than or equal to the required interval
                if [ "$current_value" -eq "$soho_value" ]; then
                    echo "$friendly_name is already set to $soho_value"
                else
                    echo "setting $friendly_name to $soho_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                # setting must be less than or equal to the required interval
                if [ "$current_value" -eq "$sslf_value" ]; then
                    echo "$friendly_name is already set to $sslf_value"
                else
                    echo "setting $friendly_name to $sslf_value"
                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name $sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        # append setting to file
                        echo "$setting_name $sslf_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

#Note: There seems to be a limit on how large ClientAliveCountMax can be, but an exact
#value could not be confirmed. The limit seemed to be 3, but this was not consistent
#across using different values for ClientAliveInterval.

#OS X 10.10
#Setting applies immediately without restart.
}



######################################################################
CCE_79922_1_disable_remote_management () {
local doc="CCE_79922_1_disable_remote_management                   (manual-test-PASSED)"
    local file_enabled=0 #confirmed as default
    local friendly_name="remote management"
    local command="/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart" #may take several seconds for the process to start after enabling the setting
    local command_options="-quiet -deactivate -stop"

    file_enabled=`ps -e | grep -ic "ARDAgent" | grep -v "grep"`

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then

        if [ "$file_enabled" == "1" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled"
        fi
    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$file_enabled" != 0 ]; then
                    echo "disabling $friendly_name"
                    $command $command_options

                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ "$file_enabled" != 0 ]; then
                    echo "disabling $friendly_name"
                    $command $command_options

                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ "$file_enabled" != 0 ]; then
                    echo "disabling $friendly_name"
                    $command $command_options

                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ "$file_enabled" != 0 ]; then
                    echo "disabling $friendly_name"
                    $command $command_options

                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac
    fi


#OS X 10.10 testing 
#It may take several seconds for the process to start after enabling the setting.
#Setting was successfully disabled using the kickstart program.
}


#Used by CCE_79932_0_system_files_and_directories_no_uneven_permissions
#An uneven permission set is defined as the owner not having all, or more
#permissions than group and other.
find_and_fix_uneven_file_permissions() {

    local tmp_file='samc_tmp_perl_script'
    local perl_program='use Getopt::Std;

        sub get_rwx_array {
            my $mode = shift;
            my @rwx_array;

            if ($mode == 7) {
                @rwx_array = qw(r w x);
            }
            elsif ($mode == 6) {
                @rwx_array = qw(r w -);
            }
            elsif ($mode == 5) {
                @rwx_array = qw(r - x);
            }
            elsif ($mode == 4) {
                @rwx_array = qw(r - -);
            }
            elsif ($mode == 3) {
                @rwx_array = qw(- w x);
            }
            elsif ($mode == 2) {
                @rwx_array = qw(- w -);
            }
            elsif ($mode == 1) {
                @rwx_array = qw(- - x);
            }
            elsif ($mode == 0) {
                @rwx_array = qw(- - -);
            }

                return @rwx_array;
        }

        my %options;
        getopts("p", \%options);
        while (<>){#while command line args

            chomp $_; #remove newline
            if (-d){
                $_ = $_ . "/";
            }
            #print $_;
            my $current_permissions=`stat -f "%OLp" "$_"`;

            #remove hidden carriage return or "invisible" chars
            $current_permissions =~ s/[\W]//g;

            #add leading 0s since stat does not include them and chmod needs them
            while (length $current_permissions < 3) {
                $current_permissions = "0" . $current_permissions;
            }

            #get setid bits
            my $setid = `stat -f "%OMp" "$_"`;
            chomp($setid);

            my $user = substr $current_permissions, 0, 1;
            my $group = substr $current_permissions, 1, 1;
            my $other = substr $current_permissions, 2, 1;
            my $uneven = 0;
            $current_permissions = $setid . $current_permissions;
            my @setid_perms;

            #extract setid bits
            if ($setid == 6) {
                @setid_perms = qw(s s);
            }
            elsif ($setid == 4) {
                @setid_perms = qw(s -);
            }
            elsif ($setid == 2) {
                @setid_perms = qw(- s);
            }
            elsif ($setid == 0) {
                @setid_perms = qw(- -);
            }

            #extract access permissions
            my @user_perms = get_rwx_array($user);
            my @group_perms = get_rwx_array($group);
            my @other_perms = get_rwx_array($other);

            #compare the user permissions with group and other
            foreach my $i (0..2) {
                my $bit = @user_perms[$i];

                #if group or other has a permission that user does not, give that
                #permission to user
                if ($bit eq "-") {
                    if (@group_perms[$i] ne "-") {
                        @user_perms[$i] = @group_perms[$i];
                        $uneven = 1;

                    }
                    elsif (@other_perms[$i] ne "-") {
                        @user_perms[$i] = @other_perms[$i];
                        $uneven = 1;
                    }
                }
            }

            #restore setuid
            if (@setid_perms[0] ne "-") {
                if ( @user_perms[2] eq "x") {
                    @user_perms[2] = "sx";
                }
                else {
                    @user_perms[2] = "S";
                }
            }

            #restore setgid
            if (@setid_perms[1] ne "-") {
                if ( @group_perms[2] eq "x") {
                    @group_perms[2] = "sx";
                }
                else {
                    @group_perms[2] = "S";
                }
            }

            #remove the - and blank spaces from each permission set
            my $user_set = "@{user_perms}";
            my $group_set = "@{group_perms}";
            my $other_set = "@{other_perms}";

            $user_set =~ s/[ -]//g;
            $group_set =~ s/[ -]//g;
            $other_set =~ s/[ -]//g;

            #create the string for use by chmod to set the user permissions
            my $permissions = "u=$user_set";

            if ($uneven) {
                if($options{p}){
                    print("	$_		uneven permissions: $current_permissions \n");
                }
                else {
                    system("chmod $permissions $_\n");
                    print("	Fixing uneven permissions on $_\n");
                }
            }

        }

        if (!$uneven) {
            #if the print option is selected
            if ($options{p}) {
                print("Files with uneven permissions do not exist\n");
            }
            #if the set option is selected
            else {
                print("No uneven file permissions were detected, so no changes were made to the system\n");
            }
        }'


    echo "$perl_program" > "$tmp_file"

    if [ "$2" == "p" ]; then
        echo "$1" | perl $tmp_file -p
    else
        echo "$1" | perl $tmp_file
    fi

    rm "$tmp_file"
}


######################################################################
CCE_79932_0_system_files_and_directories_no_uneven_permissions () {
    local doc="CCE_79932_0_system_files_and_directories_no_uneven_permissions                   (manual-test-PASSED)"

    local system_directories="/etc /bin /usr/bin /sbin /usr/sbin"

    # L option is necessary to change actual files, since /etc is a symlink to /private/etc
    local system_files=`find -L $system_directories`
    local current_permissions=""

    if [ "$print_flag" != "" ]; then
        find_and_fix_uneven_file_permissions "$system_files" "p"
    fi


    if [ "$set_flag" != "" ]; then
    case $profile_flag in
            "ent")
                find_and_fix_uneven_file_permissions "$system_files"
                ;;
            "soho")
                find_and_fix_uneven_file_permissions "$system_files"
                ;;
            "sslf")
                find_and_fix_uneven_file_permissions "$system_files"
                ;;
            "oem")
                echo "uneven file permissions will not be changed"
                ;;
        esac
    fi

#OS X 10.10
#Uneven permissions are successfully fixed.
}



######################################################################
CCE_79908_0_sudo_restrict_to_single_terminal () {
    local doc="CCE_79908_0_sudo_restrict_to_single_terminal        (manual-test-PASSED)"
local file="/etc/sudoers"
    local file_contents=`cat "$file" 2> /dev/null`
    local new_file_contents=""

    local friendly_name="restrict sudo to single terminal"
    local setting_name="tty_tickets" #Defaults tty_tickets is full setting name
    local current_value=""
    local current_string=""


    local required_value="enabled"
    local oem_value="disabled"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ -e $file ]; then
        current_string=`echo "$file_contents" | egrep -i "^Defaults[[:blank:]]*$setting_name"`

    fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_string" != "" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_string" != "" ]; then
                    echo "$friendly_name is already $required_value"
                else
                    echo "setting $friendly_name to $required_value"
                    if [ "$v_flag" != "" ]; then
                        echo "creating a backup of $file as ${file}.bk"
                    fi
                    cp "$file" "${file}.bk"

                    # append setting to file
                    echo "Defaults	${setting_name}" >> "$file"

                    #check exit code to determine if write was successful
                    visudo -qc
                    local test_sudoers=$?

                    #revert to backup file if an error occurred
                    if [ "$test_sudoers" != "0" ]; then
                        echo "write to /etc/sudoers failed: reverting to backup file"
                        mv "${file}.bk" "$file"
                    else
                        echo "write to $file was successful"
                        rm "${file}.bk" 2> /dev/null
                    fi
                fi
                ;;
            "soho")
                if [ "$current_string" != "" ]; then
                    echo "$friendly_name is already $required_value"
                else
                    echo "setting $friendly_name to $required_value"
                    if [ "$v_flag" != "" ]; then
                        echo "creating a backup of $file as ${file}.bk"
                    fi
                    cp "$file" "${file}.bk"


                    # append setting to file
                    echo "Defaults	${setting_name}" >> "$file"

                    #check exit code to determine if write was successful
                    visudo -qc
                    local test_sudoers=$?

                    #revert to backup file if an error occurred
                    if [ "$test_sudoers" != "0" ]; then
                        echo "write to /etc/sudoers failed: reverting to backup file"
                        mv "${file}.bk" "$file"
                    else
                        echo "write to $file was successful"
                        rm "${file}.bk" 2> /dev/null
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_string" != "" ]; then
                    echo "$friendly_name is already $required_value"
                else
                    echo "setting $friendly_name to $required_value"
                    if [ "$v_flag" != "" ]; then
                        echo "creating a backup of $file as ${file}.bk"
                    fi
                    cp "$file" "${file}.bk"


                    # append setting to file
                    echo "Defaults	${setting_name}" >> "$file"

                    #check exit code to determine if write was successful
                    visudo -qc
                    local test_sudoers=$?

                    #revert to backup file if an error occurred
                    if [ "$test_sudoers" != "0" ]; then
                        echo "write to /etc/sudoers failed: reverting to backup file"
                        mv "${file}.bk" "$file"
                    else
                        echo "write to $file was successful"
                        rm "${file}.bk" 2> /dev/null
                    fi
                fi
                ;;
            "oem")

                if [ "$current_value" == "$oem_value" ]; then
                    echo "$friendly_name is already $oem_value"
                else
                    echo "setting $friendly_name to $oem_value"
                    if [ "$v_flag" != "" ]; then
                        echo "creating a backup of $file as ${file}.bk"
                    fi
                    cp "$file" "${file}.bk"

                    # replace existing value with nothing for OEM
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string//"`
                    echo "$new_file_contents" > "$file"

                    #check exit code to determine if write was successful
                    visudo -qc
                    local test_sudoers=$?

                    #revert to backup file if an error occurred
                    if [ "$test_sudoers" != "0" ]; then
                        echo "write to /etc/sudoers failed: reverting to backup file"
                        mv "${file}.bk" "$file"
                    else
                        echo "write to $file was successful"
                        rm "${file}.bk" 2> /dev/null
                    fi
                fi
                ;;
        esac
    fi

#OS X 10.10
#Worked immediately without restart.
}


######################################################################
CCE_79910_6_sudo_timeout_period_set_to_0 () {
    local doc="CCE_79910_6_sudo_timeout_period_set_to_0            (manual-test-PASSED)"
    local file="/etc/sudoers"
    local file_contents=`cat "$file" 2> /dev/null`
    local new_file_contents=""

    local friendly_name="sudo timeout period"
    local setting_name="timestamp_timeout="
    local current_value=""
    local current_string=""


    local required_value="0"
    local oem_value="5"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ -e $file ]; then
        current_string=`echo "$file_contents" | egrep -i "^Defaults[[:blank:]]$setting_name"`

        if [ "$current_string" != "" ]; then
            current_value=`echo $current_string | sed -E "s/Defaults[ 	]*$setting_name//g"`
        else
            current_value="$oem_value"
        fi
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" -lt 0 ]; then
            echo "$friendly_name is set to never timeout"
        else
            echo "$friendly_name is set to $current_value minutes"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" == "$required_value" ]; then
                    echo "$friendly_name is already set to $required_value minutes"
                else
                    echo "setting $friendly_name to $required_value"
                    if [ "$v_flag" != "" ]; then
                        echo "creating a backup of $file as ${file}.bk"
                    fi
                    cp "$file" "${file}.bk"

                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/Defaults	${setting_name}${required_value}/"`
                        echo "$new_file_contents" > "$file"

                        #check exit code to determine if write was successful
                        visudo -qc
                        local test_sudoers=$?

                        #revert to backup file if an error occurred
                        if [ "$test_sudoers" != "0" ]; then
                            echo "write to /etc/sudoers failed: reverting to backup file"
                            mv "${file}.bk" "$file"
                        else
                            echo "write to $file was successful"
                            rm "${file}.bk" 2> /dev/null
                        fi
                    else
                        # append setting to file
                        echo "Defaults	${setting_name}${required_value}" >> "$file"

                        #check exit code to determine if write was successful
                        visudo -qc
                        local test_sudoers=$?

                        #revert to backup file if an error occurred
                        if [ "$test_sudoers" != "0" ]; then
                            echo "write to /etc/sudoers failed: reverting to backup file"
                            mv "${file}.bk" "$file"
                        else
                            echo "write to $file was successful"
                            rm "${file}.bk" 2> /dev/null
                        fi
                    fi
                fi
                ;;
            "soho")
                if [ "$current_value" == "$required_value" ]; then
                    echo "$friendly_name is already set to $required_value minutes"
                else
                    echo "setting $friendly_name to $required_value"
                    if [ "$v_flag" != "" ]; then
                        echo "creating a backup of $file as ${file}.bk"
                    fi
                    cp "$file" "${file}.bk"

                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/Defaults	${setting_name}${required_value}/"`
                        echo "$new_file_contents" > "$file"

                        #check exit code to determine if write was successful
                        visudo -qc
                        local test_sudoers=$?

                        #revert to backup file if an error occurred
                        if [ "$test_sudoers" != "0" ]; then
                            echo "write to /etc/sudoers failed: reverting to backup file"
                            mv "${file}.bk" "$file"
                        else
                            echo "write to $file was successful"
                            rm "${file}.bk" 2> /dev/null
                        fi
                    else
                        # append setting to file
                        echo "Defaults	${setting_name}${required_value}" >> "$file"

                        #check exit code to determine if write was successful
                        visudo -qc
                        local test_sudoers=$?

                        #revert to backup file if an error occurred
                        if [ "$test_sudoers" != "0" ]; then
                            echo "write to /etc/sudoers failed: reverting to backup file"
                            mv "${file}.bk" "$file"
                        else
                            echo "write to $file was successful"
                            rm "${file}.bk" 2> /dev/null
                        fi
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$required_value" ]; then
                    echo "$friendly_name is already set to $required_value minutes"
                else
                    echo "setting $friendly_name to $required_value"
                    if [ "$v_flag" != "" ]; then
                        echo "creating a backup of $file as ${file}.bk"
                    fi
                    cp "$file" "${file}.bk"

                    if [ "$current_string" != "" ]; then
                        # replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/Defaults	${setting_name}${required_value}/"`
                        echo "$new_file_contents" > "$file"

                        #check exit code to determine if write was successful
                        visudo -qc
                        local test_sudoers=$?

                        #revert to backup file if an error occurred
                        if [ "$test_sudoers" != "0" ]; then
                            echo "write to /etc/sudoers failed: reverting to backup file"
                            mv "${file}.bk" "$file"
                        else
                            echo "write to $file was successful"
                            rm "${file}.bk" 2> /dev/null
                        fi
                    else
                        # append setting to file
                        echo "Defaults	${setting_name}${required_value}" >> "$file"

                        #check exit code to determine if write was successful
                        visudo -qc
                        local test_sudoers=$?

                        #revert to backup file if an error occurred
                        if [ "$test_sudoers" != "0" ]; then
                            echo "write to /etc/sudoers failed: reverting to backup file"
                            mv "${file}.bk" "$file"
                        else
                            echo "write to $file was successful"
                            rm "${file}.bk" 2> /dev/null
                        fi
                    fi
                fi
                ;;
            "oem")

                if [ "$current_value" == "$oem_value" ]; then
                    echo "$friendly_name is already set to $oem_value minutes"
                else
                    echo "setting $friendly_name to $oem_value minutes"
                    if [ "$v_flag" != "" ]; then
                        echo "creating a backup of $file as ${file}.bk"
                    fi
                    cp "$file" "${file}.bk"

                    # replace existing value with nothing for OEM
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string//"`
                    echo "$new_file_contents" > "$file"

                    #check exit code to determine if write was successful
                    visudo -qc
                    local test_sudoers=$?

                    #revert to backup file if an error occurred
                    if [ "$test_sudoers" != "0" ]; then
                        echo "write to /etc/sudoers failed: reverting to backup file"
                        mv "${file}.bk" "$file"
                    else
                        echo "write to $file was successful"
                        rm "${file}.bk" 2> /dev/null
                    fi
                fi
                ;;
        esac
    fi

#OS X 10.10
#Worked immediately without restart.
}


######################################################################
CCE_79912_2_set_audit_control_flags () {
    local doc="CCE_79912_2_set_audit_control_flags    (manual-test-PASSED)"
    local file="/etc/security/audit_control"
    local setting_name="flags"
    local friendly_name="audit control flags"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="lo,ad,-all,fd,fm,^-fa,^-fc,^-cl"
    local soho_value="lo,ad,-all,fd,fm,^-fa,^-fc,^-cl"
    local sslf_value="lo,ad,-all,fd,fm,^-fa,^-fc,^-cl"
    local oem_value="lo,aa" #Confirmed default value


    #default to oem value in case file does not exist
    local oem_string="$setting_name:$oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        #store the line that begins with flags, if it exists
        current_string=`echo "$file_contents" | egrep "^$setting_name:"`

        #store just the flags, without "flags:"
        current_value=`echo "$current_string" | sed -E "s/^$setting_name://"`

    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "$friendly_name are not set"
        else
            echo "$friendly_name are set to \"$current_value\""
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                #setting must be less than or equal to the required interval
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name are already set to \"$ent_value\""
                else
                    echo "setting $friendly_name to \"$ent_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                #setting must be less than or equal to the required interval
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name are already set to \"$ent_value\""
                else
                    echo "setting $friendly_name to \"$ent_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$ent_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                #setting must be less than or equal to the required interval
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name are already set to \"$ent_value\""
                else
                    echo "setting $friendly_name to \"$ent_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$ent_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to \"$oem_value\""
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                elif [ "$current_string" == "" ]; then
                    #since setting doesn't exist, append it to the file
                    echo "setting $friendly_name to \"$oem_value\""
                    echo "$setting_name:$oem_value" >> $file
                else
                    echo "$friendly_name are already set to \"$oem_value\""
                fi
                ;;
        esac
    fi

#OS X 10.10
#The flags are successfully changed in /etc/security/audit_control. Restart required.
}


######################################################################
CCE_79915_5_restrict_remote_management_to_specific_users () {
local doc="CCE_79915_5_restrict_remote_management_to_specific_users    manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.RemoteManagement.plist"
    local file_exists=0
    local friendly_name="restricting remote management"

    #may take several seconds for the process to start after enabling the setting
    local command="/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart"

    local command_options="-quiet -configure -allowAccessFor -specifiedUsers -access -off"
    local oem_command_options="-quiet -configure -access -on -restart -agent -allowAccessFor -allUsers"

    if [ -e "$file" ]; then
        file_exists="1"
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    if [ "$print_flag" != "" ]; then

        if [ "$file_exists" == "1" ]; then
            local setting_value=`defaults read "$file" ARD_AllLocalUsers`

            if [ "$setting_value" == "0" ]; then
                echo "remote management is restricted to specific users"
            else
                echo "remote management is restricted to all local users"
            fi
        else
            echo "remote management is restricted to all local users"
        fi
    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "$friendly_name to no users"
                $command $command_options
                ;;
            "soho")
                echo "$friendly_name to no users"
                $command $command_options
                ;;
            "sslf")
                echo "$friendly_name to no users"
                $command $command_options
                ;;
            "oem")
                echo "$friendly_name to all users"
                $command $oem_command_options
                ;;
        esac
    fi

#Note: This setting does not enable/disable the remote management setting found
#in System Preferences. Instead, it configures the users that are allowed to use
#the service.

#OS X 10.10 testing
#System does not need to be restarted, but some time is necessary after making
#a change before it takes effect.
}


######################################################################
CCE_79934_6_only_root_has_uid_zero () {
    local doc="CCE_79934_6_only_root_has_uid_zero       (manual-test-PASSED)"

    #editing /etc/passwd supposedly only affects single-user mode
    #local file="/etc/passwd"
    #local search_result=`cat "$file" | egrep ".+:.+:0:.+"`


    local setting_name=""
    local friendly_name="non-root users with UID of 0"

    local user_count=0

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local offending_users=""

    #save all uids in a list
    while read -r user_name; do
        local uid=`id -u $user_name 2> /dev/null`

        if [ "$uid" == "0" -a "$user_name" != "root" ]; then

            #only store users who shouldn't have a UID of 0
            offending_users="$offending_users $user_name"
            user_count=`expr $user_count + 1`
        fi
    done <<< "$full_user_list"

    if [ "$print_flag" != "" ]; then
        #if more than one user has uid of 0, print those user names
        #root is not added to the list of invalid users
        if [ "$user_count" -gt 0 ]; then
            if [ "$v_flag" == "" ]; then
                echo "number of $friendly_name:  $user_count"
            else
                echo "$friendly_name: $offending_users"
            fi
        else

            echo "there are no $friendly_name"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$user_count" -gt 0 ]; then
                    echo "setting root as only account with UID of 0"
                    local new_uid=501

                    #look up user id, redirect error to stdout, then to grep
                    for offender in $offending_users; do

                        while [ `id -un $new_uid 2>&1 | grep -c "no such user"` == 0 ]; do
                            new_uid=`expr $new_uid + 1`
                        done

                        #change the UID to an unused one for the current user in the list
                        dscl . -change "/Users/${offender}" UniqueID 0 $new_uid
                    done

                else
                    echo "root is already the only account with UID of 0"
                fi
                ;;
            "soho")
                if [ "$user_count" -gt 0 ]; then
                    echo "setting root as only account with UID of 0"
                    local new_uid=501

                    #look up user id, redirect error to stdout, then to grep
                    for offender in $offending_users; do

                        while [ `id -un $new_uid 2>&1 | grep -c "no such user"` == 0 ]; do
                            new_uid=`expr $new_uid + 1`
                        done

                        #change the UID to an unused one for the current user in the list
                        dscl . -change "/Users/${offender}" UniqueID 0 $new_uid
                    done

                else
                    echo "root is already the only account with UID of 0"
                fi
                ;;
            "sslf")
                if [ "$user_count" -gt 0 ]; then
                    echo "setting root as only account with UID of 0"
                    local new_uid=501

                    #look up user id, redirect error to stdout, then to grep
                    for offender in $offending_users; do

                        while [ `id -un $new_uid 2>&1 | grep -c "no such user"` == 0 ]; do
                            new_uid=`expr $new_uid + 1`
                        done

                        #change the UID to an unused one for the current user in the list
                        dscl . -change "/Users/${offender}" UniqueID 0 $new_uid
                    done

                else
                    echo "root is already the only account with UID of 0"
                fi
                ;;
            "oem")
                if [ "$user_count" -gt 0 ]; then
                    echo "setting root as only account with UID of 0"
                    local new_uid=501

                    #look up user id, redirect error to stdout, then to grep
                    for offender in $offending_users; do

                        while [ `id -un $new_uid 2>&1 | grep -c "no such user"` == 0 ]; do
                            new_uid=`expr $new_uid + 1`
                        done

                        #change the UID to an unused one for the current user in the list
                        dscl . -change "/Users/${offender}" UniqueID 0 $new_uid
                    done

                else
                    echo "root is already the only account with UID of 0"
                fi
                ;;
        esac
    fi

#OS X 10.10 testing
#The UIDs of non root users that are 0 are successfully changed, effective immediately.
#If the user with a UID of 0 is currently logged in, the changes won't take effect
#until they log out and back in again.
}


######################################################################
CCE_79936_1_restrict_remote_apple_events_to_specific_users () {
    local doc="CCE_79936_1_restrict_remote_apple_events_to_specific_users   (manual-test-PASSED)"

    local file="/private/var/db/dslocal/nodes/Default/groups/com.apple.access_remote_ae.plist"
    local friendly_name="Remote Apple Events allowed for"
    local setting_name="users"
    local nestedgroups_value=
    local setting_value=
    local required_value=""
    local file_exists="0"  #does not exist by default, and default = all users allowed

    if [ -e "$file" ]; then
        file_exists="1"
    
        local key_exists=`defaults read $file | grep -c "$setting_name "`
        if [ "$key_exists" -gt 0 ]; then
            setting_value=`defaults read $file $setting_name -array`
        fi

        key_exists=`defaults read $file | grep -c "nestedgroups "`
        if [ "$key_exists" -gt 0 ]; then
            nestedgroups_value=`defaults read $file nestedgroups -array`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" -a ! -e "$file" ]; then
        echo "$friendly_name all users"
    elif [ "$print_flag" != "" ]; then
        #retrieve GeneratedIDs and remove parentheses, trailing commas, and quotes
        local nested_groups=`defaults read $file nestedgroups -array 2> /dev/null | sed 's/,$//' | sed 's/[()"]//g'`
        local current_group=""
        local group_names=""
        local short_message="" #used for normal print output

        #used for verbose print output
        local users_message=""
        local groups_message=""

        #extract nestedgroups and store their actual group names
        for group_uuid in $nested_groups; do
            #retrieve group name from the group's GeneratedID
            current_group=`dscl . readall /Groups GeneratedUID | grep -A 1 $group_uuid | grep "^RecordName:" | sed 's/^RecordName: //'`
            group_names="${group_names}$current_group, "
        done

        #if user names are specified in the allowed access file
        if [ "$setting_value" != ""  -a `echo "$setting_value" | grep -c .` != 2 ]; then
            #remove parentheses from defaults array
            users_message=`echo "$friendly_name these users:" $setting_value | sed 's/( //' | sed 's/ )//'`
            short_message="$friendly_name some users"

        else
            users_message="$friendly_name no users"
        fi

        #if group GeneratedIDs are specified in the allowed access file
        if [ "$group_names" != "" -a `echo "$nested_groups" | grep -c .` -gt 0 ]; then
            groups_message="$friendly_name these groups: `echo $group_names | sed 's/,$//'`"
            short_message="$friendly_name some users"
        else
            groups_message="$friendly_name no groups"
        fi

        #normal print
        if [ "$v_flag" == "" ]; then
            if [ "$short_message" == "" ];then
                echo "$friendly_name no users"
            else
                echo "$short_message"
            fi
        else #verbose print
            echo "$users_message"
            echo "$groups_message"
        fi
    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                #if users are specified in the file, or the files does not exist
                if [ "$setting_value" != "" -o "$nestedgroups_value" != "" -o "$file_exists" == "0" ]; then
                    echo "setting $friendly_name no users";

                    defaults write $file $setting_name -array $required_value

                    #in case the keys don't exist, don't show errors
                    defaults delete $file "groupmembers" 2> /dev/null
                    defaults delete $file "nestedgroups" 2> /dev/null

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name no users is already set"
                fi
                ;;
            "soho")
                #if users are specified in the file, or the files does not exist
                if [ "$setting_value" != "" -o "$nestedgroups_value" != "" -o "$file_exists" == "0" ]; then
                    echo "setting $friendly_name no users";

                    defaults write $file $setting_name -array $required_value

                    #in case the keys don't exist, don't show errors
                    defaults delete $file "groupmembers" 2> /dev/null
                    defaults delete $file "nestedgroups" 2> /dev/null

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name no users is already set"
                fi
                ;;
            "sslf")
                #if users are specified in the file, or the files does not exist
                if [ "$setting_value" != "" -o "$nestedgroups_value" != "" -o "$file_exists" == "0" ]; then
                    echo "setting $friendly_name no users";

                    defaults write $file $setting_name -array $required_value

                    #in case the keys don't exist, don't show errors
                    defaults delete $file "groupmembers" 2> /dev/null
                    defaults delete $file "nestedgroups" 2> /dev/null

                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name no users is already set"
                fi
                ;;
            "oem")
                if [ "$file_exists" == "1" ]; then
                    echo "setting $friendly_name all users";
                    rm $file
                else
                    echo "$friendly_name all users is already set"
                fi
                ;;
        esac

    fi


#OS X 10.10 testing
#After removing the user elements from the "users" key in $file, the users specified in
#the GUI were unchanged. The users specified in the GUI were still able to use screen
#sharing, even though the plist file key "users" was blank. After deleting the key
#"groupmembers", only Administrators showed up under "Allow access for: Only these users".

#Removing both "groupmembers" and "nestedgroups" keys in addition to setting "users" to
#blank caused the GUI to select "Only these users" and to display no users in the box.
#The last users to successfully send an event can still do so after the setting is
#disabled. After restart, previously authorized users could no longer send events.

#Applies immediately when enabling the setting, but disabling requires restart for
#users already authenticated with remote events. Other users are effected immediately.
}



######################################################################
 CCE_79938_7_disable_automatic_system_login() {
    local doc="CCE_79938_7_disable_automatic_system_login      (manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.loginwindow.plist"

    local friendly_name="automatic system login"
    local setting_name="autoLoginUser"
    local setting_value="0"
    local key_exists="0"

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$setting_name" | wc -l`
    fi

    if [ $key_exists == "1" ]; then
        setting_value=`defaults read $file $setting_name`
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $setting_value == "0" ]; then
            echo "$friendly_name is disabled";
        else
            echo "$friendly_name is enabled for $setting_value";
        fi
    fi
    

    if [ "$set_flag" != "" ]; then

        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults delete $file $setting_name
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults delete $file $setting_name
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults delete $file $setting_name
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults delete $file $setting_name
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac
    fi
    

#OS X 10.10 testing
#If 0 is written to the autoLoginUser key with defaults, the system was no longer able to
#boot. When looking at the file in single-user mode, the formatting seemed to be broken.
#Using `defaults delete /Library/Preferences/com.apple.loginwindow.plist autoLoginUser` 
#had the desired effect of disabling auto login.
}


######################################################################
CCE_79942_9_pf_enable_firewall () {
    local doc="CCE_79942_9_pf_enable_firewall                (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #make backup of original pf.conf
    local pf_conf="/etc/pf.conf"
    local friendly_name="pf firewall"
    local enabled=`pfctl -s info 2> /dev/null | grep -c "Status: Enabled"`
    local oem_pf_contents='#
# Default PF configuration file.
#
# This file contains the main ruleset, which gets automatically loaded
# at startup.  PF will not be automatically enabled, however.  Instead,
# each component which utilizes PF is responsible for enabling and disabling
# PF via -E and -X as documented in pfctl(8).  That will ensure that PF
# is disabled only when the last enable reference is released.
#
# Care must be taken to ensure that the main ruleset does not get flushed,
# as the nested anchors rely on the anchor point defined here. In addition,
# to the anchors loaded by this file, some system services would dynamically 
# insert anchors into the main ruleset. These anchors will be added only when
# the system service is used and would removed on termination of the service.
#
# See pf.conf(5) for syntax.
#

#
# com.apple anchor point
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"'
    
    
    #content for the /etc/pf.conf file, which will append to the existing file
    main_pf_content='
#
# sam_pf_anchors anchor point
#
anchor "sam_pf_anchors"
load anchor "sam_pf_anchors" from "/etc/pf.anchors/sam_pf_anchors"'

    #these 2 lines must be present for the custom rules to be loaded
    local anchor_exists=`grep -xc 'anchor "sam_pf_anchors"' "$pf_conf"`
    local load_anchor_exists=`grep -xc 'load anchor "sam_pf_anchors" from "/etc/pf.anchors/sam_pf_anchors"' "$pf_conf"`
    local anchor_loaded=`pfctl -s all 2> /dev/null | grep -c 'sam_pf_anchors'`

    local pf_content_exists="0"
    if [ "$anchor_exists" == "1" -a "$load_anchor_exists" == "1" -a "$anchor_loaded" == "1" ]; then
        pf_content_exists="1"
    fi
        
    if [ "$print_flag" != "" ]; then
        if [ "$enabled" == "1" -a "$pf_content_exists" == "1" ]; then
            echo "$friendly_name is enabled";
        elif [ "$enabled" == "1" -a "$pf_content_exists" == "0" ]; then
            echo "$friendly_name is enabled, but the sam anchor is not loaded"
        elif [ "$enabled" == "0" -a "$pf_content_exists" == "1" ]; then
            echo "$friendly_name is disabled, but the sam anchor is loaded"
        else 
            echo "$friendly_name is disabled";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                #make backup of original pf.conf
                if [ ! -e "${pf_conf}.bk" ]; then
                    cp "${pf_conf}" "${pf_conf}.bk"    
                fi
        
                #add and load sam anchor point
                if [ "$pf_content_exists" == "0" ]; then
                    echo "Adding sam anchor point to $pf_conf and loading it"
                    pfctl -f $pf_conf 2> /dev/null
                    echo "$main_pf_content" >> "$pf_conf"
                fi
                
                #enable the firewall
                if [ "$enabled" == "0" ]; then
                    echo "enabling $friendly_name"
                    pfctl -e 2> /dev/null
                    #make pf run at system startup
                    defaults write /System/Library/LaunchDaemons/com.apple.pfctl ProgramArguments '(pfctl, -f, /etc/pf.conf, -e)'
                    add_processes_to_kill_list cfprefsd
                
                else
                    echo "$friendly_name is already enabled"
                fi

                ;;
            "soho")
                #make backup of original pf.conf
                if [ ! -e "${pf_conf}.bk" ]; then
                    cp "${pf_conf}" "${pf_conf}.bk"    
                fi
        
                #add and load sam anchor point
                if [ "$pf_content_exists" == "0" ]; then
                    echo "Adding sam anchor point to $pf_conf and loading it"
                    pfctl -f $pf_conf 2> /dev/null
                    echo "$main_pf_content" >> "$pf_conf"
                fi
            
                #enable the firewall
                if [ "$enabled" == "0" ]; then
                    echo "enabling $friendly_name"
                    pfctl -e 2> /dev/null
                    #make pf run at system startup
                    defaults write /System/Library/LaunchDaemons/com.apple.pfctl ProgramArguments '(pfctl, -f, /etc/pf.conf, -e)'
                    add_processes_to_kill_list cfprefsd
                
                    pfctl -f $pf_conf 2> /dev/null #load rules last
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                #make backup of original pf.conf
                if [ ! -e "${pf_conf}.bk" ]; then
                    cp "${pf_conf}" "${pf_conf}.bk"    
                fi
        
                #add and load sam anchor point
                if [ "$pf_content_exists" == "0" ]; then
                    echo "Adding sam anchor point to $pf_conf and loading it"
                    pfctl -f $pf_conf 2> /dev/null
                    echo "$main_pf_content" >> "$pf_conf"
                fi
            
                #enable the firewall
                if [ "$enabled" == "0" ]; then
                    echo "enabling $friendly_name"
                    pfctl -e 2> /dev/null
                    #make pf run at system startup
                    defaults write /System/Library/LaunchDaemons/com.apple.pfctl ProgramArguments '(pfctl, -f, /etc/pf.conf, -e)'
                    add_processes_to_kill_list cfprefsd
                
                    pfctl -f $pf_conf 2> /dev/null #load rules last
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ "$enabled" != "0" -o "$pf_content_exists" != "0" ]; then
                    echo "disabling $friendly_name"
                    pfctl -d 2> /dev/null
                    #make pf not run at system startup
                    defaults write /System/Library/LaunchDaemons/com.apple.pfctl ProgramArguments '(pfctl, -f, /etc/pf.conf, -d)'
                    add_processes_to_kill_list cfprefsd
                
                    pfctl -F rules #flush the pf ruleset (clear out the rules)
                
                    #remove anchor text from $pf_conf
                    echo "$oem_pf_contents" > "$pf_conf" 
                
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac
        #ensure proper pfctl permissions and format
        chmod 644 /System/Library/LaunchDaemons/com.apple.pfctl.plist
        plutil -convert xml1 /System/Library/LaunchDaemons/com.apple.pfctl.plist
    fi

#10.10 testing
#pf firewall successfully enabled
}

######################################################################
CCE_79943_7_pf_rule_ftp () {
    local doc="CCE_79943_7_pf_rule_ftp                       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="FTP pf firewall rule"
    local rule_text="block in proto { tcp udp } to any port { 20 21 }"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked ftp client connection.
}

######################################################################
CCE_79944_5_pf_rule_ssh () {
    local doc="CCE_79944_5_pf_rule_ssh                       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="SSH pf firewall rule"
    local rule_text="block in proto { tcp udp } to any port 22"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked ssh client connection.
}

######################################################################
CCE_79945_2_pf_rule_telnet () {
    local doc="CCE_79945_2_pf_rule_telnet                    (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="telnet pf firewall rule"
    local rule_text="block in proto { tcp udp } to any port 23"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked telnet client connection.
}

######################################################################
CCE_79946_0_pf_rule_rexec () {
    local doc="CCE_79946_0_pf_rule_rexec                     (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="rexec pf firewall rule"
    local rule_text="block proto { tcp udp } to any port 512"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked rexec port.
}

######################################################################
CCE_79947_8_pf_rule_rsh () {
    local doc="CCE_79947_8_pf_rule_rsh                       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="rsh pf firewall rule"
    local rule_text="block proto { tcp udp } to any port 514"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked rsh port.
}

######################################################################
CCE_79948_6_pf_rule_tftp () {
    local doc="CCE_79948_6_pf_rule_tftp                      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="tftp pf firewall rule"
    local rule_text="block proto { tcp udp } to any port 69"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked tftp client connection.
}

######################################################################
CCE_79949_4_pf_rule_finger () {
    local doc="CCE_79949_4_pf_rule_finger                    (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="finger pf firewall rule"
    local rule_text="block proto tcp to any port 79"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked finger client connection.
}

######################################################################
CCE_79950_2_pf_rule_http () {
    local doc="CCE_79950_2_pf_rule_http                      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="http pf firewall rule"
    local rule_text="block in proto { tcp udp } to any port 80"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked http client connection.
}

######################################################################
CCE_79951_0_pf_rule_nfs () {
    local doc="CCE_79951_0_pf_rule_nfs                       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="nfs pf firewall rule"
    local rule_text="block proto tcp to any port 2049"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked port used by nfs.
}

######################################################################
CCE_79952_8_pf_rule_remote_apple_events () {
    local doc="CCE_79952_8_pf_rule_remote_apple_events       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="remote apple events pf firewall rule"
    local rule_text="block in proto tcp to any port 3031"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked remote apple events.
}

######################################################################
CCE_79953_6_pf_rule_smb () {
    local doc="CCE_79953_6_pf_rule_smb                       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="smb pf firewall rule"
    local rule_text1="block proto tcp to any port { 139 445 }"
    local rule_text2="block proto udp to any port { 137 138 }"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text1" "$anchor_file"` 
        if [ "$rule_present" != "0" ]; then
            rule_present=`grep -c "^$rule_text2" "$anchor_file"`
        fi
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text1" >> "$anchor_file"
                    echo "$rule_text2" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text1" >> "$anchor_file"
                    echo "$rule_text2" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text1" >> "$anchor_file"
                    echo "$rule_text2" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text1//" "$anchor_file"
                    sed -i.bk "s/^$rule_text2//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked ports used by smb.
}

######################################################################
CCE_79954_4_pf_rule_apple_file_service () {
    local doc="CCE_79954_4_pf_rule_apple_file_service        (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="apple file service pf firewall rule"
    local rule_text="block in proto tcp to any port { 548 }"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked apple file service port.
}

######################################################################
CCE_79955_1_pf_rule_uucp () {
    local doc="CCE_79955_1_pf_rule_uucp                      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="uucp pf firewall rule"
    local rule_text="block proto tcp to any port 540"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked uucp port.
}

######################################################################
CCE_79956_9_pf_rule_screen_sharing () {
    local doc="CCE_79956_9_pf_rule_screen_sharing            (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="screen_sharing pf firewall rule"
    local rule_text="block in proto tcp to any port 5900"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked screen sharing port.
}

######################################################################
CCE_79957_7_pf_rule_icmp () {
    local doc="CCE_79957_7_pf_rule_icmp                      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="icmp pf firewall rule"
    local rule_text="block in proto { tcp udp } to any port 7"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked icmp port.
}

######################################################################
CCE_79958_5_pf_rule_smtp () {
    local doc="CCE_79958_5_pf_rule_smtp                      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="smtp pf firewall rule"
    local rule_text="block in proto tcp to any port 25"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked smtp port.
}

######################################################################
CCE_79959_3_pf_rule_pop3 () {
    local doc="CCE_79959_3_pf_rule_pop3                      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="pop3 pf firewall rule"
    local rule_text="block in proto tcp to any port 110"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked pop3 port.
}

######################################################################
CCE_79960_1_pf_rule_pop3s () {
    local doc="CCE_79960_1_pf_rule_pop3s                     (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="pop3s pf firewall rule"
    local rule_text="block in proto tcp to any port 995"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked pop3s port.
}

######################################################################
CCE_79961_9_pf_rule_sftp () {
    local doc="CCE_79961_9_pf_rule_sftp                      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="sftp pf firewall rule"
    local rule_text="block in proto tcp to any port 115"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked sftp port.
}

######################################################################
CCE_79962_7_pf_rule_imap () {
    local doc="CCE_79962_7_pf_rule_imap                      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="imap pf firewall rule"
    local rule_text="block in proto tcp to any port 143"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked imap port.
}

######################################################################
CCE_79963_5_pf_rule_imaps () {
    local doc="CCE_79963_5_pf_rule_imaps                     (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="imaps pf firewall rule"
    local rule_text="block in proto tcp to any port 993"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked imaps port.
}

######################################################################
CCE_79964_3_pf_rule_printer_sharing () {
    local doc="CCE_79964_3_pf_rule_printer_sharing           (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="printer sharing pf firewall rule"
    local rule_text="block in proto tcp to any port 631"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked printer sharing port.
}

######################################################################
CCE_79965_0_pf_rule_bonjour () {
    local doc="CCE_79965_0_pf_rule_bonjour                   (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="bonjour pf firewall rule"
    local rule_text="block proto udp to any port 1900"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked Bonjour port.
}

######################################################################
CCE_79966_8_pf_rule_mDNSResponder () {
    local doc="CCE_79966_8_pf_rule_mDNSResponder             (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="mDNSResponder pf firewall rule"
    local rule_text="block proto udp to any port 5353"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked mDNSResponder port.
}

######################################################################
CCE_79967_6_pf_rule_itunes_sharing () {
    local doc="CCE_79967_6_pf_rule_itunes_sharing            (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="iTunes sharing pf firewall rule"
    local rule_text="block proto tcp to any port 3689"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Successfully blocked iTunes sharing port.
}



######################################################################
CCE_79968_4_pf_rule_optical_drive_sharing () {
    local doc="CCE_79968_4_pf_rule_optical_drive_sharing      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="optical drive sharing pf firewall rule"
    local rule_text="block proto tcp to any port 49152"
    local rule_present=0
    
    if [ -e "$anchor_file" ]; then
        rule_present=`grep -c "^$rule_text" "$anchor_file"`
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$rule_present" == "0" ]; then
            echo "$friendly_name does not exist";
        else 
            echo "$friendly_name is present";
        fi
    fi
    
    
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi 
                ;;
            "soho")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "sslf")
                if [ "$rule_present" == "0" ]; then
                    echo "enabling $friendly_name"
                    echo "#$friendly_name" >> "$anchor_file"
                    echo "$rule_text" >> "$anchor_file"
                else
                    echo "$friendly_name already enabled"
                fi
                ;;
            "oem")
                if [ "$rule_present" != "0" ]; then
                    echo "disabling $friendly_name"
                    sed -i.bk "s/^$rule_text//" "$anchor_file"
                    sed -i.bk "s/^#$friendly_name//" "$anchor_file"
                    rm ${anchor_file}.bk
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
    fi
    
#10.10 testing
#Optical drive sharing was successfully blocked.
}


######################################################################
CCE_79940_3_audit_log_max_file_size() {
    local doc="CCE_79940_3_audit_log_max_file_size      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local file="/etc/security/audit_control"
    local setting_name="filesz"
    local friendly_name="audit log individual file size"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="80M"
    local soho_value="80M"
    local sslf_value="80M"
    local oem_value="2M" #Confirmed default value

    #default to oem value in case file does not exist
    local oem_string="$setting_name:$oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        #store the line that begins with filesz, if it exists
        current_string=`echo "$file_contents" | egrep "^$setting_name:"`

        #store just the size, without "filesz:"
        current_value=`echo "$current_string" | sed -E "s/^$setting_name://"`

    fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "$friendly_name is set to \"$oem_value\""
        else
            echo "$friendly_name is set to \"$current_value\""
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                #setting must be less than or equal to the required interval
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name are already set to \"$ent_value\""
                else
                    echo "setting $friendly_name to \"$ent_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                #setting must be less than or equal to the required interval
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name are already set to \"$ent_value\""
                else
                    echo "setting $friendly_name to \"$ent_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$ent_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                #setting must be less than or equal to the required interval
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name are already set to \"$ent_value\""
                else
                    echo "setting $friendly_name to \"$ent_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$ent_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to \"$oem_value\""
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                elif [ "$current_string" == "" ]; then
                    #since setting doesn't exist, append it to the file
                    echo "setting $friendly_name to \"$oem_value\""
                    echo "$setting_name:$oem_value" >> $file
                else
                    echo "$friendly_name are already set to \"$oem_value\""
                fi
                ;;
        esac
    fi

#OS X 10.10 testing
#When max log file size is reached, a new log is created.    
}


######################################################################
CCE_79941_1_audit_log_retention () {
    local doc="CCE_79941_1_audit_log_retention      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local file="/etc/security/audit_control"
    local setting_name="expire-after"
    local friendly_name="max audit log directory size"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="30d"
    local soho_value="30d"
    local sslf_value="30d"
    local oem_value="10M" #Confirmed default value

    #default to oem value in case file does not exist
    local oem_string="$setting_name:$oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        #store the line that begins with expire-after, if it exists
        current_string=`echo "$file_contents" | egrep "^$setting_name:"`

        #store just the size, without "filesz:"
        current_value=`echo "$current_string" | sed -E "s/^$setting_name://"`

    fi

    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "$friendly_name is set to \"$oem_value\""
        else
            echo "$friendly_name is set to \"$current_value\""
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                #setting must be less than or equal to the required interval
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name are already set to \"$ent_value\""
                else
                    echo "setting $friendly_name to \"$ent_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$ent_value" >> $file
                    fi
                fi
                ;;
            "soho")
                #setting must be less than or equal to the required interval
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name are already set to \"$ent_value\""
                else
                    echo "setting $friendly_name to \"$ent_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$ent_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                #setting must be less than or equal to the required interval
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name are already set to \"$ent_value\""
                else
                    echo "setting $friendly_name to \"$ent_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$ent_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$ent_value" >> $file
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" -a "$current_string" != "" ]; then
                    echo "setting $friendly_name to \"$oem_value\""
                    new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$oem_string/"`
                    echo "$new_file_contents" > $file
                elif [ "$current_string" == "" ]; then
                    #since setting doesn't exist, append it to the file
                    echo "setting $friendly_name to \"$oem_value\""
                    echo "$setting_name:$oem_value" >> $file
                else
                    echo "$friendly_name are already set to \"$oem_value\""
                fi
                ;;
        esac
    fi

#OS X 10.10 testing
#When log files reach max age, they are deleted.
}


determine_user_and_system_properties () {
    # hardware ID unique to a system
    hw_uuid=`system_profiler SPHardwareDataType 2> /dev/null | grep 'Hardware UUID' | awk ' { print $3 }'`

    #if running sudo without specifying user, USER=root
    #if so, get the applicable user from SUDO_USER

    os_version=`system_profiler SPSoftwareDataType | grep "System Version:" | egrep -ow '[0-9]+\.[0-9]+'`

    # if user parameter is not specified, determine current user
    if [ "$all_users_flag" == "" ] && [ "$specific_user_flag" == "" ]; then
        owner="$USER"
        if [ "$owner" == "root" ]; then
            owner="$SUDO_USER"
        fi
    fi

    #determine user's primary group
    group=`groups $owner | cut -d' ' -f1`


    # gets the home directory of $owner
    home_path=~$owner
    eval home_path=$home_path

    user_list=`dscl . -list /Users`
    full_user_list="$user_list"

    local temp_user_list=""

    for user in $user_list; do
        if [ "$user" == "nobody" ] || [ "$user" == "Guest" ]; then
            continue
        fi

        # don't print an error if the user doesn't exist
        local user_id=`id -u $user 2> /dev/null`

        # users created through the GUI have IDs of 500 and up
        # only store real user accounts
        if [ "$user_id" != "" ] && (( "$user_id" >= "500" )); then
            temp_user_list="$temp_user_list
$user"
        fi
    done

    user_list="$temp_user_list"

#Starting with OS X 10.9, there is vastly more system information in its system_profiler
#report than 10.8; takes awhile to run. "-detailLevel basic" argument works for both
#10.8 and 10.9 and significantly speeds up run time.
#Edit: Using SPHardwareDataType argument restricts results further and is even
#faster than changing the detailLevel.

#OS X 10.10.2: Warning message displayed when running the command: 
#`system_profiler SPHardwareDataType`, but the hw_uuid is still retrieved
#Warning message:
#2015-03-04 15:04:20.757 system_profiler[794:77517] platformPluginDictionary: Can't get X86PlatformPlugin, return value 0
#2015-03-04 15:04:20.759 system_profiler[794:77517] platformPluginDictionary: Can't get X86PlatformPlugin, return value 0

#OS X 10.10.5 update: warning message still appears
}


# sets a user-specific setting for all specified users found on the computer
apply_settings_for_selected_users () {
    local apply_to_users_list

    # if all users
    if [ "$all_users_flag" != "" ]; then
        apply_to_users_list="$user_list"

    # run as current user or specified user
    else
        apply_to_users_list="$owner"
    fi

    echo "";
    echo "Executing settings for all specified users:";

    for user in $apply_to_users_list; do
        local user_id=`id -u $user`
        group=`groups $user | cut -d' ' -f1`

        owner=$user

        home_path=~$owner
        eval home_path=$home_path

        echo "";
        echo "Running for user $user";

        # run user-specific settings
        # user_settings_list contains all user-specific function names
        for setting in $user_settings_list; do
            $setting
        done
    done
}


# processes added here will be terminated at the end of the script execution
add_processes_to_kill_list () {
    for process in $@; do
        for existing_process in $processes_to_kill; do
            if [ "$process" == "$existing_process" ]; then
                continue 2;
            fi
        done
        processes_to_kill="$processes_to_kill
$process"

    done

}

# must be run after all setting functions to ensure the changes take effect
final_tasks () {
    # some settings may not be applied correctly if the processes are killed repeatedly
    for process in $processes_to_kill; do
        if [ "$process" != "" ]; then
            killall -HUP $process
        fi
    done
}


































######################################################################
CCE_79741_5_bluetooth_open_setup_if_no_keyboard () {
    local doc="CCE_79741_5_bluetooth_open_setup_if_no_keyboard                 (manual-test-PASSED)"
    local file=/Library/Preferences/com.apple.Bluetooth.plist
    local setting_name=BluetoothAutoSeekKeyboard
    local status=1 #default is enabled

    if [ -e $file ]; then
        local key_exists=`defaults read $file | grep "$setting_name" | wc -l`
        if [ $key_exists == "1" ]; then
            status=`defaults read $file $setting_name`
        fi
    fi
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
        if [ "$print_flag" != "" ]; then

        if [ $status == "0" ]; then
            echo "open Bluetooth setup if no keyboard is disabled";
        else
            echo "open Bluetooth setup if no keyboard is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then

    case $profile_flag in
        "ent")
        echo "disabling open Bluetooth setup if no keyboard";
        defaults write $file $setting_name -bool false
        ;;
        "soho")
        echo "disabling open Bluetooth setup if no keyboard";
        defaults write $file $setting_name -bool false
        ;;
        "sslf")
        echo "disabling open Bluetooth setup if no keyboard";
        defaults write $file $setting_name -bool false
        ;;
        "oem")
        echo "enabling open Bluetooth setup if no keyboard";
        defaults write $file $setting_name -bool true
        ;;
    esac
    fi

#Bluetooth setup assistant only appears to pop up upon logging in.
#
#OS X 10.10
#GUI acknowledges setting change without logging out first.
#VM appears to always have a virtual keyboard connected. Before changing any
#settings, disconnecting the USB keyboard did not bring up the setup assistant.

#NEEDS_REAL_HARDWARE
#OS X 10.10 real hardware test
#Successfully took effect after system restart.
}


######################################################################
CCE_79742_3_bluetooth_open_setup_if_no_mouse_trackpad () {
    local doc="CCE_79742_3_bluetooth_open_setup_if_no_mouse_trackpad             (manual-test-PASSED)"
    local file=/Library/Preferences/com.apple.Bluetooth.plist
    local setting_name=BluetoothAutoSeekPointingDevice
    local status=1 #default is enabled

    if [ -e $file ]; then
        local key_exists=`defaults read $file | grep "$setting_name" | wc -l`
        if [ $key_exists == "1" ]; then
            status=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
        if [ "$print_flag" != "" ]; then

        if [ $status == "0" ]; then
            echo "open Bluetooth setup if no mouse or trackpad is disabled";
        else
            echo "open Bluetooth setup if no mouse or trackpad is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then

        case $profile_flag in
            "ent")
            echo "disabling open Bluetooth setup if no mouse or trackpad";
            defaults write $file $setting_name -bool false
            ;;
            "soho")
            echo "disabling open Bluetooth setup if no mouse or trackpad";
            defaults write $file $setting_name -bool false
            ;;
            "sslf")
            echo "disabling open Bluetooth setup if no mouse or trackpad";
            defaults write $file $setting_name -bool false
            ;;
            "oem")
            echo "enabling open Bluetooth setup if no mouse or trackpad";
            defaults write $file $setting_name -bool true
            ;;
        esac
    fi

#Bluetooth setup assistant only appears to pop up upon logging in.
#Does not appear to trigger upon VM restart since Bluetooth adapter
#has not been initialized.
#
#OS X 10.10
#GUI acknowledges setting change without logging out first.
#After logging back in, bluetooth setup assistant did not pop up.

}


######################################################################
CCE_79745_6_bluetooth_turn_off_bluetooth () {
    local doc="CCE_79745_6_bluetooth_turn_off_bluetooth              (manual-test-PASSED)"
    local file=/Library/Preferences/com.apple.Bluetooth.plist
    local setting_name=ControllerPowerState
    local status=1 #default is enabled

    if [ -e $file ]; then
        local key_exists=`defaults read $file | grep "$setting_name" | wc -l`
        if [ $key_exists == "1" ]; then
            status=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $status == "0" ]; then
            echo "Bluetooth adapter disabled"
        else
            echo "Bluetooth adapter enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "Bluetooth unchanged";
                #do nothing
                ;;
            "soho")
                echo "Bluetooth unchanged";
                #do nothing
                ;;
            "sslf")
                echo "disabling Bluetooth";
                defaults write $file $setting_name -bool false
                ;;
            "oem")
                echo "enabling Bluetooth";
                defaults write $file $setting_name -bool true
                ;;
        esac
    fi

#*************** Profiles Changed from OS X guidance spreadsheet  ***************
#ent: not specified -> Bluetooth controller power allowed
#soho: not specified -> Bluetooth controller power allowed

#With Bluetooth enabled on physical machine, controller shows up in VM as Parallells
#BT Controller. VM does not appear capable of disabling the adapter; option is greyed out.

# Real hardware test
#OS X 10.10 
#Restart required.
}



######################################################################
CCE_79746_4_show_bluetooth_status_in_menu_bar () {
    local doc="CCE_79746_4_show_bluetooth_status_in_menu_bar                (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.systemuiserver.plist
    local setting_name=menuExtras
    local setting_value=/System/Library/CoreServices/Menu\ Extras/Bluetooth.menu
    local friendly_name="show Bluetooth status in menu bar"
    local value_exists=0

    if [ -e "$file" ]; then
        local key_exists=`defaults read $file | grep -c $setting_name`
        if [ "$key_exists" -gt 0 ]; then
            value_exists=`defaults read $file $setting_name -array | grep -c "$setting_value"`
        fi

    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then

        if [ "$value_exists" != "1" ]; then
            echo "$friendly_name disabled";
        else
            echo "$friendly_name enabled";
        fi
    fi
    

    if [ "$set_flag" != "" ]; then

        case $profile_flag in
            "ent")
                if [ "$value_exists" == 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -array-add "$setting_value"
                
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ "$value_exists" == 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -array-add "$setting_value"
                
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ "$value_exists" == 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -array-add "$setting_value"
                
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ "$value_exists" == 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -array-add "$setting_value"
                
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#Note: killing cfprefsd, SystemUIServer causes this to take effect immediately.

#Assuming same permissions issues as other user-specific settings.
#Default value in VMs appears to be icon disabled, but this could be because
#the Bluetooth adapter is not present until Parallels tools are installed.
#
#OS X 10.10 - Menu icon shows up after restart.
}



######################################################################
CCE_79748_0_bluetooth_disable_wake_computer () {
    local doc="CCE_79748_0_bluetooth_disable_wake_computer                (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/ByHost/com.apple.Bluetooth.$hw_uuid.plist
    local setting_name=RemoteWakeEnabled
    local value=1
    local friendly_name="Bluetooth waking computer"

    #defaults will automatically insert the hardware ID when -currentHost is specified
    local file_noid=$home_path/Library/Preferences/ByHost/com.apple.Bluetooth.plist

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep -c $setting_name`

        if [ $exists != "0" ]; then
            value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "0" ]; then
            echo "$friendly_name is enabled";
        else
            echo "$friendly_name is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list UserEventAgent cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ $value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list UserEventAgent cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ $value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list UserEventAgent cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $value != 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true

                    add_processes_to_kill_list UserEventAgent cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;

        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#Note: The setting incorrectly reports as enabled in a VM, since it is incapable of
#waking the machine. This is because the default value is enabled and the key is not
#present. We assume this also applies to physical machines that do not support
#Bluetooth waking.

#The spreadsheet incorrectly refers to this setting name as BluetoothSystemWakeEnable

#NEEDS_REAL_HARDWARE

#OS X 10.10 real hardware test
#Successfully took effect immediately, when killing processes. Otherwise, a restart is
#required.
}


######################################################################
CCE_79753_0_bluetooth_disable_file_sharing () {
    local doc="CCE_79753_0_bluetooth_disable_file_sharing                (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/ByHost/com.apple.Bluetooth.$hw_uuid.plist
    local setting_name=PrefKeyServicesEnabled
    local value=0
    local friendly_name="Bluetooth file sharing"

    if [ -e "$file" ]; then
        local exists=`defaults read $file | grep $setting_name | wc -l`
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            value=`defaults read $file $setting_name`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $value != "1" ]; then
            echo "$friendly_name is disabled";
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list UserEventAgent cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ $value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list UserEventAgent cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ $value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list UserEventAgent cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list UserEventAgent cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi


#Assuming same permissions issues as other user-specific settings.
#Bluetooth devices cannot see a VM's Bluetooth controller to connect to,
#regardless of whether or not it is set as discoverable.
#
#OS X 10.10
#GUI reflects Bluetooth file sharing setting change immediately.
#Enabled Bluetooth discoverable on secondary machine to allow incoming connections.
#Initiated pairing process with the VM. Files can be sent to other machine from VM,
#but can not be sent to VM from other machine.
#It appears that this setting only determines if incoming Bluetooth file sharing
#connections are allowed.

#NEEDS_REAL_HARDWARE

#OS X 10.10 real hardware
#Works after restart. Works immediately if processes are killed.
}


######################################################################
CCE_79756_3_bluetooth_unload_uninstall_kext () {
    local doc="CCE_79756_3_bluetooth_unload_uninstall_kext     (manual-test-PASSED)"
    local kext_path=/System/Library/Extensions/
    local destination=/System/Library/UnusedExtensions/

    local file1_no_ext=IOBluetoothFamily
    local file1=$file1_no_ext.kext
    local file1_loaded=`kextstat | grep $file1_no_ext | wc -l`
    local file1_exists=0

    local file2_no_ext=IOBluetoothHIDDriver
    local file2=$file2_no_ext.kext
    local file2_loaded=`kextstat | grep $file2_no_ext | wc -l`
    local file2_exists=0

    if [ -e "$kext_path$file1" ]; then file1_exists=1; fi
    if [ -e "$kext_path$file2" ]; then file2_exists=1; fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
        if [ "$v_flag" != "" ]; then
            if [ $file1_exists == "1" ]; then
                echo "$file1 is present in $kext_path"
            else
                echo "$file1 is not present in $kext_path"
            fi

            if [ $file2_exists == "1" ]; then
                echo "$file2 is present in $kext_path"
            else
                echo "$file2 is not present in $kext_path"
            fi

        else #no v flag
            if [ $file1_exists == "1" ] || [ $file2_exists == "1" ]; then
                echo "Bluetooth kext file(s) present"
            else
                echo "Bluetooth kext files not present"
            fi
        fi
    fi

#To delete kext files rather than move them, comment out the mv and chown
#lines and uncomment the srm lines
    if [ "$set_flag" != "" ]; then
    case $profile_flag in
        "ent")
            echo "Bluetooth kext files unchanged"
            ;;

        "soho")
            echo "Bluetooth kext files unchanged"
            ;;

        "sslf")
            #create destination directory
            if [ ! -e $destination ]; then
                mkdir $destination
            fi

            #Unload file1 and file2 from the kernel if they are loaded
:<<'COMMENT_BLOCK'
            if [ $file1_loaded == "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Unloading $file1 from the kernel"
                fi
                kextunload $kext_path$file1
            fi
            if [ $file2_loaded == "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Unloading $file2 from the kernel"
                fi
                kextunload $kext_path$file2
            fi
COMMENT_BLOCK


            if [ "$v_flag" == "" ]; then
                echo "Unloading and moving Bluetooth kext files to $destination"
                #echo "Removing Bluetooth kext files"
            fi

            if [ $file1_exists == "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file1 from $kext_path to $destination"
                    #echo "Removing $kext_path$file1"
                fi

                #if moving to $destination and not $destination$file, the
                #kext file may unpack
                mv -f $kext_path$file1 $destination$file1
                chown -R root:wheel $destination$file1/* #moving changes owner

                #srm -rf $kext_path$file1

            elif [ "$v_flag" != "" ]; then
                echo "$file1 has already been removed from $kext_path"

            fi

            if [ $file2_exists == "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file2 from $kext_path to $destination"
                    #echo "Removing $kext_path$file2"
                fi

                #if moving to $destination and not $destination$file, the
                #kext file may unpack
                mv -f $kext_path$file2 $destination$file2
                chown -R root:wheel $destination$file2/* #moving changes owner

                #srm -rf $kext_path$file2

            elif [ "$v_flag" != "" ]; then
                echo "$file2 has already been removed from $kext_path"

            fi
            ;;

        "oem")
            if [ "$v_flag" == "" ]; then
                echo "Moving Bluetooth kext files from $destination"
            fi

            if [ $file1_exists != "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file1 from $destination to $kext_path"
                fi
                mv -f $destination$file1 $kext_path$file1
                chown root:wheel $kext_path$file1
                chown -R root:wheel $kext_path$file1/*

            elif [ "$v_flag" != "" ]; then
                echo "$file1 already present in $kext_path"
            fi

            if [ $file2_exists != "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file2 from $destination to $kext_path"
                fi
                mv -f $destination$file2 $kext_path$file2
                chown root:wheel $kext_path$file2
                chown -R root:wheel $kext_path$file2/*

            elif [ "$v_flag" != "" ]; then
                echo "$file2 already present in $kext_path"
            fi

#Do not load kexts while unloading does not work
:<<'COMMENT_BLOCK'

            #Load file1 and file2 into the kernel if they are not currently loaded
            if [ $file1_loaded != "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Loading $file1 into the kernel"
                fi
                kextload $kext_path$file1
            fi

            #Note: file2 does not appear to be loaded by default
COMMENT_BLOCK

            ;;
        esac
    fi


#*************** Profiles Changed from OS X guidance spreadsheet  ***************
#soho: not specified -> Bluetooth kext allowed
#ent: not specified -> Bluetooth kext allowed

#Note: some kext files are actually packages that contain many kext files.
#If the owner or group of a kext file is changed, the system pops up with a
#message stating that a "system extension cannot be used" for each kext file.
#It is not necessary to "touch $kext_path" since the file removal or addition
#updates the modified time on the folder.
#
#Unloading kexts
#Attempting to unload IOBluetoothFamily.kext causes the VM to crash. Stopping the
#other Blueooth kexts and the blued Bluetooth Daemon first seemed to prevent the
#crash. However, the kext would not unload regardless of any error messages displaying.
#If there was an error message, it stated the following:
#(kernel) Can't unload kext com.apple.iokit.IOBluetoothFamily; classes have instances:
#(kernel)     Kext com.apple.iokit.IOBluetoothFamily class IOBluetoothHCIController has 1 instance.
#(kernel)     Kext com.apple.iokit.IOBluetoothFamily class IOWorkQueue has 1 instance.
#Kernel error handling kext request - (libkern/kext) kext is in use or retained (cannot unload).
#Failed to unload com.apple.iokit.IOBluetoothFamily - (libkern/kext) kext is in use or retained (cannot unload).

# NEEDS_REAL_HARDWARE

#OS X 10.10
#Works after restart.
}


######################################################################
CCE_79763_9_remove_all_preferred_wireless_networks () {
    local doc="CCE_79763_9_remove_all_preferred_wireless_networks              (manual-test-PASSED)"
    local setting_name=`networksetup -listnetworkserviceorder | grep -A1 ") Wi-Fi" | egrep -o "Device: [^\)]+" | sed "s/Device: //"`
    local friendly_name="preferred wireless networks"


    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$setting_name" == "" ]; then
            echo "wireless network adapters are not present in this system."
        else
            echo "wireless network adapter is ${setting_name}. `networksetup -listpreferredwirelessnetworks $setting_name`"
        fi
    fi


    if [ "$set_flag" != "" ]; then
        if [ "$setting_name" == "" ]; then
            echo "wireless network adapters are not present in this system."
        else
            case $profile_flag in
                "ent")
                    echo "$friendly_name for adapter $setting_name are unchanged"
                    ;;
                "soho")
                    echo "$friendly_name for adapter $setting_name are unchanged"
                    ;;
                "sslf")
                    networksetup -removeallpreferredwirelessnetworks $setting_name
                    ;;
                "oem")
                    networksetup -removeallpreferredwirelessnetworks $setting_name
                    ;;
            esac
        fi
    fi

#*************** Profiles Changed from OS X guidance spreadsheet  ***************
#ent: no preferred networks -> preferred networks allowed
#soho: no preferred networks -> preferred networks allowed

# NEEDS_REAL_HARDWARE
#OS X 10.10 Real Hardware Test
#Ad-hoc networks are not added to the preferred network list, but Internet sharing
#networks are. Successfully removed networks from the preferred networks list.
}



######################################################################
CCE_79768_8_show_wifi_status_in_menu_bar () {
    local doc="CCE_79768_8_show_wifi_status_in_menu_bar                (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.systemuiserver.plist
    local setting_name=menuExtras
    local setting_value=/System/Library/CoreServices/Menu\ Extras/AirPort.menu
    local friendly_name="show Wi-Fi status in menu bar"
    local value_exists=1

    if [ -e "$file" ]; then
        local key_exists=`defaults read $file | grep -c $setting_name`
        if [ "$key_exists" -gt 0 ]; then
            value_exists=`defaults read $file $setting_name -array | grep -c "$setting_value"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$value_exists" != "0" ]; then
            echo "$friendly_name enabled";
        else
            echo "$friendly_name disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then

        case $profile_flag in
            "ent")
                if [ "$value_exists" == 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -array-add "$setting_value"
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ "$value_exists" == 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -array-add "$setting_value"
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ "$value_exists" == 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -array-add "$setting_value"
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ "$value_exists" == 0 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -array-add "$setting_value"
                    add_processes_to_kill_list SystemUIServer cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#Assuming same permissions issues as other user-specific settings.
#Default value in VMs appears to be icon disabled, but this could be because
#the Wi-Fi adapter is not present unless it shared by the physical machine.
#Actual default value is enabled.
#
#OS X 10.10 - Menu icon shows up after restart. Killing cfprefsd and SystemUIServer
#makes the change immediate, however.
}



# Parameters: system name to validate; match found
# If a new name is required, set the new_system_name global variable
validate_system_name () {
    local current_name="$1"
    local username_match=$2

    #remove .local from HostName, since it is added automatically by the system
    current_name=`echo "$current_name" | sed 's:\.local$::'`

    if [ "$new_system_name" != "" ]; then
        if [ "$current_name" == "$new_system_name" ]; then
            eval $username_match=0
        else
            eval $username_match=1
        fi
        return;
    fi

    local all_usernames=`dscl . -list /Users UniqueID | awk '$2 >= 500 { print $1; }'`
    local all_names=""
    local short_names=""
    local new_name=$setting_value #start with current name and subtract any matches

    #get the full names of the users
    for username in $all_usernames; do

        all_names=$all_names"
"`dscl . -read /Users/$username RealName | awk -F: '{print $2 }' | sed 's/^ //'`
    done

    all_names=$all_names"
$all_usernames"

    #no spaces or underscores allowed in computer names, so change to hyphens
    #[O]RS = [output] record separator
    all_names=`echo "$all_names" | awk 1 ORS='-' RS=' '`
    all_names=`echo "$all_names" | awk 1 ORS='-' RS='_'`

    #break any names containing hyphens into multiple names
    short_names=`echo "$all_names" | awk 1 ORS='\n' RS='-'`

    #keep split names at the end so multi-part names can be matched and removed first
    all_names=$all_names"
$short_names"

    for name in $all_names; do

        #ignore names that are less than 3 chars
        if [[ ${#name} -lt 3 ]]; then
            continue
        fi
        #ignore case of user's actual name and usernames
        local current_match=`echo "$setting_value" | grep -ic -- "$name"`
        if [[ $current_match -gt 0 ]]; then
            #switch case to what matched on grep since BSD sed cannot ignore case
            name=`echo "$setting_value" | grep -oi -- "$name"`
            eval $username_match=1 #set caller's match_found=1
            new_name=`echo "$new_name" | sed "s/$name//g"` #remove matches from new name
        fi
    done


    #if a new name has already been created, use that one
    if [ "$new_system_name" != "" ]; then
        new_name="$new_system_name"
    else
        #remove matches starting with 's which appear as s-
        #host names have dashes instead of spaces, and no apostrophes
        #computer name can have space and apostrophe
        #Issue with two apostrophe fonts, so check for both
        new_name=`echo "$new_name" | sed -E "s:(^’s )|(^'s )::"`

        #delete any leading hyphens
        if [[ ${new_name:0:1} == "-" ]]; then
            new_name=`echo "$new_name" | sed "s/^-*//g"`

        fi

        #if resulting name is empty or short, attach a random number
        if [[ ${#new_name} -eq 0 ]];  then
            new_name="Mac$RANDOM"
        elif [[ ${#new_name} -lt 3 ]]; then
            new_name=$new_name$RANDOM
        #if the name is a single word that begins or ends with Mac, append random number
        elif [[ `echo "$new_name" | egrep -ic '(^Mac\w*$)|(^\w*Mac$)'` -gt 0 ]]; then
            new_name=$new_name$RANDOM
        fi

        #some names cannot handle spaces or apostrophes, so remove them
        new_name=`echo "$new_name" | sed "s/ /-/g"`
        new_name=`echo "$new_name" | sed -E "s/'|’//g"`


        #use generated name for all system names
        new_system_name="$new_name"

    fi
#This function assists with checks in CCE_79806_6_change_computer_name, 
#CCE_79805_8_change_host_name, CCE_79772_0_change_local_host_name, 
#CCE_79807_4_change_net_bios_name
}


######################################################################
#LocalHostName is used by the Bonjour service for network discovery
CCE_79772_0_change_local_host_name () {
    local doc="CCE_79772_0_change_local_host_name              (manual-test-PASSED)"
    local setting_name=LocalHostName
    local friendly_name="LocalHostName"
    local setting_value=`scutil --get $setting_name`
    local match_found=0

    # check this name for user-identifying information
    validate_system_name "$setting_value" match_found

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $match_found == 1 ]; then
            echo "$friendly_name of $setting_value identifies the owner or does not match other names"
        else
            echo "$friendly_name of $setting_value does not identify the owner"
        fi
    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    scutil --set $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "soho")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    scutil --set $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "sslf")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    scutil --set $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "oem")
                echo "$friendly_name is unchanged";
                ;;
        esac
    fi


#OS X 10.10
#LocalHostName change takes effect immediately.
}


######################################################################
#HostName is visible on the command line and can be used to SSH in
CCE_79805_8_change_host_name () {
    local doc="CCE_79805_8_change_host_name              (manual-test-PASSED)"
    local setting_name=HostName
    local friendly_name="HostName"
    local setting_value=`HostName`
    local match_found=0

    validate_system_name "$setting_value" match_found

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $match_found == 1 ]; then
            echo "$friendly_name of $setting_value identifies the owner or does not match other names"
        else
            echo "$friendly_name of $setting_value does not identify the owner"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    scutil --set $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "soho")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    scutil --set $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "sslf")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    scutil --set $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "oem")
                echo "$friendly_name is unchanged";
                ;;
        esac
    fi

#Note: Using scutil --get HostName may return "HostName: not set" if the system name has
#not been changed from the default.

#OS X 10.10
#HostName change takes effect immediately.
}




######################################################################
#Computer name is visible through Finder on other Macs
CCE_79806_6_change_computer_name () {
    local doc="CCE_79806_6_change_computer_name              (manual-test-PASSED)"
    local setting_name=ComputerName
    local friendly_name="ComputerName"
    local setting_value=`scutil --get $setting_name`
    local match_found=0

    validate_system_name "$setting_value" match_found

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $match_found == 1 ]; then
            echo "$friendly_name of $setting_value identifies the owner or does not match other names"
        else
            echo "$friendly_name of $setting_value does not identify the owner"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    scutil --set $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "soho")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    scutil --set $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "sslf")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    scutil --set $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "oem")
                echo "$friendly_name is unchanged";
                ;;
        esac
    fi


#OS X 10.10
#ComputerName change takes effect immediately.
}


######################################################################
#NetBIOSName is visible to Windows systems
CCE_79807_4_change_net_bios_name () {
    local doc="CCE_79807_4_change_net_bios_name              (manual-test-PASSED)"
    local setting_name=NetBIOSName
    local friendly_name="NetBIOSName"
    local file=/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist
    local setting_value="NO_NAME" # default placeholder name
    local match_found=0

    if [ -e $file ]; then
        local key_exists=`defaults read $file | grep -c $setting_name`
        if [ $key_exists ]; then
            setting_value=`defaults read $file $setting_name`
            validate_system_name "$setting_value" match_found
        fi
    fi



    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $match_found == 1 ]; then
            echo "$friendly_name of $setting_value identifies the owner or does not match other names"
        else
            echo "$friendly_name of $setting_value does not identify the owner"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    defaults write $file $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "soho")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    defaults write $file $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "sslf")
                if [ $match_found == 1 ]; then
                    echo "Changing $friendly_name from $setting_value to $new_system_name"
                    defaults write $file $setting_name "$new_system_name"
                else
                    echo "$friendly_name of $setting_value does not identify the owner; unchanged"
                fi
                ;;
            "oem")
                echo "$friendly_name is unchanged";
                ;;
        esac
    fi


#OS X 10.10
#Changing LocalHostName will also change NetBIOSName after a short delay.
#NetBIOSName change takes effect immediately.
}


######################################################################
CCE_79785_2_dim_display_on_battery () {
    local doc="CCE_79785_2_dim_display_on_battery              (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name=ReduceBrightness
    local setting_name="-b lessbright"
    local setting_value=1 #default is enabled
    local friendly_name="dim display when on battery power"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep -c "$internal_name"`
        if [ $key_exists -gt "0" ]; then
            setting_value=`defaults read $file | grep "$internal_name" | grep -o "1\|0"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ $setting_value == "0" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                elif [ "$setting_value" == "0" ]; then
                    echo "enabling $friendly_name"
                    pmset "$setting_name" 1
                else
                    echo "$friendly_name is already enabled";
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                elif [ "$setting_value" == "0" ]; then
                    echo "enabling $friendly_name"
                    pmset "$setting_name" 1
                else
                    echo "$friendly_name is already enabled";
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                elif [ "$setting_value" == "0" ]; then
                    echo "enabling $friendly_name"
                    pmset "$setting_name" 1
                else
                    echo "$friendly_name is already enabled";
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                elif [ "$setting_value" == "0" ]; then
                    echo "enabling $friendly_name"
                    pmset "$setting_name" 1
                else
                    echo "$friendly_name is already enabled";
                fi
                ;;
        esac
    fi

#Note: It is easier to read from the plist than to use pmset to read the current
#settings, because the current profile changes depending on whether or not the
#computer is running on AC power. This setting only appears in the battery power
#profile.

#NEEDS_REAL_HARDWARE

#OS X 10.10 real hardware test
#Setting immediately shows up as enabled in the Energy Saver GUI menu and the
#screen gets dimmer when the computer is unplugged.
}

######################################################################
CCE_79786_0_wake_when_power_source_changes () {
    local doc="CCE_79786_0_wake_when_power_source_changes            (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name="Wake On AC Change"
    local setting_name="acwake"
    local setting_value=0 #default is disabled
    local friendly_name="wake when power source changes"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep -c "$internal_name"`
        if [ $key_exists -ge "1" ]; then
            setting_value=`pmset -g | grep "$setting_name" | grep -o "1\|0"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ $setting_value == "1" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
        esac
    fi

#Note: Changing this setting's value applies it to both the battery and AC
#power profiles that are currently active. Difficult to check each power profile
#and set on an individual basis, so override existing settings each time
#a security profile is set.


#NEEDS_REAL_HARDWARE

#OS X 10.10 real hardware test
#pmset shows updated value after change.
#Nothing happens when AC power is disconnected. If AC power is connected, the power
#light indicates that the computer wakes briefly before going back to sleep. This
#does not occur when the setting is turned off.
}

######################################################################
CCE_79787_8_no_auto_restart_after_power_fail () {
    local doc="CCE_79787_8_no_auto_restart_after_power_fail          (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name="Automatic Restart On Power Loss"
    local setting_name="autorestart"
    local setting_value=0 #default is disabled
    local friendly_name="automatically restart after power failure"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep -c "$internal_name"`
        if [ $key_exists -gt "0" ]; then
            setting_value=`pmset -g | grep "$setting_name" | grep -o "1\|0"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ $setting_value == "1" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled"
    fi

    fi
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
        esac
    fi

#Note: Difficult to check each power profile and set on an individual basis,
#so override existing settings each time a security profile is set.

#NEEDS_REAL_HARDWARE
#OS X 10.10 real hardware test
#When the setting is enabled, computer restarts after power is restored. When the script
#is run, the system does not automatically turn back on.
}


######################################################################
CCE_79789_4_enable_hard_disk_sleep () {
    local doc="CCE_79789_4_enable_hard_disk_sleep            (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name="Disk Sleep Timer"
    local setting_name="disksleep"
    local setting_value=10 #default is 10 minutes
    local friendly_name="hard disk goes to sleep"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ $key_exists -ge "1" ]; then
            setting_value=`pmset -g | grep "$setting_name" | egrep -o "[0-9]+"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ $setting_value == "0" ]; then
            echo "$friendly_name never"
        else
            echo "$friendly_name after $setting_value minutes"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 10 minutes for all power profiles"
                    pmset -a "$setting_name" 10
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 10 minutes for all power profiles"
                    pmset -a "$setting_name" 10
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 10 minutes for all power profiles"
                    pmset -a "$setting_name" 10
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 10 minutes for all power profiles"
                    pmset -a "$setting_name" 10
                fi
                ;;
        esac
    fi

#Note: Difficult to check each power profile and set on an individual basis,
#so override existing settings each time a security profile is set.

#OS X 10.10
#Updated change is reflected in pmset immediately.

#Effectiveness testing not performed
}

######################################################################
CCE_79790_2_enable_display_sleep () {
    local doc="CCE_79790_2_enable_display_sleep            (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name="Display Sleep Timer"
    local setting_name="displaysleep"
    local setting_value=10 #default is 10 minutes
    local friendly_name="display goes to sleep"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ $key_exists -ge "1" ]; then
            setting_value=`pmset -g | grep "$setting_name" | egrep -o "[0-9]+"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ $setting_value == "0" ]; then
            echo "$friendly_name never"
        else
            echo "$friendly_name after $setting_value minutes"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 20 minutes for all power profiles"
                    pmset -a "$setting_name" 20
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 20 minutes for all power profiles"
                    pmset -a "$setting_name" 20
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 20 minutes for all power profiles"
                    pmset -a "$setting_name" 20
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 10 minutes for all power profiles"
                    pmset -a "$setting_name" 10
                fi
                ;;
        esac
    fi

#DEPENDENT on value in CCE_79754_8_desktop_idle_time
#If the screen goes to sleep before the computer starts its screensaver and locks,
#there is a false sense of security.

#Note: Difficult to check each power profile and set on an individual basis,
#so override existing settings each time a security profile is set.

#NEEDS_REAL_HARDWARE

#OS X 10.10 real hardware test
#The setting took effect immediately without logging out or restarting.

}

######################################################################
CCE_79791_0_dim_display_before_sleep () {
    local doc="CCE_79791_0_dim_display_before_sleep           (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name="Display Sleep Uses Dim"
    local setting_name="halfdim"
    local setting_value=1 #default is enabled
    local friendly_name="display dim before sleep"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ $key_exists -ge "1" ]; then
            setting_value=`pmset -g | grep "$setting_name" | egrep -o "[01]"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ $setting_value == "0" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
        esac
    fi

#Note: Difficult to check each power profile and set on an individual basis,
#so override existing settings each time a security profile is set.
#

#NEEDS_REAL_HARDWARE

#OS X 10.10 real hardware test
#Setting immediately applies and display dims before going to sleep.

#10.10 
#Setting could not be disabled. Confirmed that another user was unable to disable 
#halfdim on 10.10.
}

######################################################################
CCE_79792_8_wake_when_lid_opened () {
    local doc="CCE_79792_8_wake_when_lid_opened            (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name="Wake On Clamshell Open"
    local setting_name="lidwake"
    local setting_value=1 #default is enabled
    local friendly_name="wake when lid opened"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ $key_exists -ge "1" ]; then
            setting_value=`pmset -g | grep "$setting_name" | egrep -o "[01]"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ $setting_value == "0" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
        esac
    fi

#Note: Difficult to check each power profile and set on an individual basis,
#so override existing settings each time a security profile is set.

#NEEDS_REAL_HARDWARE

#OS X 10.10 real hardware test
#Setting immediately applies and takes effect without logging out or restarting.
}


######################################################################
CCE_79793_6_sleep_on_power_button () {
    local doc="CCE_79793_6_sleep_on_power_button            (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local file=/Library/Preferences/com.apple.loginwindow.plist
    local internal_name="Sleep On Power Button"
    local setting_name="PowerButtonSleepsSystem"
    local setting_value=1 #default is enabled
    local friendly_name="sleep when power button pressed"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep -c "$setting_name"`
    fi

    if [ $key_exists == "1" ]; then
        setting_value=`defaults read $file $setting_name`
    fi

    if [ "$print_flag" != "" ]; then
        if [ $setting_value == "0" ]; then
            echo "$friendly_name is disabled";
        else
            echo "$friendly_name is enabled";
        fi
    fi
    

    if [ "$set_flag" != "" ]; then

        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "$setting_value" != 1 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                if [ "$setting_value" != 1 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                if [ "$setting_value" != 1 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ "$setting_value" != 1 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac
    fi

#OS X 10.10
#Works immediately without restart.
}



######################################################################
CCE_79795_1_disable_computer_sleep () {
    local doc="CCE_79795_1_disable_computer_sleep            (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name="System Sleep Timer"
    local setting_name="sleep"
    local setting_value=10 #default is 10 minutes
    local friendly_name="computer sleep"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ $key_exists -ge "1" ]; then
            setting_value=`pmset -g | grep -w "$setting_name" | egrep -o "[0-9]+"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ $setting_value == "0" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name occurs after $setting_value minutes"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name after 10 minutes for all power profiles"
                    pmset -a "$setting_name" 10
                fi
                ;;
        esac
    fi

#Note: Difficult to check each power profile and set on an individual basis,
#so override existing settings each time a security profile is set.

#10.10 real hardware
#Works immediately.
}


######################################################################
CCE_79796_9_prevent_idle_sleep_if_tty_active () {
    local doc="CCE_79796_9_prevent_idle_sleep_if_tty_active         (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name="TTYSPreventSleep"
    local setting_name="ttyskeepawake"
    local setting_value=1 #default is enabled
    local friendly_name="remote login sessions prevent sleep"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ $key_exists -ge "1" ]; then
            setting_value=`pmset -g | grep "$setting_name" | egrep -o "[01]"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ $setting_value == "0" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
        esac
    fi

#Note: Difficult to check each power profile and set on an individual basis,
#so override existing settings each time a security profile is set.

#NEEDS_REAL_HARDWARE

#OS X 10.10 real hardware test
#Computer went to sleep when setting was disabled, during an active tty connection.
#After the script enabled it, the computer did not go to sleep during tty connection.
#Restart or logout not required.
}


######################################################################
CCE_79797_7_disable_wake_for_network_access () {
    local doc="CCE_79797_7_disable_wake_for_network_access          (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name="Wake On LAN"
    local setting_name="womp"
    local setting_value=1 #default is enabled
    local friendly_name="wake for network access"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ $key_exists -ge "1" ]; then
            setting_value=`pmset -g | grep "$setting_name" | egrep -o "[01]"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ "$setting_value" == "0" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 1
                fi
                ;;
        esac
    fi

#Note: Difficult to check each power profile and set on an individual basis,
#so override existing settings each time a security profile is set.
#This setting only affects Ethernet connections.

#NEEDS_REAL_HARDWARE

#OS X 10.10 real hardware test
#With setting enabled, file sharing and ssh woke up the system.
#With the setting disabled, the system did not show up for file sharing,
#and ssh could not find a route to the system.
#Restart or logout not required.
}

######################################################################
CCE_79798_5_turn_hibernate_off () {
    local doc="CCE_79798_5_turn_hibernate_off            (manual-test-PASSED)"
    local file=/Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist
    local internal_name="Hibernate Mode"
    local setting_name="hibernatemode"
    local setting_value=3 #default is enabled
    local friendly_name="hibernate"
    local key_exists=0

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ $key_exists -ge "1" ]; then
            setting_value=`pmset -g | grep "$setting_name" | egrep -o "[0-9]+"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ $key_exists == "0" ]; then
            echo "$friendly_name is not supported by this system"
        elif [ $setting_value == "0" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "soho")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "sslf")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "oem")
                if [ $key_exists == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 3
                fi
                ;;
        esac
    fi
    
#Physical hardware test
#OS X 10.10 
#Setting applies immediately.
}


###############################################################
CCE_79799_3_disable_bonjour_advertising() {
local doc="CCE_79799_3_disable_bonjour_advertising                (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file=/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
    local file2="/System/Library/LaunchDaemons/com.apple.discoveryd.plist"
    local setting_name=ProgramArguments
    local setting_value="-NoMulticastAdvertisements"
    local setting_value2="--no-multicast"
    local friendly_name="Bonjour advertising"
    local value_exists=0
    local value2_exists=0

    #in 10.10, up through 10.10.3, discoveryd replaces mDNSResponder
    #version 10.10.4 reverted back to using mDNSResponder
    if [ -e "$file2" ]; then
        local key2_exists=`defaults read $file2 | grep -c $setting_name`
        if [ "$key2_exists" -gt 0 ]; then
            value2_exists=`defaults read $file2 $setting_name -array | grep -c -- "$setting_value2"`
        fi
    fi
       
    if [ -e "$file" ]; then
        local key_exists=`defaults read $file | grep -c $setting_name`
        if [ "$key_exists" -gt 0 ]; then
            value_exists=`defaults read $file $setting_name -array | grep -c -- "$setting_value"`
        fi

    fi

    if [ "$print_flag" != "" ]; then
        if [ "$value_exists" != "0" ]; then
            echo "$friendly_name is disabled";
        else
            echo "$friendly_name is enabled";
        fi
    fi


    if [ "$set_flag" != "" ]; then

        case $profile_flag in
            "ent")
                if [ "$value2_exists" == 0 ]; then
                    #be sure to print a message if the other file 
                    #mDNSResponder.plist doesn't exist
                    if [ ! -e "$file" ]; then
                        echo "disabling $friendly_name";
                    fi
                
                    defaults write $file2 $setting_name -array-add "$setting_value2"
                    
                    add_processes_to_kill_list cfprefsd
                fi
                
                if [ "$value_exists" == 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -array-add "$setting_value"
                
                    add_processes_to_kill_list cfprefsd
                
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
                if [ "$value2_exists" == 0 ]; then
                    #be sure to print a message if the other file 
                    #mDNSResponder.plist doesn't exist
                    if [ ! -e "$file" ]; then
                        echo "disabling $friendly_name";
                    fi
                
                    defaults write $file2 $setting_name -array-add "$setting_value2"
                    
                    add_processes_to_kill_list cfprefsd
                fi
                
                if [ "$value_exists" == 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -array-add "$setting_value"
                
                    add_processes_to_kill_list cfprefsd
                
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ "$value2_exists" != 0 ]; then
                    local new_array2=`defaults read $file2 $setting_name | grep -v -- "$setting_value2" | egrep -v "\(|\)"`

                    #remove trailing commas
                    new_array2=`echo "$new_array" | sed "s/,$//"`

                    #delete existing array and rewrite one line at a time
                    defaults delete $file2 $setting_name
                    for line in $new_array2; do
                        defaults write $file2 $setting_name -array-add "$line"
                    done
                
                    add_processes_to_kill_list cfprefsd
                fi
                
                if [ "$value_exists" != 0 ]; then
                    echo "enabling $friendly_name";
                    local new_array=`defaults read $file $setting_name | grep -v -- "$setting_value" | egrep -v "\(|\)"`

                    #remove trailing commas
                    new_array=`echo "$new_array" | sed "s/,$//"`

                    #delete existing array and rewrite one line at a time
                    defaults delete $file $setting_name
                    for line in $new_array; do
                        defaults write $file $setting_name -array-add "$line"
                    done
                
                    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac
    fi


#Note: If cfprefsd is not restarted, this may not keep the changed setting state.

#OS X 10.10
#Works after restart. The computer no longer shows up in Finder on other computers. 
#It is still accessible on the network, so this setting works as expected.
#Research indicated that prior to 10.10.3, there may be side-effects with disabling 
#Bonjour, such as Wi-Fi network connectivity.
}


######################################################################
CCE_79800_9_disable_airdrop () {
    local doc="CCE_79800_9_disable_airdrop            (manual-test-PASSED)"

    local file=$home_path/Library/Preferences/com.apple.NetworkBrowser.plist
    local setting_name=DisableAirDrop
    local setting_value=0
    local friendly_name="AirDrop"

    if [ -e "$file" ]; then
        local key_exists=`defaults read $file | grep -c $setting_name`
        if [ "$key_exists" -gt 0 ]; then
            setting_value=`defaults read $file $setting_name`
        fi

    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then

        if [ "$setting_value" != "0" ]; then
            echo "$friendly_name is disabled";
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then

        case $profile_flag in
            "ent")
                if [ "$setting_value" == 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool true

                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
                if [ "$setting_value" == 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $file $setting_name -bool true

                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ "$setting_value" == 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool false

                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
            ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#*************** Profiles Changed from OS X guidance spreadsheet  ***************
#soho: AirDrop disabled -> AirDrop allowed

# Note: AirDrop requires an enabled Wi-Fi adapter to function.

# NEEDS_REAL_HARDWARE

# OS X 10.10
# To make the setting apply immediately, kill cfprefsd and Finder.
}

######################################################################
CCE_79801_7_wifi_unload_uninstall_kext () {
    local doc="CCE_79801_7_wifi_unload_uninstall_kext           (manual-test-PASSED)"
    local kext_path=/System/Library/Extensions/
    local destination=/System/Library/UnusedExtensions/

    local file1_no_ext=IO80211Family
    local file1=${file1_no_ext}.kext
    local file1_loaded=`kextstat | grep $file1_no_ext | wc -l`
    local friendly_name="Wi-Fi kext files"
    local file1_exists=0

    if [ -e "$kext_path$file1" ]; then file1_exists=1; fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    if [ "$print_flag" != "" ]; then
        if [ "$v_flag" != "" ]; then
            if [ $file1_exists == "1" ]; then
                echo "$file1 is present in $kext_path"
            else
                echo "$file1 is not present in $kext_path"
            fi

            if [ $file1_loaded == "1" ]; then
                echo "$file1 is loaded"
            else
                echo "$file1 is not loaded"
            fi

        else #no v flag
            if [ $file1_exists == "1" ]; then
                echo "$friendly_name are present"
            else
                echo "$friendly_name are not present"
            fi
        fi
    fi

#To delete kext files rather than move them, comment out the mv and chown
#lines and uncomment the srm lines
    if [ "$set_flag" != "" ]; then
    case $profile_flag in
        "ent")
            echo "$friendly_name are unchanged"
            ;;

        "soho")
            echo "$friendly_name are unchanged"
            ;;

        "sslf")
            #create destination directory
            if [ ! -e $destination ]; then
                mkdir $destination
            fi

            #Unloading Wi-Fi kexts does not work
:<<'COMMENT_BLOCK'
            #Unload file1 from the kernel if it is loaded
            if [ $file1_loaded == "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Unloading $file1 from the kernel"
                fi
                kextunload $kext_path$file1
            elif [ "$v_flag" != "" ]; then
                echo "$file1 is already unloaded"
            fi
COMMENT_BLOCK

            if [ $file1_exists == "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file1 from $kext_path to $destination"
                    #echo "Removing $kext_path$file1"
                else
                    echo "Moving $friendly_name to $destination"
                    #echo "Unloading and moving $friendly_name to $destination"
                    #echo "Removing $friendly_name"
                fi

                #if moving to $destination and not $destination$file, the
                #kext file may unpack
                mv -f $kext_path$file1 $destination$file1
                chown -R root:wheel $destination$file1/* #moving changes owner

                #srm -rf $kext_path$file1

            else
                echo "$file1 has already been removed from $kext_path"
            fi
            ;;

        "oem")
            if [ $file1_exists != "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Moving $file1 from $destination to $kext_path"
                else
                    echo "Moving $friendly_name from $destination to $kext_path"
                fi
                mv -f $destination$file1 $kext_path$file1
                chown root:wheel $kext_path$file1
                chown -R root:wheel $kext_path$file1/*

            else
                echo "$file1 already present in $kext_path"
            fi

#Do not load kexts because unloading does not work
:<<'COMMENT_BLOCK'

            #Load file1 into the kernel if it is not currently loaded
            if [ $file1_loaded != "1" ]; then
                if [ "$v_flag" != "" ]; then
                    echo "Loading $file1 into the kernel"
                fi
                kextload $kext_path$file1
            elif [ "$v_flag" != "" ]; then
                echo "$file1 is already loaded"
            fi

COMMENT_BLOCK

            ;;
        esac
    fi

#Note: some kext files are actually packages that contain many kext files.
#If the owner or group of a kext file is changed, the system pops up with a
#message stating that a "system extension cannot be used" for each kext file.
#It is not necessary to "touch $kext_path" since the file removal or addition
#updates the modified time on the folder.

# NEEDS_REAL_HARDWARE

#OS X 10.10 real hardware
#Restart required for enabling or disabling.
}


######################################################################
parse_arguments () {
    usage_message="usage:
    samc.sh -l                             # list the settings
    samc.sh -s ent | sslf | soho | oem     # set a profile's values
    samc.sh -p                             # print settings values
    samc.sh -h                             # usage message
    samc.sh -v                             # verbose
    samc.sh -u username                    # username to apply user-specific settings
    samc.sh -a                             # apply user-specific settings to all users
    samc.sh -k                             # skip time-consuming print/set operations"

    #if no options to the script
    if [ $# -eq 0 ]; then
        echo "$usage_message"
        exit 1
    fi

    while getopts "ls:pchvkau:" opt $@; do
    case $opt in
        l)
            list_flag="on"
            ;;
        s)
            profile_flag=`echo $OPTARG | awk '{print tolower($0)}'`
            if [ $profile_flag != "ent" ] &&
               [ $profile_flag != "soho" ] &&
               [ $profile_flag != "sslf" ] &&
               [ $profile_flag != "oem" ] ; then
                echo "profile must be one of: ent, soho, or sslf"
                exit 1  #error
            fi
            set_flag="on"
            ;;
        p)
            print_flag="on"
            ;;
        c)
            echo "checking feature TBD" >&2
            ;;
        
        h)
            echo "$usage_message"
            exit 0
            ;;
        v)
            v_flag="on"
            ;;
        a)
            all_users_flag="on"
            ;;
        u)
            specific_user_flag="on"
            # get exit status to check for valid user; suppress all output
            if id -u $OPTARG >/dev/null 2>&1; then
                owner=$OPTARG

            else
                echo "invalid user name specified";
                exit 1
            fi
            ;;
        k)
            skip_flag="on"
            ;;
        \?)
            echo "invalid option"
            exit 1
            ;;
    esac
    done
    if [ "$profile_flag" == "" ]; then profile_flag="ent"; fi
}

######################################################################
main $@ # Runs the main function and passes the command-line arguments.
        # Runs after all the other functions are defined, so no forward
        #      declarations are needed.


# left justify the path, fill 40, and add the rwx bits
#	printf "%-40s %s\n" $1 `ls -ld $1 | awk '{print $1}'`
