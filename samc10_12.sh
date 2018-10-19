#!/bin/bash

#NIST GitHub repository for related project files:
#https://github.com/usnistgov/applesec

######################################################################
:<<'COMMENT_BLOCK'

License

This software was developed by employees of the National Institute of Standards
and Technology (NIST), an agency of the Federal Government and is being made
available as a public service. Pursuant to title 17 United States Code Section
105, works of NIST employees are not subject to copyright protection in the 
United States.  This software may be subject to foreign copyright.  Permission
in the United States and in foreign countries, to the extent that NIST may hold
copyright, to use, copy, modify, create derivative works, and distribute this
software and its documentation without fee is hereby granted on a non-exclusive
basis, provided that this notice and disclaimer of warranty appears in all 
copies.

THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER
EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY
THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM
INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE 
SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT
SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT,
INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR
IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY,
CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR
PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT 
OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER.


######################################################################
This shell script performs 2 functions:
    1) set configuration items to specified NIST profile values
    2) query configuration item values

It must be run as root.

usage:

samc -l                             # list the settings
samc -s ent | sslf | soho | oem     # choose the profile to run
samc -p                             # print settings values
samc -h                             # usage message
samc -v                             # verbose
samc -u username                    # username to apply user-specific settings
samc -a                             # apply user-specific settings to all users
samc -k                             # skip time-consuming print/set operations

Note: "ent" is shorthand for "enterprise".

Commands this script uses to write configation info in macOS:
    defaults
    chmod
    chgrp
    chown
    PlistBuddy
    pwpolicy
    pmset
    scutil
    socketfilterfw
    dscl
    systemsetup
    kickstart
    visudo
    pfctl
    spctl
    launchctl

Design note:

All setting batches are invoked from the main function level and different
groups of settings can be commented out to focus on specific issues.
Each setting is implemented by a separate function that gets called from 
different batch functons. Settings in similar categories are typically grouped  
into each batch, and these batches are called by the main function.  
Each separate setting function is responsible for writing
the various profiles, displaying current values, outputing a brief
message for listing the settings ls-style, and, when additional
verbosity makes sense, supporting the -v option.


Function status tags:

#Informal testing was unable to be completed on a VM
NEEDS_REAL_HARDWARE

COMMENT_BLOCK

######################################################################
#checks for root user before running any commands
if [ "$(id -u "$(whoami)")" != "0" ]; then
    echo "Sorry, samc must be run with root privileges. Exiting..."
    exit 1
fi

# Global variables.

# This script's command-line options are stored in these variables
list_flag=""
set_flag=""
profile_flag=""
print_flag=""
v_flag=""
all_users_flag=""
specific_user_flag=""

#Used to skip time-consuming print and set operations. This is used in the function
#CCE_79502_1_update_apple_software
skip_flag=""  


home_path=""
owner=""
os_version="" #major release version, such as 10.12
processes_to_kill="" #processes that need to be restarted at the end of the script
new_system_name=""
user_list="" #non system-created user accounts (user accounts created for people)
full_user_list="" #the full list of users on the system

#audit log location is variable, so find it for later
audit_log_path="$(grep "^dir:" /etc/security/audit_control | sed "s/dir://")"

#directories containing library files
lib_dirs="/System/Library/Frameworks /Library/Frameworks /usr/lib /usr/local/lib"
#library files
lib_files="$(find $lib_dirs -type f 2> /dev/null | egrep "((\.a)|(\.so)|(\.dylib)[\.0-9]*)$")"

#needed for storing script temp files
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#When using PlistBuddy, array values must be added by index, therefore creating the need
#for a global variable to keep track of the current array position for pwpolicy settings
pw_content_index=0
pw_change_index=0
pw_auth_index=0

#This variable holds settings that will be executed for all specified users
user_settings_list=""

######################################################################
main() {
    parse_arguments "$@"

    if [ "$v_flag" != "" ]; then 
        echo "SAM script verbose mode enabled."
    fi
    echo "Executing system-wide settings."

    # sets the global variables: owner, group, and hw_uuid
    determine_user_and_system_properties

    auditing
    authentication
    built_in_applications
    firewall
    local_services
    network_services
    power_management
    ssh
    updates
    wireless

    #Contains functions for setting permissions in home directories 
    #Call this last of all the batch functions
    access_control

    # allows all user settings to be run for the specified users
    apply_settings_for_selected_users

    # performs tasks such as process killing 
    final_tasks
}



######################################################################
access_control() {
    user_settings_list="$user_settings_list
CCE_79404_0_all_files_in_a_users_home_dir_are_owned_by_that_user
CCE_79407_3_files_in_home_dir_group_owned_by_owners_group
CCE_79409_9_user_home_directories_permissions"

    CCE_79405_7_check_system_integrity_protection_status
    CCE_79406_5_enable_gatekeeper
    CCE_79408_1_set_umask
}


######################################################################
auditing() {
    CCE_79410_7_audit_log_max_file_size
    CCE_79411_5_audit_log_retention
    CCE_79412_3_do_not_send_diagnostic_info_to_apple
    CCE_79413_1_set_audit_control_flags
}	


######################################################################
authentication() {
    user_settings_list="$user_settings_list
CCE_79417_2_desktop_idle_time
CCE_79430_5_screensaver_grace_period
CCE_79431_3_start_screen_saver_hot_corner"

    CCE_79414_9_add_cli_login_banner
    CCE_79415_6_add_login_banner
    CCE_79416_4_console_login
    CCE_79418_0_fast_user_switching
    CCE_79428_9_require_admin_password_for_system_prefs
    CCE_79429_7_retries_until_hint
    CCE_79432_1_sudo_timeout_period_set_to_0
    CCE_79433_9_use_network_time_protocol
    CCE_79434_7_users_list_on_login

    #clears the current global password policy to ensure it is set properly with this script
    if [ "$set_flag" != "" ]; then
        pwpolicy -clearaccountpolicies
        
        while IFS= read -r user_name; do
            if [ "$user_name" != "" ]; then
                pwpolicy -u "$user_name" -clearaccountpolicies
            fi
        
        done <<< "$user_list"
    fi

    CCE_79419_8_password_complex_passwords_alphabetic_char
    CCE_79420_6_password_complex_passwords_numeric_char
    CCE_79421_4_password_complex_passwords_symbolic_char
    CCE_79422_2_password_enforce_password_history_restriction
    CCE_79423_0_password_failed_login_lockout_policy
    CCE_79424_8_password_guessable_pattern
    CCE_79425_5_password_maximum_age
    CCE_79426_3_password_minimum_length
    CCE_79427_1_password_uppercase_and_lowercase
}


######################################################################
built_in_applications() {
    user_settings_list="$user_settings_list
CCE_79437_0_disable_siri
CCE_79438_8_display_file_extensions
CCE_79439_6_dock_enable_autohide
CCE_79440_4_enable_safari_status_bar
CCE_79441_2_show_hidden_files
CCE_79442_0_terminal_secure_keyboard"

    CCE_79435_4_disable_lookup_suggestions
}

######################################################################
firewall() {
    CCE_79443_8_allow_signed_downloaded_sw_receive_connections 
    CCE_79444_6_allow_signed_sw_receive_connections
    CCE_79445_3_enable_firewall_logging_detail_level

    CCE_79446_1_pf_enable_firewall
    CCE_79447_9_pf_rule_apple_file_service
    CCE_79448_7_pf_rule_bonjour
    CCE_79449_5_pf_rule_finger
    CCE_79450_3_pf_rule_ftp
    CCE_79451_1_pf_rule_http
    CCE_79452_9_pf_rule_icmp
    CCE_79453_7_pf_rule_imap
    CCE_79454_5_pf_rule_imaps
    CCE_79455_2_pf_rule_itunes_sharing
    CCE_79456_0_pf_rule_mDNSResponder
    CCE_79457_8_pf_rule_nfs
    CCE_79458_6_pf_rule_optical_drive_sharing
    CCE_79459_4_pf_rule_pop3
    CCE_79460_2_pf_rule_pop3s
    CCE_79461_0_pf_rule_printer_sharing
    CCE_79462_8_pf_rule_remote_apple_events
    CCE_79463_6_pf_rule_screen_sharing
    CCE_79464_4_pf_rule_smb
    CCE_79465_1_pf_rule_smtp
    CCE_79466_9_pf_rule_ssh
    CCE_79467_7_pf_rule_telnet
    CCE_79468_5_pf_rule_tftp
    CCE_79469_3_pf_rule_uucp
    CCE_79470_1_turn_on_firewall
}


######################################################################
local_services() {
    CCE_79476_8_disable_location_services

    user_settings_list="$user_settings_list
CCE_79471_9_disable_auto_actions_on_blank_CD_insertion
CCE_79472_7_disable_auto_actions_on_blank_DVD_insertion
CCE_79473_5_disable_auto_music_CD_play
CCE_79474_3_disable_auto_picture_CD_display
CCE_79475_0_disable_auto_video_DVD_play"
}


######################################################################
network_services() {
    # the first function run will influence the name for all 4 functions
    CCE_79477_6_change_computer_name
    CCE_79478_4_change_host_name
    CCE_79479_2_change_local_host_name
    CCE_79480_0_change_net_bios_name

    CCE_79481_8_disable_apple_file_server
    CCE_79482_6_disable_bluetooth_daemon 
    CCE_79483_4_disable_bonjour_advertising
    CCE_79484_2_disable_nfs 
    CCE_79485_9_disable_wifi_services
    CCE_79486_7_restrict_remote_apple_events_to_specific_users
    CCE_79487_5_restrict_remote_management_to_specific_users
    CCE_79488_3_restrict_screen_sharing_to_specified_users
}


######################################################################
power_management() {
    CCE_79489_1_disable_computer_sleep
    CCE_79490_9_disable_wake_for_network_access
    CCE_79491_7_enable_display_sleep
}


######################################################################
ssh() {
    CCE_79492_5_ssh_challenge_response_authentication_disallowed
    CCE_79493_3_ssh_disable_pub_key_authentication
    CCE_79494_1_ssh_disable_root_login
    CCE_79495_8_ssh_keep_alive_messages
    CCE_79496_6_ssh_login_grace_period
    CCE_79497_4_ssh_max_auth_tries_4_or_less
    CCE_79498_2_ssh_remove_non_fips_140_2_ciphers
    CCE_79499_0_ssh_remove_non_fips_140_2_macs
    CCE_79500_5_ssh_restrict_users
    CCE_79501_3_ssh_set_client_timeout 
}


######################################################################
updates() {
    CCE_79502_1_update_apple_software
}


######################################################################
wireless() {
    user_settings_list="$user_settings_list
CCE_79503_9_bluetooth_disable_wake_computer
CCE_79507_0_disable_airdrop
CCE_79509_6_show_bluetooth_status_in_menu_bar"

    CCE_79504_7_bluetooth_open_setup_if_no_keyboard
    CCE_79505_4_bluetooth_open_setup_if_no_mouse_trackpad
    CCE_79506_2_bluetooth_turn_off_bluetooth
    CCE_79508_8_disable_infrared_receiver
}



######################################################################
CCE_79415_6_add_login_banner () {
    local doc="CCE_79415_6_add_login_banner                   (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local friendly_name="GUI login banner"
    local banner_file="/Library/Security/PolicyBanner.txt"
    local policy_text="You are accessing a U.S. Government information system, which includes: 1) this computer, 2) this computer network, 3) all computers connected to this network, and 4) all devices and storage media attached to this network or to a computer on this network. You understand and consent to the following: you may access this information system for authorized use only; you have no reasonable expectation of privacy regarding any communication of data transiting or stored on this information system; at any time and for any lawful Government purpose, the Government may monitor, intercept, and search and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Government purpose."
    local banner_exists=0;

    if [ -e "$banner_file" ]; then
        banner_exists="$(grep -c "$policy_text" "$banner_file")"
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
                rm "$banner_file"
            else
                echo "$friendly_name already disabled";
            fi
        ;;
    esac
    fi

#macOS 10.12
#Works on next user login.
}


######################################################################
CCE_79414_9_add_cli_login_banner () {
    local doc="CCE_79414_9_add_cli_login_banner                   (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local friendly_name="command line login banner"
    local banner_file="/etc/motd"
    local policy_text="You are accessing a U.S. Government information system, which includes: 1) this computer, 2) this computer network, 3) all computers connected to this network, and 4) all devices and storage media attached to this network or to a computer on this network. You understand and consent to the following: you may access this information system for authorized use only; you have no reasonable expectation of privacy regarding any communication of data transiting or stored on this information system; at any time and for any lawful Government purpose, the Government may monitor, intercept, and search and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Government purpose."
    local banner_exists=0;

    if [ -e "$banner_file" ]; then
        banner_exists="$(grep -c "$policy_text" "$banner_file")"
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
                rm "$banner_file"
            else
                echo "$friendly_name already disabled";
            fi
        ;;
    esac
    fi

#OS X 10.12
#Takes effect immediately.
}


######################################################################
CCE_79416_4_console_login () {
    local doc="CCE_79416_4_console_login                   (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="/Library/Preferences/com.apple.loginwindow.plist"
    local friendly_name="console login"
    local setting_name="DisableConsoleAccess"
    local setting_value="0" #default value confirmed 10.12
    local key_exists="0"

    if [ -e "$file" ]; then
        key_exists="$(defaults read "$file" | grep -c "$setting_name")"
    fi

    if [ "$key_exists" == "1" ]; then
        setting_value="$(defaults read "$file" "$setting_name")"
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" == "1" ]; then
            echo "$friendly_name is disabled";
        else
            echo "$friendly_name is enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
		if [ "$setting_value" == "1" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name";
                    defaults write "$file" $setting_name -bool true
	        fi
                ;;
            "soho")
		if [ "$setting_value" == "1" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name";
                    defaults write "$file" $setting_name -bool true
                fi
                ;;
            "sslf")
		if [ "$setting_value" == "1" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name";
                    defaults write "$file" $setting_name -bool true
	        fi
                ;;
            "oem")
		if [ "$setting_value" == "0" ]; then
		    echo "$friendly_name is already enabled"
	        else
                    echo "enabling $friendly_name";
                    defaults write "$file" $setting_name -bool false
                fi
                ;;
        esac
    fi

# If console login is enabled, typing the string ">console" for the user
# name should give a console login. This can be done only when the Users & 
# Groups option for "Display login window as:" is set to "Name and password"

# macOS 10.12
# Restart not required for setting to take effect. When testing on physical
# hardware, it froze after attempting to use console login when enabled.
}


######################################################################
CCE_79434_7_users_list_on_login () {
    local doc="CCE_79434_7_users_list_on_login             (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="/Library/Preferences/com.apple.loginwindow.plist"
    local friendly_name="login window user list"
    local setting_name="SHOWFULLNAME"
    local setting_value="0" #default value confirmed 10.12
    local key_exists="0"

    if [ -e "$file" ]; then
        key_exists="$(defaults read "$file" | grep -c "$setting_name")"
    fi

    if [ "$key_exists" == "1" ]; then
        setting_value="$(defaults read "$file" "$setting_name")"
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" == "0" ]; then
            echo "$friendly_name is displayed"
        else
            echo "$friendly_name is hidden"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
		if [ "$setting_value" == "1" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name"
                    defaults write "$file" $setting_name -int 1
	        fi
                ;;
            "soho")
		if [ "$setting_value" == "0" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name"
                    defaults write "$file" $setting_name -int 1
                fi
                ;;
            "sslf")
		if [ "$setting_value" == "1" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name"
                    defaults write "$file" $setting_name -int 1
	        fi
                ;;
            "oem")
		if [ "$setting_value" == "0" ]; then
		    echo "$friendly_name is already enabled"
	        else
                    echo "enabling $friendly_name"
                    defaults write "$file" $setting_name -int 0
                fi
                ;;
        esac
    fi

#macOS 10.12 testing
#Works immediately after logging out.
}


######################################################################
CCE_79429_7_retries_until_hint () {
    local doc="CCE_79429_7_retries_until_hint              (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local file="/Library/Preferences/com.apple.loginwindow.plist"
    local friendly_name="password retries until hint"
    local setting_name="RetriesUntilHint"
    local setting_value="3" #default value confirmed 10.12
    local key_exists="0"

    if [ -e "$file" ]; then
        key_exists="$(defaults read "$file" | grep -c "setting_name")"
    fi

    if [ "$key_exists" == "1" ]; then
        setting_value="$(defaults read "$file" "setting_name")"
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" == "0" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is $setting_value"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
		if [ "$setting_value" == "0" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name"
                    defaults write "$file" $setting_name -int 0
	        fi
                ;;
            "soho")
		if [ "$setting_value" == "0" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name"
                    defaults write "$file" $setting_name -int 0
                fi
                ;;
            "sslf")
		if [ "$setting_value" == "0" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name"
                    defaults write "$file" $setting_name -int 0
	        fi
                ;;
            "oem")
		if [ "$setting_value" == "3" ]; then
		    echo "$friendly_name is already set to 3"
	        else
                    echo "setting $friendly_name to 3"
                    defaults write "$file" $setting_name -int 3
                fi
                ;;
        esac
    fi
    

# macOS 10.12 testing
# Tested manually; hints enabled or disabled both in preferences and
# on login.  Preferences subpane needs to be closed and reopened to
# refresh the setting state.
}


######################################################################
CCE_79418_0_fast_user_switching () {
    local doc="CCE_79418_0_fast_user_switching             (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="/Library/Preferences/.GlobalPreferences.plist"
    local friendly_name="fast user switching"
    local setting_name="MultipleSessionEnabled"
    local setting_value="0" #default value confirmed 10.12
    local key_exists="0"

    if [ -e "$file" ]; then
        key_exists="$(defaults read "$file" | grep -c "setting_name")"
    fi

    if [ "$key_exists" == "1" ]; then
        setting_value="$(defaults read "$file" "setting_name")"
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" == "0" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
		if [ "$setting_value" == "0" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name"
                    defaults write "$file" $setting_name -bool false
	        fi
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
		if [ "$setting_value" == "0" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name"
                    defaults write "$file" $setting_name -bool false
	        fi
                ;;
            "oem")
		if [ "$setting_value" == "0" ]; then
		    echo "$friendly_name is already disabled"
	        else
                    echo "disabling $friendly_name"
                    defaults write "$file" $setting_name -bool false
                fi
                ;;
        esac
    fi
    


# macOS 10.12
# Tested manually.  Have to login again or switch users for the new
# setting to take effect.

#Fast user switching is disabled by default when there is only one user
#account. When the second account is created, fast user switching is turned on.
#If fast user switching is disabled, and the second user account is deleted, the
#setting remains disabled. However, if a second user account is created again,
#then fast user switching will be enabled automatically by the system.
}



#
# Set file permissions only if the existing permissions exceed the permission arguments.
# For example, if an existing file at 740 is being changed to 650, it would result in 640.
# This prevents the script from making files more permissive.
#
# $1 : file path
# $2 : owner to set
# $3 : group to set
# $4 : UNIX mode bits to set (including sticky/setuid)
#
set_max_file_permission () {
    if [ -e "$1" ]; then
        if [ "$4" != "" ]; then
            local u_bits="$(echo "$4" | cut -c1)"
            local g_bits="$(echo "$4" | cut -c2)"
            local o_bits="$(echo "$4" | cut -c3)"

            local u_subtract=""
            local g_subtract=""
            local o_subtract=""

            #only change the set id permissions if it is included in the parameter (if $4
            #is 4 characters long)
            if [ "${#4}" -eq "4" ]; then
                local id_bits="$(echo "$4" | cut -c1)"
                u_bits="$(echo "$4" | cut -c2)"
                g_bits="$(echo "$4" | cut -c3)"
                o_bits="$(echo "$4" | cut -c4)"

                #set id permissions
                if [ "$id_bits" -lt "4" ]; then
                    u_subtract="s"
                #subtract 4 so that we can check for set gid on execute(2) permission
                else
                    id_bits=$(( id_bits - 4 ))
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
                u_bits=$(( u_bits - 4 ))
            fi

            if [ "$u_bits" -lt "2" ]; then
                u_subtract="${u_subtract}w"
            else
                u_bits=$(( u_bits - 2 ))
            fi

            if [ "$u_bits" -lt "1" ]; then
                u_subtract="${u_subtract}x"
            fi


            #group permissions
            if [ "$g_bits" -lt "4" ]; then
                g_subtract="${g_subtract}r"
            else
                g_bits=$(( g_bits - 4 ))
            fi

            if [ "$g_bits" -lt "2" ]; then
                g_subtract="${g_subtract}w"
            else
                g_bits=$(( g_bits - 2 ))
            fi

            if [ "$g_bits" -lt "1" ]; then
                g_subtract="${g_subtract}x"
            fi

            #other permissions
            if [ "$o_bits" -lt "4" ]; then
                o_subtract="${o_subtract}r"
            else
                o_bits=$(( o_bits - 4 ))
            fi

            if [ "$o_bits" -lt "2" ]; then
                o_subtract="${o_subtract}w"
            else
                o_bits=$(( o_bits - 2 ))
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



######################################################################
CCE_79430_5_screensaver_grace_period () {
    local doc="CCE_79430_5_screensaver_grace_period                 (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/ByHost/com.apple.screensaver.$hw_uuid.plist
    local file2=$home_path/Library/Preferences/com.apple.screensaver.plist

    local friendly_name="screensaver grace period"
    local delay="300" # default value for 10.12
    local target_delay=5 # number of seconds to set grace period to

    local setting_name=askForPasswordDelay

    # if the ByHost file exists, then first try to access it
    if [ -e "$file" ]; then
        local key_exists="$(defaults read "$file" | grep -c "$setting_name")"

        if [ "$key_exists" == 1 ]; then
            delay="$(defaults read "$file" "$setting_name")"
        # if the key is not present, then try to read file2
        else
            if [ -e "$file2" ]; then
                key_exists="$(defaults read "$file2" | grep -c "$setting_name")"
                if [ "$key_exists" == 1 ]; then
                    delay="$(defaults read "$file2" "$setting_name")"
                    file="$file2"  # since $file2 has the key, change that one
                fi

            fi
        fi
    #if ByHost file doesn't exist, try to access file2
    elif [ -e "$file2" ]; then
        key_exists="$(defaults read "$file2" | grep -c "$setting_name")"
        if [ "$key_exists" == 1 ]; then
            delay="$(defaults read "$file2" "$setting_name")"
            file="$file2"  # since $file2 has the key, change that one
        fi
    # else do nothing, since neither file exists, and the default value will be used
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$delay" != "0" ]; then
            echo "$delay seconds $friendly_name";
        else
            echo "$friendly_name is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$delay" != "$target_delay" ]; then
                    echo "setting screensaver grace period to $target_delay seconds";
                    defaults write "$file" "$setting_name" -int "$target_delay"
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already set to $target_delay seconds"
                fi
                ;;
            "soho")
                if [ "$delay" != "$target_delay" ]; then
                    echo "setting screensaver grace period to $target_delay seconds";
                    defaults write "$file" "$setting_name "-int "$target_delay"
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already set to $target_delay seconds"
                fi
                ;;
            "sslf")
                if [ "$delay" != "$target_delay" ]; then
                    echo "setting screensaver grace period to $target_delay seconds";
                    defaults write "$file" "$setting_name" -int "$target_delay"
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already set to $target_delay seconds"
                fi
                ;;
            "oem")
                if [ "$delay" != "300" ]; then
                    echo "setting screensaver grace period to 300 seconds";
                    defaults write "$file" "$setting_name" -int 300
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already set to 300 seconds"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group "$file" #restore original owner/group
        fi
    fi

# macOS 10.12 - tested
# After restarting, the setting appears in the GUI and works with manual testing.
}


######################################################################
CCE_79431_3_start_screen_saver_hot_corner () {
    local doc="CCE_79431_3_start_screen_saver_hot_corner      (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.dock.plist

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local active=0

    # suppress error message in case the domain/default pair doesn't exist
    local btm_left="$(defaults read "$file" wvous-bl-corner 2> /dev/null)"
    local btm_right="$(defaults read "$file" wvous-br-corner 2> /dev/null)"
    local top_left="$(defaults read "$file" wvous-tl-corner 2> /dev/null)"
    local top_right="$(defaults read "$file" wvous-tr-corner 2> /dev/null)"

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
                if [ "$active" == 0 ]; then
                    echo "setting start screen saver to bottom-left hot corner";
                    defaults write "$file" wvous-bl-corner -int 5
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "start screen saver hot corner is already set"
                fi
                ;;
            "soho")
                if [ "$active" == 0 ]; then
                    echo "setting start screen saver to bottom-left hot corner";
                    defaults write "$file" wvous-bl-corner -int 5
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "start screen saver hot corner is already set"
                fi
                ;;
            "sslf")
                if [ "$active" == 0 ]; then
                    echo "setting start screen saver to bottom-left hot corner";
                    defaults write "$file" wvous-bl-corner -int 5
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "start screen saver hot corner is already set"
                fi
                ;;
            "oem")
                if [ "$btm_left" == "5" ]; then
                    echo "removing action from bottom-left hot corner";
                    defaults write "$file" wvous-bl-corner -int 1
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "start screen saver bottom-left hot corner is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group "$file" #restore original owner/group
        fi
    fi

# macOS 10.12
# Requires restart to take effect. If this value is set through the script and the
# user only logs out and back in, the setting goes back to its original value before 
# making the change. No command key modifiers were applied when enabling this.
}


######################################################################
CCE_79417_2_desktop_idle_time () {
    local doc="CCE_79417_2_desktop_idle_time           (manual-test-PASSED)"

    local file=$home_path/Library/Preferences/ByHost/com.apple.screensaver.$hw_uuid.plist
    local file2=$home_path/Library/Preferences/com.apple.screensaver.plist

    local setting_value=1200 #assume default of 1200 if no value is found in config files
    local target_value=1200 #desired value for all profiles
    local setting_name="idleTime"

    # if the ByHost file exists, then first try to access it
    if [ -e "$file" ]; then
        local key_exists="$(defaults read "$file" | grep -c "$setting_name")"
        if [ "$key_exists" == 1 ]; then
            setting_value="$(defaults read "$file" "$setting_name")"
        # if the key is not present, then try to read file2
        else
            if [ -e "$file2" ]; then
                key_exists="$(defaults read "$file2" | grep -c "$setting_name")"
                if [ "$key_exists" == 1 ]; then
                    setting_value="$(defaults read "$file2" "$setting_name")"
                    file="$file2"  # since $file2 has the key, change that one
                fi

            fi
        fi
    #if ByHost file doesn't exist, try to access file2
    elif [ -e "$file2" ]; then
        key_exists="$(defaults read "$file2" | grep -c "$setting_name")"
        if [ "$key_exists" == 1 ]; then
            setting_value="$(defaults read "$file2" "$setting_name")"
            file="$file2"  # since $file2 has the key, change that one
        fi
    # else do nothing, since neither file exists, and the default value will be used
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then

        if [ "$setting_value" == 1200 ]; then
            echo "desktop idle time before screensaver is default value of 1200 seconds (20 minutes)";
        elif [ "$setting_value" != 0 ]; then
            echo "desktop idle time before screensaver is $setting_value seconds";
        else
            echo "screensaver is disabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then

        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "$setting_value" -gt "$target_value" ] || [ "$setting_value" -eq 0 ]; then
                    echo "setting start screensaver after 20 minutes of idle time";
                    defaults write "$file" idleTime -int "$target_value"

                    add_processes_to_kill_list Dock cfprefsd
                
                else
                    echo "screensaver already starts after 20 minutes or less of idle time"
                fi
                ;;
            "soho")
                if [ "$setting_value" -gt "$target_value" ] || [ "$setting_value" -eq 0 ]; then
                    echo "setting start screensaver after 20 minutes of idle time";
                    defaults write "$file" idleTime -int "$target_value"

                    add_processes_to_kill_list Dock cfprefsd

                else
                    echo "screensaver already starts after 20 minutes or less of idle time"
                fi
                ;;
            "sslf")
                if [ "$setting_value" -gt "$target_value" ] || [ "$setting_value" -eq 0 ]; then
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
            chown $owner:$group "$file" #restore original owner/group
        fi
    fi

#NOTE: If the screensaver is set to a value that is not an option through the GUI (never, 
#1, 2, 5, 10, 20, 30, 60 minutes), the value will not stay after the preferences window 
#is opened. It will change automatically to the default value of 20 minutes.

#macOS 10.12
#Requires restart to take effect.
}


######################################################################
CCE_79419_8_password_complex_passwords_alphabetic_char () {
    local doc="CCE_79419_8_password_complex_passwords_alphabetic_char      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="number of alphabetic characters required in passwords"
    local policy_category="policyCategoryPasswordContent"
    local parameter_name="minimumAlphaCharacters"
    local parameter_value="1"
    local policy_content="policyAttributePassword matches \'(.*[A-Za-z].*)\{$parameter_value\}\'"
    local policy_identifier="Contains at least $parameter_value alphabetic char(s)"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists="$($plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null)"
    
    local current_value="$(defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//")"
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are first cleared when running with set flag
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

#macOS 10.12
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79420_6_password_complex_passwords_numeric_char () {
    local doc="CCE_79420_6_password_complex_passwords_numeric_char       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="number of numeric characters required in passwords"
    local policy_category="policyCategoryPasswordContent"
    local parameter_value="1"
    local policy_identifier="Contains at least $parameter_value numeric char(s)"
    local parameter_name="minimumNumericCharacters"
    local policy_content="policyAttributePassword matches \'(.*[0-9].*)\{$parameter_value\}\'"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists="$($plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null)"
    
    local current_value="$(defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//")"
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are first cleared when running with set flag
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

#macOS 10.12
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79421_4_password_complex_passwords_symbolic_char () {
    local doc="CCE_79421_4_password_complex_passwords_symbolic_char       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="number of symbolic characters required in passwords"
    local policy_category="policyCategoryPasswordContent"
    local parameter_value="1"
    local policy_content="policyAttributePassword matches \'(.*[^0-9a-zA-Z].*)\{$parameter_value\}\'"
    local policy_identifier="Contains at least $parameter_value symbolic char(s)"
    local parameter_name="minimumSymbolicCharacters"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists="$($plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null)"
    
    local current_value="$(defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//")"
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are first cleared when running with set flag
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

#macOS 10.12
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79427_1_password_uppercase_and_lowercase () {
    local doc="CCE_79427_1_password_uppercase_and_lowercase       (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="number of upper and lowercase characters required in passwords"
    local policy_category="policyCategoryPasswordContent"
    local parameter_value="1"
    local policy_content="policyAttributePassword matches \'(.*[a-z].*[A-Z].*)|(.*[A-Z].*[a-z].*)\'"
    local policy_identifier="Contains at least 1 upper and 1 lower case char"
    local parameter_name="minimumMixedCaseInstances"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists="$($plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null)"
    
    local current_value="$(defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//")"
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are first cleared when running with set flag
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
    
#macOS 10.12
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79422_2_password_enforce_password_history_restriction () {
    local doc="CCE_79422_2_password_enforce_password_history_restriction       (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"


    local friendly_name="number of remembered passwords"
    local policy_category="policyCategoryPasswordContent"
    local policy_content="none policyAttributePasswordHashes in policyAttributePasswordHistory"
    local parameter_name="policyAttributePasswordHistoryDepth"
    local parameter_value="15"
    local policy_identifier="Last $parameter_value passwords cannot be reused"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists="$($plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null)"
    
    local current_value="$(defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//")"
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are first cleared when running with set flag
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

#macOS 10.12
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79426_3_password_minimum_length () {
    local doc="CCE_79426_3_password_minimum_length       (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="minimum password length"
    local policy_category="policyCategoryPasswordContent"
    local parameter_value="12"
    local policy_content="policyAttributePassword matches \'(.){$parameter_value,}\'"
    local policy_identifier="Contains at least $parameter_value characters"
    local parameter_name="minimumChars"
    
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists="$($plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null)"
    
    local current_value="$(defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//")"
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value"
        fi
    fi

    #global policies are first cleared when running with set flag
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


#macOS 10.12
#Works using new pwpolicy commands with loading a plist file for global policies.
}


######################################################################
CCE_79425_5_password_maximum_age () {
    local doc="CCE_79425_5_password_maximum_age       (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="maximum password age"
    local timeUnit="days"
    local policy_category="policyCategoryPasswordChange"
    local parameter_value="60"
    local policy_content="policyAttributeCurrentTime > policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)"
    local policy_identifier="Password expires every $parameter_value days"
    local parameter_name="policyAttributeExpiresEveryNDays"
    
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists="$($plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null)"
    
    local current_value="$(defaults read "$temp_file" 2> /dev/null | egrep "^( *$parameter_name)" |  sed -E "s/ *$parameter_name *= *//" | sed "s/;//")"
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value $timeUnit"
        fi
    fi

    #global policies are first cleared when running with set flag
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

#macOS 10.12
#User is forced to change their password after the specified period.
}


password_guessable_pattern_helper () {
    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local policy_category="policyCategoryPasswordContent"
    local policy_content="policyAttributeConsecutiveCharacters < policyAttributeMaximumConsecutiveCharacters"
    local parameter_value="3"
    local policy_identifier="Contains less than $parameter_value consecutive chars"
    local parameter_name="policyAttributeMaximumConsecutiveCharacters"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists="$($plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null)"
    
    #this policy has two requirements, so check both values
    local current_value="$(defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//")"
    

    #global policies are first cleared when running with set flag
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
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
                ;;
        esac
        
        pwpolicy -setaccountpolicies "$temp_file" &> /dev/null
    fi    

    #Rules must be added to the policy one-by-one, and using the proper array index. If
    #it is not incremented after each rule, the rules will overwrite one another.
    pw_content_index=$(( pw_content_index + 1 ))

    #remove temp file created here
    rm "$temp_file"

#called by CCE_79424_8_password_guessable_pattern
}


######################################################################
CCE_79424_8_password_guessable_pattern () {
    local doc="CCE_79424_8_password_guessable_pattern      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="no guessable patterns in passwords"
    local policy_category="policyCategoryPasswordContent"
    local policy_content="policyAttributeSequentialCharacters < policyAttributeMaximumSequentialCharacters"
    local parameter_value="3"
    local policy_identifier="Contains less than $parameter_value sequential chars"
    local parameter_name="policyAttributeMaximumSequentialCharacters"
    
    #parameter2 is set in helper function; this is used for printing only
    local parameter_name2="policyAttributeMaximumConsecutiveCharacters"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists="$($plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null)"
    
    #this policy has two requirements, so check both values
    local current_value="$(defaults read "$temp_file" 2> /dev/null | grep "$parameter_name" | sed -E "s/ *$parameter_name *= *//" | sed "s/;//")"
    
    #current_value2 is set in helper function; this is used for printing only
    local current_value2="$(defaults read "$temp_file" 2> /dev/null | grep "$parameter_name2" | sed -E "s/ *$parameter_name2 *= *//" | sed "s/;//")"
    
    
    
    if [ "$print_flag" != "" ]; then
        if [ "$current_value" == "" ] || [ "$current_value2" == "" ]; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to enabled"
        fi
    fi

    #global policies are first cleared when running with set flag
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "setting $friendly_name to enabled"
                
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
                echo "setting $friendly_name to enabled"
                
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
                echo "setting $friendly_name to enabled"
                
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
    
    #call helper function, since two paramaters are needed for this setting
    password_guessable_pattern_helper
    

#macOS 10.12
#Works with all tested patterns, such as "aaa", "123.aaaa", "1234.aaa", "121".
}



######################################################################
CCE_79423_0_password_failed_login_lockout_policy () {
    local doc="CCE_79423_0_password_failed_login_lockout_policy      (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    #store the curent policy in a temp file
    local temp_file="${script_dir}/samc_current_pwpolicy.plist"
    pwpolicy -getaccountpolicies | tail -n +2 > "$temp_file"

    local friendly_name="failed logins lock accounts"
    local time_unit="minutes"
    local policy_category="policyCategoryAuthentication"
    local policy_content="(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > policyAttributeLastFailedAuthenticationTime + lockoutDuration * 60)"
    local parameter_name="lockoutDuration"
    local parameter_value="15"
    local parameter_name2="policyAttributeMaximumFailedAuthentications"
    local parameter_value2="3"
    local policy_identifier="$parameter_value2 failed login attempts lock user accounts for $parameter_value $time_unit"
    
    local plistbuddy="/usr/libexec/PlistBuddy"
    local category_exists="$($plistbuddy -c "Print :$policy_category" "$temp_file" 2> /dev/null | egrep -c "." 2> /dev/null)"
    
    local current_value="$(defaults read "$temp_file" 2> /dev/null | egrep "^( *$parameter_name)" |  sed -E "s/ *$parameter_name *= *//" | sed "s/;//")"

    local current_value2="$(defaults read "$temp_file" 2> /dev/null | egrep "^( *$parameter_name2)" |  sed -E "s/ *$parameter_name2 *= *//" | sed "s/;//")"
    


    if [ "$print_flag" != "" ]; then

        if [ "$current_value" == "" ] || [ "$current_value2" == "" ] ; then
            echo "policy does not exist for $friendly_name"
        else
            echo "$friendly_name is set to $current_value2 failed attempts cause $current_value $time_unit lockout"
        fi
    fi

    #global policies are first cleared when running with set flag
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "setting $friendly_name to $parameter_value2 failed attempts cause $parameter_value $time_unit lockout"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyParameters:$parameter_name2 integer $parameter_value2" "$temp_file"
                ;;
            "soho")
                echo "setting $friendly_name to $parameter_value2 failed attempts cause $parameter_value $time_unit lockout"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyParameters:$parameter_name2 integer $parameter_value2" "$temp_file"
                ;;
            "sslf")
                echo "setting $friendly_name to $parameter_value2 failed attempts cause $parameter_value $time_unit lockout"
                
                #main array - create if it doesn't exist
                if [ "$category_exists" == "0" ]; then
                    $plistbuddy -c "Add :$policy_category array" "$temp_file"
                fi
                
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyContent string $policy_content" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyIdentifier string $policy_identifier" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyParameters dict" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyParameters:$parameter_name integer $parameter_value" "$temp_file"
                $plistbuddy -c "Add :$policy_category:$pw_auth_index:policyParameters:$parameter_name2 integer $parameter_value2" "$temp_file"
                ;;
            "oem")
                echo "Resetting global policies to default (none)"
                ;;
        esac
        
        pwpolicy -setaccountpolicies "$temp_file" &> /dev/null
    fi    

    pw_auth_index=$(( pw_auth_index + 1 ))

    #remove temp file created here
    rm "$temp_file"

#macOS 10.12 testing
#Takes effect immediately. This was tested by failing to login to a user account until
#the account was locked, and timed the duration before the account was active again.
}


######################################################################
CCE_79428_9_require_admin_password_for_system_prefs () {
    local doc="CCE_79428_9_require_admin_password_for_system_prefs    (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local script_dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
    
    
    local setting_value="" #by default on 10.12 password is not required
    local temp_file="${script_dir}/tmpsysprefs.plist"
    local db_table="system.preferences"
    local friendly_name="admin password required for system preferences"
    
    # get the contents of the table containing the shared key
    security authorizationdb read "$db_table" > "$temp_file" 2> /dev/null
    
    # get the value of the shared key
    setting_value="$(defaults read "$temp_file" shared)"
    
    if [ "$print_flag" != "" ]; then
        # if shared is true, settings can be accessed by all users because
        # no password is required
        if [ "$setting_value" == "false" ] || [ "$setting_value" == "0" ]; then
            echo "$friendly_name is enabled.";

        else
            echo "$friendly_name is disabled.";
        fi
    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$setting_value" == "true" ] || [ "$setting_value" == "1" ]; then
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
                if [ "$setting_value" == "true" ] || [ "$setting_value" == "1" ]; then
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
                if [ "$setting_value" == "true" ] || [ "$setting_value" == "1" ]; then
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
                if [ "$setting_value" == "false" ] || [ "$setting_value" == "0" ]; then
                    echo "disabling $friendly_name";
                
                    # write the new value to the temp plist and then write the plist
                    # to the system.preferences table
                    defaults write "$temp_file" shared -bool true
                    security authorizationdb write "$db_table" < "$temp_file" 2> /dev/null
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac
    fi

    rm -f "$temp_file"


#10.12 testing
#Works without restart. Tested using the "Sharing" pane in System Preferences.
}


######################################################################
CCE_79404_0_all_files_in_a_users_home_dir_are_owned_by_that_user () {
    local doc="CCE_79404_0_all_files_in_a_users_home_dir_are_owned_by_that_user   (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    #since this can be a lengthy operation, only search if running in print or set mode
    if [ "$print_flag" != "" ] || [ "$set_flag" != "" ]; then
        local file_list="$(find $home_path ! -user $owner -print)"
        local file_count="$(echo "$file_list" | grep -c "^/")"
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$v_flag" == "" ]; then
            echo "number of files in $owner's home directory with wrong owner: $file_count";
        else
            while read -r file; do
                echo "$file is not owned by $owner";
            done <<< "$file_list"

            if [ "$file_count" == "0" ]; then
                echo "all files in $owner's home directory belong to $owner";
            fi
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
    case $profile_flag in
        "ent")
            if [ "$file_list" != "" ]; then
                while read -r file; do
                    if [ "$v_flag" != "" ]; then
                        echo "changing owner of $file to $owner";
                    fi
                    chown "$owner" "$file"
                done <<< "$file_list"
            fi
            echo "$file_count files have had the owner changed";
            ;;
        "soho")
            # do not change ownership
            echo "file ownership is unchanged";
            ;;
        "sslf")
             if [ "$file_list" != "" ]; then
                while read -r file; do
                    if [ "$v_flag" != "" ]; then
                        echo "changing owner of $file to $owner";
                    fi
                    chown "$owner" "$file"
                done <<< "$file_list"
            fi
            echo "$file_count files have had the owner changed";
            ;;
        "oem")
            # do not change ownership
            echo "file ownership is unchanged";
            ;;
    esac
    fi


# macOS 10.12
# Verified changed ownership in home directory and all subdirectories
}


######################################################################
CCE_79407_3_files_in_home_dir_group_owned_by_owners_group () {
    local doc="CCE_79407_3_files_in_home_dir_group_owned_by_owners_group      (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    #since these can be lengthy operations, only search if running in print or set mode
    if [ "$print_flag" != "" ] || [ "$set_flag" != "" ]; then
    
        # gets all groups the specified user is part of
        local groups=`groups $owner`

        # format groups output for use by find
        local groups_cmd="$(echo "$groups" | sed 's/ / -a ! -group /g')"

        local file_list="$(find $home_path ! -group $groups_cmd -print)"
        local file_count="$(echo "$file_list" | grep -c "^/")"

    fi


    if [ "$print_flag" != "" ]; then
        if [ "$v_flag" == "" ]; then
            echo "number of files in $owner's home directory with wrong group: $file_count";
        else
            if [ "$file_count" == "0" ]; then
                echo "all files in $owner's home directory belong to an appropriate group";
            else
                while read -r file; do
                    echo "$file does not belong to one of $owner's groups";
                done <<< "$file_list"
            fi
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "$file_list" != "" ]; then
                    while read -r file; do
                        if [ "$v_flag" != "" ]; then
                            echo "changing group of $file to $group";
                        fi
                        chgrp "$group" "$file"
                    done <<< "$file_list"
                fi
                echo "$file_count files have had the group changed";
                ;;
            "soho")
                # do not change group ownership
                echo "home folders group ownership unchanged";
                ;;
            "sslf")
                if [ "$file_list" != "" ]; then
                    while read -r file; do
                        if [ "$v_flag" != "" ]; then
                            echo "changing group of $file to $group";
                        fi
                        chgrp "$group" "$file"
                    done <<< "$file_list"
                fi
                echo "$file_count files have had the group changed";
                ;;
            "oem")
                # do not change group ownership
                echo "home folders group ownership unchanged";
            ;;
        esac
    fi


# Testing macOS 10.12
# Verified changed group ownership in home directory and all subdirectories
}


######################################################################
CCE_79433_9_use_network_time_protocol () {
    local doc="CCE_79433_9_use_network_time_protocol      (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local setting_name=networktimeserver
    local setting2_name=usingnetworktime #used to enable automatic time syncing
    local friendly_name="use network time protocol for system time"
    local required_value="time.nist.gov" #varies by organization

    if [ "$print_flag" != "" ]; then
        systemsetup -get$setting2_name
        systemsetup -get$setting_name
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                echo "enabling $friendly_name";
                systemsetup -set$setting_name $required_value > /dev/null
                systemsetup -set$setting2_name on > /dev/null
                ;;
            "soho")
                echo "enabling $friendly_name";
                systemsetup -set$setting_name $required_value > /dev/null
                systemsetup -set$setting2_name on > /dev/null
                ;;
            "sslf")
                echo "enabling $friendly_name";
                systemsetup -set$setting_name $required_value > /dev/null
                systemsetup -set$setting2_name on > /dev/null
                ;;
            "oem")
                echo "enabling $friendly_name";
                systemsetup -set$setting_name $required_value > /dev/null
                systemsetup -set$setting2_name on > /dev/null
                ;;
        esac
    fi

# Testing macOS 10.12
# Manually tested and works as expected.
# Setting the value took effect immediately.
}


#If the power management files don't exist, write a default value to create them.
#This allows the system's power management capabilities to be reported.
power_management_helper() {

    if [ ! -e "/Library/Preferences/com.apple.PowerManagement.plist" ]; then
        pmset -a disksleep 11
        pmset -a disksleep 10 #10.12 default value
    fi
    
    if [ ! -e "/Library/Preferences/com.apple.PowerManagement.$hw_uuid.plist" ]; then
        pmset -a ttyskeepawake 0
        pmset -a ttyskeepawake 1 #10.12 default value
    fi

#macOS 10.12
#The power management config file used to be /Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist" and is now /Library/Preferences/com.apple.PowerManagement.plist."
}


######################################################################
CCE_79438_8_display_file_extensions () {
    local doc="CCE_79438_8_display_file_extensions               (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/.GlobalPreferences.plist
    local setting_name=AppleShowAllExtensions
    local friendly_name="show all file extensions"
    local value=0

    if [ -e "$file" ]; then
        local exists="$(defaults read "$file" | grep -c $setting_name)"
        #if key not present, it has default value
        if [ "$exists" != "0" ]; then
            value="$(defaults read "$file" $setting_name)"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$value" != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$value" != "1" ]; then
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
                if [ "$value" != "1" ]; then
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
                if [ "$value" != "1" ]; then
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
                if [ "$value" != "0" ]; then
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

#Note: The "All My Files" shortcut in Finder ignores the setting and hides extensions
#on a per file basis. Files may have their extensions shown/hidden on an individual
#basis. See this reference for more information:
#https://support.apple.com/kb/PH25381?viewlocale=en_US&locale=en_US

# Testing - macOS 10.12
# Successfully takes effect immediately.
}


######################################################################
CCE_79441_2_show_hidden_files () {
    local doc="CCE_79441_2_show_hidden_files               (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/com.apple.finder.plist
    local setting_name=AppleShowAllFiles
    local friendly_name="show hidden files"
    local value=0 #default value on 10.12

    if [ -e "$file" ]; then
        local exists="$(defaults read $file | grep -c $setting_name)"
        #if key not present, it has default value
        if [ "$exists" != "0" ]; then
            value="$(defaults read $file $setting_name)"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$value" != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled";
        fi
    fi

    if [ "$set_flag" != "" ]; then
        #only change values that aren't already set for that profile
        case $profile_flag in
            "ent")
                echo "$friendly_name is unchanged"
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
                if [ "$value" != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                    add_processes_to_kill_list Finder cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ "$value" != "0" ]; then
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


#macOS 10.12
#The setting takes effect immediately.
}


######################################################################
CCE_79439_6_dock_enable_autohide () {
    local doc="CCE_79439_6_dock_enable_autohide         (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/com.apple.dock.plist"

    local setting_name=autohide
    local friendly_name="dock autohide"
    local value="0" #default value on 10.12

    if [ -e "$file" ]; then
        local exists="$(defaults read "$file" | grep -c $setting_name)"
        #if key not present, it has default value
        if [ "$exists" != "0" ]; then
            value="$(defaults read "$file" $setting_name)"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$value" != "1" ]; then
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
                if [ "$value" != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool true
                
                    add_processes_to_kill_list Dock cfprefsd
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                if [ "$value" != "0" ]; then
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

#macOS 10.12
#Must kill cfprefsd for setting to take effect. If not terminating the Dock process,
#it will apply after restart.
}


######################################################################
CCE_79496_6_ssh_login_grace_period () {
    local doc="CCE_79496_6_ssh_login_grace_period               (manual-test-PASSED)"
    local file="/etc/ssh/sshd_config"
    local setting_name="LoginGraceTime"
    local friendly_name="SSH login grace time"
    local current_string=""
    local file_contents="$(cat "$file" 2> /dev/null)"
    local new_file_contents=""
    local current_value=""

    local oem_value="2m" # confirmed value on 10.12 through testing
    local oem_string="#$setting_name $oem_value"

    local required_value="30"
    local required_string="$setting_name $required_value"

    if [ -e "$file" ]; then
        current_string="$(echo "$file_contents" | grep "$setting_name")"
        if [ "$(echo "$current_string" | grep -c "^#")" -gt 0 ]; then
            current_value=""
        else
            current_value="$(echo "$current_string" | sed -E "s/^$setting_name //")"
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        #no value indicates oem value
        if [ "$current_value" == "" ]; then
            echo "$friendly_name is $oem_value"
        else
            #if time is expressed in minutes
            if [ "$(echo "$current_value" | grep -c "m$")" -gt 0 ]; then
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
                        new_file_contents="$(echo "$file_contents" | sed -E "s/^#?LoginGraceTime .+/$required_string/")"

                        echo "$new_file_contents" > "$file"
                    # otherwise, append
                    else
                        echo "$required_string" >> "$file"
                    fi

                else
                    #if time is expressed in minutes
                    if [ "$(echo "$required_value" | grep -c "m$")" -gt 0 ]; then
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
                        new_file_contents="$(echo "$file_contents" | sed -E "s/^#?LoginGraceTime .+/$required_string/")"

                        echo "$new_file_contents" > "$file"
                    # otherwise, append
                    else
                        echo "$required_string" >> "$file"
                    fi

                else
                    #if time is expressed in minutes
                    if [ "$(echo "$required_value" | grep -c "m$")" -gt 0 ]; then
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
                        new_file_contents="$(echo "$file_contents" | sed -E "s/^#?LoginGraceTime .+/$required_string/")"

                        echo "$new_file_contents" > "$file"
                    # otherwise, append
                    else
                        echo "$required_string" >> "$file"
                    fi

                else
                    #if time is expressed in minutes
                    if [ "$(echo "$required_value" | grep -c "m$")" -gt 0 ]; then
                        echo "$friendly_name is already set to $required_value";
                    else
                        echo "$friendly_name is already set to $required_value seconds";
                    fi
                fi
                ;;
            "oem")
                if [ "$current_string" != "$oem_string" ] && [ "$current_string" != "" ]; then
                    echo "setting $friendly_name to $oem_value"
                    if [ "$current_string" != "" ]; then
                        new_file_contents="$(echo "$file_contents" | sed -E "s/^#?LoginGraceTime .+/$oem_string/")"
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

# macOS 10.12 Testing
# Setting applies immediately without restart.
}


######################################################################
CCE_79498_2_ssh_remove_non_fips_140_2_ciphers () {
    local doc="CCE_79498_2_ssh_remove_non_fips_140_2_ciphers        (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="/etc/ssh/sshd_config"
    local setting_name="Ciphers"
    local friendly_name="FIPS 140-2 compliant SSH ciphers"
    
    #10.12 Confirmed defaults
    local oem_value="chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"


    local required_value="Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc"
    local current_string=""
    local current_value="" #holds a list of ciphers separated by commas
    local file_contents="$(sed 's/^ciphers/Ciphers/' $file)" #normalize case
    local new_file_contents=""

    if [ -e "$file" ]; then
        current_string="$(echo "$file_contents" | grep -i "^$setting_name")"
        current_value="$(echo "$current_string" | sed -E "s/$setting_name //")"

        #if the key Ciphers is not present, oem values are used
        if [ "$current_string" == "" ]; then
            current_value="$oem_value"
        fi
    fi


    if [ "$print_flag" != "" ]; then
        if [ "$current_string" == "$required_value" ]; then
            echo "the ciphers in use match $friendly_name"
        else
            echo "not all ciphers in use match $friendly_name"
            if [ "$v_flag" != "" ]; then
                echo "ciphers currently present in $file are: $current_value"
            fi
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_string" == "$required_value" ]; then
                    echo "only $friendly_name are present" 
                else
                    echo "removing non-$friendly_name and adding allowed ciphers"
                    if [ "$current_string" != "" ]; then
                        #replace list of ciphers
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$required_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of ciphers
                        echo "$required_value" >> $file
                    fi
                fi
                ;;
            "soho")
                if [ "$current_string" == "$required_value" ]; then
                    echo "only $friendly_name are present" 
                else
                    echo "removing non-$friendly_name and adding allowed ciphers"
                    if [ "$current_string" != "" ]; then
                        #replace list of ciphers
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$required_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of ciphers
                        echo "$required_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_string" == "$required_value" ]; then
                    echo "only $friendly_name are present" 
                else
                    echo "removing non-$friendly_name and adding allowed ciphers"
                    if [ "$current_string" != "" ]; then
                        #replace list of ciphers
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$required_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #append list of ciphers
                        echo "$required_value" >> $file
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

# Testing Process
# Verified accepted sshd ciphers by using ssh with -c option to specify a cipher.
# Query available client ciphers by using the command `ssh -Q cipher`

# Supported ciphers:
# 3des-cbc,blowfish-cbc,cast128-cbc,arcfour,arcfour128,arcfour256,aes128-cbc,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com

# macOS 10.12 Testing
# When specifying an accepted cipher, the ssh connection was successful; otherwise, it
# was terminated. The change in acceptable ciphers took effect immediately.
}


######################################################################
CCE_79499_0_ssh_remove_non_fips_140_2_macs () {
    local doc="CCE_79499_0_ssh_remove_non_fips_140_2_macs           (manual-test-indeterminate)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="/etc/ssh/sshd_config"
    local setting_name="MACs"
    local friendly_name="non FIPS 140-2 SSH MACs"

    #confirmed default on 10.12
    local oem_value="umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"

    local current_string=""
    local current_value="" #holds a list of MACs separated by commas
    local file_contents="$(cat $file 2> /dev/null | sed 's/^macs/MACs/')" #normalize case
    local new_file_contents=""
    local allowed_macs="hmac-sha1,hmac-sha2-256,hmac-sha2-512"


    if [ -e "$file" ]; then
        current_string="$(echo "$file_contents" | grep -i "^$setting_name")"
        current_value="$(echo "$current_string" | sed -E "s/$setting_name //")"

        #if the key MACs is not present oem values are used
        if [ "$current_string" == "" ]; then
            current_value="$oem_value"
        fi
    fi

    # create a list of existing MACs, with one per line
    local macs_list=`echo "$current_value" | sed -E 's/, ?/\\
/g'`
    # separate MACs into lists based on FIPS compliance
    local bad_macs=`echo "$macs_list" | egrep -xv "(hmac-sha2-256)|(hmac-sha2-512)|(hmac-sha1)"`
    local good_macs=`echo "$macs_list" | egrep -x "(hmac-sha2-256)|(hmac-sha2-512)|(hmac-sha1)"`

    #no valid MACs were found, so set to the allowed MACs
    if [ "$good_macs" == "" ]; then
        good_macs="$allowed_macs"
    fi

    #format for sshd_config file
    good_macs=`echo $good_macs | sed 's/ /,/g'`


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
                    #remove list of MACs from file
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

# Testing Process
# Verified accepted sshd MACs by using ssh with -m option to specify a MAC. Query available 
# client MACs by using the command `ssh -Q mac`

# Supported MACs:
# hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96,hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,umac-128@openssh.com

#macOS 10.12 testing
#Effectiveness of setting MACs could not be confirmed. SSH could connect using MACs not
#listed in the /etc/ssh/sshd_config file when a specific list was present. However,
#if the MACs key existed in the config file with no values, an SSH session could not be
#established.
}


######################################################################
CCE_79492_5_ssh_challenge_response_authentication_disallowed () {
    local doc="CCE_79492_5_ssh_challenge_response_authentication_disallowed           (manual-test-PASSED)"
    local file="/etc/ssh/sshd_config"
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

        # do not allow comments for current_value because they do not affect the setting;
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

#Note: In order to see the effectiveness of this setting, change the 
#"PasswordAuthentication" entry to yes

#macOS 10.12 testing
#The setting change applied immediately. This setting disables login using
#a password through PAM. PAM's password authentication mechanism takes precedence
#over sshd's password authentication; if both are enabled, PAM is used.
}


######################################################################
CCE_79493_3_ssh_disable_pub_key_authentication () {
    local doc="CCE_79493_3_ssh_disable_pub_key_authentication   (manual-test-PASSED)"
    local file="/etc/ssh/sshd_config"
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

        # do not allow comments for current_value because they do not affect the setting;
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

#macOS 10.12 testing
#The setting applies immediately. If enabled, takes precedence over other authentication
#means.
}


######################################################################
CCE_79500_5_ssh_restrict_users () {
    local doc="CCE_79500_5_ssh_restrict_users                    (manual-test-PASSED)"
    local file="/etc/ssh/sshd_config"
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

        # do not allow comments for current_value because they do not affect the setting;
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

#Notes: When using AllowUser, all users on the allowed list were properly
#permitted to connect, and users not specified were properly denied access.

#macOS 10.12 testing
#The setting takes effect immediately; all users are denied SSH access.
}

######################################################################
CCE_79501_3_ssh_set_client_timeout () {
    local doc="CCE_79501_3_ssh_set_client_timeout        (manual-test-PASSED)"
    local file="/etc/ssh/sshd_config"
    local setting_name="ClientAliveInterval"
    local friendly_name="SSH client alive interval"
    local file_contents=`cat $file 2> /dev/null`

    #profile values - actual values may be less than these specified values (more strict)
    local ent_value="900"
    local soho_value="900"
    local sslf_value="900"
    local oem_value="0" #Confirmed default value on 10.12

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not affect the setting;
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


#Testing methodology:
#Initiated an SSH connection to the VM, then disabled the VM's network connection.
#Used `netstat -f inet` to watch the ssh connection's Send-Q increase in size each
#interval of ClientAliveInterval seconds.
#As an example, if the setting is set to 900 (seconds), the Send-Q will increment after
#15 minutes. Then, after about a minute of not recieving a response, the connection
#will be terminated. Even if the VM's network connection is re-enabled before issuing
#commands on the client computer, the connection is still terminated after approximately
#16 minutes.

#macOS 10.12 testing
#Setting took effect immediately. After ClientAliveInterval, the connection shown by
#`netstat -f inet` was terminated.

#Note that setting an interval less than 60? seconds may not function as expected.
}


######################################################################
CCE_79497_4_ssh_max_auth_tries_4_or_less () {
    local doc="CCE_79497_4_ssh_max_auth_tries_4_or_less        (manual-test-PASSED)"
    local file="/etc/ssh/sshd_config"
    local setting_name="MaxAuthTries"
    local friendly_name="SSH authentication attempts limit"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="4"
    local soho_value="4"
    local sslf_value="4"
    local oem_value="6" #Confirmed from testing on 10.12

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not affect the setting;
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
# the client's NumberOfPasswordPrompts (ssh config file: /etc/ssh/ssh_config).

# macOS 10.12 testing
# Setting applied immediately.
}


######################################################################
CCE_79476_8_disable_location_services () {
    local doc="CCE_79476_8_disable_location_services      (manual-test-PASSED)"
    local defaults_file="/private/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.$hw_uuid.plist"
    local daemon_file="/System/Library/LaunchDaemons/com.apple.locationd.plist"
    local process_name="locationd"

    local friendly_name="location services"
    local setting_name="LocationServicesEnabled"
    local setting_value="0"
    local key_exists="0"

    if [ -e $defaults_file ]; then
        key_exists=`defaults read $defaults_file | grep "$setting_name" | wc -l`
        if [ "$key_exists" == "1" ]; then
            setting_value=`defaults read $defaults_file $setting_name`
        fi
    fi

    local process_running=`ps -ax | fgrep "$process_name" | fgrep -v "fgrep" -c`

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then

        if [ $setting_value == "1" ]; then
            echo "$friendly_name is enabled";
        else
            echo "$friendly_name is disabled";
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

        # only disable the setting if it is not already disabled
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
                    defaults write $defaults_file $setting_name -bool false
                
                    if [ "$process_running" -gt 0 ]; then
                        #prevents the locationd service from restarting
                        launchctl bootout system/com.apple.locationd 2> /dev/null
                        if [ "$v_flag" != "" ]; then
                            echo "stopping the $friendly_name process $process_name"
                        fi
                    fi
                elif [ "$process_running" -gt 0 ]; then
                    echo "$friendly_name is already disabled; stopping the $process_name process";
                    #prevents the locationd service from restarting
                    launchctl bootout system/com.apple.locationd 2> /dev/null
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ $setting_value != 0 ]; then
                    echo "disabling $friendly_name";
                    defaults write $defaults_file $setting_name -bool false
                
                    if [ "$process_running" -ne 1 ]; then
                        #restarts the locationd process, since it runs by default
                        launchctl bootstrap system/ $daemon_file
                        if [ "$v_flag" != "" ]; then
                            echo "starting the $friendly_name process $process_name"
                        fi
                    fi
                elif [ "$process_running" -ne 1 ]; then
                    echo "$friendly_name is already disabled; starting the $process_name process";
                    #restarts the locationd process, since it runs by default
                    launchctl bootstrap system/ $daemon_file
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


#macOS 10.12
#The launchctl command is necessary to prevent the "locationd" process from immediately 
#restarting. This also prevents the location services setting from being toggled in
#the GUI. To allow location services to be re-enabled using the GUI, run the command 
#`launchctl bootstrap system/ /System/Library/LaunchDaemons/com.apple.locationd.plist`
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
    # action 107 = "Open Photos"
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
        echo "$friendly_name is set to \"Open Photos\"";
    elif [ $setting_value == "109" ]; then
        echo "$friendly_name is set to \"Open Front Row\"";
    # if the key doesn't exist or is 2, the setting is "Ask what to do"
    else
        echo "$friendly_name is set to \"Ask what to do\"";
    fi
}


######################################################################
CCE_79471_9_disable_auto_actions_on_blank_CD_insertion () {
    local doc="CCE_79471_9_disable_auto_actions_on_blank_CD_insertion     (manual-test-indeterminate)"
    local file="$home_path/Library/Preferences/com.apple.digihub.plist"

    local setting_name="action"
    local dictionary_name="com.apple.digihub.blank.cd.appeared"

    local friendly_name="blank CD insertion action"
    local setting_value="2" # default value is "Ask what to do" confirmed on 10.12
    local required_value="1"
    local friendly_string="\"Ignore\""

    if [ -e $file ]; then
        local dict_exists=`defaults read $file | grep -c "$dictionary_name"`

        if [ $dict_exists == 1 ]; then
            local key_exists=`defaults read $file $dictionary_name | grep -c "$setting_name"`
            if [ "$key_exists" == 1 ]; then
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

#macOS 10.12
#Value was changed in the file and in the GUI, but its effectiveness could not be
#confirmed.
}


######################################################################
CCE_79472_7_disable_auto_actions_on_blank_DVD_insertion () {
    local doc="CCE_79472_7_disable_auto_actions_on_blank_DVD_insertion     (manual-test-indeterminate)"
    local file="$home_path/Library/Preferences/com.apple.digihub.plist"

    local setting_name="action"
    local dictionary_name="com.apple.digihub.blank.dvd.appeared"

    local friendly_name="blank DVD insertion action"
    local setting_value="2" # default value is "Ask what to do" confirmed on 10.12
    local required_value="1"
    local friendly_string="\"Ignore\""

    if [ -e $file ]; then
        local dict_exists=`defaults read $file | grep -c "$dictionary_name"`

        if [ $dict_exists == 1 ]; then
            local key_exists=`defaults read $file $dictionary_name | grep -c "$setting_name"`
            if [ "$key_exists" == 1 ]; then
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


#macOS 10.12
#Value was changed in the file and in the GUI, but its effectiveness could not be
#confirmed.
}


######################################################################
CCE_79473_5_disable_auto_music_CD_play () {
    local doc="CCE_79473_5_disable_auto_music_CD_play        (manual-test-indeterminate)"

    local file="$home_path/Library/Preferences/com.apple.digihub.plist"

    local setting_name="action"
    local dictionary_name="com.apple.digihub.cd.music.appeared"

    local friendly_name="music CD insertion action"
    local setting_value="101" # default value is "Open iTunes" confirmed on 10.12
    local required_value="1"
    local friendly_string="\"Ignore\""


    if [ -e $file ]; then
        local dict_exists=`defaults read $file | grep -c "$dictionary_name"`

        if [ $dict_exists == 1 ]; then
            local key_exists=`defaults read $file $dictionary_name | grep -c "$setting_name"`
            if [ "$key_exists" == 1 ]; then
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


#macOS 10.12
#Value was changed in the file and in the GUI, but its effectiveness could not be
#confirmed.
}


######################################################################
CCE_79474_3_disable_auto_picture_CD_display () {
    local doc="CCE_79474_3_disable_auto_picture_CD_display        (manual-test-indeterminate)"

    local file="$home_path/Library/Preferences/com.apple.digihub.plist"

    local setting_name="action"
    local dictionary_name="com.apple.digihub.cd.picture.appeared"

    local friendly_name="picture CD insertion action"
    local setting_value="107" # default value is "Photos" confirmed on 10.12
    local required_value="1"
    local friendly_string="\"Ignore\""

    if [ -e $file ]; then
        local dict_exists=`defaults read $file | grep -c "$dictionary_name"`

        if [ $dict_exists == 1 ]; then
            local key_exists=`defaults read $file $dictionary_name | grep -c "$setting_name"`
            if [ "$key_exists" == 1 ]; then
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


#macOS 10.12
#Value was changed in the file and in the GUI, but its effectiveness could not be
#confirmed.
}


######################################################################
CCE_79475_0_disable_auto_video_DVD_play () {
    local doc="CCE_79475_0_disable_auto_video_DVD_play        (manual-test-indeterminate)"
    local file="$home_path/Library/Preferences/com.apple.digihub.plist"

    local setting_name="action"
    local dictionary_name="com.apple.digihub.dvd.video.appeared"

    local friendly_name="video DVD insertion action"
    local setting_value="105" # default value is "Open DVD Player" on 10.12
    local required_value="1"
    local friendly_string="\"Ignore\""

    if [ -e $file ]; then
        local dict_exists=`defaults read $file | grep -c "$dictionary_name"`

        if [ $dict_exists == 1 ]; then
            local key_exists=`defaults read $file $dictionary_name | grep -c "$setting_name"`
            if [ "$key_exists" == 1 ]; then
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

#macOS 10.12
#Value was changed in the file and in the GUI, but its effectiveness could not be
#confirmed.
}


######################################################################
CCE_79445_3_enable_firewall_logging_detail_level () {
    local doc="CCE_79445_3_enable_firewall_logging_detail_level         (manual-test-PASSED)"

    local setting_name="--setloggingopt"
    local command_name="/usr/libexec/ApplicationFirewall/socketfilterfw"

    local friendly_name="firewall logging level"
    local oem_value="throttled" #Confirmed as default value on 10.12
    local setting_value=`$command_name --getloggingopt | egrep -o "(detail|brief|throttled)"`
    local required_value="detail"


    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        echo "$friendly_name is $setting_value"
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "soho")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "sslf")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "oem")
                if [ $setting_value != "$oem_value" ]; then
                    echo "turning $friendly_name $oem_value";
                    "$command_name" "$setting_name" "$oem_value" > /dev/null
                else
                    echo "$friendly_name is already $oem_value"
                fi
                ;;
        esac
    fi


#macOS !0.12
#Both /var/log/alf.log and /var/log/appfirewall.log exist by default, but the new
#logging system does not use these files. The new Unified Logging system uses the
#command `log`. 

#10.12 test process:
#`/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingopt detail`
#In Application Firewall GUI, maake sure remote login (SSH) is allowed.
#Connect to target system with SSH.
#View logs with `log show --predicate 'process == "socketfilterfw"' --info --debug --last 1h`
#Note the message with text "socketfilterfw: [com.apple.alf.] <private>"
}


######################################################################
CCE_79494_1_ssh_disable_root_login () {
    local doc="CCE_79494_1_ssh_disable_root_login           (manual-test-PASSED)"
    local file="/etc/ssh/sshd_config"
    local setting_name="PermitRootLogin"
    local friendly_name="SSH permit root login"
    local current_string=""
    local file_contents=`cat $file`
    local new_file_contents=""
    local current_value=""

    local oem_value="prohibit-password" # changed from yes on 10.10 to this on 10.12
    local oem_string="#$setting_name $oem_value"

    local required_value="no"
    local required_string="$setting_name $required_value"

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not affect the setting;
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


# macOS 10.12 testing
# Setting value changes in the file, and root user is properly denied direct login
# through SSH. If the root account is set up, users are still allowed to `su -` to log
# in to the root user after they have logged in with valid credentials.
}


######################################################################
CCE_79444_6_allow_signed_sw_receive_connections () {
    local doc="CCE_79444_6_allow_signed_sw_receive_connections     (manual-test-PASSED)"

    local defaults_file="/Library/Preferences/com.apple.alf.plist"
    local defaults_name="allowsignedenabled"

    local setting_name="--setallowsigned"
    local command_name="/usr/libexec/ApplicationFirewall/socketfilterfw"

    local friendly_name="allow built-in signed software to receive connections"

    # Confirmed as default value; isn't checked off in the GUI when block all incoming
    # connections is checked off. The plist file reports that it is on, however.
    local oem_value="on"

    local setting_value="$oem_value"
    local required_value="on"
    local sslf_value="off"
    local required_defaults_value="1"

    if [ -e $defaults_file ]; then
        local key_exists=`defaults read "$defaults_file" | grep -c "$defaults_name"`
        if [ "$key_exists" == 1 ]; then
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
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "soho")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "sslf")
                if [ $setting_value != "$sslf_value" ]; then
                    echo "setting $friendly_name to $sslf_value";
                    "$command_name" "$setting_name" "$sslf_value" > /dev/null
                else
                    echo "$friendly_name is already $sslf_value"
                fi
                ;;
            "oem")
                if [ $setting_value != "$oem_value" ]; then
                    echo "turning $friendly_name $oem_value";
                    "$command_name" "$setting_name" "$oem_value" > /dev/null
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

#macOS 10.12
#This setting changed from 10.10, and is now 2 different settings. This setting now only
#affects built-in applications. Works immediately.
}


######################################################################
CCE_79443_8_allow_signed_downloaded_sw_receive_connections () {
    local doc="CCE_79443_8_allow_signed_downloaded_sw_receive_connections   (manual-test-PASSED)"

    local defaults_file="/Library/Preferences/com.apple.alf.plist"
    local defaults_name="allowdownloadsignedenabled"

    local setting_name="--setallowsignedapp"
    local command_name="/usr/libexec/ApplicationFirewall/socketfilterfw"

    local friendly_name="allow downloaded signed software to receive connections"

    # Confirmed as default value; isn't checked off in the GUI when block all incoming
    # connections is checked off. The plist file reports that it is on, however.
    local oem_value="on"

    local setting_value="$oem_value"
    local required_value="off"
    local required_defaults_value="1"

    if [ -e $defaults_file ]; then
        local key_exists=`defaults read "$defaults_file" | grep -c "$defaults_name"`
        if [ "$key_exists" == 1 ]; then
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
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "soho")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "sslf")
                if [ $setting_value != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value";
                    "$command_name" "$setting_name" "$required_value" > /dev/null
                else
                    echo "$friendly_name is already $required_value"
                fi
                ;;
            "oem")
                if [ $setting_value != "$oem_value" ]; then
                    echo "turning $friendly_name $oem_value";
                    "$command_name" "$setting_name" "$oem_value" > /dev/null
                else
                    echo "$friendly_name is already $oem_value"
                fi
                ;;
        esac
    fi

#macOS 10.12
#Notes: This setting only affects applications not installed by default on macOS.

#Testing: Ran a program from the App Store that requried incoming connections with this 
#setting turned off. Programs using built-in tools, such as Python, are considered 
#to be built-in programs, and are not affected by this setting.

#Results
#Works without restart.
}

######################################################################
CCE_79470_1_turn_on_firewall () {
    local doc="CCE_79470_1_turn_on_firewall                (manual-test-PASSED)"

    local defaults_file="/Library/Preferences/com.apple.alf.plist"
    local defaults_name="globalstate"

    local lenient_setting_name="--setglobalstate"
    local strict_setting_name="--setblockall"
    local command_name="/usr/libexec/ApplicationFirewall/socketfilterfw"

    local friendly_name="application firewall"
    local oem_value="off" #Confirmed as default on 10.12
    local setting_value="$oem_value"
    local required_value="on"
    local lenient_string="on"
    local strict_string="block all incoming connections"

    if [ -e $defaults_file ]; then
        local key_exists=`defaults read "$defaults_file" | grep -c "$defaults_name"`
        if [ "$key_exists" == 1 ]; then
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
                if [ $defaults_value != "1" ]; then
                    echo "setting $friendly_name to $lenient_string";
                    "$command_name" "$lenient_setting_name" "$required_value" > /dev/null

                else
                    echo "$friendly_name is already set to $lenient_string"
                fi
                ;;
            "soho")
                if [ $defaults_value != "1" ]; then
                    echo "setting $friendly_name to $lenient_string";
                    "$command_name" "$lenient_setting_name" "$required_value" > /dev/null

                else
                    echo "$friendly_name is already set to $lenient_string"
                fi
                ;;
            "sslf")
                if [ $defaults_value != "2" ]; then
                    echo "setting $friendly_name to $strict_string";
                    "$command_name" "$strict_setting_name" "$required_value" > /dev/null

                else
                    echo "$friendly_name is already set to $strict_string"
                fi
                ;;
            "oem")
                if [ $defaults_value != "0" ]; then
                    echo "setting $friendly_name to $oem_value";
                    "$command_name" "$lenient_setting_name" "$oem_value" > /dev/null

                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi


#10.12 testing
#Shows as active in GUI immediately, but not effective until after restart. Killing 
#the socketfilterfw process has no effect.
}
 

######################################################################
CCE_79440_4_enable_safari_status_bar () {
    local doc="CCE_79440_4_enable_safari_status_bar           (manual-test-PASSED)"

    local file="$home_path/Library/Preferences/com.apple.Safari.plist"

    local setting_name="ShowOverlayStatusBar"
    local friendly_name="Safari status bar"
    local value="0" #10.12 confirmed defaults to off

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

#macOS 10.12
#Works immediately without restart.
}


######################################################################
CCE_79508_8_disable_infrared_receiver () {
    local doc="CCE_79508_8_disable_infrared_receiver          (manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.driver.AppleIRController.plist"

    local friendly_name="infrared receiver"
    local setting_name="DeviceEnabled"
    local setting_value="true" #confirmed default on 10.12
    local key_exists="0"

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep -c "$setting_name"`
        if [ "$key_exists" == "1" ]; then
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
        # only disable the setting if it is not already disabled
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

# Testing - macOS 10.12
# This setting applies in the GUI immediately, but requires a restart for the
# actual setting to take effect. May not always require restart.
}


######################################################################
CCE_79412_3_do_not_send_diagnostic_info_to_apple () {
    local doc="CCE_79412_3_do_not_send_diagnostic_info_to_apple        (manual-test-indeterminate)"
    local file="/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"
    local setting_name="AutoSubmit"
    local friendly_name="sending of diagnostic info to Apple"
    local setting_value="0" #confirmed as default on 10.12


    if [ -e "$file" ]; then
        local exists="$(defaults read "$file" | grep -c "setting_name")"
        #if key not present, it has default value
        if [ "$exists" != "0" ]; then
            setting_value="$(defaults read "$file" "setting_name")"
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
        # only disable the setting if it is not already set
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
                if [ "$setting_value" != "1" ]; then
                    echo "enabling $friendly_name";
                    defaults write "$file" $setting_name -bool true
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac
    fi

#macOS 10.12
#Changes immediately in the preferences GUI, but effectiveness not confirmed.
}


######################################################################
CCE_79488_3_restrict_screen_sharing_to_specified_users () {
    local doc="CCE_79488_3_restrict_screen_sharing_to_specified_users   (manual-test-PASSED)"

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
                    killall opendirectoryd #this process does not respond to the -TERM option
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
                    killall opendirectoryd #this process does not respond to the -TERM option
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
                    killall opendirectoryd #this process does not respond to the -TERM option
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
                killall opendirectoryd #this process does not respond to the -TERM option
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

#macOS 10.12
#Works immediately when killing processes.
}


######################################################################
CCE_79502_1_update_apple_software () {
    local doc="CCE_79502_1_update_apple_software                (manual-test-PASSED)"
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

#macOS 10.12 testing
#Successfully applied the required updates.
}


######################################################################
CCE_79495_8_ssh_keep_alive_messages () {
    local doc="CCE_79495_8_ssh_keep_alive_messages             (manual-test-PASSED)"
    local file="/etc/ssh/sshd_config"
    local setting_name="ClientAliveCountMax"
    local friendly_name="SSH client alive count max"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="0"
    local soho_value="0"
    local sslf_value="0"
    local oem_value="3" #Confirmed default value on 10.12

    #default to oem value in case file does not exist
    local oem_string="#$setting_name $oem_value"
    local current_value="$oem_value"
    local current_string=""

    if [ -e "$file" ]; then
        # allow comments for current_string so it can be replaced in the file
        current_string=`echo "$file_contents" | egrep -i "^#?$setting_name"`

        # do not allow comments for current_value because they do not affect the setting;
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

#macOS 10.12
#When this setting (ClientAliveCountMax) is set to 0, SSH connections timeout after
#ClientAliveInterval seconds of idle time.
}


######################################################################
CCE_79432_1_sudo_timeout_period_set_to_0 () {
    local doc="CCE_79432_1_sudo_timeout_period_set_to_0            (manual-test-PASSED)"
    local file="/etc/sudoers"
    local file_contents=`cat "$file" 2> /dev/null`
    local new_file_contents=""

    local friendly_name="sudo timeout period"
    local setting_name="timestamp_timeout="
    local current_value=""
    local current_string=""


    local required_value="0"
    local oem_value="5" #confirmed 10.12

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
                echo "$friendly_name is unchanged"
                ;;
            "soho")
                echo "$friendly_name is unchanged"
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

#macOS 10.12
#Worked immediately without restart.
}


######################################################################
CCE_79413_1_set_audit_control_flags () {
    local doc="CCE_79413_1_set_audit_control_flags    (manual-test-PASSED)"
    local file="/etc/security/audit_control"
    local setting_name="flags"
    local friendly_name="audit control flags"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="lo,ad,-all,fd,fm,^-fa,^-fc,^-cl"
    local soho_value="lo,ad,-all,fd,fm,^-fa,^-fc,^-cl"
    local sslf_value="lo,ad,-all,fd,fm,^-fa,^-fc,^-cl"
    local oem_value="lo,aa" #Confirmed default value on 10.12


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

#Notes:
#auditd cannot be disabled across system restarts due to System Integrity Protection. It 
#can be disabled for the current session using `audit -t`

#macOS 10.12
#Audit flags were successfully changed in /etc/security/audit_control.
}


######################################################################
CCE_79487_5_restrict_remote_management_to_specific_users () {
local doc="CCE_79487_5_restrict_remote_management_to_specific_users    manual-test-PASSED)"
    local file="/Library/Preferences/com.apple.RemoteManagement.plist"
    local file_exists=0
    local setting_value="1"
    local setting_name="ARD_AllLocalUsers"
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
            local key_exists=`defaults read $file | grep -c "$setting_name"`
            if [ "$key_exists" -gt 0 ]; then
                setting_value=`defaults read "$file" ARD_AllLocalUsers`
	    fi

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

#macOS 10.12 testing
#Works without restarting.
}


######################################################################
CCE_79486_7_restrict_remote_apple_events_to_specific_users () {
    local doc="CCE_79486_7_restrict_remote_apple_events_to_specific_users   (manual-test-PASSED)"

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
                #if users are specified in the file, or the file does not exist
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
                #if users are specified in the file, or the file does not exist
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
                #if users are specified in the file, or the file does not exist
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


#macOS 10.12 testing
#After removing the user elements from the "users" key in $file, the users specified in
#the GUI were unchanged. The users specified in the GUI were still able to use screen
#sharing, even though the plist file key "users" was blank. After deleting the key
#"groupmembers", only Administrators showed up under "Allow access for: Only these users".

#Removing both "groupmembers" and "nestedgroups" keys in addition to setting "users" to
#blank caused the GUI to select "Only these users" and to display no users in the box.
#The last users to successfully send an event can still do so after the setting is
#disabled. After restart, previously authorized users could no longer send events.

#Applies immediately when enabling the setting, but disabling requires restart for
#users already authenticated with remote events. Other users are affected immediately.
}


######################################################################
CCE_79446_1_pf_enable_firewall () {
    local doc="CCE_79446_1_pf_enable_firewall                (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local sam_pfctl_plist="/Library/LaunchDaemons/sam.pfctl.plist"
    local sam_anchor="/etc/pf.anchors/sam_pf_anchors"
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
    sam_pf_content='
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
        if [ ! -e "$sam_pfctl_plist" ]; then
            #copy the plist because SIP prevents changes to /System/Library
            cp "/System/Library/LaunchDaemons/com.apple.pfctl.plist" "$sam_pfctl_plist"
            #allow pf to be enabled when the job is loaded
            /usr/libexec/PlistBuddy -c "Add :ProgramArguments:1 string -e" $sam_pfctl_plist
            #use new label to not conflict with System's pfctl
            /usr/libexec/PlistBuddy -c "Set :Label sam.pfctl" $sam_pfctl_plist
        fi

        case $profile_flag in
            "ent")
                #create the anchor file if it doesn't exist
                if [ ! -s "$sam_anchor" ]; then
                    echo "#sam pf anchor file" > "$sam_anchor"
                fi
 
                #make backup of original pf.conf
                if [ ! -e "${pf_conf}.bk" ]; then
                    cp "${pf_conf}" "${pf_conf}.bk"    
                fi
                #enable the firewall
                if [ "$enabled" == "0" ]; then
                    pfctl -e 2> /dev/null
                    echo "enabling $friendly_name"
                    #make pf run at system startup
                    launchctl enable system/sam.pfctl
                    launchctl bootstrap system $sam_pfctl_plist

                    #add and load sam anchor point
                    if [ "$pf_content_exists" == "0" ]; then
                        echo "Adding sam anchor point to $pf_conf and loading it"
                        echo "$sam_pf_content" >> "$pf_conf"
                    fi
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "soho")
                #create the anchor file if it doesn't exist
                if [ ! -s "$sam_anchor" ]; then
                    echo "#sam pf anchor file" > "$sam_anchor"
                fi

                #make backup of original pf.conf
                if [ ! -e "${pf_conf}.bk" ]; then
                    cp "${pf_conf}" "${pf_conf}.bk"    
                fi
                #enable the firewall
                if [ "$enabled" == "0" ]; then
                    pfctl -e 2> /dev/null
                    echo "enabling $friendly_name"
                    #make pf run at system startup
                    launchctl enable system/sam.pfctl
                    launchctl bootstrap system $sam_pfctl_plist

                    #add and load sam anchor point
                    if [ "$pf_content_exists" == "0" ]; then
                        echo "Adding sam anchor point to $pf_conf and loading it"
                        echo "$sam_pf_content" >> "$pf_conf"
                    fi
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "sslf")
                #create the anchor file if it doesn't exist
                if [ ! -s "$sam_anchor" ]; then
                    echo "#sam pf anchor file" > "$sam_anchor"
                fi

                #make backup of original pf.conf
                if [ ! -e "${pf_conf}.bk" ]; then
                    cp "${pf_conf}" "${pf_conf}.bk"    
                fi
                #enable the firewall
                if [ "$enabled" == "0" ]; then
                    pfctl -e 2> /dev/null
                    echo "enabling $friendly_name"
                    #make pf run at system startup
                    launchctl enable system/sam.pfctl
                    launchctl bootstrap system $sam_pfctl_plist

                    #add and load sam anchor point
                    if [ "$pf_content_exists" == "0" ]; then
                        echo "Adding sam anchor point to $pf_conf and loading it"
                        echo "$sam_pf_content" >> "$pf_conf"
                    fi
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
            "oem")
                echo "disabling $friendly_name"
                pfctl -d 2> /dev/null
                #make pf not run at system startup
                launchctl disable system/sam.pfctl
                launchctl bootout system/sam.pfctl
                
                #remove anchor text from $pf_conf
                echo "$oem_pf_contents" > "$pf_conf" 
                ;;
        esac
        pfctl -f rules 2> /dev/null #flush the pf ruleset (reload the rules)        
    fi

#macOS 10.12 testing
#pf firewall successfully enabled
}

######################################################################
CCE_79450_3_pf_rule_ftp () {
    local doc="CCE_79450_3_pf_rule_ftp                       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="20 21"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="ftp --ports $port-- pf firewall rule"
    local rule_text="block in proto { tcp udp } to any port { $port }"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked ftp client connection.
}

######################################################################
CCE_79466_9_pf_rule_ssh () {
    local doc="CCE_79466_9_pf_rule_ssh                       (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="22"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="ssh --port $port-- pf firewall rule"
    local rule_text="block in proto { tcp udp } to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac
        
        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked ssh client connection.
}

######################################################################
CCE_79467_7_pf_rule_telnet () {
    local doc="CCE_79467_7_pf_rule_telnet                    (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="23"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="telnet --port $port-- pf firewall rule"
    local rule_text="block in proto { tcp udp } to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked telnet client connection.
}


######################################################################
CCE_79468_5_pf_rule_tftp () {
    local doc="CCE_79468_5_pf_rule_tftp                   (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="69"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="tftp --port $port-- pf firewall rule"
    local rule_text="block proto { tcp udp } to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked tftp client connection.
}

######################################################################
CCE_79449_5_pf_rule_finger () {
    local doc="CCE_79449_5_pf_rule_finger                 (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="79"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="finger --port $port-- pf firewall rule"
    local rule_text="block proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked finger client connection.
}

######################################################################
CCE_79451_1_pf_rule_http () {
    local doc="CCE_79451_1_pf_rule_http                   (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="80"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="http --port $port-- pf firewall rule"
    local rule_text="block in proto { tcp udp } to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked http client connection.
}

######################################################################
CCE_79457_8_pf_rule_nfs () {
    local doc="CCE_79457_8_pf_rule_nfs                    (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="2049"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="nfs --port $port-- pf firewall rule"
    local rule_text="block proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked port used by nfs.
}

######################################################################
CCE_79462_8_pf_rule_remote_apple_events () {
    local doc="CCE_79462_8_pf_rule_remote_apple_events    (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="3031"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="remote apple events --port $port-- pf firewall rule"
    local rule_text="block in proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked remote apple events.
}

######################################################################
CCE_79464_4_pf_rule_smb () {
    local doc="CCE_79464_4_pf_rule_smb                    (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="139 445"
    local port2="137 138"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="smb --ports $port $port2-- pf firewall rule"
    local rule_text1="block proto tcp to any port { $port }"
    local rule_text2="block proto udp to any port { $port2 }"
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
                    local oem_content="$(egrep -v "(^$rule_text1)|(^$rule_text2)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked ports used by smb.
}

######################################################################
CCE_79447_9_pf_rule_apple_file_service () {
    local doc="CCE_79447_9_pf_rule_apple_file_service     (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="548"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="apple file service --port $port-- pf firewall rule"
    local rule_text="block in proto tcp to any port { $port }"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked apple file service port.
}

######################################################################
CCE_79469_3_pf_rule_uucp () {
    local doc="CCE_79469_3_pf_rule_uucp                   (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="540"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="uucp --port $port-- pf firewall rule"
    local rule_text="block proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked uucp port.
}

######################################################################
CCE_79463_6_pf_rule_screen_sharing () {
    local doc="CCE_79463_6_pf_rule_screen_sharing         (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="5900"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="screen_sharing --port $port-- pf firewall rule"
    local rule_text="block in proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked screen sharing port.
}

######################################################################
CCE_79452_9_pf_rule_icmp () {
    local doc="CCE_79452_9_pf_rule_icmp                      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="icmp pf firewall rule"
    local rule_text="block in proto icmp"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked icmp port.
}

######################################################################
CCE_79465_1_pf_rule_smtp () {
    local doc="CCE_79465_1_pf_rule_smtp                   (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="25"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="smtp --port $port-- pf firewall rule"
    local rule_text="block in proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked smtp port.
}

######################################################################
CCE_79459_4_pf_rule_pop3 () {
    local doc="CCE_79459_4_pf_rule_pop3                   (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="110"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="pop3 --port $port-- pf firewall rule"
    local rule_text="block in proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked pop3 port.
}

######################################################################
CCE_79460_2_pf_rule_pop3s () {
    local doc="CCE_79460_2_pf_rule_pop3s                  (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="995"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="pop3s --port $port-- pf firewall rule"
    local rule_text="block in proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked pop3s port.
}


######################################################################
CCE_79453_7_pf_rule_imap () {
    local doc="CCE_79453_7_pf_rule_imap                   (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="143"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="imap --port $port-- pf firewall rule"
    local rule_text="block in proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked imap port.
}

######################################################################
CCE_79454_5_pf_rule_imaps () {
    local doc="CCE_79454_5_pf_rule_imaps                  (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="993"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="imaps --port $port-- pf firewall rule"
    local rule_text="block in proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked imaps port.
}

######################################################################
CCE_79461_0_pf_rule_printer_sharing () {
    local doc="CCE_79461_0_pf_rule_printer_sharing        (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="631"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="printer sharing --port $port-- pf firewall rule"
    local rule_text="block in proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked printer sharing port.
}

######################################################################
CCE_79448_7_pf_rule_bonjour () {
    local doc="CCE_79448_7_pf_rule_bonjour                (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="1900"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="bonjour component SSDP --port $port-- pf firewall rule"
    local rule_text="block proto udp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked Bonjour port.
}

######################################################################
CCE_79456_0_pf_rule_mDNSResponder () {
    local doc="CCE_79456_0_pf_rule_mDNSResponder          (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="5353"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="mDNSResponder --port $port-- pf firewall rule"
    local rule_text="block proto udp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#Tested using Bonjour Browser. After blocking the port, the services were no 
#longer discoverable by a networked computer.

#macOS 10.12 testing
#Successfully blocked mDNSResponder port.
}

######################################################################
CCE_79455_2_pf_rule_itunes_sharing () {
    local doc="CCE_79455_2_pf_rule_itunes_sharing         (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="3689"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="iTunes sharing --port $port-- pf firewall rule"
    local rule_text="block proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#macOS 10.12 testing
#Successfully blocked iTunes sharing port.
}


######################################################################
CCE_79458_6_pf_rule_optical_drive_sharing () {
    local doc="CCE_79458_6_pf_rule_optical_drive_sharing      (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local pf_conf="/etc/pf.conf"
    local port="49152"
    local anchor_file="/etc/pf.anchors/sam_pf_anchors" #pf rules go here
    local friendly_name="optical drive sharing --port $port-- pf firewall rule"
    local rule_text="block proto tcp to any port $port"
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
                    local oem_content="$(egrep -v "(^$rule_text)|(^#$friendly_name)" "$anchor_file")"
                    echo "$oem_content" > "$anchor_file" 
                else
                    echo "$friendly_name already disabled"
                fi
                ;;
        esac

        pfctl -f "$pf_conf" 2> /dev/null
    fi
    
#Testing notes: When trying to use an optical drive over the network, the pf rule prevented
#the drive's contents from being accessed.

#macOS 10.12 testing
#Optical drive sharing was successfully blocked.
}


######################################################################
CCE_79410_7_audit_log_max_file_size() {
    local doc="CCE_79410_7_audit_log_max_file_size        (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local file="/etc/security/audit_control"
    local setting_name="filesz"
    local friendly_name="audit log individual file size"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="80M"
    local soho_value="80M"
    local sslf_value="80M"
    local oem_value="2M" #Confirmed default value for 10.12

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

#macOS 10.12 testing
#When max log file size is reached, a new log is created.
}


######################################################################
CCE_79411_5_audit_log_retention () {
    local doc="CCE_79411_5_audit_log_retention            (manual-test-PASSED)"
    
    if [ "$list_flag" != "" ]; then echo "$doc"; fi
    
    local file="/etc/security/audit_control"
    local setting_name="expire-after"
    local friendly_name="audit logs expire after"
    local file_contents=`cat $file 2> /dev/null`

    #profile values
    local ent_value="30d AND 5G"
    local soho_value="30d AND 5G"
    local sslf_value="30d AND 5G"
    local oem_value="10M" #Confirmed default value on 10.12

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
            echo "$friendly_name \"$oem_value\""
        else
            echo "$friendly_name \"$current_value\""
        fi
    fi

    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                if [ "$current_value" == "$ent_value" ]; then
                    echo "$friendly_name already set to \"$ent_value\""
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
                if [ "$current_value" == "$soho_value" ]; then
                    echo "$friendly_name already set to \"$soho_value\""
                else
                    echo "setting $friendly_name to \"$soho_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$soho_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$soho_value" >> $file
                    fi
                fi
                ;;
            "sslf")
                if [ "$current_value" == "$sslf_value" ]; then
                    echo "$friendly_name already set to \"$sslf_value\""
                else
                    echo "setting $friendly_name to \"$sslf_value\""
                    if [ "$current_string" != "" ]; then
                        #replace existing value with new value
                        new_file_contents=`echo "$file_contents" | sed "s/^$current_string/$setting_name:$sslf_value/"`
                        echo "$new_file_contents" > $file
                    else
                        #since setting doesn't exist, append it to the file
                        echo "$setting_name:$sslf_value" >> $file
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

#macOS 10.12 testing
#When the log files directory reaches max age and and size, the oldest files are deleted.
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
}


# sets a user-specific setting for all specified users found on the computer
apply_settings_for_selected_users () {
    local apply_to_users_list

    # if all users
    if [ "$all_users_flag" != "" ]; then
        apply_to_users_list="$user_list"

    elif [ "$owner" == "root" ]; then
        echo "Skipping user-specific settings, because user is root. Please specify user(s) or run the script from userspace with sudo."
	return

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
            killall -TERM $process
        fi
    done
}


######################################################################
CCE_79504_7_bluetooth_open_setup_if_no_keyboard () {
    local doc="CCE_79504_7_bluetooth_open_setup_if_no_keyboard      (manual-test-PASSED)"
    local file=/Library/Preferences/com.apple.Bluetooth.plist
    local setting_name=BluetoothAutoSeekKeyboard
    local status=1 #default on 10.12 is enabled

    if [ -e $file ]; then
        local key_exists=`defaults read $file | grep "$setting_name" | wc -l`
        if [ "$key_exists" == "1" ]; then
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
            echo "open Bluetooth setup if no keyboard setting is unchanged";
            ;;
        "soho")
            echo "open Bluetooth setup if no keyboard setting is unchanged";
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

#Note: Bluetooth setup assistant only appears to display upon logging in.

#NEEDS_REAL_HARDWARE

#macOS 10.12 real hardware test
#Works after restart.
}


######################################################################
CCE_79505_4_bluetooth_open_setup_if_no_mouse_trackpad () {
    local doc="CCE_79505_4_bluetooth_open_setup_if_no_mouse_trackpad     (manual-test-PASSED)"
    local file=/Library/Preferences/com.apple.Bluetooth.plist
    local setting_name=BluetoothAutoSeekPointingDevice
    local status=1 #default is enabled

    if [ -e $file ]; then
        local key_exists=`defaults read $file | grep "$setting_name" | wc -l`
        if [ "$key_exists" == "1" ]; then
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
                echo "open Bluetooth setup if no mouse or trackpad setting is unchanged";
                ;;
            "soho")
                echo "open Bluetooth setup if no mouse or trackpad setting is unchanged";
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

#Note: Bluetooth setup assistant only appears to pop up upon logging in.

#NEEDS_REAL_HARDWARE

#macOS 10.12 real hardware test
#Works after restart.
}


######################################################################
CCE_79506_2_bluetooth_turn_off_bluetooth () {
    local doc="CCE_79506_2_bluetooth_turn_off_bluetooth              (manual-test-PASSED)"
    local file=/Library/Preferences/com.apple.Bluetooth.plist
    local setting_name=ControllerPowerState
    local status=1 #default is enabled

    if [ -e $file ]; then
        local key_exists=`defaults read $file | grep "$setting_name" | wc -l`
        if [ "$key_exists" == "1" ]; then
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
                defaults write "$file" "$setting_name" -bool false
                ;;
            "oem")
                echo "enabling Bluetooth";
                defaults write "$file" "$setting_name" -bool true
                ;;
        esac
    fi


#NEEDS_REAL_HARDWARE

#macOS 10.12 
#Restart required.
}



######################################################################
CCE_79509_6_show_bluetooth_status_in_menu_bar () {
    local doc="CCE_79509_6_show_bluetooth_status_in_menu_bar                (manual-test-PASSED)"
    local file="$home_path/Library/Preferences/com.apple.systemuiserver.plist"
    local setting_name=menuExtras
    local setting_value="/System/Library/CoreServices/Menu\ Extras/Bluetooth.menu"
    local friendly_name="show Bluetooth status in menu bar"
    local value_exists=0

    if [ -e "$file" ]; then
        local key_exists=`defaults read "$file" | grep -c $setting_name`
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
                if [ "$value_exists" == 1 ]; then
                    echo "disabling $friendly_name";
                    /usr/libexec/PlistBuddy -c "Delete :$setting_name $setting_value" $file
                    add_processes_to_kill_list SystemUIServer cfprefsd 
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi

#Note: killing cfprefsd, SystemUIServer causes this to take effect immediately.

#macOS 10.12 - Icon appears without restart.
}



######################################################################
CCE_79503_9_bluetooth_disable_wake_computer () {
    local doc="CCE_79503_9_bluetooth_disable_wake_computer            (manual-test-PASSED)"
    local file=$home_path/Library/Preferences/ByHost/com.apple.Bluetooth.$hw_uuid.plist
    local setting_name=RemoteWakeEnabled
    local value=1 #default value on 10.12
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


#NEEDS_REAL_HARDWARE

#macOS 10.12 real hardware test
#Took effect immediately.
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
#This function assists with checks in CCE_79477_6_change_computer_name, 
#CCE_79478_4_change_host_name, CCE_79479_2_change_local_host_name, 
#CCE_79480_0_change_net_bios_name
}


######################################################################
#LocalHostName is used by the Bonjour service for network discovery
CCE_79479_2_change_local_host_name () {
    local doc="CCE_79479_2_change_local_host_name              (manual-test-PASSED)"
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


#macOS 10.12
#LocalHostName change takes effect immediately.
}


######################################################################
#HostName is visible on the command line and can be used to SSH in
CCE_79478_4_change_host_name () {
    local doc="CCE_79478_4_change_host_name              (manual-test-PASSED)"
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

#macOS 10.12
#HostName change takes effect immediately.
}


######################################################################
#Computer name is visible through Finder on other Macs
CCE_79477_6_change_computer_name () {
    local doc="CCE_79477_6_change_computer_name              (manual-test-PASSED)"
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


#macOS 10.12
#ComputerName change takes effect immediately.
}


######################################################################
#NetBIOSName is visible to Windows systems
CCE_79480_0_change_net_bios_name () {
    local doc="CCE_79480_0_change_net_bios_name              (manual-test-PASSED)"
    local setting_name=NetBIOSName
    local friendly_name="NetBIOSName"
    local file=/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist
    local setting_value="NO_NAME" # default placeholder name
    local match_found=0

    if [ -e $file ]; then
        local key_exists=`defaults read $file | grep -c $setting_name`
        if [ "$key_exists" ]; then
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


#macOS 10.12
#Changing LocalHostName will also change NetBIOSName after a short delay.
#NetBIOSName change takes effect immediately.
}


######################################################################
CCE_79491_7_enable_display_sleep () {
    local doc="CCE_79491_7_enable_display_sleep            (manual-test-PASSED)"
    local file=/Library/Preferences/com.apple.PowerManagement.plist
    local internal_name="Display Sleep Timer"
    local setting_name="displaysleep"
    local setting_value=10 #default is 10 minutes on 10.12
    local friendly_name="display goes to sleep"
    local key_exists=0

    #If the power management file doesn't exist, write a default value to create it.
    #This prevents an error when trying to read/write this file.
    power_management_helper 

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ "$key_exists" -ge "1" ]; then
            setting_value=`pmset -g | grep "$setting_name" | egrep -o "[0-9]+"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$key_exists" == "0" ]; then
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
                if [ "$key_exists" == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 20 minutes for all power profiles"
                    pmset -a "$setting_name" 20
                fi
                ;;
            "soho")
                if [ "$key_exists" == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 20 minutes for all power profiles"
                    pmset -a "$setting_name" 20
                fi
                ;;
            "sslf")
                if [ "$key_exists" == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "setting $friendly_name after 20 minutes for all power profiles"
                    pmset -a "$setting_name" 20
                fi
                ;;
            "oem")
                if [ "$key_exists" == "0" ]; then
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

#NEEDS_REAL_HARDWARE

#macOS 10.12 real hardware test
#The setting took effect immediately without logging out or restarting.
}


######################################################################
CCE_79489_1_disable_computer_sleep () {
    local doc="CCE_79489_1_disable_computer_sleep            (manual-test-PASSED)"
    local file=/Library/Preferences/com.apple.PowerManagement.plist
    local internal_name="System Sleep Timer"
    local setting_name="sleep"
    local setting_value=10 #default is 10 minutes
    local friendly_name="computer sleep"
    local key_exists=0

    #If the power management file doesn't exist, write a default value to create it.
    #This prevents an error when trying to read/write this file.
    power_management_helper 

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ "$key_exists" -ge "1" ]; then
            setting_value=`pmset -g | grep -w "$setting_name" | egrep -o "[0-9]+"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$key_exists" == "0" ]; then
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
                if [ "$key_exists" == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -c "$setting_name" 0
                fi
                ;;
            "soho")
                if [ "$key_exists" == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -c "$setting_name" 0
                fi
                ;;
            "sslf")
                if [ "$key_exists" == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -c "$setting_name" 0
                fi
                ;;
            "oem")
                if [ "$key_exists" == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name after 10 minutes for all power profiles"
                    pmset -c "$setting_name" 10
                fi
                ;;
        esac
    fi

#Note: Difficult to check each power profile and set on an individual basis,
#so override existing settings each time a security profile is set.
#Also, changing this setting to a value less than displaysleep is invalid, so the
#system instead uses a default value.

#macOS 10.12 testing
#Works immediately.
}


######################################################################
CCE_79490_9_disable_wake_for_network_access () {
    local doc="CCE_79490_9_disable_wake_for_network_access          (manual-test-PASSED)"
    local file=/Library/Preferences/com.apple.PowerManagement.plist
    local internal_name="Wake On LAN"
    local setting_name="womp"
    local setting_value=1 #default is enabled on 10.12
    local friendly_name="wake for network access"
    local key_exists=0

    #If the power management file doesn't exist, write a default value to create it.
    #This prevents an error when trying to read/write this file.
    power_management_helper 

    if [ -e $file ]; then
        key_exists=`defaults read $file | grep "$internal_name" | wc -l`
        if [ "$key_exists" -ge "1" ]; then
            setting_value=`pmset -g | grep "$setting_name" | egrep -o "[01]"`
        fi
    fi

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    if [ "$print_flag" != "" ]; then
        if [ "$key_exists" == "0" ]; then
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
                if [ "$key_exists" == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "soho")
                if [ "$key_exists" == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "enabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "sslf")
                if [ "$key_exists" == "0" ]; then
                    echo "$friendly_name is not supported by this system"
                else
                    echo "disabling $friendly_name for all power profiles"
                    pmset -a "$setting_name" 0
                fi
                ;;
            "oem")
                if [ "$key_exists" == "0" ]; then
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

#macOS 10.12 real hardware test
#With setting enabled, file sharing and ssh woke up the system.
#With the setting disabled, the system did not show up for file sharing,
#and ssh could not find a route to the system.
#Applies immediately.
}


###############################################################
CCE_79483_4_disable_bonjour_advertising() {
local doc="CCE_79483_4_disable_bonjour_advertising                (manual-test-PASSED)"

    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file=/Library/Preferences/com.apple.mDNSResponder.plist
    local setting_name="NoMulticastAdvertisements"
    local setting_value=0 #default value on 10.12
    local friendly_name="Bonjour advertising"
    
    if [ -e "$file" ]; then
        local key_exists=`defaults read $file | grep -c $setting_name`
        if [ "$key_exists" -gt 0 ]; then
            setting_value=`defaults read $file $setting_name`
        fi
    fi

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
                
                    add_processes_to_kill_list cfprefsd
                
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
                
                    add_processes_to_kill_list cfprefsd
                
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ "$setting_value" == 1 ]; then
                    echo "enabling $friendly_name";
                    defaults write $file $setting_name -bool false
                
                    add_processes_to_kill_list cfprefsd
                
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac
    fi


#macOS 10.12
#Works after restart. The computer no longer shows up in Finder on other computers. 
#It is still accessible on the network using SMB, so this setting works as expected.
#Could not connect using AFP.
}


######################################################################
CCE_79507_0_disable_airdrop () {
    local doc="CCE_79507_0_disable_airdrop            (manual-test-PASSED)"

    local file=$home_path/Library/Preferences/com.apple.NetworkBrowser.plist
    local setting_name=DisableAirDrop
    local setting_value=0 #default value on 10.12
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


# Note: AirDrop requires an enabled Wi-Fi adapter to function.

# NEEDS_REAL_HARDWARE

# macOS 10.12
# To make the setting apply immediately, kill cfprefsd and Finder.
}


######################################################################
CCE_79437_0_disable_siri () {
    local doc="CCE_79437_0_disable_siri              (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="$home_path/Library/Preferences/com.apple.assistant.support.plist"
    local setting_name="Assistant Enabled"
    local friendly_name="Siri"
    local setting_value="1" #confirmed default on 10.12

    if [ -e "$file" ]; then
        local exists="$(defaults read $file | grep -c "$setting_name")"
        #if key not present, it has default value
        if [ $exists != "0" ]; then
            setting_value="$(defaults read "$file" "$setting_name")"
        fi
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" == "1" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only disable the setting if it is not already disabled
        case $profile_flag in
            "ent")
                if [ "$setting_value" != "0" ]; then
                    echo "disabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 0
                    add_processes_to_kill_list cfprefsd Siri
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ "$setting_value" != "0" ]; then
                    echo "disabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 0
                    add_processes_to_kill_list cfprefsd Siri 
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ "$setting_value" != "0" ]; then
                    echo "disabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 0
                    add_processes_to_kill_list cfprefsd Siri
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ "$setting_value" != "1" ]; then
                    echo "enabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 1
                    add_processes_to_kill_list cfprefsd Siri
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi


#macOS 10.12 testing
#Works immediately with process killing (processes are restarted after
#being killed).
}


######################################################################
CCE_79406_5_enable_gatekeeper () {
    local doc="CCE_79406_5_enable_gatekeeper              (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local permissive_msg="Gatekeeper allow apps downloaded from the App Store and identified developers"
    local restrictive_msg="Gatekeeper only allows apps downloaded from the App Store"

    #default is allow App Store and identified developers
    local setting_value="$(spctl --status -v)" 
    local gatekeeper_on="$(echo $setting_value | grep -c "assessments enabled")"

    #if gatekeeper is off, the developer string is not present
    #if this is enabled, apps from identified developers are allowed
    local developer_id_value="$(echo $setting_value | grep -c "developer id enabled")"


    if [ "$print_flag" != "" ]; then
        if [ "$developer_id_value" == "1" ]; then
            echo "$permissive_msg"
        elif [ "$gatekeeper_on" == "1" ]; then
            echo "$restrictive_msg"
        else
            echo "Gatekeeper is disabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "$developer_id_value" != "1" ]; then
                    echo "enabling $permissive_msg"
                    spctl --master-enable
                    spctl --enable #allow approved developers
                else
                    echo "$permissive_msg is already enabled"
                fi
                ;;
            "soho")
                if [ "$developer_id_value" != "1" ]; then
                    echo "enabling $permissive_msg"
                    spctl --master-enable
                    spctl --enable #allow approved developers
                else
                    echo "$permissive_msg is already enabled"
                fi
                ;;
            "sslf")
                #if gatekeeper is on, developer_id needs to be off; if gatekeeper is off,
                #it needs to be enabled
                if [ "$gatekeeper_on" != "0" -a "$developer_id_value" != "0" ] || [ "$gatekeeper_on" == "0" ]; then
                    echo "enabling $restrictive_msg"
                    spctl --master-enable
                    spctl --disable #allow from app store only
                else
                    echo "$restrictive_msg is already enabled"
                fi
                ;;
            "oem")
                if [ "$developer_id_value" != "1" ]; then
                    echo "enabling $permissive_msg"
                    spctl --master-enable
                    spctl --enable #allow approved developers
                else
                    echo "$permissive_msg is already enabled"
                fi
                ;;
        esac
    fi
   
#testing process
#Used Atom text editor downloaded from atom.io. After trying to open the file,
#press cancel so an exception is not stored.

#macOS 10.12
#File could not be opened without allowed developers option enabled.
#Setting changes took effect immediately.
}


######################################################################
CCE_79435_4_disable_lookup_suggestions () {
    local doc="CCE_79435_4_disable_lookup_suggestions           (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="$home_path/Library/Preferences/com.apple.lookup.shared.plist"
    local setting_name="LookupSuggestionsDisabled"
    local friendly_name="Lookup suggestions"
    local setting_value="0" #confirmed default on 10.12

    if [ -e "$file" ]; then
        local exists="$(defaults read $file | grep -c "$setting_name")"
        #if key not present, it has default value
        if [ "$exists" != "0" ]; then
            setting_value="$(defaults read "$file" "$setting_name")"
        fi
    fi

    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" == "0" ]; then
            echo "$friendly_name is enabled"
        else
            echo "$friendly_name is disabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only enable the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "$setting_value" != "1" ]; then
                    echo "disabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 1
                    add_processes_to_kill_list cfprefsd 
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "soho")
                if [ "$setting_value" != "1" ]; then
                    echo "disabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 1
                    add_processes_to_kill_list cfprefsd 
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "sslf")
                if [ "$setting_value" != "1" ]; then
                    echo "disabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 1
                    add_processes_to_kill_list cfprefsd 
                else
                    echo "$friendly_name is already disabled"
                fi
                ;;
            "oem")
                if [ "$setting_value" != "0" ]; then
                    echo "enabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 0
                    add_processes_to_kill_list cfprefsd 
                else
                    echo "$friendly_name is already enabled"
                fi
                ;;
        esac

        if [ -e "$file" ]; then
            chown $owner:$group $file #restore original owner/group
        fi
    fi


#macOS 10.12 testing
#Works immediately with process killing (processes are restarted after
#being killed).
}


######################################################################
CCE_79482_6_disable_bluetooth_daemon () {
    local doc="CCE_79482_6_disable_bluetooth_daemon           (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="/System/Library/LaunchDaemons/com.apple.blued.plist"
    local setting_name="system/com.apple.blued"
    local friendly_name="Bluetooth daemon"

    #service is running by default on 10.12
    local setting_value="$(launchctl print system | grep -c "blued")"


    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" == "0" ]; then
            echo "$friendly_name is not running"
        else
            echo "$friendly_name is running"
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
                if [ "$setting_value" != "0" ]; then
                    echo "stopping the $friendly_name"
                    launchctl disable "$setting_name"
                    launchctl bootout "$setting_name" 2> /dev/null
                else
                    echo "$friendly_name has already been stopped"
                fi
                ;;
            "oem")
                if [ "$setting_value" == "0" ]; then
                    echo "starting the $friendly_name"
                    launchctl enable "$setting_name"
                    launchctl bootstrap system "$file"
                else
                    echo "$friendly_name has already been started"
                fi
                ;;
        esac
    fi

#macOS 10.12 testing
#Works immediately for the sslf profile. May require a restart for oem.
}


######################################################################
CCE_79485_9_disable_wifi_services () {
    local doc="CCE_79485_9_disable_wifi_services            (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file[0]="/System/Library/LaunchDaemons/com.apple.airportd.plist"
    local file[1]="/System/Library/LaunchDaemons/com.apple.airport.wps.plist"

    local setting_name[0]="system/com.apple.airportd"
    local setting_name[1]="system/com.apple.airport.wps"
    local friendly_name="wifi services"

    #services are running by default on 10.12
    local setting_value[0]="$(launchctl print system | grep -c "airportd")"
    local setting_value[1]="$(launchctl print system | grep -c "airport.wps")"

    if [ "$print_flag" != "" ]; then
        if [ "${setting_value[0]}" == "0" ] && [ "${setting_value[1]}" == "0" ]; then
            echo "$friendly_name are not running"
        else
            echo "$friendly_name are running"
        fi
    fi


    if [ "$set_flag" != "" ]; then
        # only modify the setting if it is not already set
        case $profile_flag in
            "ent")
                echo "$friendly_name is unchanged"
                ;;
            "soho")
                echo "$friendly_name is unchanged"
                ;;
            "sslf")
                if [ "${setting_value[0]}" != "0" ] || [ "${setting_value[1]}" != "0" ]; then
                    echo "stopping the $friendly_name"
                    launchctl disable "${setting_name[0]}" 2> /dev/null
                    launchctl bootout "${setting_name[0]}" 2> /dev/null

                    launchctl disable "${setting_name[1]}" 2> /dev/null
                    launchctl bootout "${setting_name[1]}" 2> /dev/null
                else
                    echo "$friendly_name have already been stopped"
                fi
                ;;
            "oem")
                if [ "${setting_value[0]}" == "0" ] || [ "${setting_value[1]}" == "0" ]; then
                    echo "starting the $friendly_name"
                    launchctl enable "${setting_name[0]}" 2> /dev/null
                    launchctl bootstrap system "${file[0]}" 2> /dev/null

                    launchctl enable "${setting_name[1]}" 2> /dev/null
                    launchctl bootstrap system "${file[1]}" 2> /dev/null
                else
                    echo "$friendly_name have already been started"
                fi
                ;;
        esac
    fi

#macOS 10.12 testing
#Works after restart.
}


######################################################################
CCE_79484_2_disable_nfs () {
    local doc="CCE_79484_2_disable_nfs                    (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file[0]="/System/Library/LaunchDaemons/com.apple.nfsd.plist"
    local file[1]="/System/Library/LaunchDaemons/com.apple.lockd.plist"
    local file[2]="/System/Library/LaunchDaemons/com.apple.statd.notify.plist"

    local setting_name[0]="system/com.apple.nfsd"
    local setting_name[1]="system/com.apple.lockd"
    local setting_name[2]="system/com.apple.statd.notify"
    local friendly_name="nfs services"

    #services are running by default on 10.12
    local setting_value[0]="$(launchctl print system | grep -c "nfsd")"
    local setting_value[1]="$(launchctl print system | grep -c "lockd")"
    local setting_value[2]="$(launchctl print system | grep -c "statd.notify")"


    if [ "$print_flag" != "" ]; then
        if [ "${setting_value[0]}" == "0" ] && [ "${setting_value[1]}" == "0" ] && [ "${setting_value[2]}" == "0" ] ; then
            echo "$friendly_name are not running"
        else
            echo "$friendly_name are running"
        fi
    fi


    if [ "$set_flag" != "" ]; then
        # only modify the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "${setting_value[0]}" != "0" ] || [ "${setting_value[1]}" != "0" ] || [ "${setting_value[2]}" != "0" ]; then
                    echo "stopping the $friendly_name"
                    launchctl disable "${setting_name[0]}"
                    launchctl bootout "${setting_name[0]}" 2> /dev/null

                    launchctl disable "${setting_name[1]}"
                    launchctl bootout "${setting_name[1]}" 2> /dev/null
                    
                    launchctl disable "${setting_name[2]}"
                    launchctl bootout "${setting_name[2]}" 2> /dev/null
                else
                    echo "$friendly_name have already been stopped"
                fi
                ;;
            "soho")
                if [ "${setting_value[0]}" != "0" ] || [ "${setting_value[1]}" != "0" ] || [ "${setting_value[2]}" != "0" ]; then
                    echo "stopping the $friendly_name"
                    launchctl disable "${setting_name[0]}"
                    launchctl bootout "${setting_name[0]}" 2> /dev/null

                    launchctl disable "${setting_name[1]}"
                    launchctl bootout "${setting_name[1]}" 2> /dev/null
                    
                    launchctl disable "${setting_name[2]}"
                    launchctl bootout "${setting_name[2]}" 2> /dev/null
                else
                    echo "$friendly_name have already been stopped"
                fi
                ;;
            "sslf")
                if [ "${setting_value[0]}" != "0" ] || [ "${setting_value[1]}" != "0" ] || [ "${setting_value[2]}" != "0" ]; then
                    echo "stopping the $friendly_name"
                    launchctl disable "${setting_name[0]}"
                    launchctl bootout "${setting_name[0]}" 2> /dev/null

                    launchctl disable "${setting_name[1]}"
                    launchctl bootout "${setting_name[1]}" 2> /dev/null
                    
                    launchctl disable "${setting_name[2]}"
                    launchctl bootout "${setting_name[2]}" 2> /dev/null
                else
                    echo "$friendly_name have already been stopped"
                fi
                ;;
            "oem")
                if [ "${setting_value[0]}" == "0" ] || [ "${setting_value[1]}" == "0" ] || [ "${setting_value[2]}" == "0" ]; then
                    echo "starting the $friendly_name"
                    launchctl enable "${setting_name[0]}" 2> /dev/null
                    launchctl bootstrap system "${file[0]}" 2> /dev/null

                    launchctl enable "${setting_name[1]}" 2> /dev/null
                    launchctl bootstrap system "${file[1]}" 2> /dev/null

                    launchctl enable "${setting_name[2]}" 2> /dev/null
                    launchctl bootstrap system "${file[2]}" 2> /dev/null
                else
                    echo "$friendly_name have already been started"
                fi
                ;;
        esac
    fi

#Setting up nfs server for testing:
#Create file "/etc/exports" with the following content
#/path/to/share -mapall=501

#From remote machine, create an empty folder. Then run
#sudo mount -o rw -t nfs SERVER_IP_ADDRESS:/path/to/share /local/empty/folder

#macOS 10.12 testing
#Works immediately.
}


######################################################################
CCE_79481_8_disable_apple_file_server () {
    local doc="CCE_79481_8_disable_apple_file_server            (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file[0]="/System/Library/LaunchDaemons/com.apple.AppleFileServer.plist"
    local file[1]="/System/Library/LaunchDaemons/com.apple.smbd.plist"

    local setting_name[0]="system/com.apple.AppleFileServer"
    local setting_name[1]="system/com.apple.smbd"
    local friendly_name="Apple File Server services"

    local setting_value[0]="$(launchctl print system | grep -c "AppleFileServer")" #default disabled
    local setting_value[1]="$(launchctl print system | grep -c "smbd")" #default enabled

    if [ "$print_flag" != "" ]; then
        if [ "${setting_value[0]}" == "0" ] && [ "${setting_value[1]}" == "0" ]; then
            echo "$friendly_name are not running"
        else
            echo "$friendly_name are running"
        fi
    fi


    if [ "$set_flag" != "" ]; then
        # only modify the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "${setting_value[0]}" != "0" ] || [ "${setting_value[1]}" != "0" ]; then
                    echo "stopping the $friendly_name"
                    launchctl disable "${setting_name[0]}" 2> /dev/null
                    launchctl bootout "${setting_name[0]}" 2> /dev/null

                    launchctl disable "${setting_name[1]}" 2> /dev/null
                    launchctl bootout "${setting_name[1]}" 2> /dev/null
                else
                    echo "$friendly_name have already been stopped"
                fi
                ;;
            "soho")
                if [ "${setting_value[0]}" != "0" ] || [ "${setting_value[1]}" != "0" ]; then
                    echo "stopping the $friendly_name"
                    launchctl disable "${setting_name[0]}" 2> /dev/null
                    launchctl bootout "${setting_name[0]}" 2> /dev/null

                    launchctl disable "${setting_name[1]}" 2> /dev/null
                    launchctl bootout "${setting_name[1]}" 2> /dev/null
                else
                    echo "$friendly_name have already been stopped"
                fi
                ;;
            "sslf")
                if [ "${setting_value[0]}" != "0" ] || [ "${setting_value[1]}" != "0" ]; then
                    echo "stopping the $friendly_name"
                    launchctl disable "${setting_name[0]}" 2> /dev/null
                    launchctl bootout "${setting_name[0]}" 2> /dev/null

                    launchctl disable "${setting_name[1]}" 2> /dev/null
                    launchctl bootout "${setting_name[1]}" 2> /dev/null
                else
                    echo "$friendly_name have already been stopped"
                fi
                ;;
            "oem")
                if [ "${setting_value[0]}" != "0" ]; then
                    echo "disabling AFP" 
                    launchctl disable "${setting_name[0]}" 2> /dev/null
                    launchctl bootout "${setting_name[0]}" 2> /dev/null
                fi

                if  [ "${setting_value[1]}" == "0" ]; then
                    echo "enabling SMB"
                    launchctl enable "${setting_name[1]}" 2> /dev/null
                    launchctl bootstrap system "${file[1]}" 2> /dev/null
                fi

                if [ "${setting_value[0]}" == "0" ] && [ "${setting_value[1]}" != "0" ]; then
                    echo "$friendly_name have already been started"
                fi
                ;;
        esac
    fi

#Note: It is possible for more than one instance of the process to be running. This was
#observed during an active SMB sharing session.

#macOS 10.12 testing
#Works without restart.
}


######################################################################
CCE_79442_0_terminal_secure_keyboard () {
    local doc="CCE_79442_0_terminal_secure_keyboard          (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="$home_path/Library/Preferences/com.apple.Terminal.plist"
    local setting_name="SecureKeyboardEntry"
    local setting_value="0" #default on 10.12
    local friendly_name="secure keyboard entry in Terminal"

    if [ -e "$file" ]; then
        local key_exists="$(defaults read "$file" | grep -c "$setting_name")"
        if [ "$key_exists" -gt 0 ]; then
            setting_value="$(defaults read "$file" "$setting_name")"
        fi

    fi


    if [ "$print_flag" != "" ]; then
        if [ "$setting_value" != "1" ]; then
            echo "$friendly_name is disabled"
        else
            echo "$friendly_name is enabled"
        fi
    fi

    if [ "$set_flag" != "" ]; then
        # only modify the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "$setting_value" != "1" ]; then
                    echo "enabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 1
		    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name has already been enabled"
                fi
                ;;
            "soho")
                if [ "$setting_value" != "1" ]; then
                    echo "enabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 1
		    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name has already been enabled"
                fi
                ;;
            "sslf")
                if [ "$setting_value" != "1" ]; then
                    echo "enabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 1
		    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name has already been enabled"
                fi
                ;;
            "oem")
                if [ "$setting_value" != "0" ]; then
                    echo "disabling $friendly_name"
                    defaults write "$file" "$setting_name" -int 0
		    add_processes_to_kill_list cfprefsd
                else
                    echo "$friendly_name has already been disabled"
                fi
                ;;
        esac
        if [ -e "$file" ]; then
            chown $owner:$group "$file" #restore original owner/group
        fi
    fi

#Testing process
#Used the Keyboard Viewer program accessed through the "Show keyboard and emoji viewers
#in menu bar" option in System Preferences/Keyboard. Non-modifier keys in the viewer 
#highlight when typing on the physical keyboard when this setting is disabled. They no
#longer highlight when the setting is enabled, and the "Secure Keyboard Entry" option 
#under the Terminal top menu is checked.

#macOS 10.12 testing
#Works after restarting Terminal.
}


######################################################################
CCE_79408_1_set_umask () {
    local doc="CCE_79408_1_set_umask                    (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="/private/var/db/com.apple.xpc.launchd/config/user.plist"
    local setting_name="launchctl config user umask"
    local oem_value="0022"
    local setting_value="$oem_value" #default is 0022 on 10.12
    local friendly_name="umask"
    local required_value="0027"

    if [ -e "$file" ]; then
        local decimal_umask="$(defaults read "$file" Umask)"
        setting_value="$(bc <<< "obase=8;$decimal_umask")"
    fi

    if [ "$print_flag" != "" ]; then
        echo "$friendly_name is $setting_value";
    fi


    if [ "$set_flag" != "" ]; then
        # only modify the setting if it is not already set
        case $profile_flag in
            "ent")
                if [ "$setting_value" != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value"
                    $setting_name $required_value
                else
                    echo "$friendly_name is already set to $required_value"
                fi
                ;;
            "soho")
                if [ "$setting_value" != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value"
                    $setting_name $required_value
                else
                    echo "$friendly_name is already set to $required_value"
                fi
                ;;
            "sslf")
                if [ "$setting_value" != "$required_value" ]; then
                    echo "setting $friendly_name to $required_value"
                    $setting_name $required_value
                else
                    echo "$friendly_name is already set to $required_value"
                fi
                ;;
            "oem")
                if [ "$setting_value" != "$oem_value" ]; then
                    echo "setting $friendly_name to $oem_value"
                    $setting_name $oem_value
                else
                    echo "$friendly_name is already set to $oem_value"
                fi
                ;;
        esac
    fi

#Worked after restart. Note that the umask value stored in the 
#/private/var/db/com.apple.xpc.launchd/config/user.plist file is in base 10, not octal. The
#value is reported normally when using the `umask` command to see the current state.

#macOS 10.12 testing
#must restart for the setting to take effect. Reading the setting value will not be accurate
#if a restart has not been performed after changing the value.
}


######################################################################
CCE_79405_7_check_system_integrity_protection_status () {
   local doc="CCE_79405_7_check_system_integrity_protection_status    (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="/System/Library/Sandbox/rootless.conf"
    local friendly_name="System Integrity Protection"
    
    if [ "$print_flag" != "" ]; then
        local result="$(csrutil status | egrep -io "(enabled|disabled)")"
        echo "$friendly_name is $result"

        #only print the config file if SIP is turned on
        if [ "$result" == "enabled" ] && [ "$v_flag" != "" ]; then
            echo "The following files and directories are protected by $friendly_name"
            cat $file
        fi
    fi

    #Since this can only be changed in recovery mode, nothing is changed here
    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "$friendly_name can only be toggled from the recovery mode using the commands: csrutil enable; csrutil disable"
                ;;
            "soho")
                echo "$friendly_name can only be toggled from the recovery mode using the commands: csrutil enable; csrutil disable"
                ;;
            "sslf")
	        echo "$friendly_name can only be toggled from the recovery mode using the commands: csrutil enable; csrutil disable"
                ;;
            "oem")
	        echo "$friendly_name can only be toggled from the recovery mode using the commands: csrutil enable; csrutil disable"
                ;;
        esac
    fi

#macOS 10.12 testing
#Prints the current state of SIP.
}


######################################################################
CCE_79409_9_user_home_directories_permissions () {
   local doc="CCE_79409_9_user_home_directories_permissions        (manual-test-PASSED)"
    if [ "$list_flag" != "" ]; then echo "$doc"; fi

    local file="$home_path/"
    local friendly_name="home directory permissions"
    local required_value="700"

    
    if [ "$print_flag" != "" ]; then
        echo "$friendly_name are the following:"
        stat -f "Path: %N   Permissions: %Lp" "$file"
    fi


    if [ "$set_flag" != "" ]; then
        case $profile_flag in
            "ent")
                echo "setting $friendly_name to $required_value"
                set_max_file_permission "$file" "" "" "$required_value"
                ;;
            "soho")
                echo "setting $friendly_name to $required_value"
                set_max_file_permission "$file" "" "" "$required_value"
                ;;
            "sslf")
                echo "setting $friendly_name to $required_value"
                set_max_file_permission "$file" "" "" "$required_value"
                ;;
            "oem")
                echo "$friendly_name are unchanged"
                ;;
        esac
    fi

#macOS 10.12 testing
#Works immediately.
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

    if [ "$profile_flag" == "" ]; then 
        profile_flag="ent" 
    fi
}

######################################################################
main $@ # Runs the main function and passes the command-line arguments.
        # Runs after all the other functions are defined, so no forward
        #      declarations are needed.
