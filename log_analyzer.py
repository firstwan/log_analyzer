#!/usr/bin/python3
import os
import re
import sys
import argparse

new_user = []
change_pass = []
delete_user = []
user_switch = []
all_cmd = []

DEFAULT_LOG_FILE_PATH = "/var/log/auth.log"

# Options for this script
def option_menu():
    parser = argparse.ArgumentParser(description="Auth log analyzer")
    parser.add_argument('-f', "--file", metavar="<file>", default=None, help="Path of auth.log file. Default path is '/var/log/auth.log'")

    return parser.parse_args()

# Extract the datetime from the line of log
def extract_datetime(log):
    log_date = re.search(r"^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}", log);
    if log_date:
        return log_date.group()
    else:
        return log.split()[0]

def log_parse(log_content):
    for log in log_content:
        if "new user" in log:                                                       # New user
            details = re.search(r"(\bnew user: )(.+$)", log)
            new_user.append((extract_datetime(log), details.group(2)))
        elif "password changed" in log:                                             # Change password
            change_pass.append((extract_datetime(log), log.split()[-1]))
        elif "delete user" in log:                                                  # Delete user
            delete_user.append((extract_datetime(log), log.split()[-1]))
        elif "pam_unix(su:session): session opened" in log:                         # Switch user
            from_usr = re.search(r"(by )(\w+)" ,log).group(2)
            switch_to = log.split()[-3]
            user_switch.append((extract_datetime(log), from_usr, switch_to, True))
        elif "su:auth): authentication failure;" in log:                            # Failed to switch user
            from_usr = re.search(r'(\bruser=)(\w+)', log).group(2)
            switch_to = re.search(r'(\buser=)(\w+)', log).group(2)
            user_switch.append((extract_datetime(log), from_usr, switch_to, False))
        elif "sudo:" in log and "pam_unix" not in log:                              # Sudo command
            line = re.search(r'(sudo:\s+)(\w+) : (.+$)', log)
            execute_by = line.group(2)
            details = line.group(3)

            all_cmd.append((extract_datetime(log), execute_by, details, False if "incorrect password attempts" in log else True))


def main():
    args = option_menu()

    # Require proper privilege to access /var/log/auth.log
    if os.getuid() != 0 and args.file is None:
        print("[!] Require proper privilege to access auth log file. Pls try run with SUDO command.")
        sys.exit(1)

    # Decide which file to read
    log_file_path = DEFAULT_LOG_FILE_PATH if args.file is None else args.file

    # Read the log file
    try:
        with open(log_file_path, 'r') as file:
            file_content = file.readlines()
    except Exception as ex:
        print("[!] Failed open the file: {}".format(ex))
        sys.exit(1)

    # Extract information from log content
    log_parse(file_content)

    print("[#] All command in auth.log")
    print("=========================================================================")

    for item in all_cmd:
        cmd = re.search(r"(\bCOMMAND=)(.+$)", item[2])
        print("[+] Datetime: {}, Executed by: {}, Command: {}".format(item[0], item[1], cmd.group(2)))

    print()
    print("[#] Newly added users")
    print("=========================================================================")
    for item in new_user:
        print("[+] Datetime: {}, {}".format(item[0], item[1]))

    print()
    print("[#] Users who changed password")
    print("=========================================================================")
    for item in change_pass:
        print("[+] Datetime: {}, Username: {}".format(item[0], item[1]))


    print()
    print("[#] Deleted users")
    print("=========================================================================")
    for item in delete_user:
        print("[+] Datetime: {}, Username: {}".format(item[0], item[1]))

    print()
    print("[#] User that run su command switch to other user")
    print("=========================================================================")
    for item in user_switch:
        print("[+] Datetime: {}, From user: {}, Switch to: {}, Is successful: {}".format(item[0], item[1], item[2], item[3]))

    print()
    print("[#] User that run sudo command")
    print("=========================================================================")
    for item in all_cmd:
        if item[3]:
            print("[+] Datetime: {}, Executed by: {}, Details: {}".format(item[0], item[1], item[2].replace(" ;", ",")))

    print()
    print("[!!!] ALLERT! User tried to run sudo command but failed to authenticate")
    print("=========================================================================")
    for item in all_cmd:
        if not item[3]:
            print("[+] Datetime: {}, Executed by: {}, Details: {}".format(item[0], item[1], item[2].replace(" ;", ",")))


main()