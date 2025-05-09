"""
This script is used to run a python file with low integrity level.

How to use:
- First activate venv
- Reinstall requirements.txt (pip install -r requirements.txt)
  - Or install pywin32 manually (pip install pywin32)
- Run the main server through this sandbox script:
python sandbox.py main.py --temp_dir temp --allowed_dir output --allowed_dir user --allowed_dir input

This will run main.py in a python process with low integrity level.
--temp_dir creates a temp directory and deletes if after execution. This used to
be done in main.py, but low integrity process cannot create directories in
arbitrary locations, hence moved to sandbox code.
--allowed_dir gives the process write access to the specified directory (can be
specified multiple times for multiple directories).

By default the low integrity process has read access to the entire file system,
but write access only to directories provided in --temp_dir and --allowed_dir.

This is for demo only - final design will vary.
"""

import win32event
import win32security
import win32process
import win32con
import win32api
import sys
import argparse
import subprocess
import os
import shutil


LOW_INTEGRITY_SID_STRING = "S-1-16-4096"


def get_process_integrity_level(token):
    token_info = win32security.GetTokenInformation(
        token, win32security.TokenIntegrityLevel
    )
    return token_info[0]


def get_current_process_token():
    # Get current process handle
    current_process = win32process.GetCurrentProcess()

    # Open process token
    token = win32security.OpenProcessToken(
        current_process,
        win32con.TOKEN_QUERY | win32con.TOKEN_QUERY_SOURCE | win32con.TOKEN_DUPLICATE,
    )

    # Get token information
    token_info = win32security.GetTokenInformation(token, win32security.TokenUser)

    # Convert SID to string
    sid_string = win32security.ConvertSidToStringSid(token_info[0])

    return token, sid_string


def duplicate_token(original_token):
    # Duplicate the token with the same access level
    duplicated_token = win32security.DuplicateTokenEx(
        original_token,
        win32security.SecurityImpersonation,
        win32security.TOKEN_ALL_ACCESS,
        win32security.TokenPrimary,
    )

    # Get token information for the duplicated token
    token_info = win32security.GetTokenInformation(
        duplicated_token, win32security.TokenUser
    )

    # Convert SID to string
    sid_string = win32security.ConvertSidToStringSid(token_info[0])

    return duplicated_token, sid_string


def set_token_integrity_level(token):
    sid = win32security.ConvertStringSidToSid(LOW_INTEGRITY_SID_STRING)
    attributes = win32security.SE_GROUP_INTEGRITY

    # Set the integrity level of the token
    win32security.SetTokenInformation(
        token, win32security.TokenIntegrityLevel, (sid, 0)
    )


def create_process_with_token(token, command_line):
    print(f"\nAttempting to create process: {command_line}")
    process_info = win32process.CreateProcessAsUser(
        token,
        None,  # appName
        command_line,  # commandLine
        None,  # processAttributes
        None,  # threadAttributes
        True,  # bInheritHandles
        # win32process.CREATE_NEW_CONSOLE,  # dwCreationFlags
        0,
        None,  # newEnvironment
        None,  # currentDirectory
        win32process.STARTUPINFO(),  # startupInfo
    )
    print("Process created")
    hProcess, hThread, dwProcessId, dwThreadId = process_info

    try:
        win32event.WaitForSingleObject(hProcess, win32event.INFINITE)
    except:
        print("Process exited")


def set_integrity_level(directory, level):
    # Run icacls to set directory integrity level to low
    print(f"Setting integrity level of {directory} to {level}")
    if not os.path.exists(directory):
        print(f"Directory {directory} does not exist, creating it")
        os.makedirs(directory)
    result = subprocess.run(
        ["icacls.exe", directory, "/setintegritylevel", level],
        check=True,
        capture_output=True,
        text=True,
    )
    print(result.stdout)


def create_temp_directory(directory):
    print(f"Creating temp directory {directory}")
    os.makedirs(directory, exist_ok=True)
    set_integrity_level(directory, "low")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Run a command with low integrity level."
    )
    parser.add_argument("python_file", type=str, help="The python file to execute.")
    parser.add_argument(
        "--allowed_dir",
        type=str,
        action="append",
        help="Allow access to this directory. Can be specified multiple times.",
    )
    parser.add_argument(
        "--temp_dir",
        type=str,
        action="append",
        help="Create this temp directory. Deleted after execution. Can be specified multiple times.",
    )
    args = parser.parse_args()
    command_to_run = f'"{sys.executable}" "{args.python_file}"'

    if args.allowed_dir:
        for allowed_dir in args.allowed_dir:
            set_integrity_level(allowed_dir, "low")

    if args.temp_dir:
        for temp_dir in args.temp_dir:
            create_temp_directory(temp_dir)

    # Get original token
    original_token, original_sid = get_current_process_token()
    print(f"Original Process Token (SID): {original_sid}")
    print(
        "Original token integrity level: ", get_process_integrity_level(original_token)
    )

    # Duplicate the token
    duplicated_token, duplicated_sid = duplicate_token(original_token)
    print(f"Duplicated Token (SID): {duplicated_sid}")
    # Set the integrity level of the duplicated token
    set_token_integrity_level(duplicated_token)
    print(
        "Duplicated token integrity level: ",
        get_process_integrity_level(duplicated_token),
    )

    # Create a new process with the duplicated token
    create_process_with_token(duplicated_token, command_to_run)

    # Clean up
    original_token.Close()
    duplicated_token.Close()

    print("Reverting back directories to original integrity level")
    if args.allowed_dir:
        for allowed_dir in args.allowed_dir:
            set_integrity_level(allowed_dir, "medium")

    if args.temp_dir:
        for temp_dir in args.temp_dir:
            print(f"Deleting temp directory {temp_dir}")
            try:
                shutil.rmtree(temp_dir)
            except FileNotFoundError:
                print(f"Warning: Temp directory {temp_dir} does not exist")
