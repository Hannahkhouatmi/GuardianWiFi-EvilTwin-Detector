# nic_manager.py

import subprocess
import os
import sys

INTERFACE_NAME = "" # To be set in detector_core

def check_root():
    """Ensure the script is run with root privileges (required for NIC control)."""
    if os.geteuid() != 0:
        print("[CRITICAL] This script requires root privileges (sudo) for interface manipulation.")
        sys.exit(1)

def run_cmd(command: list):
    """Executes a shell command robustly, raising an error on failure."""
    try:
        # Use check=True to raise CalledProcessError on non-zero exit code
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {' '.join(command)}")
        print(f"        Stderr: {e.stderr.strip()}")
        raise
    except FileNotFoundError:
        print(f"[ERROR] Required command not found: {command[0]}. Is 'iw' or 'ip' installed?")
        sys.exit(1)

def set_mode(mode: str):
    """
    Switches the interface mode (e.g., 'monitor' or 'managed').
    """
    if not INTERFACE_NAME:
        raise ValueError("INTERFACE_NAME is not set.")
        
    print(f"[NIC] Setting interface {INTERFACE_NAME} to mode '{mode}'...")
    
    # 1. Bring interface down
    run_cmd(["ip", "link", "set", INTERFACE_NAME, "down"])
    
    # 2. Set the type/mode
    run_cmd(["iw", "dev", INTERFACE_NAME, "set", "type", mode])
    
    # 3. Bring interface up
    run_cmd(["ip", "link", "set", INTERFACE_NAME, "up"])
    
    print(f"[NIC] Interface {INTERFACE_NAME} is now in '{mode}' mode.")

def set_channel(channel: int):
    """
    Sets the operating channel for the interface.
    """
    if not INTERFACE_NAME:
        raise ValueError("INTERFACE_NAME is not set.")

    # Using 'iw' to set the channel on the monitor interface
    run_cmd(["iw", "dev", INTERFACE_NAME, "set", "channel", str(channel)])
    # print(f"[NIC] Channel set to {channel}.") # Keep quiet for hopping loop

def cleanup():
    """
    CRITICAL: Returns the interface to 'managed' mode and ensures it is up.
    This must be called in a finally block in the main script.
    """
    if not INTERFACE_NAME:
        return # Nothing to clean up
        
    print("\n[CLEANUP] Restoring interface to 'managed' mode...")
    try:
        # Set back to managed mode
        set_mode("managed")
        print("[CLEANUP] Successfully restored.")
    except Exception as e:
        print(f"[CLEANUP ERROR] Failed to restore {INTERFACE_NAME}: {e}")