import subprocess
import os
import sys

INTERFACE_NAME = ""

def run_cmd(command: list):
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise OSError(f"Command failed: {' '.join(command)}")

def check_root():
    if os.geteuid() != 0:
        print("[CRITICAL] Sudo requis."); sys.exit(1)

def set_mode(mode: str):
    if not INTERFACE_NAME: return
    print(f"[NIC] Mode -> {mode}")
    run_cmd(["ip", "link", "set", INTERFACE_NAME, "down"])
    run_cmd(["iw", "dev", INTERFACE_NAME, "set", "type", mode])
    run_cmd(["ip", "link", "set", INTERFACE_NAME, "up"])

def set_channel(channel: int):
    if not INTERFACE_NAME: return
    try:
        run_cmd(["iw", "dev", INTERFACE_NAME, "set", "channel", str(channel)])
    except: pass

def cleanup():
    if INTERFACE_NAME:
        print("\n[CLEANUP] Restoration mode Managed...")
        try: set_mode("managed")
        except: pass