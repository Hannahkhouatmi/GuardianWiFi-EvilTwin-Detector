import subprocess, os, sys

# ICI : Mets le nom EXACT que tu vois après l'étape 1 (probablement wlan0mon)
INTERFACE_NAME = "wlan0mon" 

def check_root():
    if os.getuid() != 0:
        print("SUDO REQUIS"); sys.exit(1)

def auto_setup_monitor():
    # On ne fait plus rien ici, on considère que tu as lancé le mode moniteur à la main
    print(f"[*] Interface configurée sur : {INTERFACE_NAME}")
    return INTERFACE_NAME

def set_channel(channel):
    # Commande ultra-simple pour changer de canal
    subprocess.run(["iw", "dev", INTERFACE_NAME, "set", "channel", str(channel)], capture_output=True)

def cleanup():
    # On ne touche à rien à la fin pour ne pas perdre l'interface pendant la démo
    print("[*] Fin de session.")