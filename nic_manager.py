import subprocess
import os
import sys
import time

INTERFACE_NAME = "wlan0" # Remplace par le nom de TA carte (ex: wlan0 ou wlan1)

def run_cmd(command: list):
    try:
        # On utilise shell=False pour la sécurité
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERREUR] Commande échouée : {' '.join(command)}")
        return False
    return True

def auto_setup_monitor():
    """Active le mode moniteur automatiquement sur Kali Linux."""
    if os.geteuid() != 0:
        print("\n[!] ERREUR : Tu dois lancer le script avec SUDO.")
        sys.exit(1)

    print(f"[*] Configuration de {INTERFACE_NAME}...")

    # 1. Tuer les processus bloquants (airmon-ng check kill)
    print("[*] Nettoyage des processus gênants (NetworkManager...)")
    run_cmd(["airmon-ng", "check", "kill"])

    # 2. Passer en mode moniteur
    print(f"[*] Passage de {INTERFACE_NAME} en mode moniteur...")
    run_cmd(["ip", "link", "set", INTERFACE_NAME, "down"])
    run_cmd(["iw", "dev", INTERFACE_NAME, "set", "type", "monitor"])
    run_cmd(["ip", "link", "set", INTERFACE_NAME, "up"])
    
    print("[OK] Mode Moniteur activé.")
    time.sleep(1)

def cleanup():
    """Remet la carte en mode normal à la fin."""
    print(f"\n[*] Restauration de {INTERFACE_NAME} en mode Managed...")
    run_cmd(["ip", "link", "set", INTERFACE_NAME, "down"])
    run_cmd(["iw", "dev", INTERFACE_NAME, "set", "type", "managed"])
    run_cmd(["ip", "link", "set", INTERFACE_NAME, "up"])
    print("[*] Relance de NetworkManager...")
    run_cmd(["systemctl", "restart", "NetworkManager"])
    print("[OK] Système restauré.")