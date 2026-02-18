import argparse
import json
import os
import re
import sys
import time
import threading
from pathlib import Path
from datetime import datetime
from colorama import init as colorama_init, Fore, Style
from plyer import notification

# Imports de nos modules locaux
from ap_model import *
import nic_manager
import packet_sniffer
import simulator
import logger
import GUI

# --- CONFIGURATION ET VARIABLES GLOBALES ---
colorama_init(autoreset=True)
STOP_EVENT = threading.Event()
LAST_NOTIFIED = {} 
_SCRIPT_DIR = Path(__file__).resolve().parent
WHITELIST_PATH = _SCRIPT_DIR / "known_networks.json"

# Patterns de noms suspect
SUSPECT_SSID_PATTERNS = [
    re.compile(r"free|gratuit|public|guest|orange|sfr|bouygues|starbucks|wifi", re.I),
    re.compile(r"pineapple|pwned|hack|captive", re.I)
]

def send_alert_notification(ap):
    """Envoie une notification sur le bureau Kali."""
    now = time.time()
    # On évite de spammer (1 alerte toutes les 5 minutes par BSSID)
    if ap.bssid not in LAST_NOTIFIED or (now - LAST_NOTIFIED[ap.bssid]) > 300:
        try:
            notification.notify(
                title="🛡️ GUARDIANWIFI : DANGER",
                message=f"Réseau Suspect : {ap.ssid}\nScore : {ap.danger_score}/10\nMotif : {ap.anomaly_reason}",
                timeout=5
            )
            LAST_NOTIFIED[ap.bssid] = now
        except Exception as e:
            pass

def run_detection_check():
    """Analyse les réseaux et calcule les scores."""
    whitelist = set()
    if WHITELIST_PATH.exists():
        try:
            data = json.loads(WHITELIST_PATH.read_text())
            whitelist = {b.upper() for b in data.get("bssids", [])}
        except: pass

    with AP_STORE_LOCK:
        # Extraire les noms des réseaux de confiance
        trusted_ssids = [ap.ssid for b, ap in AP_STORE.items() if b in whitelist]
        
        ssid_map = {}
        for bssid, ap in AP_STORE.items():
            if bssid in whitelist:
                ap.danger_score = 0
                continue

            # 1. Détection Typosquatting (Levenshtein)
            if ap.ssid != "Inconnu":
                for ts in trusted_ssids:
                    if ap.ssid != ts and levenshtein_distance(ap.ssid, ts) <= 2:
                        ap.similar_ssid = True

                # 2. Détection Doublons (Evil Twin)
                if ap.ssid not in ssid_map: ssid_map[ap.ssid] = []
                ssid_map[ap.ssid].append(bssid)
        
        for ssid, bssids in ssid_map.items():
            if len(bssids) > 1:
                for b in bssids:
                    if b not in whitelist: AP_STORE[b].duplicate_ssid = True

        # 3. Calcul final et Notification
        for ap in AP_STORE.values():
            old_score = ap.danger_score
            ap.calculate_danger_level()
            if ap.danger_score >= 4 and old_score < 4:
                send_alert_notification(ap)

def hopper_worker(iface):
    """Fait défiler les canaux Wi-Fi."""
    channels = [1, 6, 11, 1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
    idx = 0
    while not STOP_EVENT.is_set():
        nic_manager.set_channel(channels[idx % len(channels)])
        idx += 1
        time.sleep(0.4)

def display_aps():
    """Affiche le tableau dans le terminal."""
    os.system("clear")
    width = 110
    print(f"{Fore.CYAN}{'='*width}")
    print(f"🛡️  GUARDIANWIFI PRO | {datetime.now().strftime('%H:%M:%S')} | SCAN EN COURS...")
    print(f"{Fore.CYAN}{'='*width}")
    header = f"| {'SSID':<20} | {'BSSID':<18} | {'CH':<3} | {'RSSI':<5} | {'SCORE':<5} | {'REASON':<25} |"
    print(header)
    print("-" * width)

    with AP_STORE_LOCK:
        aps = sorted(AP_STORE.values(), key=lambda x: x.rssi, reverse=True)
        for ap in aps:
            color = Fore.GREEN
            if ap.danger_score >= 4: color = Fore.RED + Style.BRIGHT
            elif ap.danger_score >= 2: color = Fore.YELLOW
            
            line = f"| {ap.ssid[:20]:<20} | {ap.bssid:<18} | {ap.channel:<3} | {ap.rssi:<5} | {ap.danger_score:<5} | {str(ap.anomaly_reason)[:25]:<25} |"
            print(f"{color}{line}")
    print(f"{Fore.CYAN}{'='*width}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()

    try:
        if not args.simulate:
            nic_manager.check_root()
            iface = nic_manager.auto_setup_monitor()
            threading.Thread(target=packet_sniffer.start_sniffing, args=(iface, STOP_EVENT), daemon=True).start()
            threading.Thread(target=hopper_worker, args=(iface,), daemon=True).start()
        else:
            threading.Thread(target=simulator.start_simulation, args=(STOP_EVENT,), daemon=True).start()

        def detection_loop():
            while not STOP_EVENT.is_set():
                run_detection_check()
                cleanup_stale_aps(60)
                time.sleep(1.5)

        threading.Thread(target=detection_loop, daemon=True).start()

        if args.cli:
            while not STOP_EVENT.is_set():
                display_aps()
                time.sleep(1.5)
        else:
            GUI.start_gui(simulate=args.simulate)

    except KeyboardInterrupt:
        pass
    finally:
        STOP_EVENT.set()
        if not args.simulate: nic_manager.cleanup()
        print("\n[OK] Programme arrêté proprement.")

if __name__ == "__main__":
    main()