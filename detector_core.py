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
from ap_model import (
    AP_STORE, AP_STORE_LOCK, APInfo, 
    cleanup_stale_aps, get_danger_level_name, update_ap_store,
    levenshtein_distance
)
import nic_manager
import packet_sniffer
import simulator
import logger, GUI

# Initialisation
colorama_init(autoreset=True)
STOP_EVENT = threading.Event()
LAST_NOTIFIED = {} # Pour éviter de spammer les notifications
_SCRIPT_DIR = Path(__file__).resolve().parent
WHITELIST_PATH = _SCRIPT_DIR / "known_networks.json"

# Patterns de noms de réseaux souvent utilisés par les pirates
SUSPECT_SSID_PATTERNS = [
    re.compile(r"free|gratuit|public|guest|orange|sfr|bouygues|starbucks|mcdonald|hotel|airport", re.I),
    re.compile(r"captive|portal|login|signin|linksys|default|netgear|wifi", re.I),
    re.compile(r"pineapple|pwned|hack", re.I)
]

def load_whitelist():
    """Charge les BSSIDs de confiance depuis le fichier JSON."""
    if not WHITELIST_PATH.exists():
        WHITELIST_PATH.write_text(json.dumps({"bssids": []}), encoding="utf-8")
        return set()
    try:
        data = json.loads(WHITELIST_PATH.read_text(encoding="utf-8"))
        return {str(b).strip().upper() for b in data.get("bssids", [])}
    except:
        return set()

def send_alert_notification(ap):
    """Envoie une notification système en cas de danger critique."""
    now = time.time()
    
    # DEBUG : Pour voir dans le terminal si la fonction est déclenchée
    # print(f"[DEBUG] Tentative d'alerte pour {ap.ssid} (Score: {ap.danger_score})")

    if ap.bssid not in LAST_NOTIFIED or (now - LAST_NOTIFIED[ap.bssid]) > 300:
        try:
            # On simplifie l'appel plyer pour Linux
            notification.notify(
                title="ALERTE GUARDIANWIFI",
                message=f"Réseau Suspect: {ap.ssid}\nScore: {ap.danger_score}/10",
                timeout=5
            )
            LAST_NOTIFIED[ap.bssid] = now
            # print(f"[DEBUG] Notification envoyée avec succès.")
        except Exception as e:
            print(f"[ERREUR NOTIFICATION] {e}")

def hopper_worker(interface, channels):
    """Change de canal Wi-Fi régulièrement (Channel Hopping)."""
    idx = 0
    while not STOP_EVENT.is_set():
        nic_manager.set_channel(channels[idx % len(channels)])
        idx += 1
        time.sleep(0.5)

def run_detection_check():
    """Analyse tous les APs pour détecter les anomalies et calculer les scores."""
    whitelist_bssids = load_whitelist()

    with AP_STORE_LOCK:
        # On récupère les noms des réseaux de confiance pour la détection Levenshtein
        known_ssids = [
            ap.ssid for b, ap in AP_STORE.items() 
            if b in whitelist_bssids and ap.ssid not in ["Hidden/Unknown", ""]
        ]
        
        ssid_map = {} # Pour détecter les doublons exacts

        for bssid, ap in AP_STORE.items():
            # 1. Reset si Whitelist
            if bssid in whitelist_bssids:
                ap.danger_score = 0
                ap.is_evil_twin = False
                continue

            # 2. Détection Pattern Suspect
            ap.suspect_ssid = any(p.search(ap.ssid) for p in SUSPECT_SSID_PATTERNS)
            
            # 3. Détection Imitation (Levenshtein)
            ap.similar_ssid = False
            if ap.ssid not in ["Hidden/Unknown", ""]:
                for target_ssid in known_ssids:
                    if ap.ssid != target_ssid:
                        dist = levenshtein_distance(ap.ssid, target_ssid)
                        if 1 <= dist <= 2:
                            ap.similar_ssid = True
                            break

            # 4. Préparation Doublons
            if ap.ssid not in ["Hidden/Unknown", ""]:
                if ap.ssid not in ssid_map: ssid_map[ap.ssid] = []
                ssid_map[ap.ssid].append(bssid)
            
            # 5. Calcul Final du Score
            ap.calculate_danger_level()

            # 6. Notification si score critique
            if ap.danger_score >= 4:
                send_alert_notification(ap)

        # 7. Marquage des doublons SSID
        for ssid, bssids in ssid_map.items():
            if len(bssids) > 1:
                for b in bssids:
                    if b not in whitelist_bssids:
                        AP_STORE[b].duplicate_ssid = True
                        AP_STORE[b].is_evil_twin = True

def display_aps():
    os.system("clear" if os.name == "posix" else "cls")
    width = 125
    
    # Header principal
    print(f"{Fore.CYAN}{'='*width}")
    print(f"| GuardianWiFi Pro | SCANNING... | {datetime.now().strftime('%H:%M:%S')} | CTRL+C POUR QUITTER |")
    print(f"{Fore.CYAN}{'='*width}")
    
    # En-tête du tableau
    header = f"| {'SSID':<20} | {'BSSID':<17} | {'VENDOR':<15} | {'CH':<3} | {'RSSI':<4} | {'SCORE':<5} | {'REASON':<20} |"
    print(header)
    print("-" * width)

    # Affichage des lignes du tableau
    with AP_STORE_LOCK:
        # On trie par RSSI pour voir les plus proches
        aps = sorted(AP_STORE.values(), key=lambda x: x.rssi, reverse=True)
        for ap in aps:
            color = Fore.GREEN
            if ap.danger_score >= 4: 
                color = Fore.RED + Style.BRIGHT
            elif ap.danger_score >= 2: 
                color = Fore.YELLOW
            
            s_name = ap.ssid[:20]
            v_name = ap.vendor[:15]
            reason = str(ap.anomaly_reason or "Normal")[:20]
            
            line = f"| {s_name:<20} | {ap.bssid:<17} | {v_name:<15} | {ap.channel:<3} | {ap.rssi:<4} | {ap.danger_score:<5} | {reason:<20} |"
            print(f"{color}{line}")

    print(f"{Fore.CYAN}{'='*width}")

    alerts_found = []
    with AP_STORE_LOCK:
        for ap in aps:
            if ap.danger_score >= 4:
                # On prépare le message d'alerte
                msg = f"!!! ATTENTION : {ap.ssid} ({ap.bssid}) -> {ap.anomaly_reason} !!!"
                alerts_found.append(msg)

    if alerts_found:
        print(f"\n{Fore.RED}{Style.BRIGHT}{'#'*width}")
        print(f"{Fore.RED}{Style.BRIGHT}  ZONES DE DANGER DÉTECTÉES :")
        for a in alerts_found:
            print(f"{Fore.RED}{Style.BRIGHT}  [!] {a}")
        print(f"{Fore.RED}{Style.BRIGHT}{'#'*width}")
    else:
        print(f"\n{Fore.GREEN}[OK] Aucun danger critique détecté dans la zone.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--cli", action="store_true", help="Lancer en mode Terminal au lieu de GUI")
    args = parser.parse_args()

    try:
        # --- 1. INITIALISATION DU MATÉRIEL ---
        if not args.simulate:
            nic_manager.check_root() # Vérifie si on est root
            nic_manager.auto_setup_monitor() # Active le mode moniteur auto
            iface = nic_manager.INTERFACE_NAME
            print(f"[*] Sniffing actif sur l'interface : {iface}")
            threading.Thread(target=packet_sniffer.start_sniffing, args=(iface, STOP_EVENT), daemon=True).start()
        else:
            print("[*] Mode SIMULATION activé.")
            threading.Thread(target=simulator.start_simulation, args=(STOP_EVENT,), daemon=True).start()

        # --- 2. LANCEMENT DU MOTEUR DE DÉTECTION (Thread de calcul) ---
        def detection_loop():
            while not STOP_EVENT.is_set():
                run_detection_check()
                logger.logger_instance.log_aps(AP_STORE)
                cleanup_stale_aps(60)
                time.sleep(1.5)

        threading.Thread(target=detection_loop, daemon=True).start()

        # --- 3. CHOIX DU MODE D'AFFICHAGE (UI) ---
        if args.cli:
            print("[INFO] Lancement du mode Terminal (Appuyez sur CTRL+C pour quitter)")
            while True:
                display_aps()
                time.sleep(1.5)
        else:
            print("[INFO] Lancement de l'interface graphique...")
            GUI.start_gui(simulate=args.simulate)

    except KeyboardInterrupt:
        print("\n[!] Arrêt manuel détecté.")
    
    except Exception as e:
        print(f"\n[!] Erreur imprévue : {e}")

    finally:
        # --- 4. NETTOYAGE AUTOMATIQUE ---
        STOP_EVENT.set()
        if not args.simulate:
            nic_manager.cleanup()
        print("[OK] Fin du programme.")
        sys.exit(0)

if __name__ == "__main__":
    main()