import argparse, json, os, re, shutil, sys, time, threading
from pathlib import Path
from datetime import datetime
from colorama import init as colorama_init, Fore, Style
from ap_model import (
    AP_STORE, AP_STORE_LOCK, APInfo, 
    cleanup_stale_aps, get_danger_level_name, update_ap_store
)
import nic_manager, packet_sniffer, simulator, logger # Ajout de simulator et logger
colorama_init(autoreset=True)
STOP_EVENT = threading.Event()
_SCRIPT_DIR = Path(__file__).resolve().parent
WHITELIST_PATH = _SCRIPT_DIR / "known_networks.json"

SUSPECT_SSID_PATTERNS = [
    re.compile(r"free|gratuit|public|guest|orange|sfr|bouygues|starbucks|mcdonald|hotel|airport", re.I),
    re.compile(r"captive|portal|login|signin|linksys|default|netgear|wifi", re.I)
]

def load_whitelist():
    if not WHITELIST_PATH.exists():
        WHITELIST_PATH.write_text(json.dumps({"bssids": []}), encoding="utf-8")
        return set()
    try:
        data = json.loads(WHITELIST_PATH.read_text(encoding="utf-8"))
        return {str(b).strip().upper() for b in data.get("bssids", [])}
    except: return set()

def hopper_worker(interface, channels):
    idx = 0
    while not STOP_EVENT.is_set():
        nic_manager.set_channel(channels[idx % len(channels)])
        idx += 1
        time.sleep(2.5)

def run_detection_check():
    whitelist = load_whitelist()
    with AP_STORE_LOCK:
        ssid_map = {}
        for bssid, ap in AP_STORE.items():
            if bssid in whitelist:
                ap.danger_score = 0
                ap.is_evil_twin = False
                continue

            ap.suspect_ssid = any(p.search(ap.ssid) for p in SUSPECT_SSID_PATTERNS)
            
            if ap.ssid not in ["Hidden/Unknown", ""]:
                if ap.ssid not in ssid_map: ssid_map[ap.ssid] = []
                ssid_map[ap.ssid].append(bssid)
            
            ap.calculate_danger_level()

        for ssid, bssids in ssid_map.items():
            if len(bssids) > 1:
                for b in bssids:
                    AP_STORE[b].duplicate_ssid = True
                    # On marque comme Evil Twin seulement si ce n'est pas dans la whitelist
                    if b not in whitelist:
                        AP_STORE[b].is_evil_twin = True

def display_aps():
    # Nettoyage de l'écran (s'adapte à Windows ou Linux)
    os.system("clear" if os.name == "posix" else "cls")

    # Largeur totale du tableau
    width = 120
    
    print(f"{Fore.CYAN}{'='*width}")
    print(f"| GuardianWiFi Pro | SCANNING... | {datetime.now().strftime('%H:%M:%S')} | CTRL+C POUR QUITTER |")
    print(f"{Fore.CYAN}{'='*width}")

    # En-tête des colonnes
    header = f"| {'SSID':<20} | {'BSSID':<17} | {'VENDOR':<15} | {'CH':<3} | {'RSSI':<4} | {'SCORE':<5} | {'NIVEAU':<8} |"
    print(header)
    print("-" * width)

    with AP_STORE_LOCK:
        # On trie les réseaux par puissance de signal (RSSI) pour voir les plus proches en haut
        aps = sorted(AP_STORE.values(), key=lambda x: x.rssi, reverse=True)
        
        for ap in aps:
            # Choix de la couleur selon le score de danger
            color = Fore.GREEN
            if ap.danger_score >= 4:
                color = Fore.RED + Style.BRIGHT
            elif ap.danger_score >= 2:
                color = Fore.YELLOW
            
            # Traduction du score en texte (Faible, Modéré, Critique)
            lvl = get_danger_level_name(ap.danger_score)
            
            # On tronque le SSID et le Vendor s'ils sont trop longs pour l'affichage
            s_name = (ap.ssid[:20] if ap.ssid else "Hidden/Unknown")
            v_name = (ap.vendor[:15] if ap.vendor else "Unknown")
            
            # Création de la ligne formatée
            line = f"| {s_name:<20} | {ap.bssid:<17} | {v_name:<15} | {ap.channel:<3} | {ap.rssi:<4} | {ap.danger_score:<5} | {lvl:<8} |"
            print(f"{color}{line}")

    # Pied de tableau
    print(f"{Fore.CYAN}{'='*width}")

    # Zone d'alertes textuelles (s'affiche uniquement si un danger est détecté)
    with AP_STORE_LOCK:
        checked_ssids = set()
        for ap in aps:
            if ap.duplicate_ssid and ap.ssid not in checked_ssids:
                if ap.ssid not in ["Hidden/Unknown", ""]:
                    print(f"{Fore.RED}{Style.BRIGHT}!! ALERTE CRITIQUE : Le SSID [{ap.ssid}] est diffusé par plusieurs antennes.")
                    print(f"{Fore.RED}   -> Cela indique une attaque Evil Twin en cours !")
                    checked_ssids.add(ap.ssid)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", default="wlan0mon")
    parser.add_argument("-c", "--channels", default="1-13")
    parser.add_argument("--simulate", action="store_true", help="Lancer en mode simulation (sans carte Wi-Fi)")
    args = parser.parse_args()

    if args.simulate:
        print(f"{Fore.YELLOW}[MODE SIMULATION] Démarrage sans matériel...")
        # Lance le simulateur au lieu du vrai sniffer
        threading.Thread(target=simulator.start_simulation, args=(STOP_EVENT,), daemon=True).start()
    else:
        # Mode réel : nécessite root et interface moniteur
        if "-" in args.channels:
            low, high = map(int, args.channels.split("-"))
            chans = list(range(low, high + 1))
        else:
            chans = [int(c) for c in args.channels.split(",")]

        nic_manager.INTERFACE_NAME = args.interface
        nic_manager.check_root()
        nic_manager.set_mode("monitor")

        threading.Thread(target=hopper_worker, args=(args.interface, chans), daemon=True).start()
        threading.Thread(target=packet_sniffer.start_sniffing, args=(args.interface, STOP_EVENT), daemon=True).start()

    try:
        while True:
            run_detection_check()
            display_aps()
            with AP_STORE_LOCK:
                logger.logger_instance.log_aps(AP_STORE) # <--- AJOUT
                
            cleanup_stale_aps(60)
            time.sleep(1.5)
    except KeyboardInterrupt:
            cleanup_stale_aps(60)
            time.sleep(1.5)
    except KeyboardInterrupt:
        print("\nArrêt en cours...")
        STOP_EVENT.set()
        if not args.simulate:
            nic_manager.cleanup()

if __name__ == "__main__":
    main()