import argparse, json, os, re, shutil, sys, time, threading
from pathlib import Path
from datetime import datetime
from colorama import init as colorama_init, Fore, Style
from ap_model import (
    AP_STORE, AP_STORE_LOCK, APInfo, 
    cleanup_stale_aps, get_danger_level_name, update_ap_store
)
import nic_manager, packet_sniffer

colorama_init(autoreset=True)
STOP_EVENT = threading.Event()
_SCRIPT_DIR = Path(__file__).resolve().parent
WHITELIST_PATH = _SCRIPT_DIR / "known_networks.json"

# Signatures SSIDs
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
            # 1. Reset & Whitelist
            if bssid in whitelist:
                ap.danger_score = 0
                ap.is_evil_twin = False
                continue

            # 2. Suspect SSID
            ap.suspect_ssid = any(p.search(ap.ssid) for p in SUSPECT_SSID_PATTERNS)
            
            # 3. Duplicate Detection
            if ap.ssid not in ["Hidden/Unknown", ""]:
                if ap.ssid not in ssid_map: ssid_map[ap.ssid] = []
                ssid_map[ap.ssid].append(bssid)
            
            ap.calculate_danger_level()

        # Marquer les doublons
        for ssid, bssids in ssid_map.items():
            if len(bssids) > 1:
                for b in bssids:
                    AP_STORE[b].duplicate_ssid = True
                    AP_STORE[b].is_evil_twin = True

def display_aps():
    os.system("clear")
    print(f"{Fore.CYAN}{'='*105}")
    print(f"| GuardianWiFi Pro | SCANNING... | {datetime.now().strftime('%H:%M:%S')} | CTRL+C POUR QUITTER |")
    print(f"{Fore.CYAN}{'='*105}")
    header = f"| {'SSID':<25} | {'BSSID':<17} | {'CH':<3} | {'RSSI':<4} | {'SCORE':<5} | {'NIVEAU':<8} | {'REASON':<20} |"
    print(header)
    print("-" * 105)

    with AP_STORE_LOCK:
        aps = sorted(AP_STORE.values(), key=lambda x: x.rssi, reverse=True)
        for ap in aps:
            color = Fore.GREEN
            if ap.danger_score >= 4: color = Fore.RED + Style.BRIGHT
            elif ap.danger_score >= 2: color = Fore.YELLOW
            
            lvl = get_danger_level_name(ap.danger_score)
            reason = (ap.anomaly_reason or "")[:20]
            line = f"| {ap.ssid[:25]:<25} | {ap.bssid:<17} | {ap.channel:<3} | {ap.rssi:<4} | {ap.danger_score:<5} | {lvl:<8} | {reason:<20} |"
            print(f"{color}{line}")

    # Alertes de conflit en bas
    print(f"{Fore.CYAN}{'='*105}")
    with AP_STORE_LOCK:
        # Analyse des doublons pour affichage alerte
        checked_ssids = set()
        for ap in aps:
            if ap.duplicate_ssid and ap.ssid not in checked_ssids:
                print(f"{Fore.RED}{Style.BRIGHT}ALERTE : Plusieurs antennes diffusent le SSID [{ap.ssid}] ! RISQUE EVIL TWIN.")
                checked_ssids.add(ap.ssid)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", default="wlan0")
    parser.add_argument("-c", "--channels", default="1-13")
    args = parser.parse_args()

    # Parsing canaux
    if "-" in args.channels:
        low, high = map(int, args.channels.split("-"))
        chans = list(range(low, high + 1))
    else:
        chans = [int(c) for c in args.channels.split(",")]

    nic_manager.INTERFACE_NAME = args.interface
    nic_manager.check_root()
    nic_manager.set_mode("monitor")

    # Lancement Threads
    threading.Thread(target=hopper_worker, args=(args.interface, chans), daemon=True).start()
    threading.Thread(target=packet_sniffer.start_sniffing, args=(args.interface, STOP_EVENT), daemon=True).start()

    try:
        while True:
            run_detection_check()
            display_aps()
            cleanup_stale_aps(60)
            time.sleep(1.5)
    except KeyboardInterrupt:
        print("\nArrêt en cours...")
        STOP_EVENT.set()
        nic_manager.cleanup()

if __name__ == "__main__":
    main()