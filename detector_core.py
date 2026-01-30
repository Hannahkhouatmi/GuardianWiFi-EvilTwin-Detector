# detector_core.py

import argparse
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Dict, List, Pattern, Set

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    Fore = type("Fore", (), {k: "" for k in ("GREEN", "YELLOW", "RED", "RESET", "CYAN", "MAGENTA")})()
    Style = type("Style", (), {"BRIGHT": "", "RESET_ALL": "", "DIM": ""})()

import nic_manager
import packet_sniffer
from ap_model import (
    AP_STORE,
    AP_STORE_LOCK,
    CHANNELS,
    APInfo,
    cleanup_stale_aps,
    get_danger_level_name,
)

from datetime import datetime

# --- Configuration (surchargées par argparse) ---
INTERFACE = "wlan0"
SCAN_DURATION_PER_CHANNEL = 3
# [SARA] Âge max (secondes) pour le nettoyage des AP non revus
CLEANUP_STALE_SECONDS = 60.0

# Fichier des réseaux de confiance (BSSIDs whitelistés)
_SCRIPT_DIR = Path(__file__).resolve().parent
WHITELIST_PATH = _SCRIPT_DIR / "known_networks.json"

# --- Signatures SSID suspects (portails captifs / noms type WiFi Pineapple) ---
SUSPECT_SSID_SIGNATURES: Set[str] = {
    "Free Public WiFi",
    "Starbucks_Guest",
    "Starbucks Guest",
    "Orange_Open",
    "Orange Open",
    "Guest_Access",
    "Guest Access",
    "Airport_Free_WiFi",
    "McDonald's Free WiFi",
    "Hotel_Guest",
    "Train WiFi",
    "TGV WiFi",
    "SNCF WiFi",
    "Captive Portal",
    "Free WiFi",
    "Public WiFi",
    "AttWiFi",
    "xfinitywifi",
    "Boingo Hotspot",
    "Wayport_Access",
    "linksys",
    "default",
    "wifi",
    "Wireless",
    "NETGEAR",
    "TP-LINK_Guest",
}

# Patterns regex pour noms imitant portails captifs / génériques (WiFi Pineapple, etc.)
# re.IGNORECASE utilisé à la place de (?i) (invalide en Python 3.11+ si non en tout début)
_FLAGS_ICASE = re.IGNORECASE
SUSPECT_SSID_PATTERNS: List[Pattern[str]] = [
    re.compile(r"^(free|gratuit|guest|public)\s*(wifi|wi-?fi|wireless)", _FLAGS_ICASE),
    re.compile(r"^(starbucks|mcdonald|hotel|airport|train|tgv|sncf)\s*[-_]?\s*(guest|wifi|free)?", _FLAGS_ICASE),
    re.compile(r"^(orange|sfr|bouygues|free)\s*[-_]?\s*(open|wifi|mobile)?", _FLAGS_ICASE),
    re.compile(r"^captive[-_]?portal", _FLAGS_ICASE),
    re.compile(r"^(connect|login|signin)[-_]?(wifi|network|here)", _FLAGS_ICASE),
    re.compile(r"^(att|xfinity|boingo|wayport)[-_]?(wifi|hotspot|access)?", _FLAGS_ICASE),
    re.compile(r"^(linksys|netgear|tp[-_]?link|d[-_]?link)[-_]?(guest|default)?", _FLAGS_ICASE),
    re.compile(r"^(default|wifi|wireless)$", _FLAGS_ICASE),
]


def is_suspect_ssid(ssid: str) -> bool:
    """
    [HANNAH - DÉTECTION FAUX SSIDs]
    Filtre par signatures exactes et regex : SSIDs imitant portails captifs
    ou noms génériques souvent utilisés par outils type WiFi Pineapple.
    Léger (set + regex courtes) pour temps réel.
    """
    if not ssid or ssid.strip() == "" or ssid == "Hidden/Unknown":
        return False
    ssid_stripped = ssid.strip()
    if ssid_stripped in SUSPECT_SSID_SIGNATURES:
        return True
    for pat in SUSPECT_SSID_PATTERNS:
        if pat.search(ssid_stripped):
            return True
    return False


def load_whitelist() -> Set[str]:
    """
    Charge la liste des BSSIDs de confiance depuis known_networks.json.
    Si le fichier n'existe pas, le crée avec une liste vide.
    Retourne un set de BSSIDs en majuscules.
    """
    default_content: Dict[str, List[str]] = {"bssids": []}
    if not WHITELIST_PATH.exists():
        try:
            WHITELIST_PATH.write_text(json.dumps(default_content, indent=2), encoding="utf-8")
        except OSError:
            pass
        return set()
    try:
        data = json.loads(WHITELIST_PATH.read_text(encoding="utf-8"))
        bssids = data.get("bssids", data if isinstance(data, list) else [])
        return {str(b).strip().upper() for b in bssids}
    except (json.JSONDecodeError, TypeError):
        return set()


def apply_whitelist(whitelist: Set[str]) -> None:
    """
    Si un BSSID est dans la whitelist, force danger_score = 0 et is_evil_twin = False
    pour éviter les faux positifs sur réseaux légitimes.
    """
    with AP_STORE_LOCK:
        for bssid in whitelist:
            if bssid in AP_STORE:
                ap = AP_STORE[bssid]
                ap.danger_score = 0
                ap.is_evil_twin = False


def parse_channels(channels_arg: str) -> List[int]:
    """
    [SARA] Parse l'argument -c : "1,6,11" ou "1-13" -> liste d'entiers.
    Valeurs invalides ignorées ; vide ou invalide -> défaut 1-13.
    """
    channels_arg = (channels_arg or "").strip()
    if not channels_arg:
        return list(CHANNELS)
    # Format "1-13"
    if "-" in channels_arg and "," not in channels_arg:
        parts = channels_arg.split("-", 1)
        try:
            low, high = int(parts[0].strip()), int(parts[1].strip())
            if low <= high and 1 <= low <= 14 and 1 <= high <= 14:
                return list(range(low, high + 1))
        except (ValueError, IndexError):
            pass
    # Format "1,6,11"
    out: List[int] = []
    for s in channels_arg.split(","):
        try:
            c = int(s.strip())
            if 1 <= c <= 14:
                out.append(c)
        except ValueError:
            continue
    return out if out else list(CHANNELS)


def check_system_dependencies() -> None:
    """
    [SARA] Vérifie la présence des dépendances système nécessaires au sniffing
    (ex. tcpdump / libpcap). Lève SystemExit avec message explicite si absent.
    """
    if shutil.which("tcpdump") is None:
        print(
            "[CRITICAL] Dépendance système manquante : 'tcpdump' est requis pour la capture Wi-Fi.\n"
            "Installez-le (ex. sudo apt install tcpdump) puis relancez.",
            file=sys.stderr,
        )
        sys.exit(1)


def _row_style(ap: APInfo) -> str:
    """Retourne le préfixe colorama pour une ligne selon danger_score (sans scintillement)."""
    if not HAS_COLORAMA:
        return ""
    if ap.danger_score <= 1:
        return Fore.GREEN
    if ap.danger_score <= 3:
        return Fore.YELLOW + Style.BRIGHT
    return Fore.RED + Style.BRIGHT


def _reset_style() -> str:
    if not HAS_COLORAMA:
        return ""
    return Style.RESET_ALL


def display_aps() -> None:
    """
    Affiche le tableau des AP avec couleurs selon danger_score :
    Vert = sûr, Jaune/Orange = modéré, Rouge gras = critique.
    Un bloc d'alerte détaillé est affiché en cas d'Evil Twin (doublon SSID).
    """
    os.system("cls" if os.name == "nt" else "clear")

    header = (
        f"| {'SSID':<28} | {'BSSID':<17} | {'CH':<3} | {'RSSI':<4} | {'BCON':<4} | "
        f"{'SCORE':<5} | {'NIV.':<7} | {'EVIL T.':<7} | {'Reason':<18} |"
    )
    sep_len = len(header) + 2
    print("=" * sep_len)
    print(f"| Wi-Fi AP Scanner & Evil Twin Detector | Last Updated: {datetime.now().strftime('%H:%M:%S')} |")
    print("=" * sep_len)
    print(header)
    print("-" * sep_len)

    with AP_STORE_LOCK:
        ap_list = list(AP_STORE.values())
    sorted_aps = sorted(ap_list, key=lambda ap: ap.rssi, reverse=True)

    for ap in sorted_aps:
        prefix = _row_style(ap)
        evil_status = "!! YES !!" if ap.is_evil_twin else "No"
        reason = (ap.anomaly_reason or "")[:18]
        level = get_danger_level_name(ap.danger_score)
        line = (
            f"| {ap.ssid[:28]:<28} | {ap.bssid:<17} | {ap.channel:<3} | {ap.rssi:<4} | "
            f"{ap.beacon_count:<4} | {ap.danger_score:<5} | {level:<7} | {evil_status:<7} | {reason:<18} |"
        )
        print(f"{prefix}{line}{_reset_style()}")

    with AP_STORE_LOCK:
        total_aps = len(AP_STORE)
    print("=" * sep_len)
    print(f"Total Unique APs Detected: {total_aps}")

    # Résumé de conflit : Evil Twin (doublon SSID)
    ssid_to_bssids: Dict[str, List[str]] = {}
    for ap in sorted_aps:
        if ap.ssid in ("Hidden/Unknown", "") or ap.ssid.isspace():
            continue
        if ap.ssid not in ssid_to_bssids:
            ssid_to_bssids[ap.ssid] = []
        ssid_to_bssids[ap.ssid].append(ap.bssid)

    for ssid, bssids in ssid_to_bssids.items():
        if len(bssids) > 1:
            mac_list = " et ".join(bssids)
            block = (
                f"\n  ATTENTION : Le SSID [{ssid}] est diffusé par deux antennes différentes ({mac_list}).\n"
                "  Risque Evil Twin : ne vous connectez pas sans vérifier la légitimité du réseau.\n"
            )
            if HAS_COLORAMA:
                print(Fore.RED + Style.BRIGHT + block + _reset_style())
            else:
                print(block)


def run_detection_check() -> None:
    """
    Logique de détection : indicateurs (SSID suspect, anomalie RSSI, doublon),
    calcul du danger_score, puis application de la whitelist.
    Lecture de AP_STORE sous Lock pour cohérence thread-safe.
    """
    whitelist = load_whitelist()

    with AP_STORE_LOCK:
        ap_items = list(AP_STORE.items())
    # Réinitialiser les indicateurs recalculés à chaque cycle (rssi_anomaly reste tel quel)
    for _bssid, ap in ap_items:
        ap.suspect_ssid = False
        ap.duplicate_ssid = False

    ssid_to_bssid_map: Dict[str, List[str]] = {}

    for bssid, ap in ap_items:
        if ap.ssid == "Hidden/Unknown" or ap.ssid.isspace():
            continue

        if is_suspect_ssid(ap.ssid):
            ap.suspect_ssid = True
            ap.is_evil_twin = True
            if not ap.anomaly_reason:
                ap.anomaly_reason = "Suspect SSID (captive/generic)"

        if ap.ssid not in ssid_to_bssid_map:
            ssid_to_bssid_map[ap.ssid] = []
        ssid_to_bssid_map[ap.ssid].append(bssid)

    with AP_STORE_LOCK:
        for ssid, bssids in ssid_to_bssid_map.items():
            if len(bssids) > 1:
                for bssid in bssids:
                    if bssid in AP_STORE:
                        ap = AP_STORE[bssid]
                        ap.duplicate_ssid = True
                        ap.is_evil_twin = True
                        if not ap.anomaly_reason:
                            ap.anomaly_reason = "Duplicate SSID (multiple BSSIDs)"

    with AP_STORE_LOCK:
        ap_list = list(AP_STORE.values())
    for ap in ap_list:
        ap.calculate_danger_level()

    # Whitelist : réseaux de confiance forcés à 0 et non Evil Twin
    apply_whitelist(whitelist)


def parse_args() -> argparse.Namespace:
    """
    [SARA] Arguments CLI : interface et canaux.
    -i/--interface : interface Wi-Fi (ex. wlan0mon). Défaut : wlan0.
    -c/--channels : canaux à scanner, ex. "1,6,11" ou "1-13". Défaut : 1-13.
    """
    parser = argparse.ArgumentParser(
        description="GuardianWiFi — Détection Evil Twin et analyse Wi-Fi en mode moniteur.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default="wlan0",
        metavar="IFACE",
        help="Interface Wi-Fi en mode moniteur (ex. wlan0mon)",
    )
    parser.add_argument(
        "-c", "--channels",
        type=str,
        default="1-13",
        metavar="LIST",
        help="Canaux à scanner : liste séparée par des virgules (1,6,11) ou plage (1-13)",
    )
    return parser.parse_args()


def main() -> None:
    """
    Point d'entrée : vérification des prérequis, configuration depuis la CLI,
    boucle de channel hopping, sniffing, détection, affichage et nettoyage périodique.
    """
    args = parse_args()
    interface = args.interface.strip() or "wlan0"
    channels = parse_channels(args.channels)

    # 1. Prérequis
    nic_manager.check_root()
    check_system_dependencies()

    nic_manager.INTERFACE_NAME = interface
    packet_sniffer.INTERFACE_NAME = interface

    if interface == "wlan0":
        print(f"[WARNING] Interface is set to default '{interface}'. REMEMBER TO CHANGE IT.")
        time.sleep(2)

    current_channel_index = 0

    try:
        # 2. Passage en mode moniteur
        nic_manager.set_mode("monitor")

        # 3. Boucle principale : channel hopping, sniff, détection, affichage, cleanup
        print("\n[START] Beginning channel scanning and sniffing...")
        print(f"[CONFIG] Interface: {interface} | Canaux: {channels}")

        while True:
            current_channel = channels[current_channel_index % len(channels)]

            try:
                nic_manager.set_channel(current_channel)
            except (OSError, ValueError) as e:
                print(f"[NIC ERROR] Canal {current_channel} : {e}", file=sys.stderr)
                current_channel_index += 1
                continue

            try:
                packet_sniffer.start_sniffing(
                    iface=interface,
                    duration=SCAN_DURATION_PER_CHANNEL,
                )
            except OSError as e:
                print(
                    f"[SNIFFER ERROR] Interface '{interface}' indisponible ou déconnectée : {e}",
                    file=sys.stderr,
                )
                print("Vérifiez que l'interface existe et est en mode moniteur.", file=sys.stderr)
                raise
            except PermissionError as e:
                print(f"[SNIFFER ERROR] Droits insuffisants pour capturer sur {interface} : {e}", file=sys.stderr)
                raise

            # Détection, affichage, nettoyage des AP non revus depuis 60 s
            run_detection_check()
            display_aps()
            removed = cleanup_stale_aps(CLEANUP_STALE_SECONDS)
            if removed > 0:
                print(f"[CLEANUP] {removed} AP(s) supprimé(s) (inactifs > {int(CLEANUP_STALE_SECONDS)} s)")

            current_channel_index += 1

    except KeyboardInterrupt:
        print("\n[INFO] Sniffing interrupted by user (Ctrl+C).")
    except Exception as e:
        print(f"\n[CRITICAL FAILURE] Project stopped unexpectedly: {e}", file=sys.stderr)
    finally:
        nic_manager.cleanup()
        sys.exit(0)


if __name__ == "__main__":
    main()