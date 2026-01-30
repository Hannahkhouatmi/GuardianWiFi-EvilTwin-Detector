# packet_sniffer.py

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from ap_model import update_ap_store
import sys
from typing import Optional

# Valeur par défaut si RSSI introuvable (signal très faible)
DEFAULT_RSSI = -100
# Plage RSSI réaliste pour Wi-Fi (dBm)
RSSI_MIN, RSSI_MAX = -100, -20


def get_rssi(pkt) -> int:
    """
    [HANNAH - EXTRACTION RSSI - MULTI-DRIVERS]
    Extrait la puissance du signal (dBm) depuis la couche Radiotap.
    Compatible Realtek, Atheros, Broadcom : essaie dBm_AntSignal, puis
    champs alternatifs et parsing des octets bruts (present / notdecoded).
    """
    if not pkt.haslayer("Radiotap"):
        return DEFAULT_RSSI

    rt = pkt.radiotap
    rssi: Optional[int] = None

    # 1) Champ standard (majorité des drivers)
    if hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
        try:
            rssi = int(rt.dBm_AntSignal)
        except (TypeError, ValueError):
            pass
    if rssi is not None and RSSI_MIN <= rssi <= RSSI_MAX:
        return rssi

    # 2) Champ dBm_AntNoise absent pour RSSI direct ; certains firmwares
    #    exposent seulement un "signal" dans un champ proche -> on ne déduit pas RSSI du bruit.

    # 3) Champs alternatifs (noms possibles selon variantes Radiotap / Scapy)
    for field_name in ("dB_AntSignal", "Antenna_Signal", "Signal_strength"):
        if rssi is not None:
            break
        val = getattr(rt, field_name, None)
        if val is not None:
            try:
                rssi = int(val)
                # dB_AntSignal peut être en dB relatif ; bornage réaliste
                if field_name == "dB_AntSignal" and (rssi > 0 or rssi < -120):
                    rssi = max(RSSI_MIN, min(RSSI_MAX, rssi))
            except (TypeError, ValueError):
                pass
    if rssi is not None and RSSI_MIN <= rssi <= RSSI_MAX:
        return rssi

    # 4) Parsing notdecoded : drivers qui mettent le RSSI dans les octets bruts
    #    (souvent dernier octet : unsigned -> dBm = byte - 256, ou signed)
    try:
        extra = getattr(rt, "notdecoded", None)
        if extra and len(extra) >= 1:
            last_byte = extra[-1]
            if isinstance(last_byte, int):
                # Interprétation courante : unsigned -> dBm
                rssi_raw = last_byte - 256 if last_byte > 127 else last_byte
            else:
                rssi_raw = ord(last_byte) - 256 if ord(last_byte) > 127 else ord(last_byte)
            if RSSI_MIN <= rssi_raw <= RSSI_MAX:
                return rssi_raw
            # Premier octet parfois utilisé (certains chips)
            if len(extra) >= 2:
                first_byte = extra[0]
                v = first_byte if isinstance(first_byte, int) else ord(first_byte)
                rssi_raw = v - 256 if v > 127 else v
                if RSSI_MIN <= rssi_raw <= RSSI_MAX:
                    return rssi_raw
    except (IndexError, TypeError, ValueError):
        pass

    # 5) Valeur déjà lue mais hors plage : on borne
    if rssi is not None:
        return max(RSSI_MIN, min(RSSI_MAX, rssi))

    return DEFAULT_RSSI

def handle_packet(pkt):
    """
    Analyse chaque paquet capturé pour trouver les Beacons (annonces Wi-Fi).
    """
    # On ne s'intéresse qu'aux trames Dot11 (Wi-Fi)
    if not pkt.haslayer(Dot11Beacon):
        return

    # 1. Extraction BSSID (Adresse MAC)
    bssid = pkt[Dot11].addr2
    
    # 2. Extraction SSID (Nom du réseau)
    try:
        # Le SSID est dans la couche Dot11Elt avec l'ID 0
        # info.decode() peut échouer si caractères bizarres
        ssid = pkt[Dot11Elt].info.decode('utf-8', 'ignore')
    except:
        ssid = "Hidden/Unknown"
        
    # 3. Extraction du Canal
    try:
        # Scapy a une fonction stats qui extrait souvent le canal automatiquement
        stats = pkt[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        if not channel:
             # Fallback manuel si network_stats échoue
             channel = int(ord(pkt[Dot11Elt:3].info))
    except:
        channel = 0

    # 4. [HANNAH] Extraction du RSSI
    rssi = get_rssi(pkt)
    
    # 5. Envoi des données pour stockage/mise à jour
    update_ap_store(
        bssid=bssid, 
        ssid=ssid, 
        channel=channel, 
        rssi=rssi  # On passe le signal extrait à la structure AP
    )

def start_sniffing(iface: str, duration: int) -> None:
    """
    Lance l'écoute sur l'interface donnée.
    Lève OSError si l'interface est absente, déconnectée ou invalide.
    Lève PermissionError si les droits de capture sont insuffisants.
    """
    try:
        sniff(
            iface=iface,
            prn=handle_packet,
            timeout=duration,
            store=0,
            monitor=True,
        )
    except OSError as e:
        print(f"[ERREUR SNIFFER] Interface '{iface}' : {e}", file=sys.stderr)
        raise
    except PermissionError as e:
        print(f"[ERREUR SNIFFER] Droits insuffisants sur '{iface}' : {e}", file=sys.stderr)
        raise
    except Exception as e:
        print(f"[ERREUR SNIFFER] {e}", file=sys.stderr)
        raise