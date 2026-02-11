from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from ap_model import update_ap_store
import sys

DEFAULT_RSSI = -100
RSSI_MIN, RSSI_MAX = -100, -20

def get_rssi(pkt) -> int:
    """Extraction RSSI Robuste (Realtek, Atheros, Broadcom)."""
    if not pkt.haslayer("Radiotap"): return DEFAULT_RSSI
    rt = pkt.radiotap
    
    # 1. Champ Standard
    rssi = getattr(rt, "dBm_AntSignal", None)
    
    # 2. Parsing 'notdecoded' pour les drivers spécifiques
    if rssi is None:
        try:
            extra = getattr(rt, "notdecoded", None)
            if extra and len(extra) >= 1:
                last_byte = extra[-1]
                rssi = last_byte - 256 if last_byte > 127 else last_byte
        except: pass
        
    if rssi is not None and RSSI_MIN <= rssi <= RSSI_MAX:
        return int(rssi)
    return DEFAULT_RSSI

def handle_packet(pkt):
    if not pkt.haslayer(Dot11Beacon): return
    
    bssid = pkt[Dot11].addr2
    pkt_time = float(pkt.time)
    
    try:
        ssid = pkt[Dot11Elt].info.decode('utf-8', 'ignore')
        if not ssid.strip(): ssid = "Hidden/Unknown"
    except: ssid = "Hidden/Unknown"
    
    try:
        stats = pkt[Dot11Beacon].network_stats()
        channel = stats.get("channel", 0)
    except: channel = 0
    
    rssi = get_rssi(pkt)
    update_ap_store(bssid, ssid, channel, rssi, pkt_time)

def start_sniffing(iface: str, stop_event):
    """Boucle de capture continue."""
    try:
        while not stop_event.is_set():
            sniff(iface=iface, prn=handle_packet, timeout=1, store=0, monitor=True)
    except Exception as e:
        print(f"[ERROR SNIFFER] {e}")