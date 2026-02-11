from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth
from ap_model import update_ap_store, AP_STORE, AP_STORE_LOCK

def get_rssi(pkt):
    if not pkt.haslayer("Radiotap"): return -100
    try:
        rssi = pkt.radiotap.dBm_AntSignal
        if rssi is None:
            extra = getattr(pkt.radiotap, "notdecoded", None)
            if extra: rssi = extra[-1] - 256
        return int(rssi) if rssi else -100
    except: return -100

def handle_packet(pkt):
    if pkt.haslayer(Dot11Deauth):
        bssid = pkt[Dot11].addr2
        if bssid:
            with AP_STORE_LOCK:
                if bssid.upper() in AP_STORE: AP_STORE[bssid.upper()].deauth_count += 1
        return

    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        try:
            sc = pkt[Dot11].SC
            seq_num = sc >> 4
        except: seq_num = -1
        
        try:
            ssid = pkt[Dot11Elt].info.decode('utf-8', 'ignore') or "Hidden/Unknown"
        except: ssid = "Hidden/Unknown"
        
        try:
            chan = int(ord(pkt[Dot11Elt:3].info))
        except: chan = 0
        
        update_ap_store(bssid, ssid, chan, get_rssi(pkt), float(pkt.time), seq_num)

def start_sniffing(iface, stop_event):
    while not stop_event.is_set():
        sniff(iface=iface, prn=handle_packet, timeout=1, store=0, monitor=True)