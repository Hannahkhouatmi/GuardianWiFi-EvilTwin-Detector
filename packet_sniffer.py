from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, conf
from ap_model import update_ap_store
import time

conf.use_pcap = True # Pour Kali

def handle_packet(pkt):
    if pkt.haslayer(Dot11):
        bssid = pkt.addr2.upper() if pkt.addr2 else None
        if not bssid: return

        # 1. CAS ATTAQUE DEAUTH
        if pkt.haslayer(Dot11Deauth):
            update_ap_store(bssid, "Inconnu", 0, -100, -1, is_deauth=True)
            return

        # 2. CAS BEACON (Point d'accès)
        if pkt.haslayer(Dot11Beacon):
            ssid = "Inconnu"
            chan = 0
            if pkt.haslayer(Dot11Elt):
                try:
                    ssid = pkt[Dot11Elt].info.decode('utf-8', 'ignore')
                except: pass
                
                # Extraction Canal
                try:
                    p = pkt[Dot11Elt]
                    while isinstance(p, Dot11Elt):
                        if p.ID == 3:
                            chan = int(ord(p.info))
                            break
                        p = p.payload
                except: pass

            # Extraction Sequence Number
            seq_num = pkt.SC >> 4 if hasattr(pkt, 'SC') else -1
            
            # Extraction RSSI
            rssi = -100
            if hasattr(pkt, 'dBm_AntSignal'): rssi = pkt.dBm_AntSignal
            
            update_ap_store(bssid, ssid, chan, rssi, seq_num)

def start_sniffing(iface, stop_event):
    sniff(iface=iface, prn=handle_packet, store=0)