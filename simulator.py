import time, random
from ap_model import update_ap_store, AP_STORE, AP_STORE_LOCK

def start_simulation(stop_event):
    scenarios = [
        ("Ma_Box_Orange", "E8:ED:F3:11:22:33", 1, -60),
        ("Hacker_Alfa", "00:C0:CA:88:99:AA", 6, -50),
        ("Ma_B0x_Orange", "FF:EE:DD:44:55:66", 1, -65)
    ]
    while not stop_event.is_set():
        for ssid, bssid, chan, rssi in scenarios:
            update_ap_store(bssid, ssid, chan, rssi + random.randint(-2, 2), time.time())
        
        # Simulation Attaque Sequence Jump + Deauth
        if int(time.time()) % 15 > 10:
            update_ap_store("E8:ED:F3:11:22:33", "Ma_Box_Orange", 1, -40, time.time(), random.randint(2000, 3000))
            with AP_STORE_LOCK:
                if "00:C0:CA:88:99:AA" in AP_STORE: AP_STORE["00:C0:CA:88:99:AA"].deauth_count += 5
        time.sleep(1.5)