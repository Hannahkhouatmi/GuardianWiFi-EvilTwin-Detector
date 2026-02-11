import time
import random
import threading
from ap_model import update_ap_store

class WiFiSimulator:
    def __init__(self):
        self.running = False
        # Liste de scénarios : (SSID, BSSID, Channel, Base_RSSI)
        self.scenarios = [
    ("Ma_Box_Maison", "AA:BB:CC:11:22:33", 1, -60), # Ton réseau officiel (ajoute ce BSSID à ta whitelist)
    ("Ma_B0x_Maison", "FF:EE:DD:44:55:66", 1, -65), # L'imitateur (Le 'o' est devenu un '0')
]

    def start(self, stop_event):
        self.running = True
        print("[SIMULATEUR] Lancement du mode simulation...")
        
        while not stop_event.is_set():
            for ssid, bssid, chan, base_rssi in self.scenarios:
                # On ajoute un petit changement aléatoire au signal (RSSI)
                fake_rssi = base_rssi + random.randint(-5, 5)
                fake_time = time.time()
                
                # Envoyer la donnée au modèle
                update_ap_store(bssid, ssid, chan, fake_rssi, fake_time)
                
            # Simulation d'une attaque Evil Twin après 10 secondes
            if int(time.time()) % 20 > 10:
                # On crée un faux jumeau pour "Ma_Box_Maison"
                update_ap_store("FF:FF:FF:EE:EE:EE", "Ma_Box_Maison", 1, -30, time.time())

            time.sleep(1.0) # On simule des beacons toutes les secondes

def start_simulation(stop_event):
    sim = WiFiSimulator()
    sim.start(stop_event)