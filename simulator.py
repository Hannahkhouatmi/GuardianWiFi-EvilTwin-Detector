import time
import random
from ap_model import update_ap_store

def start_simulation(stop_event):
    print("[*] Moteur de simulation activé (5 scénarios d'attaques)...")
    
    # --- SCÉNARIOS ---
    
    # 1. Le Réseau Légitime (La cible)
    # BSSID d'une Livebox Orange réelle
    legit_bssid = "E8:ED:F3:AA:BB:CC"
    legit_ssid = "Orange-WiFi-A1B2"

    # 2. Scénario : Evil Twin (Doublon exact)
    # Même nom, mais adresse MAC différente (Hacker avec une antenne Alfa)
    evil_twin_bssid = "00:C0:CA:11:22:33" 
    
    # 3. Scénario : Typosquatting (Levenshtein)
    # Nom presque pareil pour tromper l'utilisateur
    typo_ssid = "Orange-W1Fi-A1B2" # "1" au lieu de "i"
    typo_bssid = "DE:AD:BE:EF:01:02"

    # 4. Scénario : Attaque Deauth Active
    # Un réseau qui envoie des paquets de déconnexion en masse
    deauth_target_bssid = "AA:BB:CC:DD:EE:FF"
    deauth_target_ssid = "Starbucks_Free"

    # 5. Scénario : Hardware Mismatch (Sequence Jump)
    # Un hacker essaie d'imiter un réseau mais son compteur de paquets saute
    seq_jump_bssid = "74:DA:38:99:88:77"
    seq_jump_ssid = "Home_WiFi"

    step = 0
    while not stop_event.is_set():
        # --- ENVOI DES DONNÉES SIMULÉES ---
        
        # Le réseau Normal
        update_ap_store(legit_bssid, legit_ssid, 1, -60, random.randint(100, 200))

        # Attaque 1 : Evil Twin (SSID identique)
        update_ap_store(evil_twin_bssid, legit_ssid, 6, -45, random.randint(500, 600))

        # Attaque 2 : Typosquatting (Nom similaire)
        update_ap_store(typo_bssid, typo_ssid, 11, -50, random.randint(1000, 1100))

        # Attaque 3 : Deauth (On simule l'augmentation du compteur)
        update_ap_store(deauth_target_bssid, deauth_target_ssid, 1, -65, -1, is_deauth=(step % 5 == 0))

        # Attaque 4 : Sequence Jump
        # On simule un compteur qui saute brusquement de 2000 à 5000
        current_seq = 2000 if step % 10 < 5 else 5500
        update_ap_store(seq_jump_bssid, seq_jump_ssid, 6, -40, current_seq)

        step += 1
        time.sleep(1.5)