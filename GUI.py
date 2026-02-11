import customtkinter as ctk
import threading
import time
from datetime import datetime
from ap_model import AP_STORE, AP_STORE_LOCK, get_danger_level_name

# Configuration du thème
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class GuardianGUI(ctk.CTk):
    def __init__(self, simulate=False):
        super().__init__()

        self.title("GuardianWiFi Pro - Evil Twin Detector")
        self.geometry("1100x750")
        
        # --- GRID LAYOUT ---
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR (Gauche) ---
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="🛡️ GUARDIANWIFI", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.pack(pady=30, padx=20)

        self.status_label = ctk.CTkLabel(self.sidebar, text="Statut: SCAN EN COURS", text_color="#2ecc71")
        self.status_label.pack(pady=10)

        # Stats rapides sur le côté
        self.stat_ap_count = ctk.CTkLabel(self.sidebar, text="Total APs: 0")
        self.stat_ap_count.pack(pady=5)
        self.stat_alert_count = ctk.CTkLabel(self.sidebar, text="Alertes: 0", text_color="#e74c3c")
        self.stat_alert_count.pack(pady=5)

        # --- MAIN VIEW (Droite) ---
        self.main_view = ctk.CTkFrame(self, corner_radius=15)
        self.main_view.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        self.tabview = ctk.CTkTabview(self.main_view)
        self.tabview.pack(expand=True, fill="both", padx=10, pady=10)
        
        self.tab_scan = self.tabview.add("Live Scan")
        self.tab_history = self.tabview.add("Historique & Stats")

        # --- ONGLET 1 : LIVE SCAN ---
        self.scrollable_frame = ctk.CTkScrollableFrame(self.tab_scan, label_text="Analyse des réseaux en temps réel")
        self.scrollable_frame.pack(expand=True, fill="both", padx=10, pady=10)
        self.ap_rows = {}

        # --- ONGLET 2 : HISTORIQUE & STATS ---
        self.history_log = ctk.CTkTextbox(self.tab_history, width=700, height=400, font=("Courier New", 12))
        self.history_log.pack(expand=True, fill="both", padx=20, pady=20)
        self.history_log.insert("0.0", f"--- SESSION DÉMARRÉE LE {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n\n")

        # Lancement du thread de rafraîchissement
        self.total_alerts_seen = 0
        self.logged_bssids = set() # Pour éviter de loguer 100 fois la même alerte
        self.update_ui()

    def update_ui(self):
        """Mise à jour de l'interface toutes les secondes."""
        with AP_STORE_LOCK:
            aps = sorted(AP_STORE.values(), key=lambda x: x.rssi, reverse=True)
            current_alerts = 0
            
            # Mise à jour des Stats dans la barre latérale
            self.stat_ap_count.configure(text=f"Total APs: {len(aps)}")

            for ap in aps:
                # 1. Gestion des couleurs
                color = "transparent"
                text_color = "white"
                if ap.danger_score >= 4:
                    color = "#4d0000"
                    text_color = "#ff4d4d"
                    current_alerts += 1
                elif ap.danger_score >= 2:
                    color = "#404000"
                    text_color = "#ffff4d"

                # 2. Création/Mise à jour de la ligne dans Live Scan
                if ap.bssid not in self.ap_rows:
                    row = ctk.CTkFrame(self.scrollable_frame)
                    row.pack(fill="x", pady=2, padx=5)
                    
                    lbl_name = ctk.CTkLabel(row, text="", width=200, anchor="w", font=("Arial", 13, "bold"))
                    lbl_name.pack(side="left", padx=10)
                    
                    lbl_info = ctk.CTkLabel(row, text="", width=400, anchor="w")
                    lbl_info.pack(side="left", padx=10)
                    
                    lbl_score = ctk.CTkLabel(row, text="", width=120)
                    lbl_score.pack(side="right", padx=10)
                    
                    self.ap_rows[ap.bssid] = (row, lbl_name, lbl_info, lbl_score)

                row_frame, lbl_name, lbl_info, lbl_score = self.ap_rows[ap.bssid]
                row_frame.configure(fg_color=color)
                lbl_name.configure(text=f"{ap.ssid[:20]}", text_color=text_color)
                lbl_info.configure(text=f"{ap.bssid} | {ap.vendor[:15]} | CH: {ap.channel} | RSSI: {ap.rssi}", text_color=text_color)
                lbl_score.configure(text=f"Danger: {ap.danger_score}/10", text_color=text_color)

                # 3. Remplissage de l'onglet HISTORIQUE
                if ap.danger_score >= 4:
                    # On crée une clé unique (BSSID + raison) pour ne pas répéter l'alerte
                    alert_key = f"{ap.bssid}_{ap.anomaly_reason}"
                    if alert_key not in self.logged_bssids:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        log_entry = f"[{timestamp}] ⚠️ ALERTE : {ap.ssid} ({ap.bssid})\n"
                        log_entry += f"      -> Raison : {ap.anomaly_reason}\n"
                        log_entry += f"      -> Constructeur : {ap.vendor} | Score : {ap.danger_score}\n"
                        log_entry += "-"*60 + "\n"
                        
                        self.history_log.insert("end", log_entry)
                        self.history_log.see("end") # Scroll automatique vers le bas
                        self.logged_bssids.add(alert_key)
                        self.total_alerts_seen += 1

            self.stat_alert_count.configure(text=f"Alertes: {self.total_alerts_seen}")

        # On relance la mise à jour dans 1 seconde
        self.after(1000, self.update_ui)

def start_gui(simulate=False):
    app = GuardianGUI(simulate=simulate)
    app.mainloop()