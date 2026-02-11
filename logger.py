import csv
import os
from datetime import datetime
from pathlib import Path

# Création du dossier logs s'il n'existe pas
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

class GuardianLogger:
    def __init__(self):
        # On crée un nom de fichier unique pour chaque session (ex: scan_20231027_1430.csv)
        self.filename = LOG_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self._prepare_csv()

    def _prepare_csv(self):
        """Prépare les colonnes du fichier CSV."""
        with open(self.filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "SSID", "BSSID", "Channel", "RSSI", "Score", "Reason"])

    def log_aps(self, ap_store):
        """Enregistre l'état actuel des points d'accès."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.filename, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for bssid, ap in ap_store.items():
                writer.writerow([
                    timestamp,
                    ap.ssid,
                    ap.bssid,
                    ap.channel,
                    ap.rssi,
                    ap.danger_score,
                    ap.anomaly_reason or "N/A"
                ])

# Instance globale pour être utilisée partout
logger_instance = GuardianLogger()