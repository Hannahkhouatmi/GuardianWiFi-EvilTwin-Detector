import csv, os
from datetime import datetime
from pathlib import Path

class GuardianLogger:
    def __init__(self):
        Path("logs").mkdir(exist_ok=True)
        self.filename = f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(self.filename, 'w', newline='') as f:
            csv.writer(f).writerow(["Time", "SSID", "BSSID", "Vendor", "RSSI", "Score", "Reason"])

    def log_aps(self, store):
        with open(self.filename, 'a', newline='') as f:
            writer = csv.writer(f)
            t = datetime.now().strftime("%H:%M:%S")
            for ap in store.values():
                writer.writerow([t, ap.ssid, ap.bssid, ap.vendor, ap.rssi, ap.danger_score, ap.anomaly_reason])

logger_instance = GuardianLogger()