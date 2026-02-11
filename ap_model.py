import threading
import statistics
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

# --- GLOBAL STORE ---
AP_STORE: Dict[str, "APInfo"] = {}
AP_STORE_LOCK = threading.Lock()

# --- CONFIGURATION ---
RSSI_HISTORY_SIZE = 15
Z_SCORE_THRESHOLD = 2.5
MIN_SAMPLES_FOR_STATS = 5

# --- CHARGEMENT DE LA BASE OUI (CONSTRUCTEURS) ---
OUI_FILE = Path(__file__).resolve().parent / "oui_database.json"
OUI_DB = {}
if OUI_FILE.exists():
    try:
        OUI_DB = json.loads(OUI_FILE.read_text(encoding="utf-8"))
    except Exception:
        OUI_DB = {}

@dataclass
class APInfo:
    ssid: str = "Hidden/Unknown"
    bssid: str = ""
    channel: int = 0
    rssi: int = -100
    last_seen: datetime = field(default_factory=datetime.now)
    beacon_count: int = 0
    
    # Historiques pour analyses statistiques
    rssi_history: List[int] = field(default_factory=list)
    arrival_times: List[float] = field(default_factory=list)
    
    # Informations Constructeur
    vendor: str = "Unknown"
    
    # États de détection
    is_evil_twin: bool = False
    anomaly_reason: Optional[str] = field(default=None)
    danger_score: int = 0
    
    # Indicateurs de risque (Drapeaux)
    suspect_ssid: bool = False
    rssi_anomaly: bool = False
    duplicate_ssid: bool = False
    timing_anomaly: bool = False
    suspect_vendor: bool = False

    def __post_init__(self):
        """Initialisation après création de l'objet."""
        self.bssid = self.bssid.upper()
        # Identification du constructeur via les 3 premiers octets du BSSID
        prefix = ":".join(self.bssid.split(":")[:3])
        self.vendor = OUI_DB.get(prefix, "Unknown")

    def update_metrics(self, new_rssi: int, pkt_time: float):
        """Analyse statistique du signal (Z-Score) et du Jitter (Timing)."""
        self.rssi = new_rssi
        self.last_seen = datetime.now()
        self.beacon_count += 1
        
        # Mise à jour historique RSSI
        self.rssi_history.append(new_rssi)
        if len(self.rssi_history) > RSSI_HISTORY_SIZE: self.rssi_history.pop(0)
        
        # Mise à jour historique temps d'arrivée
        self.arrival_times.append(pkt_time)
        if len(self.arrival_times) > RSSI_HISTORY_SIZE: self.arrival_times.pop(0)

        # 1. Détection RSSI par Z-Score (Saut de signal anormal)
        if len(self.rssi_history) >= MIN_SAMPLES_FOR_STATS:
            mean = statistics.mean(self.rssi_history[:-1])
            stdev = statistics.stdev(self.rssi_history[:-1])
            if stdev > 0:
                z = abs(new_rssi - mean) / stdev
                if z > Z_SCORE_THRESHOLD and new_rssi > mean:
                    self.rssi_anomaly = True
                    self.anomaly_reason = f"RSSI Spike ({z:.1f}σ)"

        # 2. Analyse du Jitter (Stabilité du timer matériel)
        if len(self.arrival_times) >= 5:
            intervals = [self.arrival_times[i] - self.arrival_times[i-1] for i in range(1, len(self.arrival_times))]
            jitter = statistics.stdev(intervals)
            # Un routeur réel est très stable. Une attaque logicielle oscille bcp (> 0.04s).
            if jitter > 0.04: 
                self.timing_anomaly = True
                self.anomaly_reason = "Jitter/Timing Anomaly"

    def calculate_danger_level(self) -> int:
        """Calcule le score de danger final sur 10."""
        score = 0
        if self.suspect_ssid: score += 1
        if self.rssi_anomaly: score += 2
        if self.timing_anomaly: score += 2
        if self.duplicate_ssid: score += 3
        
        # Bonus Malus : Constructeur suspect (Alfa Network, Realtek, etc.)
        suspect_vendors = ["Alfa Network", "Realtek", "Shenzhen Tenda"]
        if self.vendor in suspect_vendors:
            self.suspect_vendor = True
            score += 2
        
        self.danger_score = score
        # On marque comme Evil Twin si le score est critique
        if self.danger_score >= 4:
            self.is_evil_twin = True
            
        return score

def get_danger_level_name(score: int) -> str:
    """Traduit le score numérique en texte lisible."""
    if score <= 1: return "Faible"
    if score <= 3: return "Modéré"
    return "Critique"

def update_ap_store(bssid: str, ssid: str, channel: int, rssi: int, pkt_time: float):
    """Met à jour ou crée un point d'accès dans la base de données globale."""
    bssid = bssid.upper()
    with AP_STORE_LOCK:
        if bssid in AP_STORE:
            ap = AP_STORE[bssid]
            ap.update_metrics(rssi, pkt_time)
            if ssid and ssid != "Hidden/Unknown":
                ap.ssid = ssid
        else:
            new_ap = APInfo(ssid=ssid, bssid=bssid, channel=channel)
            new_ap.update_metrics(rssi, pkt_time)
            AP_STORE[bssid] = new_ap

def cleanup_stale_aps(max_age: float = 60.0):
    """Supprime les points d'accès qui n'ont pas été vus depuis X secondes."""
    now = datetime.now()
    with AP_STORE_LOCK:
        to_remove = [b for b, a in AP_STORE.items() if (now - a.last_seen).total_seconds() > max_age]
        for b in to_remove:
            del AP_STORE[b]
    return len(to_remove)