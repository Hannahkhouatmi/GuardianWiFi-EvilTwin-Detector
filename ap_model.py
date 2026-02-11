import threading
import statistics
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

AP_STORE: Dict[str, "APInfo"] = {}
AP_STORE_LOCK = threading.Lock()

# Configuration
RSSI_HISTORY_SIZE = 15
Z_SCORE_THRESHOLD = 2.5
MIN_SAMPLES_FOR_STATS = 5

# Chargement OUI
OUI_FILE = Path(__file__).resolve().parent / "oui_database.json"
OUI_DB = json.loads(OUI_FILE.read_text(encoding="utf-8")) if OUI_FILE.exists() else {}

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2): return levenshtein_distance(s2, s1)
    if len(s2) == 0: return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

@dataclass
class APInfo:
    ssid: str = "Hidden/Unknown"
    bssid: str = ""
    channel: int = 0
    rssi: int = -100
    last_seen: datetime = field(default_factory=datetime.now)
    vendor: str = "Unknown"
    
    # Historiques & Stats
    rssi_history: List[int] = field(default_factory=list)
    arrival_times: List[float] = field(default_factory=list)
    last_seq: int = -1
    
    # Compteurs d'attaques
    deauth_count: int = 0
    seq_jumps: int = 0
    
    # Drapeaux de danger
    is_evil_twin: bool = False
    danger_score: int = 0
    anomaly_reason: Optional[str] = field(default=None)
    suspect_ssid: bool = False
    rssi_anomaly: bool = False
    duplicate_ssid: bool = False
    timing_anomaly: bool = False
    suspect_vendor: bool = False
    similar_ssid: bool = False
    seq_anomaly: bool = False

    def __post_init__(self):
        self.bssid = self.bssid.upper()
        prefix = ":".join(self.bssid.split(":")[:3])
        self.vendor = OUI_DB.get(prefix, "Unknown")

    def update_metrics(self, new_rssi: int, pkt_time: float, seq_num: int = -1):
        self.rssi = new_rssi
        self.last_seen = datetime.now()
        
        # 1. RSSI Stats
        self.rssi_history.append(new_rssi)
        if len(self.rssi_history) > RSSI_HISTORY_SIZE: self.rssi_history.pop(0)
        if len(self.rssi_history) >= MIN_SAMPLES_FOR_STATS:
            mean = statistics.mean(self.rssi_history[:-1])
            stdev = statistics.stdev(self.rssi_history[:-1])
            if stdev > 0:
                z = abs(new_rssi - mean) / stdev
                if z > Z_SCORE_THRESHOLD and new_rssi > mean:
                    self.rssi_anomaly = True
                    self.anomaly_reason = "RSSI Spike"

        # 2. Sequence Analysis
        if seq_num != -1 and self.last_seq != -1:
            diff = abs(seq_num - self.last_seq)
            if 500 < diff < 3500:
                self.seq_jumps += 1
                if self.seq_jumps > 3:
                    self.seq_anomaly = True
                    self.anomaly_reason = "Sequence Jump"
        self.last_seq = seq_num

    def calculate_danger_level(self) -> int:
        score = 0
        if self.suspect_ssid: score += 1
        if self.rssi_anomaly: score += 2
        if self.duplicate_ssid: score += 3
        if self.suspect_vendor: score += 2
        if self.similar_ssid: score += 3
        if self.deauth_count > 10: 
            score += 4
            self.anomaly_reason = "Deauth Attack"
        if self.seq_anomaly: score += 4
        
        self.danger_score = min(score, 10)
        self.is_evil_twin = (self.danger_score >= 4)
        return self.danger_score

def get_danger_level_name(score: int) -> str:
    if score <= 1: return "Faible"
    if score <= 3: return "Modéré"
    return "Critique"

def update_ap_store(bssid: str, ssid: str, channel: int, rssi: int, pkt_time: float, seq_num: int = -1):
    bssid = bssid.upper()
    with AP_STORE_LOCK:
        if bssid in AP_STORE:
            ap = AP_STORE[bssid]
            ap.update_metrics(rssi, pkt_time, seq_num)
            if ssid and ssid != "Hidden/Unknown": ap.ssid = ssid
        else:
            new_ap = APInfo(ssid=ssid, bssid=bssid, channel=channel)
            new_ap.update_metrics(rssi, pkt_time, seq_num)
            AP_STORE[bssid] = new_ap

def cleanup_stale_aps(max_age: float = 60.0):
    now = datetime.now()
    with AP_STORE_LOCK:
        to_remove = [b for b, a in AP_STORE.items() if (now - a.last_seen).total_seconds() > max_age]
        for b in to_remove: del AP_STORE[b]