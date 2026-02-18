import threading, time, json
from pathlib import Path

AP_STORE = {}
AP_STORE_LOCK = threading.Lock()

# Chargement de la base de données des constructeurs (OUI)
OUI_DB = {}
OUI_FILE = Path(__file__).resolve().parent / "oui_database.json"
if OUI_FILE.exists():
    try:
        OUI_DB = json.loads(OUI_FILE.read_text(encoding="utf-8"))
    except: pass

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

def get_danger_level_name(score):
    if score <= 1: return "Faible"
    if score <= 3: return "Modéré"
    return "Critique"

class APInfo:
    def __init__(self, bssid, ssid, chan, rssi):
        self.bssid = bssid.upper()
        self.ssid = ssid
        self.channel = chan
        self.rssi = rssi
        self.last_seen = time.time()
        self.last_seq = -1
        self.deauth_count = 0
        self.danger_score = 0
        self.anomaly_reason = "Normal"
        self.is_evil_twin = False
        
        # Nouvelles options
        self.duplicate_ssid = False
        self.similar_ssid = False
        self.seq_jump = False
        self.suspect_vendor = False
        
        # Identification du constructeur
        prefix = ":".join(self.bssid.split(":")[:3])
        self.vendor = OUI_DB.get(prefix, "Inconnu")
        if "Alfa" in self.vendor or "Realtek" in self.vendor:
            self.suspect_vendor = True

    def calculate_danger_level(self):
        score = 0
        reasons = []
        if self.duplicate_ssid: 
            score += 3
            reasons.append("Evil Twin")
        if self.similar_ssid:
            score += 3
            reasons.append("Imitation Name")
        if self.deauth_count > 5:
            score += 4
            reasons.append("Deauth Attack")
        if self.seq_jump:
            score += 4
            reasons.append("Sequence Jump")
        if self.suspect_vendor and self.duplicate_ssid:
            score += 2
            reasons.append("Suspect Hardware")
        
        self.danger_score = min(score, 10)
        self.is_evil_twin = (self.danger_score >= 4)
        self.anomaly_reason = ", ".join(reasons) if reasons else "Normal"

def update_ap_store(bssid, ssid, chan, rssi, seq_num, is_deauth=False):
    with AP_STORE_LOCK:
        bssid = bssid.upper()
        if bssid not in AP_STORE:
            AP_STORE[bssid] = APInfo(bssid, ssid, chan, rssi)
        
        ap = AP_STORE[bssid]
        ap.last_seen = time.time()
        if is_deauth:
            ap.deauth_count += 1
        else:
            ap.rssi = rssi
            ap.ssid = ssid if (ssid != "Inconnu" and ssid != "Hidden") else ap.ssid
            ap.channel = chan if chan != 0 else ap.channel
            if seq_num != -1 and ap.last_seq != -1:
                if 500 < abs(seq_num - ap.last_seq) < 3500:
                    ap.seq_jump = True
            ap.last_seq = seq_num

def cleanup_stale_aps(max_age=60):
    now = time.time()
    with AP_STORE_LOCK:
        to_remove = [b for b, a in AP_STORE.items() if (now - a.last_seen) > max_age]
        for b in to_remove: del AP_STORE[b]