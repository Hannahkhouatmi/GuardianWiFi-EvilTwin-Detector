# ap_model.py

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Dictionnaire global (La base de données de Hannah)
AP_STORE: Dict[str, "APInfo"] = {}
# [SARA] Lock pour accès thread-safe au dictionnaire (cleanup, update_ap_store)
AP_STORE_LOCK = threading.Lock()

# Taille de l'historique RSSI pour la moyenne glissante et la détection d'anomalie
RSSI_HISTORY_SIZE = 10
# Seuil (dBm) au-delà duquel un gain brutal par rapport à la moyenne = suspect (Evil Twin)
RSSI_ANOMALY_GAIN_THRESHOLD_DBM = 20

# Seuils du Danger Score : 0-1 Faible, 2-3 Modéré, 4+ Critique
DANGER_LEVEL_LOW_MAX = 1
DANGER_LEVEL_MODERATE_MAX = 3


@dataclass
class APInfo:
    """
    [HANNAH - STRUCTURE]
    C'est la carte d'identité de l'AP.
    Historique des N derniers RSSI pour moyenne glissante et détection d'anomalie.
    """
    ssid: str = "Hidden/Unknown"
    bssid: str = field(init=False)  # Adresse MAC (l'ID unique) - défini après init
    channel: int = 0
    rssi: int = -100  # [HANNAH] Force du signal (par défaut faible)
    last_seen: datetime = field(default_factory=datetime.now)
    beacon_count: int = 1
    is_evil_twin: bool = False
    # [HANNAH] Historique des 10 dernières valeurs RSSI (moyenne glissante / anomalie)
    rssi_history: List[int] = field(default_factory=list)
    # [HANNAH] Raison du marquage suspect (anomalie RSSI, SSID piège, etc.)
    anomaly_reason: Optional[str] = field(default=None)
    # [HANNAH] Score de danger (0 = sûr, 4+ = critique). Mis à jour par la logique de détection.
    danger_score: int = 0
    # Indicateurs pour le calcul du score (SSID suspect +1, anomalie RSSI +2, doublon +3)
    suspect_ssid: bool = False
    rssi_anomaly: bool = False
    duplicate_ssid: bool = False

    def __post_init__(self):
        """Convertit le BSSID en majuscules pour la cohérence."""
        if hasattr(self, "bssid"):
            self.bssid = self.bssid.upper()

    def _rssi_average(self) -> Optional[float]:
        """Moyenne des valeurs dans rssi_history. None si vide. Léger O(n), n <= 10."""
        if not self.rssi_history:
            return None
        return sum(self.rssi_history) / len(self.rssi_history)

    def check_rssi_anomaly(self, new_rssi: int) -> Tuple[bool, Optional[str]]:
        """
        [HANNAH - ANOMALIE RSSI]
        Compare le signal entrant à la moyenne historique.
        Si le nouveau signal est brutalement plus fort (ex: gain > RSSI_ANOMALY_GAIN_THRESHOLD_DBM),
        marque l'AP comme suspect et retourne (True, raison). Sinon (False, None).
        """
        avg = self._rssi_average()
        if avg is None:
            return False, None
        gain_dbm = new_rssi - avg
        if gain_dbm > RSSI_ANOMALY_GAIN_THRESHOLD_DBM:
            reason = f"RSSI jump +{gain_dbm:.0f} dBm vs avg {avg:.0f} dBm"
            self.is_evil_twin = True
            self.anomaly_reason = reason
            self.rssi_anomaly = True
            return True, reason
        return False, None

    def calculate_danger_level(self) -> int:
        """
        [HANNAH - DANGER SCORE]
        Pondère les risques : +1 SSID suspect, +2 anomalie RSSI, +3 doublon SSID.
        Seuils : 0-1 Faible, 2-3 Modéré, 4+ Critique.
        """
        self.danger_score = 0
        if self.suspect_ssid:
            self.danger_score += 1
        if self.rssi_anomaly:
            self.danger_score += 2
        if self.duplicate_ssid:
            self.danger_score += 3
        return self.danger_score


def get_danger_level_name(score: int) -> str:
    """Retourne le libellé du niveau de danger : Faible, Modéré, Critique."""
    if score <= DANGER_LEVEL_LOW_MAX:
        return "Faible"
    if score <= DANGER_LEVEL_MODERATE_MAX:
        return "Modéré"
    return "Critique"

def cleanup_stale_aps(max_age_seconds: float = 60.0) -> int:
    """
    [SARA - NETTOYAGE]
    Supprime de AP_STORE toute entrée dont last_seen est plus ancien que
    max_age_seconds par rapport à l'heure actuelle. Thread-safe (Lock).
    Retourne le nombre d'entrées supprimées.
    """
    now = datetime.now()
    with AP_STORE_LOCK:
        to_remove = [
            bssid
            for bssid, ap in AP_STORE.items()
            if (now - ap.last_seen).total_seconds() > max_age_seconds
        ]
        for bssid in to_remove:
            del AP_STORE[bssid]
    return len(to_remove)


def update_ap_store(bssid: str, ssid: str, channel: int, rssi: int) -> None:
    """
    [HANNAH - MISE À JOUR]
    Met à jour les infos. Si l'AP existe, met à jour le RSSI, l'historique,
    et vérifie une anomalie RSSI (gain brutal -> is_evil_twin). Thread-safe (Lock).
    """
    bssid = bssid.upper()
    with AP_STORE_LOCK:
        if bssid in AP_STORE:
            ap = AP_STORE[bssid]
            ap.last_seen = datetime.now()
            ap.beacon_count += 1

            # Historique RSSI : garder les N dernières valeurs (léger, temps réel)
            ap.rssi_history.append(rssi)
            if len(ap.rssi_history) > RSSI_HISTORY_SIZE:
                ap.rssi_history.pop(0)
            ap.rssi = rssi

            # Détection anomalie : gain brutal vs moyenne glissante
            ap.check_rssi_anomaly(rssi)

            if ssid and ssid != "Hidden/Unknown":
                ap.ssid = ssid
        else:
            new_ap = APInfo(
                ssid=ssid if ssid else "Hidden/Unknown",
                channel=channel,
                rssi=rssi,
                rssi_history=[rssi],
            )
            new_ap.bssid = bssid
            AP_STORE[bssid] = new_ap

# Liste des canaux standards 2.4GHz
CHANNELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

