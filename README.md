# GuardianWiFi

Outil de détection d’**Evil Twin** et d’analyse Wi-Fi en temps réel, développé en Python. GuardianWiFi scanne les points d’accès, calcule un score de danger et signale les réseaux suspects (SSID piège, anomalie de signal, doublons SSID/BSSID).

---

## Description

GuardianWiFi permet de :

- **Sniffer** les beacons Wi-Fi en mode moniteur (Scapy).
- **Détecter** les SSIDs suspects (portails captifs, noms type WiFi Pineapple).
- **Repérer** les anomalies RSSI (sauts de signal typiques d’un Evil Twin).
- **Identifier** les doublons de SSID avec des BSSIDs différents (Evil Twin).
- **Noter** chaque AP avec un **danger score** (0–1 Faible, 2–3 Modéré, 4+ Critique).
- **Exclure** les faux positifs via une **whitelist** de BSSIDs de confiance.
- **Afficher** un tableau coloré (vert / jaune / rouge) et un bloc d’alerte en cas de conflit.

---

## Prérequis

- **Python** 3.8+
- **Scapy** : capture et analyse des paquets Wi-Fi (couche Radiotap, Dot11).
- **Colorama** (optionnel) : couleurs dans le terminal (vert / jaune / rouge).
- **Interface Wi-Fi** compatible **mode moniteur** (Atheros, Realtek, Broadcom, etc.).
- **Droits root** (sudo) pour passer l’interface en mode moniteur et changer de canal.

### Vérifier le mode moniteur

Sous Linux :

```bash
# Lister les interfaces
iw dev

# Passer en mode moniteur (ex. wlan0)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

---

## Installation

1. **Cloner ou télécharger** le projet dans un répertoire (ex. `Projet Advanced`).

2. **Créer un environnement virtuel** (recommandé) :

   ```bash
   cd "Projet Advanced"
   python3 -m venv venv
   source venv/bin/activate   # Linux/macOS
   # ou : venv\Scripts\activate   # Windows
   ```

3. **Installer les dépendances** :

   ```bash
   pip install -r requirements.txt
   ```

4. **Configurer l’interface** dans `detector_core.py` : modifier la variable `INTERFACE` (par défaut `"wlan0"`) pour correspondre à votre interface en mode moniteur.

5. **(Optionnel)** Renseigner les réseaux de confiance dans `known_networks.json` (voir ci‑dessous).

---

## Utilisation

Lancer le scanner avec les droits root :

```bash
sudo python3 detector_core.py
```

- Le programme fait du **channel hopping** sur les canaux 2,4 GHz (1–13), sniff les beacons, met à jour le **danger score** et la whitelist à chaque cycle.
- **Arrêt** : `Ctrl+C`. L’interface est remise en mode managé à la sortie.

### Tableau affiché

- **Vert** : score 0–1 (Faible).
- **Jaune / Orange** : score 2–3 (Modéré).
- **Rouge gras** : score 4+ (Critique).

En cas de **doublon SSID** (même nom, BSSIDs différents), un bloc d’alerte rouge s’affiche sous le tableau :

```text
ATTENTION : Le SSID [NomReseau] est diffusé par deux antennes différentes (AA:BB:CC:DD:EE:FF et 11:22:33:44:55:66).
Risque Evil Twin : ne vous connectez pas sans vérifier la légitimité du réseau.
```

---

## Whitelist (réseaux de confiance)

Le fichier **`known_networks.json`** contient la liste des BSSIDs (adresses MAC) de confiance. Tout AP dont le BSSID figure dans cette liste a son **danger_score** forcé à **0** et **is_evil_twin** à **False**, même si d’autres indicateurs seraient positifs.

### Format de `known_networks.json`

```json
{
  "bssids": [
    "AA:BB:CC:DD:EE:FF",
    "11:22:33:44:55:66"
  ]
}
```

- Si le fichier n’existe pas au premier lancement, il est créé avec `"bssids": []`.
- Les BSSIDs sont comparés en majuscules ; vous pouvez les saisir en minuscules ou majuscules.

---

## Structure du projet

| Fichier                 | Rôle |
|-------------------------|------|
| `detector_core.py`     | Point d’entrée, channel hopping, détection, affichage coloré, whitelist, alerte conflit |
| `ap_model.py`          | Modèle `APInfo`, score de danger, anomalie RSSI, mise à jour `AP_STORE` |
| `packet_sniffer.py`     | Sniffing des beacons, extraction RSSI (Radiotap multi‑drivers) |
| `nic_manager.py`       | Gestion de l’interface (mode moniteur, canal, nettoyage) |
| `known_networks.json`  | Whitelist des BSSIDs de confiance |
| `requirements.txt`     | Dépendances Python (Scapy, Colorama) |

---

## Algorithme du danger score

Pour chaque point d’accès :

- **+1** si le SSID correspond à un pattern suspect (ex. « Free_WiFi », portail captif).
- **+2** si une anomalie de signal (RSSI jump) a été détectée.
- **+3** si un doublon de SSID avec un BSSID différent est détecté.

Seuils :

- **0–1** : Faible  
- **2–3** : Modéré  
- **4+** : Critique  

Les AP dont le BSSID est dans la whitelist sont forcés à **0** (et non marqués Evil Twin).

---

## Licence et responsabilité

À utiliser uniquement sur des réseaux dont vous avez l’autorisation. Les auteurs déclinent toute responsabilité en cas d’usage illégal.
