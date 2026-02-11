🛡️ GuardianWiFi Pro - Evil Twin Detector

GuardianWiFi Pro est un outil de cybersécurité développé en Python permettant de détecter en temps réel les attaques de type Evil Twin (Jumeau Maléfique) et d'analyser la sécurité des réseaux Wi-Fi environnants.
Contrairement aux scanners classiques, GuardianWiFi analyse l'ADN technique (empreintes matérielles, comportements radio) pour différencier un point d'accès légitime d'une antenne pirate.

🌟 Fonctionnalités Principales

1. Détection Avancée
-Analyse OUI (Vendor) : Identifie le constructeur de l'antenne (ex: Sagemcom, Apple, Cisco) et signale les constructeurs suspects souvent utilisés par les hackers (ex: Alfa Network, Realtek).
- Distance de Levenshtein : Détecte le "Typosquatting" de SSID (ex: détecter qu'un faux réseau MaB0x tente d'imiter le réseau officiel MaBox).
- Analyse des Numéros de Séquence : Repère la présence physique de deux émetteurs pour un même réseau en analysant les compteurs de paquets matériels.
- Détection d'Attaque Deauth : Alerte immédiate si une vague de paquets de déconnexion forcée est détectée.
- Danger Score (0-10) : Un algorithme intelligent calcule un score de risque pour chaque réseau.
- 
2. Interface et Alertes
 Dashboard GUI : Interface graphique moderne (Dark Mode) développée avec CustomTkinter.
 Mode CLI : Version terminal colorée pour une utilisation légère ou sur serveur.
 Notifications Système : Alertes "Pop-up" sur le bureau dès qu'une menace critique est identifiée.
 Historique & Logs : Enregistrement automatique de chaque session dans des fichiers CSV pour analyse post-scan.

3. Flexibilité
- Mode Simulation : Permet de tester toutes les fonctionnalités et scénarios d'attaques sans carte Wi-Fi spécifique (idéal pour les démonstrations).
- Whitelist : Gestion des réseaux de confiance via known_networks.json.
- Structure du Projet
Fichier	Description
detector_core.py	Point d'entrée principal, gère la logique de détection et les threads.
gui_dashboard.py	Code de l'interface graphique (Dashboard).
ap_model.py	Modèle de données, calculs statistiques et score de danger.
packet_sniffer.py	Module de capture et d'analyse des paquets (Scapy).
simulator.py	Générateur d'attaques virtuelles pour le mode simulation.
nic_manager.py	Gestion de l'interface réseau (Mode moniteur, canaux).
logger.py	Enregistrement des données dans le dossier /logs.
oui_database.json	Base de données des identifiants constructeurs (OUI).

🚀 Installation
Prérequis
Linux (Kali Linux recommandé).
Python 3.10+.
Une interface Wi-Fi supportant le mode moniteur (pour le scan réel).
Installation des dépendances
code
Bash
pip install customtkinter scapy colorama plyer --break-system-packages
Note : Sur Kali Linux, libnotify-bin est requis pour les notifications (sudo apt install libnotify-bin).

💻 Utilisation
1. Mode Simulation (Démonstration)
Idéal pour présenter le projet sans matériel spécifique :
code
Bash
python3 detector_core.py --simulate
2. Mode Réel (Scan Wi-Fi)
Nécessite les droits administrateur (root) et une interface en mode moniteur :
code
Bash
sudo python3 detector_core.py -i wlan0mon
3. Mode Terminal (Sans interface graphique)
code
Bash
python3 detector_core.py --simulate --cli

🧠 Comprendre le Danger Score
Le score est cumulatif. Un réseau est considéré comme Critique à partir de 4/10.
Critère	Points	Description
Evil Twin	+3	Même nom (SSID) mais adresse MAC (BSSID) différente.
Imitation	+3	Le nom ressemble à 90% à un réseau connu (Levenshtein).
Saut Séquence	+4	Preuve matérielle de deux émetteurs différents.
Attaque Deauth	+4	Tentative active de déconnecter les utilisateurs.
Vendor	+2	L'antenne appartient à une marque suspecte.
RSSI Spike	+2	Augmentation brutale et anormale du signal.

📖 Lexique pour les débutants
BSSID : L'adresse physique unique d'un routeur (sa plaque d'immatriculation).
SSID : Le nom que vous voyez dans votre liste Wi-Fi.
Deauth : Un paquet envoyé pour forcer un appareil à se déconnecter.
OUI : Les premiers chiffres de l'adresse MAC qui identifient le fabricant (Apple, Samsung, Alfa).
⚖️ Licence et Responsabilité
Cet outil est destiné à un usage éducatif et à des tests de pénétration autorisés uniquement. L'auteur décline toute responsabilité en cas d'usage illégal.