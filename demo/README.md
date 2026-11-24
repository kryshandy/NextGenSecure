# Démonstration CoreGuard (laboratoire)

Ce dossier contient les spécimens de démonstration de CoreGuard.

## Principe

Les scénarios utilisent des **spécimens bénins de laboratoire** : des fichiers et scripts conçus uniquement pour déclencher les détecteurs de CoreGuard.

- **Aucune nuisance réelle** : un spécimen ne chiffre, ne vole et ne modifie rien en dehors de son périmètre de test.
- **Exécution isolée** : les scénarios tournent dans un dossier de test dédié, jamais sur des données utilisateur.
- **Kill switch** : chaque scénario peut être interrompu immédiatement, et le kill switch réseau de CoreGuard coupe les communications si besoin.

## Scénarios prévus

| # | Scénario | Cible de détection | Défense attendue |
|---|----------|--------------------|------------------|
| 1 | Ransomware simulé + suppression des copies VSS | Modification massive de fichiers, `vssadmin delete shadows` (ETW) | Canaris anti-ransomware, arrêt du processus, restauration |
| 2 | Désactivation de la protection | Tentative d'arrêt du service ou de l'antivirus | Anti-`taskkill`, réaction immédiate |
| 3 | Script PowerShell malveillant | Contenu du script analysé par AMSI avant exécution | Blocage du script par AMSI |
| 4 | Périphérique BadUSB | Comportement de frappe automatique d'un périphérique HID | Détection comportementale, alerte |
| 5 | Injection mémoire | Relation parent-enfant suspecte et écriture dans un processus tiers (ETW) | Détection comportementale, arrêt du processus |
| 6 | Phishing visuel | Page imitant une page de connexion connue, détectée par OCR | Alerte via l'extension navigateur (OCR) |
| 7 | Vol d'identifiants | Accès aux données de connexion stockées par le navigateur | Anti-infostealer navigateur, alerte |
| 8 | Crypto-clipper | Remplacement d'une adresse de portefeuille dans le presse-papiers | Presse-papiers intelligent, restauration de la valeur |
| 9 | Persistance | Ajout d'une entrée Run/RunOnce, tâche planifiée ou service | Gardien de persistance, signalement et retrait |
| 10 | Accès caméra | Ouverture de la caméra par un processus non autorisé | Privacy Guard, alerte et blocage |

> Les colonnes « Cible » et « Défense » sont à valider avec le document de référence du projet (« CoreGuard — Topo Complet »), qui n'est pas dans le dépôt.

---

## Spécimens fournis (tous « DÉMO — INOFFENSIF »)

Tous les chemins de test sont sous `%TEMP%\CoreGuardDemo`, `127.0.0.1`/`localhost` uniquement, données factices. Depuis `demo/`, avec PowerShell (`-ExecutionPolicy Bypass -File ...` si besoin). Les scénarios 2 (désactivation de la protection), 5 (injection mémoire) et 10 (caméra) n'ont volontairement pas de spécimen : ils seraient réellement offensifs ou intrusifs.

| Dossier | Scénario | Lancer | Déclenche | Défense attendue | Nettoyage |
|---------|----------|--------|-----------|------------------|-----------|
| `01-powershell-amsi` | 3 | `.\01-powershell-amsi\demo-amsi.ps1` | Base64 + `FromBase64String` + `Invoke-Expression` (texte décodé : `DEMO-INOFFENSIF`), via AMSI/règles comportementales | Alerte/blocage AMSI | Aucun |
| `02-ransomware-canari` | 1 | `.\02-ransomware-canari\demo-ransomware.ps1` (`-NbFichiers N`) | Fichiers canari (`~coreguard_canary.docx`, `_aaa_canary.txt`), rafale d'écritures/renommages `.coreguard-demo` dans `%TEMP%\CoreGuardDemo\ransomware` (CoreGuard.RealTime), ligne de commande `vssadmin delete shadows` simulée par un `echo` (jamais exécutée) | Canaris, arrêt du processus | `-Nettoyer` ; kill switch : créer le fichier `STOP` dans le dossier de test |
| `03-persistance` | 9 | `.\03-persistance\demo-persistance.ps1` | Clé `HKCU\...\Run\CoreGuardDemo` + tâche `CoreGuardDemoTask` (ONLOGON) vers `inoffensif.cmd` (écrit une ligne dans un journal de test) | Gardien de persistance | **Obligatoire** : `.\03-persistance\demo-persistance.ps1 -Nettoyer` |
| `04-badusb-hid` | 4 | `dotnet run --project .\04-badusb-hid` | Injection `SendInput` à ~1500 car/s dans sa propre fenêtre de test (garde-fou : arrêt si elle n'est pas au premier plan) | Moniteur HID (à venir) | Fermer la fenêtre ou `Échap` (kill switch) |
| `05-crypto-clipper` | 8 | `dotnet run --project .\05-crypto-clipper` | Remplacement d'une fausse adresse BTC par une autre dans le presse-papiers (CoreGuard.Privacy) | Presse-papiers intelligent, restauration | `Ctrl+C` ou 60 s ; rien à nettoyer |
| `06-phishing-visuel` | 6 | `.\06-phishing-visuel\serve-phishing-demo.ps1` puis ouvrir `http://localhost:8080` | Faux « Sign in » Microsoft rendu en image (texte absent du HTML), sans formulaire | OCR anti-phishing (extension navigateur) | `Ctrl+C` ou `http://localhost:8080/stop` |
| `07-vol-identifiants` | 7 | `.\07-vol-identifiants\demo-infostealer.ps1` | Ouverture/lecture/copie d'un FAUX `Login Data` dans un faux profil de test (jamais le vrai) | Règle anti-infostealer (à venir) | `-Nettoyer` |

Les projets C# (`BadUsbSim.csproj`, `ClipperSim.csproj`) sont isolés et ne sont pas dans `AntivirusIA.slnx`.
