# Guide de CoreGuard

Antivirus nouvelle génération pour Windows 10/11, **100 % local** (aucune donnée n'est envoyée). Ce guide explique
comment l'installer, l'utiliser, le tester, et comment le code est organisé.

---

## 1. Installer

1. Récupérer l'installateur complet, au choix :
   - **local** : `artifacts\CoreGuard-Setup-1.0.0-complet.zip` (construit par `./scripts/build-setup.ps1`, ~2,9 Go, tout
     inclus, modèle d'IA compris) ou le dossier `artifacts\CoreGuard-Setup` ;
   - **GitHub** (*Releases*) : `CoreGuard-Setup-<version>.zip` + `Llama-3.2-3B-Instruct-Q4_K_M.gguf` (GitHub limite un
     fichier à 2 Go) ; décompresser le zip et placer le `.gguf` **à côté de `CoreGuard-Setup.exe`**.
   Décompresser sur le PC cible.
2. Lancer **`CoreGuard-Setup.exe`** (accepter la demande d'administrateur).
3. **Mot de passe de protection** (8 caractères minimum) : il sera demandé pour arrêter CoreGuard, désactiver le Mode
   Paranoïa, associer un téléphone. Un logiciel malveillant ne peut donc pas couper la protection.
4. Laisser les options cochées → **Installer**. Rien n'est téléchargé : l'IA locale (2 Go), le runtime .NET et le runtime
   Visual C++ (requis par ONNX Runtime et llama.cpp, installé silencieusement) sont dans l'installateur.

Désinstaller : *Paramètres Windows > Applications > CoreGuard*, ou menu Démarrer > *Désinstaller CoreGuard*
(mot de passe de protection demandé).

**Extension navigateur** (anti-phishing, coffre-fort) — une fois par navigateur : `edge://extensions` (ou
`chrome://extensions`) > *Mode développeur* > *Charger l'extension non empaquetée* >
`C:\Program Files\CoreGuard\Extension`.

## 2. Utiliser au quotidien

CoreGuard démarre avec Windows, **caché** : son bouclier est près de l'horloge (si besoin : flèche **^**, puis
glisser l'icône sur la barre). Clic : ouvrir ; clic droit : *Verrouiller le PC*, *Quitter*.

| Je veux… | Où / comment |
|---|---|
| Analyser un fichier ou un dossier | **Analyse** > choisir ; verdict Sain / Suspect / Malveillant, explication par l'IA locale |
| Voir les alertes | **Tableau de bord** > *Alertes en temps réel* (bulle Windows si la fenêtre est cachée) |
| Restaurer un fichier mis en quarantaine | **Quarantaine** > *Restaurer* |
| Savoir si un téléchargement est sûr | automatique : fenêtre **vert / orange / rouge** (site d'origine, signature, moteurs, IA) |
| Bloquer un programme qui s'installe au démarrage | automatique : fenêtre **Autoriser / Bloquer** |
| Couper caméra / micro à une application | **Tableau de bord** > *Couper* à côté de l'application |
| Gérer mes mots de passe | **Coffre-fort** (Argon2id + AES-256) ; remplissage par l'extension, refusé sur un site douteux |
| Verrouiller le PC en urgence | **Tableau de bord** > *Verrouiller le PC* ; déverrouiller : Ctrl+R puis mot de passe |
| Durcir le PC (voyage, prêt, doute) | **Mode Paranoïa** : USB bloqué, pare-feu durci, programmes non signés de Téléchargements/%TEMP% arrêtés |
| Agir depuis mon téléphone | **Réglages > Contrôle à distance** (section 3) |
| Ne plus être alerté pour un site | page d'alerte > *Je fais confiance* (confirmé dans CoreGuard) ; retirer : **Réglages > Anti-phishing** |

## 3. Contrôle à distance par téléphone (sans Internet)

1. **Sans box** : *Réglages > Contrôle à distance > Point d'accès mobile de Windows* : activer le point d'accès, puis
   connecter le téléphone à ce Wi-Fi. **Avec une box** : téléphone et PC sur le même Wi-Fi.
2. *Associer un téléphone* > mot de passe de protection > un **QR code** apparaît : le scanner avec l'appareil photo.
3. La page CoreGuard s'ouvre sur le téléphone : **Verrouiller**, **Déverrouiller**, **Activer / Désactiver le Mode
   Paranoïa**, état du PC. Ajouter la page à l'écran d'accueil pour la retrouver.

Sécurité : le QR code contient une clé secrète de 256 bits (après le `#`, jamais envoyée sur le réseau) ; chaque ordre
est signé (HMAC-SHA256) sur un défi à usage unique ; 5 échecs = 5 minutes de blocage ; port ouvert au réseau local
uniquement (jamais à Internet). *Révoquer* coupe l'accès du téléphone.

## 4. Tester CoreGuard (spécimens inoffensifs)

Tous les spécimens sont dans `C:\Program Files\CoreGuard\Demo` (ou `demo\` du dépôt). Ils **imitent** un malware sans
rien abîmer. Procédure détaillée, commandes exactes et résultats attendus : **[TESTING.md](TESTING.md)**.

| Spécimen | Commande | Attendu |
|---|---|---|
| 01 Script obfusqué | `powershell -File .\01-powershell-amsi\demo-amsi.ps1` | bloqué avant exécution (AMSI) |
| 02 Ransomware | `.\02-ransomware-canari\RansomwareSim\RansomwareSim.exe` | arrêté au premier leurre (code 0xC0DE0001) |
| 03 Persistance | `powershell -File .\03-persistance\demo-persistance.ps1` puis `-Nettoyer` | fenêtres Autoriser / Bloquer |
| 04 BadUSB | `.\04-badusb-hid\BadUsbSim.exe` | clavier bloqué 10 s |
| 05 Crypto-clipper | `.\05-crypto-clipper\ClipperSim.exe` | adresse d'origine restaurée |
| 07 Voleur d'identifiants | `powershell -File .\07-vol-identifiants\demo-infostealer.ps1` | arrêté en lisant le faux profil |
| 08 Anti-arrêt | `powershell -File .\08-anti-kill\demo-anti-kill.ps1` | « Accès refusé », service toujours actif |
| 09 Injection mémoire | `.\09-injection-memoire\MemoryInjectionSim.exe` | arrêté au scan mémoire (≤ 30 s) |
| 10 Phishing + IA | `powershell -File .\10-phishing-ia\serve-phishing-lab.ps1` puis les adresses du README | page « CoreGuard n'aime pas ce site » |
| 11 Téléchargements | `powershell -File .\11-telechargement\demo-telechargement.ps1` | fenêtres vert / orange / rouge |
| 12 Paranoïa | activer le Mode Paranoïa, puis `powershell -File .\12-paranoia\demo-paranoia.ps1` | programme arrêté |
| 13 Pare-feu WFP | console administrateur : `dotnet run --project demo\13-pare-feu-wfp` | curl bloqué puis débloqué |

## 5. Comprendre le code

```
AntivirusIA.UI          Application WPF (MVVM) : tableau de bord, analyse, quarantaine, coffre, réglages, icône
AntivirusIA.Core        Modèles et interfaces (IDetectionEngine, IKernelActionProvider, IAiProvider…)
AntivirusIA.Engines     Moteurs : signatures, règles, heuristiques, entropie, PE statique, Authenticode
AntivirusIA.Ml          IA niveau 1 : caractéristiques EMBER + modèle LightGBM exporté en ONNX
AntivirusIA.AI          LLM local (LLamaSharp, Llama 3.2 3B) : explications, revue anti-phishing
AntivirusIA.Infrastructure  Quarantaine chiffrée (AES-256-GCM), historique SQLite
CoreGuard.Service       Service SYSTEM : ETW, leurres + audit NTFS, anti-infostealer, AMSI, mémoire, verrouillage,
                        Mode Paranoïa, contrôle à distance (HTTP + HMAC), auto-défense (DACL, watchdog)
CoreGuard.Ipc           Canal UI ↔ service (named pipe, ACL, défi-réponse HMAC), relais navigateur ↔ application
CoreGuard.Behavior      ETW, règles comportementales, persistance, blocage d'exécution du Mode Paranoïa
CoreGuard.RealTime      Surveillance de fichiers, leurres (canaris), marque du Web (Zone.Identifier)
CoreGuard.Network       Pare-feu natif WFP (FwpmFilterAdd0) et pare-feu Windows (COM)
CoreGuard.Privacy       Presse-papiers, caméra / micro, Mode Paranoïa (politique)
CoreGuard.Devices       BadUSB (cadence de frappe), verrouillage clavier / souris
CoreGuard.Memory        Scan mémoire (code injecté, image PE hors fichier)
CoreGuard.Response      Actions : arrêt / suspension de processus, ACL, isolement réseau
CoreGuard.Vault         Coffre-fort de mots de passe
CoreGuard.Extension     Hôte de l'extension : base de confiance, OCR, QR, cascade anti-phishing ; extension\ (MV3)
CoreGuard.AmsiProvider  Fournisseur AMSI natif (NativeAOT, COM)
CoreGuard.Setup         Assistant d'installation hors ligne
```

**Construire, tester, livrer**

```powershell
dotnet build AntivirusIA.slnx          # compiler
dotnet test AntivirusIA.slnx           # 466 tests automatisés
./scripts/build-setup.ps1              # installateur complet hors ligne → artifacts\CoreGuard-Setup
```

**Principes** : chaque module démarre et échoue seul (une panne n'arrête pas les autres) ; tout ce qui vient d'un
fichier, d'une page web ou d'une IA est traité comme **non fiable** ; toute action qui affaiblit la protection exige le
mot de passe de protection ; l'IA ne peut qu'**aggraver** un verdict, jamais rassurer seule.

Pour aller plus loin : [README](../README.md), [AUDIT](AUDIT.md) (état de chaque fonctionnalité),
[IA-ENTRAINEMENT](IA-ENTRAINEMENT.md) (comment le modèle est entraîné et évalué).
