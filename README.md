# 🛡️ CoreGuard — Antivirus nouvelle génération augmenté par l'IA

> Suite de sécurité pour Windows 10/11, **100 % locale** : aucune donnée envoyée, aucun cloud, fonctionne hors ligne.
> Projet de cours C# — « en surface du C#, en dessous bien plus ».

CoreGuard combine des moteurs de détection classiques, de l'**IA embarquée** (classifieur EMBER / ONNX et modèle de
langage local Llama 3.2 3B), une **protection comportementale temps réel** assurée par un service SYSTEM qui se défend
lui-même, une **extension navigateur** anti-phishing avec coffre-fort, et un **contrôle à distance par téléphone**.

| Document | Pour qui | Contenu |
|---|---|---|
| [`docs/GUIDE.md`](docs/GUIDE.md) | tout le monde | installer, utiliser, téléphone, tester, comprendre le code (court) |
| [`docs/TESTING.md`](docs/TESTING.md) | démonstration, soutenance | commande exacte, résultat attendu et observé pour chaque fonctionnalité |
| [`docs/AUDIT.md`](docs/AUDIT.md) | évaluation | état réel de chaque fonctionnalité, preuves, limites |
| [`docs/IA-ENTRAINEMENT.md`](docs/IA-ENTRAINEMENT.md) | IA | comment le modèle est entraîné et évalué (AUC 0,980) |
| [`docs/CoreGuard-Phase1-Explication.html`](docs/CoreGuard-Phase1-Explication.html) | découverte | explication illustrée, en français simple et en termes techniques |

---

## Installer (sans rien télécharger)

1. Construire l'installateur une fois, sur la machine de développement : `./scripts/build-setup.ps1`
   → `artifacts\CoreGuard-Setup\` (~2,6 Go : application, runtime .NET, **modèle d'IA local**, modèle ONNX, service,
   fournisseur AMSI, extension, guide, spécimens de démonstration).
2. Copier ce dossier sur le PC cible et lancer **`CoreGuard-Setup.exe`** : choisir le **mot de passe de protection**,
   garder les options, *Installer*. Désinstallation : *Paramètres Windows > Applications > CoreGuard*.
3. Extension navigateur : `edge://extensions` > *Mode développeur* > *Charger l'extension non empaquetée* >
   `C:\Program Files\CoreGuard\Extension`.

## Cas d'usage

| Situation | Ce que fait CoreGuard | Comment l'utiliser |
|---|---|---|
| Je télécharge un fichier | verdict **vert / orange / rouge** : site d'origine (`Zone.Identifier`), signature, moteurs, IA | automatique ; *Mettre en quarantaine* en un clic |
| Je veux vérifier un fichier ou un dossier | analyse (signatures, règles, PE, entropie, IA EMBER/ONNX) + explication par l'IA locale | page **Analyse** |
| Un ransomware chiffre mes fichiers | leurres cachés : le coupable est **arrêté au premier leurre** (audit NTFS, PID exact) | automatique (service) |
| Un script PowerShell malveillant se lance | analysé **avant exécution** (fournisseur AMSI) et bloqué | automatique |
| Un programme vole mes mots de passe de navigateur | tout lecteur qui n'est pas le navigateur signé est **arrêté** | automatique (service) |
| Un malware s'injecte en mémoire (sans fichier) | scan mémoire toutes les 30 s, processus arrêté | automatique (service) |
| Un programme s'installe au démarrage | fenêtre **Autoriser / Bloquer** avec niveau de risque | répondre à la fenêtre |
| Une clé USB « tape » toute seule (BadUSB) | frappe surhumaine détectée, **clavier bloqué 10 s** | automatique |
| Mon adresse crypto est remplacée au collage | valeur d'origine **restaurée** | automatique |
| Une application allume ma caméra / mon micro | alerte, bouton **Couper** | tableau de bord |
| J'ouvre un site d'arnaque | page **« CoreGuard n'aime pas ce site »** ; doute → fenêtre ; IA locale en zone grise | extension navigateur |
| Je veux gérer mes mots de passe | **coffre-fort** chiffré, remplissage refusé sur un site douteux | page **Coffre-fort** + extension |
| Je m'absente / je prête le PC / je doute | **Mode Paranoïa** : USB bloqué, pare-feu WFP durci, programmes non signés de Téléchargements bloqués | interrupteur du tableau de bord |
| On m'a volé le PC / je suis loin | **verrouillage d'urgence** : écran CoreGuard, USB et périphériques refusés | bouton, BadUSB, ou **téléphone** |
| Je veux agir depuis mon téléphone, sans Internet | page signée (HMAC) sur le Wi-Fi ou le **point d'accès du PC** : verrouiller, déverrouiller, Paranoïa | *Réglages > Contrôle à distance* > QR code |
| Un malware essaie de tuer l'antivirus | `taskkill` refusé, watchdog, arrêt uniquement avec le **mot de passe** | automatique |

Tester chaque cas avec les spécimens inoffensifs : [`docs/TESTING.md`](docs/TESTING.md).

## Fonctionnalités

**Détection**
- ✅ Analyse à la demande et **Smart Download Guard** (marque du Web, signature Authenticode, moteurs, IA)
- ✅ Signatures SHA-256 multi-sources ; **règles de contenu** de type YARA (EICAR, Mimikatz, contournement AMSI, suppression des clichés, notes de rançon, *download cradles*, vol d'identifiants, chargeurs réflectifs)
- ✅ **Analyse PE statique** (IAT pondérée, entropie et RWX par section, packers) ; **Authenticode** hors ligne
- ✅ **IA niveau 1** : classifieur EMBER 2018 (LightGBM → ONNX), AUC 0,980 sur 100 561 fichiers de test, 0 fausse alerte au seuil haut sur 2 177 exécutables Windows, ≈ 17 ms par fichier ([méthode](docs/IA-ENTRAINEMENT.md))
- ✅ **IA niveau 2** : LLM local (Llama 3.2 3B, LLamaSharp) qui explique les alertes et relit les sites douteux ; il ne peut qu'aggraver un verdict
- ✅ **AMSI** : fournisseur natif (NativeAOT, COM), scripts analysés par le service avant exécution
- ✅ **ETW** : règles comportementales (Office → shell, suppression des clichés), arrêt immédiat de `vssadmin`/`wmic`/`diskshadow`

**Réaction et protection**
- ✅ **Quarantaine** AES-256-GCM (clé DPAPI), restauration refusée si le fichier est altéré
- ✅ **Anti-ransomware** (leurres + audit NTFS), **anti-infostealer**, **scan mémoire** fileless, **gardien de persistance**
- ✅ **Pare-feu natif WFP** (`FwpmFilterAdd0` par AppId) : isolement d'un programme, Mode Paranoïa
- ✅ **Auto-défense** : DACL durcie, watchdog mutuel, arrêt et désactivations par **mot de passe** (défi-réponse HMAC)
- ✅ **BadUSB**, **verrouillage d'urgence** (Ctrl+R puis mot de passe pour déverrouiller), **Mode Paranoïa** réel
- ✅ **Contrôle à distance par téléphone** : réseau local ou point d'accès mobile du PC, clé de 256 bits par QR code, ordres signés sur défi à usage unique, blocage après 5 échecs
- ✅ **Mode arrière-plan** : icône près de l'horloge, démarrage avec Windows, bulles d'alerte

**Navigateur et vie privée**
- ✅ **Anti-phishing** : base de confiance locale (100 000 domaines, Public Suffix List, liste noire OpenPhish), OCR + QR, IA locale, page d'interception ; seul l'utilisateur peut faire confiance à un site (confirmé dans CoreGuard) ; mesuré : 11/11 arnaques, 0 fausse alerte sur 19 cas
- ✅ **Coffre-fort** (Argon2id + AES-256-GCM), remplissage par l'extension refusé hors navigateur signé et sur site douteux
- ✅ **Presse-papiers** (anti-crypto-clipper, effacement des secrets), **caméra / micro** (alerte, bouton Couper)

---

## Développer

```powershell
git clone https://github.com/kryshandy/NextGenSecure.git
cd NextGenSecure
./scripts/setup.ps1                     # paquets, modèle IA local (~2 Go, une fois), compilation
dotnet run --project AntivirusIA.UI     # lancer l'application
dotnet test AntivirusIA.slnx            # tests automatisés
./scripts/install-service.ps1           # service de protection (console administrateur)
./scripts/build-setup.ps1               # installateur complet hors ligne
```

Prérequis : Windows 10/11 x64, SDK .NET 10+, outils C++ de Visual Studio (fournisseur AMSI uniquement).

```
AntivirusIA.Core / Engines / Ml / AI / Infrastructure   analyse, IA, quarantaine
AntivirusIA.UI                                           application WPF (MVVM)
CoreGuard.Service / Ipc                                  service SYSTEM, canal sécurisé, contrôle à distance
CoreGuard.Behavior / RealTime / Network / Memory         ETW, leurres, WFP, mémoire
CoreGuard.Response / Devices / Privacy / Vault           réponse, BadUSB, vie privée, coffre
CoreGuard.Extension / AmsiProvider / Setup               navigateur, AMSI natif, installateur
demo/                                                    spécimens inoffensifs de démonstration
```

Détail par module : [`docs/MODULES.md`](docs/MODULES.md) ; collaboration : [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Sécurité et limites assumées

- **Phase 1 = mode utilisateur** (service SYSTEM, aucun driver) : un administrateur doté de SeDebugPrivilege peut encore
  arrêter le service et son watchdog ensemble ; le gestionnaire de services le relance. Le driver noyau (Phase 2, en pause)
  supprimera cette limite via `IKernelActionProvider`.
- Le canal application ↔ service n'accepte que ce qui **renforce** la protection (verrouiller, activer le Mode Paranoïa,
  analyser un script) ; tout ce qui l'**affaiblit** (arrêt, déverrouillage, désactivation, association d'un téléphone)
  exige la preuve du mot de passe de protection.
- Les données de l'application (`%LocalAppData%\CoreGuard`) restent lisibles par un programme du même compte ; DPAPI
  protège la clé de quarantaine contre la copie vers une autre machine.
- Le contrôle à distance est volontairement limité au **réseau local** (Wi-Fi ou point d'accès du PC), en HTTP signé :
  pas d'accès par Internet.
- L'IA assiste et explique ; les règles déterministes restent la base des décisions.
