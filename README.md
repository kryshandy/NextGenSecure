# 🛡️ CoreGuard — Antivirus nouvelle génération augmenté par l'IA

> Suite de sécurité hybride pour Windows 10/11, **100 % locale**, sans cloud ni télémétrie sortante.
> Projet de cours C# — « en surface du C#, en dessous bien plus ».

CoreGuard combine des moteurs de détection classiques, de l'**IA embarquée** (classifieur statique ONNX + LLM local pour l'explication) et une couche de **protection comportementale temps réel**. Il est livré en **deux phases** :

| Phase | Périmètre | État |
|-------|-----------|------|
| **Phase 1** (en cours) | 100 % user-mode (Ring 3 / service `SYSTEM`) — aucune VM, aucun *test signing*, aucun driver. | 🚧 En développement |
| **Phase 2** (en pause) | Driver noyau Rust (minifilter + `ObRegisterCallbacks`), rebranchable via l'abstraction `IKernelActionProvider`. | ⏸️ En pause |

> **État réel, fonctionnalité par fonctionnalité** : voir l'audit [`docs/AUDIT.md`](docs/AUDIT.md) (ce qui est complet, partiel ou absent, et le plan pour rendre les 10 démos démontrables).

---

## Mise en route rapide

```powershell
git clone https://github.com/kryshandy/NextGenSecure.git
cd NextGenSecure
./scripts/setup.ps1
dotnet run --project AntivirusIA.UI
```

`setup.ps1` restaure les paquets, **télécharge le modèle IA local** (~2 Go, hors git) et compile. Détails de collaboration : [`CONTRIBUTING.md`](CONTRIBUTING.md).

Pour une **distribution autonome** (runtime .NET + modèle embarqués, aucune installation requise sur la machine cible) :

```powershell
./scripts/publish.ps1
```
Résultat : un dossier unique `publish/CoreGuard` qui fonctionne hors-ligne.

## Architecture (Phase 1)

```
CoreGuard.sln
├─ AntivirusIA.Core           Contrats, modèles, pipeline de scan, scoring
├─ AntivirusIA.Engines        Moteurs : signatures, règles de contenu, entropie, heuristiques, PE statique, Authenticode
├─ AntivirusIA.AI             IA : LLM local (LLamaSharp) — classifieur ONNX (EMBER) prévu
├─ AntivirusIA.Infrastructure Quarantaine chiffrée (AES-256-GCM, clé DPAPI), historique SQLite
├─ CoreGuard.RealTime         Temps réel : FileSystemWatcher, canaris anti-ransomware
├─ CoreGuard.Behavior         Comportement : ETW, client AMSI, gardien de persistance
├─ CoreGuard.Network          Pare-feu natif WFP (FwpmFilterAdd0 par AppId), pare-feu Windows (COM), ports, kill switch
├─ CoreGuard.Response         Actions de réponse user-mode (IKernelActionProvider) : arrêt, suspension, ACL, DACL
├─ CoreGuard.Ipc              Canal UI ↔ service (named pipe local, ACL, vérification du serveur)
├─ CoreGuard.Service          Service Windows LocalSystem : ETW, canaris, analyse AMSI, auto-défense
├─ CoreGuard.AmsiProvider     Fournisseur AMSI natif (NativeAOT, COM) chargé dans PowerShell & co.
├─ CoreGuard.Devices          Moniteur BadUSB : cadence de frappe, blocage de l'injection
├─ CoreGuard.Memory           Scan mémoire « fileless » (images PE injectées)
├─ CoreGuard.Vault            Coffre-fort mots de passe (SQLite + Argon2id + AES-GCM)
├─ CoreGuard.Privacy          Privacy Guard (caméra/micro), presse-papiers, Mode Paranoïa
├─ AntivirusIA.UI             Interface WPF (MVVM) — dashboard temps réel
├─ CoreGuard.Extension        Extension navigateur (Manifest V3 + Native Messaging + OCR)
└─ AntivirusIA.Tests          Tests (MSTest)
```

> `CoreGuard.Service` (LocalSystem) héberge la télémétrie ETW et la réponse ; l'UI s'y connecte par named pipe et garde les modules liés à la session de l'utilisateur. Sans service installé, l'UI fonctionne seule (ETW alors limité aux sessions administrateur).

---

## Fonctionnalités

✅ = disponible · 🟡 = partiel · ⏳ = prévu (détail dans [`docs/AUDIT.md`](docs/AUDIT.md))

**Détection**
- ✅ Scan à la demande (fichier / dossier récursif) + **Smart Download Guard** : chaque nouveau téléchargement reçoit un verdict vert / orange / rouge (marque du Web `Zone.Identifier` : site d'origine, signature Authenticode, moteurs)
- ✅ Signatures SHA-256 multi-sources (JSON + listes `.txt` issues de flux publics, dossier `%LocalAppData%\CoreGuard\signatures`)
- ✅ **Règles de contenu** inspirées de YARA (texte, hex avec jokers, UTF-16, conditions) : EICAR, Mimikatz, contournement AMSI, suppression des clichés, notes de rançon, *download cradles*, vol d'identifiants navigateur, chargeurs réflectifs
- ✅ **Analyse PE statique** (IAT pondérée, entropie et RWX par section, packers) ; un PE malformé est jugé suspect (échec sécurisé)
- ✅ **Signature Authenticode** (WinVerifyTrust, hors ligne) : atténue les heuristiques, jamais les preuves fortes
- ✅ **IA niveau 2** — LLM local (Llama 3.2 3B via LLamaSharp) : explique les alertes, **ne décide jamais** du blocage
- 🟡 **ETW** — règles Office→shell (Base64), `vssadmin`/`wmic`/`diskshadow`, persistance (droits admin requis ; alerte sans blocage)
- ✅ **AMSI** — fournisseur natif enregistré auprès de Windows : chaque script PowerShell / VBScript / JScript / macro est analysé par le service **avant exécution** (règles + Base64 décodé) et bloqué s'il est malveillant. Compilation : `scripts/build-amsi-provider.ps1` (outils C++ de Visual Studio) ; enregistrement par `install-service.ps1`
- ⏳ **IA niveau 1** — classifieur statique ONNX (type EMBER), scoring < 50 ms

**Réaction / protection**
- ✅ Quarantaine **AES-256-GCM** authentifiée, clé protégée par **DPAPI**, droits NTFS restreints (exécution refusée), restauration refusée si le fichier est altéré
- ✅ **Arrêt immédiat** des commandes de suppression des clichés instantanés (`vssadmin`, `wmic`, `diskshadow`) repérées par ETW, via `IKernelActionProvider` (garde-fous : jamais de processus critique de Windows)
- ✅ **Anti-ransomware** : canaris cachés dans les dossiers de chaque utilisateur, restauration immédiate, et **arrêt du processus coupable** identifié par l'audit NTFS (PID exact, événement 4663 ; activé par `install-service.ps1`). Sans audit : alerte et restauration, jamais d'arrêt sur supposition
- ✅ **Mode arrière-plan** — icône dans la zone de notification (Ouvrir / Verrouiller le PC / Quitter), fermer la fenêtre la masque sans arrêter la protection, bulles Windows pour les alertes, lancement caché à l'ouverture de session (`--background`, sans admin), instance unique
- ✅ **Gardien de persistance** (Run/RunOnce, tâches planifiées, dossier Démarrage, services 7045) — fenêtre **Autoriser / Bloquer** avec niveau de risque, retrait réel (fichier Démarrage mis en quarantaine), choix mémorisé
- ✅ Pare-feu : **WFP natif** (filtres par AppId dans une sous-couche CoreGuard, session dynamique ou persistante) pour isoler un programme et pour le Mode Paranoïa ; kill switch via le pare-feu Windows
- ✅ **Auto-défense** du service : DACL durcie (taskkill refusé), watchdog mutuel (chaque processus relance l'autre), `sc stop` refusé, arrêt uniquement par **mot de passe** (défi-réponse HMAC, verrouillage après 5 échecs)
- ✅ **Moniteur BadUSB** : un faux clavier USB qui tape à une vitesse surhumaine (ou à un rythme de machine) est bloqué 10 s ; un nouveau clavier branché déclenche une alerte et une vigilance renforcée
- ✅ **Verrouillage d'urgence du PC** : bouton, BadUSB détecté ou ordre à distance (dossier synchronisé, opt-in) ; écran CoreGuard plein écran, raccourcis système bloqués, clés USB et nouveaux périphériques refusés, réseau coupé en option ; déverrouillage devant le PC : **Ctrl+R** puis le mot de passe de protection
- ✅ **Scan mémoire** (menaces sans fichier) : toutes les 30 s, le service parcourt la mémoire des processus ; un exécutable chargé hors de tout fichier (DLL réflective, process hollowing) fait arrêter le processus
- ✅ **Anti-infostealer** : la lecture des mots de passe, cookies et cartes enregistrés dans Chrome, Edge, Brave ou Firefox par un programme qui n'est pas un navigateur signé fait arrêter ce programme ; un faux profil Chromium sert de leurre

**Modules utilisateur**
- ✅ **Presse-papiers intelligent** (anti-crypto-clipper, vidage des secrets après 30 s)
- ✅ **Privacy Guard** : alerte quand une application utilise la caméra ou le micro, bouton **Couper** (arrêt de l'application, retrait de l'autorisation) et interdiction aux applications de bureau en un clic
- ✅ **Gestionnaire de mots de passe** : page « Coffre-fort » (Argon2id + AES-256-GCM, générateur, verrouillage auto), auto-remplissage par l'extension sans presse-papiers, refusé à tout programme qui n'est pas lancé par un navigateur signé
- ✅ **Mode Paranoïa** : USB bloqué, WFP (entrées refusées, mshta/certutil/bitsadmin… coupés d'Internet), tout exécutable non signé lancé depuis Téléchargements / %TEMP% / %APPDATA% arrêté au démarrage (ETW) ; désactivation protégée par le mot de passe de protection ; sans service, l'application bloque seule l'exécution
- ✅ **Anti-phishing** : base de confiance **locale** (100 000 domaines Tranco, Public Suffix List, liste noire OpenPhish, mise à jour optionnelle désactivée par défaut), règles d'URL (homographes, typosquatting, IP, marque en sous-domaine, http), page d'interception « CoreGuard n'aime pas ce site » et fenêtre « CoreGuard doute de ce site » ; seul l'utilisateur peut déclarer un site de confiance, confirmé dans CoreGuard ; installation : `./scripts/install-browser-extension.ps1`
- ✅ **Anti-phishing visuel + IA** : OCR (`Windows.Media.Ocr`) + QR (quishing) dès qu'un mot de passe est demandé sur un site non connu, puis revue de la zone grise par l'**IA locale** (Llama 3.2 3B), qui ne peut qu'aggraver le verdict, et seulement sur indice objectif (marque usurpée, données sensibles) ; mesure sur 19 cas : règles seules 9/11 arnaques, règles + IA 11/11, 0 fausse alerte (`dotnet run --project demo/10-phishing-ia/eval`)

---

## Prérequis

- **Windows 10/11 x64**
- **.NET SDK 10+** (testé avec SDK 11)
- Certaines fonctions temps réel / réseau nécessitent des **droits administrateur**

## Modèle IA local

Le LLM est un fichier GGUF placé dans `models/` (ignoré par git) :

```
models/Llama-3.2-3B-Instruct-Q4_K_M.gguf   (~2 Go)
```

Téléchargement (si absent) :

```powershell
curl -L -o "models/Llama-3.2-3B-Instruct-Q4_K_M.gguf" "https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf"
```

## Service Windows (protection système)

Depuis une console PowerShell **administrateur**, à la racine du dépôt :

```powershell
./scripts/install-service.ps1
```

Le service `CoreGuardService` est publié dans `%ProgramFiles%\CoreGuard\Service`, démarre automatiquement et redémarre après un arrêt anormal. À la première installation, le script demande un **mot de passe de protection** : il sera exigé pour tout arrêt (Réglages > Service et auto-défense > Désactiver, ou `CoreGuard.Service.exe --stop`). Désinstallation : `./scripts/uninstall-service.ps1` (mot de passe demandé).

En développement, le service peut tourner en console (`dotnet run --project CoreGuard.Service`) ; l'UI ne l'accepte alors que si elle est compilée en Debug **et** lancée avec `COREGUARD_DEV_SERVICE=1`. En Release, seul un vrai service (session 0) est accepté.

## Compiler & lancer

```powershell
dotnet build AntivirusIA.slnx
```

```powershell
dotnet run --project AntivirusIA.UI
```

## Tests

```powershell
dotnet test AntivirusIA.slnx
```

434 tests MSTest (moteurs, quarantaine, règles, comportement, réseau, réponse, IPC, service, fournisseur AMSI natif, vie privée, coffre, extension). Procédure de test manuelle : [`docs/TESTING.md`](docs/TESTING.md).

---

## Démonstration (laboratoire)

Les scénarios de démo utilisent des **spécimens bénins** (aucune nuisance réelle, exécution isolée, *kill switch*) conçus uniquement pour déclencher les détecteurs de CoreGuard — voir [`demo/README.md`](demo/README.md).

## Collaboration

Le projet est pensé pour le travail à plusieurs (humains **et** sous-agents IA) grâce à l'**isolation des modules** : chaque fonctionnalité vit dans son propre projet `CoreGuard.*` qui ne dépend que de `AntivirusIA.Core`.

- Flux Git (branches `feat/…`, Pull Requests, revue, *squash merge*), conventions de code et mise en route : voir [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Équipe de sous-agents prête à l'emploi pour **Claude Code** (`.claude/agents/`) et **OpenCode** (`opencode.json`), répartie par modèle pour l'économie : voir [`.opencode/README.md`](.opencode/README.md).
- Cartographie des modules : [`docs/MODULES.md`](docs/MODULES.md). Plan détaillé : [`docs/PLAN.md`](docs/PLAN.md).

## Sécurité & limites assumées

- Sans le driver, 4 protections passent de « blocage » à « détection + réaction immédiate » : canaris, anti-`taskkill`, coffre-fort, anti-infostealer navigateur.
- Les données de l'UI (`%LocalAppData%\CoreGuard`) et son processus restent accessibles à tout programme lancé sous le même compte : DPAPI protège la clé de quarantaine contre la copie vers une autre machine, pas contre un malware de la même session.
- Le canal UI ↔ service n'accepte qu'une commande, l'arrêt, et seulement après preuve du mot de passe ; aucune autre action ne peut être demandée au service SYSTEM.
- En mode utilisateur, un administrateur disposant de SeDebugPrivilege peut encore tuer le service et son watchdog en même temps ; le gestionnaire de services relance alors le service. Le driver Ring 0 supprimera cette limite.
- L'IA assiste et explique ; elle ne remplace pas les règles déterministes.
- Voir [`docs/PLAN.md`](docs/PLAN.md) pour le détail complet.
