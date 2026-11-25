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
├─ CoreGuard.Network          Pare-feu Windows (COM), énumération ports, kill switch réseau — WFP natif prévu
├─ CoreGuard.Response         Actions de réponse user-mode (IKernelActionProvider) : arrêt, suspension, ACL, DACL
├─ CoreGuard.Ipc              Canal UI ↔ service (named pipe local, ACL, vérification du serveur)
├─ CoreGuard.Service          Service Windows LocalSystem : télémétrie ETW et réponse
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
- ✅ Scan à la demande (fichier / dossier récursif) + scan automatique des nouveaux téléchargements
- ✅ Signatures SHA-256 multi-sources (JSON + listes `.txt` issues de flux publics, dossier `%LocalAppData%\CoreGuard\signatures`)
- ✅ **Règles de contenu** inspirées de YARA (texte, hex avec jokers, UTF-16, conditions) : EICAR, Mimikatz, contournement AMSI, suppression des clichés, notes de rançon, *download cradles*, vol d'identifiants navigateur, chargeurs réflectifs
- ✅ **Analyse PE statique** (IAT pondérée, entropie et RWX par section, packers) ; un PE malformé est jugé suspect (échec sécurisé)
- ✅ **Signature Authenticode** (WinVerifyTrust, hors ligne) : atténue les heuristiques, jamais les preuves fortes
- ✅ **IA niveau 2** — LLM local (Llama 3.2 3B via LLamaSharp) : explique les alertes, **ne décide jamais** du blocage
- 🟡 **ETW** — règles Office→shell (Base64), `vssadmin`/`wmic`/`diskshadow`, persistance (droits admin requis ; alerte sans blocage)
- 🟡 **AMSI** — client `AmsiScanBuffer` ; l'interception des scripts (fournisseur AMSI) est prévue
- ⏳ **IA niveau 1** — classifieur statique ONNX (type EMBER), scoring < 50 ms

**Réaction / protection**
- ✅ Quarantaine **AES-256-GCM** authentifiée, clé protégée par **DPAPI**, droits NTFS restreints (exécution refusée), restauration refusée si le fichier est altéré
- ✅ **Arrêt immédiat** des commandes de suppression des clichés instantanés (`vssadmin`, `wmic`, `diskshadow`) repérées par ETW, via `IKernelActionProvider` (garde-fous : jamais de processus critique de Windows)
- 🟡 Anti-ransomware par **canaris** + restauration immédiate (l'arrêt du processus est encore simulé)
- 🟡 **Gardien de persistance** (Run/RunOnce, tâches planifiées, services 7045) — détection sans pop-up de blocage
- 🟡 Pare-feu : règles par application et **kill switch** via le pare-feu Windows ; WFP natif prévu
- 🟡 Auto-défense : durcissement de la DACL du processus disponible (non activé au démarrage) ; watchdog et arrêt protégé par HMAC prévus
- ⏳ Scan mémoire, moniteur BadUSB, anti-infostealer

**Modules utilisateur**
- ✅ **Presse-papiers intelligent** (anti-crypto-clipper, vidage des secrets après 30 s)
- 🟡 **Privacy Guard** (détection caméra/micro ; bouton de coupure prévu), **Vault** (crypto complète, non branché à l'UI), **Mode Paranoïa** (interrupteur sans action réelle)
- 🟡 **Anti-phishing visuel** par OCR (`Windows.Media.Ocr`) + QR (quishing) dans l'extension ; hôte Native Messaging à enregistrer à la main (`CoreGuard.Extension/INSTALL.txt`)

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

Le service `CoreGuardService` est publié dans `%ProgramFiles%\CoreGuard\Service`, démarre automatiquement et redémarre après un arrêt anormal. Désinstallation : `./scripts/uninstall-service.ps1`.

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

250 tests MSTest (moteurs, quarantaine, règles, comportement, réseau, réponse, IPC, vie privée, coffre, extension). Procédure de test manuelle : [`docs/TESTING.md`](docs/TESTING.md).

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
- Le canal UI ↔ service est en lecture seule : aucune commande ne peut être envoyée au service SYSTEM tant que l'authentification HMAC (étape 3) n'existe pas.
- L'IA assiste et explique ; elle ne remplace pas les règles déterministes.
- Voir [`docs/PLAN.md`](docs/PLAN.md) pour le détail complet.
