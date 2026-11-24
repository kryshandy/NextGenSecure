# 🛡️ CoreGuard — Antivirus nouvelle génération augmenté par l'IA

> Suite de sécurité hybride pour Windows 10/11, **100 % locale**, sans cloud ni télémétrie sortante.
> Projet de cours C# — « en surface du C#, en dessous bien plus ».

CoreGuard combine des moteurs de détection classiques, de l'**IA embarquée** (classifieur statique ONNX + LLM local pour l'explication) et une couche de **protection comportementale temps réel**. Il est livré en **deux phases** :

| Phase | Périmètre | État |
|-------|-----------|------|
| **Phase 1** (en cours) | 100 % C# user-mode — aucune VM, aucun *test signing*, aucun driver. ~80 % du produit. | 🚧 En développement |
| **Phase 2** (plus tard) | Driver noyau Rust (minifilter + `ObRegisterCallbacks`) pour transformer les détections en blocages inviolables. | ⏳ Reporté |

---

## Mise en route rapide

```powershell
git clone https://github.com/kryshandy/NextGenSecure.git
cd NextGenSecure
./scripts/setup.ps1
dotnet run --project AntivirusIA.UI
```

`setup.ps1` restaure les paquets, **télécharge le modèle IA local** (~2 Go, hors git) et compile. Détails de collaboration : [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Architecture (Phase 1)

```
CoreGuard.sln
├─ AntivirusIA.Core           Contrats, modèles, pipeline de scan, scoring
├─ AntivirusIA.Engines        Moteurs : signatures, entropie, heuristiques, PE statique
├─ AntivirusIA.AI             IA : classifieur ONNX (EMBER) + LLM local (LLamaSharp)
├─ AntivirusIA.Infrastructure Quarantaine chiffrée (AES-256), historique SQLite
├─ CoreGuard.RealTime         Temps réel : FileSystemWatcher, canaris anti-ransomware
├─ CoreGuard.Behavior         Comportement : ETW, AMSI, gardien de persistance
├─ CoreGuard.Network          Pare-feu WFP, énumération ports, kill switch réseau
├─ CoreGuard.Vault            Coffre-fort mots de passe (SQLite + Argon2id + AES-GCM)
├─ CoreGuard.Privacy          Privacy Guard (caméra/micro), presse-papiers, Mode Paranoïa
├─ AntivirusIA.UI             Interface WPF (MVVM) — dashboard temps réel
├─ CoreGuard.Extension        Extension navigateur (Manifest V3 + Native Messaging + OCR)
└─ AntivirusIA.Tests          Tests (MSTest)
```

> Note : les projets `CoreGuard.*` sont ajoutés au fil de la Phase 1. Le socle `AntivirusIA.*` existe déjà et est réutilisé.

---

## Fonctionnalités Phase 1

**Détection**
- Scan à la demande (fichier / dossier récursif) + **protection temps réel** (`FileSystemWatcher`)
- Moteurs : signatures SHA-256, entropie de Shannon, heuristiques (RLO, double extension…), **analyse PE statique** (en-têtes, IAT, entropie par section)
- **IA niveau 1** — classifieur statique ONNX (type EMBER), scoring < 50 ms
- **IA niveau 2** — LLM local (Llama 3.2 3B via LLamaSharp) : explique les alertes, désobfusque, **ne décide jamais** du blocage
- **AMSI** — analyse des scripts PowerShell/VBS avant exécution
- **ETW** — télémétrie comportementale (relations parent-enfant, `vssadmin delete shadows`, persistance)

**Réaction / protection**
- Quarantaine chiffrée AES-256, **kill switch réseau** (WFP), anti-ransomware par **canaris** + restauration
- **Gardien de persistance** (Run/RunOnce, tâches planifiées, services)

**Modules utilisateur**
- **Vault** (coffre-fort de mots de passe), **Privacy Guard** (caméra/micro), **presse-papiers intelligent** (anti-crypto-clipper), **Mode Paranoïa**, **Smart Download Guard**
- **Anti-phishing visuel** par OCR (`Windows.Media.Ocr`) + lecture QR (quishing) via l'extension navigateur

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

## Compiler & lancer

```powershell
dotnet build AntivirusIA.slnx
```

```powershell
dotnet run --project AntivirusIA.UI
```

## Tests

```powershell
dotnet test
```

---

## Démonstration (laboratoire)

Les scénarios de démo utilisent des **spécimens bénins** (aucune nuisance réelle, exécution isolée, *kill switch*) conçus uniquement pour déclencher les détecteurs de CoreGuard — voir [`demo/README.md`](demo/README.md).

## Collaboration

Le projet est pensé pour le travail à plusieurs (humains **et** sous-agents IA) grâce à l'**isolation des modules** : chaque fonctionnalité vit dans son propre projet `CoreGuard.*` qui ne dépend que de `AntivirusIA.Core`.

- Flux Git (branches `feat/…`, Pull Requests, revue, *squash merge*), conventions de code et mise en route : voir [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Équipe de sous-agents prête à l'emploi pour **Claude Code** (`.claude/agents/`) et **OpenCode** (`opencode.json`), répartie par modèle pour l'économie : voir [`.opencode/README.md`](.opencode/README.md).
- Cartographie des modules : [`docs/MODULES.md`](docs/MODULES.md). Plan détaillé : [`docs/PLAN.md`](docs/PLAN.md).

## Sécurité & limites assumées

- Sans le driver (Phase 1), 4 protections passent de « blocage » à « détection + réaction immédiate » : canaris, anti-`taskkill`, coffre-fort, anti-infostealer navigateur.
- L'IA assiste et explique ; elle ne remplace pas les règles déterministes.
- Voir [`docs/PLAN.md`](docs/PLAN.md) pour le détail complet.
