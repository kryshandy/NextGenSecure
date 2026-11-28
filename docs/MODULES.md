# CoreGuard — Modules

Référence rapide des projets de la solution. L'état détaillé de chaque fonctionnalité et le plan de finalisation sont dans [`AUDIT.md`](AUDIT.md) ; le découpage historique en lots est dans [`PLAN.md`](PLAN.md).

Chaque module est un projet isolé qui ne référence que `AntivirusIA.Core`. Le driver Rust (Ring 0) est **en pause** : aucun module n'en dépend.

| Module | Rôle | État |
|--------|------|------|
| `AntivirusIA.Core` | Contrats (`IDetectionEngine`, `IFileTrustProvider`, `IQuarantineService`…), modèles, pipeline de scan, scoring | Complet |
| `AntivirusIA.Engines` | Signatures multi-sources, règles de contenu (`rules.json`), heuristiques, entropie, PE statique, Authenticode | Complet |
| `AntivirusIA.AI` | LLM local (LLamaSharp) pour l'explication ; classifieur ONNX EMBER prévu | Partiel |
| `AntivirusIA.Infrastructure` | Quarantaine AES-256-GCM (clé DPAPI, ACL NTFS), historique SQLite | Complet |
| `CoreGuard.RealTime` | Surveillance de dossiers (`FileSystemWatcher`), canaris cachés anti-ransomware, attribution par audit NTFS (événement 4663) | Complet |
| `AntivirusIA.Ml` | IA niveau 1 : caractéristiques EMBER (616), modèle LightGBM exporté en ONNX, moteur `EmberOnnxEngine` | Complet (AUC 0,980 sur le test EMBER) |
| `CoreGuard.Behavior` | ETW processus, règles comportementales, client AMSI, gardien de persistance (évaluation du risque, retrait Run/tâche/service) | Partiel (suppression des clichés arrêtée, autres règles en alerte) |
| `CoreGuard.Network` | Pare-feu Windows (COM), ports, kill switch ; WFP natif prévu | Partiel |
| `CoreGuard.Response` | `UserModeActionProvider` : implémentation user-mode de `IKernelActionProvider` (arrêt, suspension, blocage réseau, ACL NTFS, DACL de processus) | Complet (étape 1) |
| `CoreGuard.Vault` | Coffre-fort (SQLite, Argon2id, AES-256-GCM) ; page Coffre-fort dans l'UI, auto-remplissage via `VaultBroker` | Complet |
| `CoreGuard.Privacy` | Privacy Guard (caméra/micro), presse-papiers intelligent, Mode Paranoïa | Partiel (Paranoïa sans action réelle) |
| `AntivirusIA.UI` | Interface WPF (MVVM) et composition root (DI) ; client du service, héberge les modules liés à la session | Partiel |
| `CoreGuard.Extension` | Extension MV3 0.2.0 (vérification des pages, bandeau, fenêtre, auto-remplissage), hôte Native Messaging (OCR, QR, URL, coffre) ; installation `scripts/install-browser-extension.ps1` | Complet |
| `CoreGuard.Ipc` | Canal UI ↔ service : trames JSON bornées, `PipeServer` (ACL, diffusion), `ServiceClient` (rejet des serveurs hors session 0), arrêt authentifié (PBKDF2 + HMAC) | Complet |
| `CoreGuard.Service` | Service Windows LocalSystem : ETW, canaris + audit NTFS, anti-infostealer, analyse AMSI, scan mémoire, verrouillage d'urgence (USB, périphériques, réseau, ordre à distance), auto-défense, état et alertes sur le pipe | Partiel (persistance HKLM et réseau à migrer) |
| `CoreGuard.Setup` | Assistant d'installation hors ligne (payload construit par `scripts/build-setup.ps1`), désinstallation | Complet |
| `CoreGuard.AmsiProvider` | Fournisseur AMSI natif (NativeAOT, COM) : transmet chaque script au service avant exécution, bloque sur son verdict | Complet (x64, non signé) |
| `CoreGuard.Devices` | Moniteur BadUSB : cadence de frappe (hook clavier), blocage de l'injection, détection des nouveaux claviers | Complet |
| `CoreGuard.Memory` | Scan mémoire « fileless » : régions privées exécutables, détection d'images PE injectées | Complet |
| Tests (`*.Tests`) | 380 tests MSTest | Complet pour l'existant |
