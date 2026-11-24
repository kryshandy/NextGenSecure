# CoreGuard — Modules

Référence rapide des projets de la solution. L'état détaillé de chaque fonctionnalité et le plan de finalisation sont dans [`AUDIT.md`](AUDIT.md) ; le découpage historique en lots est dans [`PLAN.md`](PLAN.md).

Chaque module est un projet isolé qui ne référence que `AntivirusIA.Core`. Le driver Rust (Ring 0) est **en pause** : aucun module n'en dépend.

| Module | Rôle | État |
|--------|------|------|
| `AntivirusIA.Core` | Contrats (`IDetectionEngine`, `IFileTrustProvider`, `IQuarantineService`…), modèles, pipeline de scan, scoring | Complet |
| `AntivirusIA.Engines` | Signatures multi-sources, règles de contenu (`rules.json`), heuristiques, entropie, PE statique, Authenticode | Complet |
| `AntivirusIA.AI` | LLM local (LLamaSharp) pour l'explication ; classifieur ONNX EMBER prévu | Partiel |
| `AntivirusIA.Infrastructure` | Quarantaine AES-256-GCM (clé DPAPI), historique SQLite | Complet (ACL NTFS prévues) |
| `CoreGuard.RealTime` | Surveillance de dossiers (`FileSystemWatcher`), canaris anti-ransomware | Partiel (arrêt du processus simulé) |
| `CoreGuard.Behavior` | ETW processus, règles comportementales, client AMSI, gardien de persistance | Partiel (détection sans blocage) |
| `CoreGuard.Network` | Pare-feu Windows (COM), ports, kill switch ; WFP natif prévu | Partiel |
| `CoreGuard.Vault` | Coffre-fort (SQLite, Argon2id, AES-256-GCM) | Complet côté crypto, non branché à l'UI |
| `CoreGuard.Privacy` | Privacy Guard (caméra/micro), presse-papiers intelligent, Mode Paranoïa | Partiel (Paranoïa sans action réelle) |
| `AntivirusIA.UI` | Interface WPF (MVVM) et composition root (DI) ; héberge aujourd'hui les modules temps réel | Partiel |
| `CoreGuard.Extension` | Extension MV3, hôte Native Messaging, OCR anti-phishing, QR | Partiel (hôte à enregistrer à la main) |
| `CoreGuard.Service` | Worker Service `SYSTEM`, IPC named pipe, auto-défense | Prévu |
| Tests (`*.Tests`) | 228 tests MSTest | Complet pour l'existant |
