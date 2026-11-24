# CoreGuard — Modules (Phase 1)

Référence rapide des projets de la solution. Le détail du découpage en lots et des agents responsables est dans [`PLAN.md`](PLAN.md) ; l'architecture générale est dans le [`README.md`](../README.md).

Chaque module est un projet isolé qui référence `AntivirusIA.Core`.

| Module | Rôle | État prévu (lot) |
|--------|------|------------------|
| `AntivirusIA.Core` | Contrats, modèles, pipeline de scan et scoring | Socle existant, réutilisé |
| `AntivirusIA.Engines` | Moteurs de détection : signatures, entropie, heuristiques, analyse PE statique | Socle existant ; analyse PE statique en lot B1 |
| `AntivirusIA.AI` | Classifieur ONNX (type EMBER) et LLM local (LLamaSharp) pour l'explication | Lot B2 (classifieur ONNX) ; lot A2 (provider LLM) |
| `AntivirusIA.Infrastructure` | Quarantaine chiffrée AES-256 et historique SQLite | Socle existant, réutilisé |
| `CoreGuard.Behavior` | Protection comportementale : AMSI, ETW, surveillance de fichiers, persistance | Lot B3 (AMSI, ETW) ; lots C2 (canaris) et C3 (persistance) |
| `CoreGuard.Network` | Pare-feu WFP, énumération des ports, kill switch réseau | Lot C1 |
| `CoreGuard.Vault` | Coffre-fort de mots de passe (SQLite, Argon2id, AES-256-GCM, générateur) | Lot D1 |
| `CoreGuard.RealTime` | Protection temps réel (`FileSystemWatcher`) : module non détaillé dans les sources, voir note ci-dessous | Non planifié séparément dans `PLAN.md` |
| `CoreGuard.Privacy` | Privacy Guard (caméra/micro), presse-papiers intelligent, Mode Paranoïa | Lot D2 |
| `AntivirusIA.UI` | Interface WPF (MVVM) : dashboard, scan, quarantaine, historique, thème | Lot A3 |
| `CoreGuard.Extension` | Extension navigateur Manifest V3, Native Messaging, OCR (phishing) et lecture QR | Lot D3 |
| `AntivirusIA.Tests` | Tests MSTest, minimaux pour chaque livrable | Transverse (lot E2 pour les tests supplémentaires) |

> **Note** : `CoreGuard.RealTime` n'apparaît pas dans l'architecture du `README.md`, où la surveillance temps réel (`FileSystemWatcher`) est rattachée à `CoreGuard.Behavior`. Ce module et son périmètre exact restent à arbitrer par l'orchestrateur.
