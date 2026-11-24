# CoreGuard — Plan de projet (Phase 1)

Document de pilotage. Référence fonctionnelle = « CoreGuard — Topo Complet ». Ce plan ne couvre que la **Phase 1 (user-mode, sans driver/VM/test signing)**.

## 0. Principes

- **Réutiliser** le socle `AntivirusIA.*` existant, ne pas repartir de zéro.
- Chaque module = **projet isolé** référençant `AntivirusIA.Core` → parallélisable sans collision.
- Chaque livrable doit **compiler** et venir avec des **tests** minimaux.
- L'intégration dans `AntivirusIA.slnx` et le *composition root* (DI) sont faits par l'orchestrateur, pas par les agents, pour éviter les conflits.

## 1. État du socle existant

| Élément | État |
|---------|------|
| Pipeline de scan, scoring | ✅ Présent |
| Moteurs signatures / entropie / heuristiques | ✅ Présents |
| Quarantaine chiffrée AES-256 | ✅ Présente |
| Historique SQLite | ✅ Présent |
| Couche IA (prompt durci + parser) | ⚠️ Pas de provider ; non branchée au pipeline |
| UI WPF | ❌ Vide (template) |
| Composition root / DI | ❌ Absent |

## 2. Backlog modulaire (lots) et affectation

Légende modèle : 🟢 haiku (mécanique/bulk) · 🔵 sonnet (dev standard) · 🟣 opus (archi/algo difficile)

### Lot A — Socle vivant (prioritaire, séquentiel, orchestrateur)
- A1. *Composition root* + DI (`Microsoft.Extensions.DependencyInjection`) 🟣
- A2. Provider LLM `LLamaSharpProvider : IAiProvider` + branchement IA dans le pipeline 🔵
- A3. UI WPF MVVM « top » : dashboard, scan, quarantaine, historique, thème clair/sombre 🔵

### Lot B — Détection avancée (parallélisable)
- B1. `AntivirusIA.Engines` : **analyse PE statique** (en-têtes, IAT, entropie par section) 🔵
- B2. `AntivirusIA.AI` : **classifieur ONNX** (OnnxRuntime) + extracteur de features 🔵/🟣
- B3. `CoreGuard.Behavior` : **AMSI** + **ETW** (parent-enfant, vssadmin, injection) 🔵

### Lot C — Réaction & réseau (parallélisable)
- C1. `CoreGuard.Network` : pare-feu WFP (P/Invoke), énumération ports, kill switch 🔵
- C2. Anti-ransomware **canaris** (FileSystemWatcher + kill + restauration) 🔵
- C3. **Gardien de persistance** (Run/RunOnce, tâches, services via ETW/WMI) 🔵

### Lot D — Modules utilisateur (parallélisable, « effort faible, effet max »)
- D1. `CoreGuard.Vault` : SQLite + Argon2id + AES-256-GCM + générateur 🔵
- D2. `CoreGuard.Privacy` : Privacy Guard (caméra/micro), presse-papiers intelligent, Mode Paranoïa 🔵
- D3. `CoreGuard.Extension` : Manifest V3 + Native Messaging + OCR (phishing) + QR 🔵
- D4. Smart Download Guard (flux NTFS `Zone.Identifier`) 🟢

### Lot E — Démo & qualité (parallélisable)
- E1. `demo/` : spécimens **bénins** (ransomware simulé, persistance, clipper, phishing visuel…) 🔵
- E2. Tests supplémentaires + données (`signatures.json` enrichi) 🟢
- E3. Docs (README modules, guide de démo) 🟢

## 3. Répartition par sous-agent (voir `.claude/agents/` et `.opencode/`)

| Agent | Modèle | Lots |
|-------|--------|------|
| `cg-architect` | 🟣 opus | A1, B2 (algo), revues d'intégration |
| `cg-backend` | 🔵 sonnet | B1, B3, C1, C2, C3, D1 |
| `cg-ai` | 🔵 sonnet | A2, B2 |
| `cg-ui` | 🔵 sonnet | A3 |
| `cg-frontend-ext` | 🔵 sonnet | D2, D3 |
| `cg-redteam` | 🔵 sonnet | E1 |
| `cg-scribe` | 🟢 haiku | D4, E2, E3, données JSON, boilerplate |

## 4. Jalons

1. **M1 — Socle vivant** : Lot A → l'app se lance, scanne un fichier, l'IA explique le verdict, quarantaine visible dans l'UI.
2. **M2 — Détection next-gen** : Lots B + C2 → PE statique + ONNX + temps réel + canaris.
3. **M3 — Protection système** : Lots C1/C3 + D1 → réseau, persistance, coffre-fort.
4. **M4 — Modules & démo** : Lots D2/D3/D4 + E → privacy, extension, scénarios de démo bout en bout.

## 5. Ordre d'exécution des vagues d'agents

- **Vague 1** (après le socle de contrats) : B1, D1, C2 — projets isolés, zéro collision.
- **Vague 2** : B3, C1, C3, D2.
- **Vague 3** : A3 (UI) une fois les services disponibles, D3, E1.
- Intégration continue par l'orchestrateur entre chaque vague (ajout aux `.slnx`, DI, build, test).
