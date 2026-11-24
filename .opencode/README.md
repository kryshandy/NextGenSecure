# Sous-agents CoreGuard — Claude Code & OpenCode

Les mêmes 7 sous-agents sont définis pour les deux outils, avec une **répartition par modèle** pour l'économie :

| Agent | Rôle | Modèle | Coût |
|-------|------|--------|------|
| `cg-architect` | Architecture, contrats, DI, algos difficiles | **opus** | 🟣 élevé |
| `cg-backend` | Moteurs, services, P/Invoke (ETW/AMSI/WFP) | sonnet | 🔵 moyen |
| `cg-ai` | LLM local + classifieur ONNX | sonnet | 🔵 moyen |
| `cg-ui` | UI WPF MVVM haut de gamme | sonnet | 🔵 moyen |
| `cg-frontend-ext` | Extension navigateur, OCR, Privacy, presse-papiers | sonnet | 🔵 moyen |
| `cg-redteam` | Spécimens de démo bénins | sonnet | 🔵 moyen |
| `cg-scribe` | Docs, données JSON, tests simples, boilerplate | **haiku** | 🟢 faible |

## Où sont les définitions

- **Claude Code** : `.claude/agents/*.md` (invocables via le Task/Agent tool ou `@cg-...`).
- **OpenCode** : `opencode.json` (clé `agent`). Lancement : `opencode` puis bascule d'agent, ou appel en sous-agent via l'agent principal.

## Note modèles OpenCode

Les identifiants `anthropic/claude-*-5-5` suivent le catalogue models.dev d'OpenCode. Si un identifiant n'est pas reconnu par ta version d'OpenCode, remplace-le par celui listé via `opencode models` (même famille : opus pour l'architecte, sonnet pour le dev, haiku pour le scribe).

## Principe anti-collision

Chaque agent travaille dans un **projet/dossier isolé** et ne touche jamais à `AntivirusIA.slnx` ni au composition root : l'orchestrateur intègre entre chaque vague (voir `docs/PLAN.md`).
