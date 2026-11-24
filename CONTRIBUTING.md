# Contribuer à CoreGuard

Bienvenue ! Ce guide explique comment travailler ensemble sur CoreGuard, proprement et sans se marcher dessus.

## 1. Mise en route (une seule commande)

```powershell
git clone https://github.com/kryshandy/NextGenSecure.git
cd NextGenSecure
./scripts/setup.ps1
```

`setup.ps1` restaure les paquets NuGet, **télécharge le modèle IA local** (~2 Go, non versionné) et compile la solution. Ensuite :

```powershell
dotnet run --project AntivirusIA.UI
```

## 2. Prérequis

- Windows 10/11 x64, **.NET SDK 10+**
- Git, et [GitHub CLI](https://cli.github.com/) (`gh`) pour les PR
- ~3 Go d'espace libre (modèle IA)

## 3. Le modèle IA n'est pas dans le dépôt

Le fichier `models/*.gguf` (~2 Go) dépasse la limite de 100 Mo de GitHub : il est donc **ignoré par git** et téléchargé par `scripts/download-model.ps1` (appelé par `setup.ps1`). Ne le committe jamais.

## 4. Flux de collaboration (Git)

On ne pousse jamais directement sur `master`. Chaque contribution passe par une branche + une Pull Request.

```powershell
git switch -c feat/mon-module        # feat/, fix/, docs/, refactor/, test/
# ... travail ...
dotnet build AntivirusIA.slnx
dotnet test AntivirusIA.slnx
git add -A
git commit -m "feat(network): ajoute l'énumération des ports TCP/UDP"
git push -u origin feat/mon-module
gh pr create --fill
```

- **Nommage des branches :** `feat/…`, `fix/…`, `docs/…`, `refactor/…`, `test/…`
- **Messages de commit :** style [Conventional Commits](https://www.conventionalcommits.org/) (`type(scope): description`), en français.
- **Une PR = un sujet.** Build + tests verts obligatoires avant de demander une revue.
- Au moins **une relecture** avant fusion. On fusionne en *squash* pour garder un historique lisible.

## 5. Règle d'or : isolation des modules

Chaque module vit dans **son propre projet** (`CoreGuard.*`) et référence uniquement `AntivirusIA.Core` pour les contrats. Cela permet à plusieurs personnes (ou agents IA) de travailler **en parallèle sans conflit**.

- On ne modifie `AntivirusIA.slnx` et le *composition root* (`AntivirusIA.UI/App.xaml.cs`) **que lors d'une étape d'intégration dédiée**, pas depuis un module.
- Les contrats partagés (interfaces, modèles) vont dans `AntivirusIA.Core`. On les change avec prudence (ça impacte tout le monde).

## 6. Conventions de code

- C# moderne : `nullable` activé, `async`/`await` + `CancellationToken`, `sealed`, `record`.
- **Commentaires et noms métier en français** (cohérent avec l'existant).
- Tout nom/chemin/contenu de fichier analysé est une **donnée non fiable** : on ne l'exécute jamais, on l'assainit.
- Chaque module livré vient avec ses **tests** (MSTest), suivant le style de `AntivirusIA.Tests`.
- Les secrets (clés, mots de passe, `vault.cgdb`, quarantaine) ne sont **jamais** versionnés ni journalisés.

## 7. Développement assisté par sous-agents IA

Le dépôt embarque une équipe de sous-agents configurés pour **Claude Code** (`.claude/agents/*.md`) et **OpenCode** (`opencode.json`), avec une répartition par modèle pour maîtriser le coût :

| Agent | Modèle | Rôle |
|-------|--------|------|
| `cg-architect` | opus | architecture, contrats, composition root, algos difficiles |
| `cg-backend` | sonnet | moteurs, services, P/Invoke (ETW/AMSI/WFP) |
| `cg-ai` | sonnet | LLM local + classifieur ONNX |
| `cg-ui` | sonnet | interface WPF MVVM |
| `cg-frontend-ext` | sonnet | extension navigateur, OCR, privacy |
| `cg-redteam` | sonnet | spécimens de démo **bénins** |
| `cg-scribe` | haiku | docs, données JSON, boilerplate |

Voir [`.opencode/README.md`](.opencode/README.md) pour le détail. Chaque agent respecte la règle d'isolation des modules ci-dessus.

## 8. Démonstrations = spécimens bénins uniquement

Les artefacts de `demo/` servent à **déclencher** les détecteurs de CoreGuard sans aucune nuisance réelle (exécution isolée, `localhost`, données factices, *kill switch*). On n'ajoute jamais de code réellement malveillant, armé ou capable d'exfiltration/propagation. Voir [`demo/README.md`](demo/README.md).
