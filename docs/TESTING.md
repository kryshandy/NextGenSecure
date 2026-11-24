# Guide de test CoreGuard — User stories & procédure

Ce document explique **où se trouve tout**, **comment tester efficacement**, et **ce que chaque test déclenche** dans l'antivirus. Il est honnête sur le statut : certaines défenses sont **actives dès maintenant**, d'autres sont un **détecteur à venir** (Phase 2 ou câblage complémentaire).

---

## 0. Où se trouve tout

| Besoin | Emplacement | Commande |
|--------|-------------|----------|
| **Installer / préparer** | `scripts/setup.ps1` | `./scripts/setup.ps1` (restaure, télécharge le modèle IA, compile) |
| Télécharger seulement le modèle IA | `scripts/download-model.ps1` | `./scripts/download-model.ps1` |
| **Distribution autonome** (tout embarqué) | `scripts/publish.ps1` | `./scripts/publish.ps1` → `publish/CoreGuard/` |
| **Lancer l'application** | projet `AntivirusIA.UI` | `dotnet run --project AntivirusIA.UI` (depuis la racine du dépôt) |
| **Tests automatisés** (196) | projets `*.Tests` | `dotnet test AntivirusIA.slnx` |
| **Scripts de démo** (spécimens) | `demo/01…07/` | voir §4 et `demo/README.md` |

> **Important :** lance toujours l'app **depuis la racine du dépôt** (`dotnet run --project AntivirusIA.UI`), sinon le modèle IA (`models/…gguf`) n'est pas trouvé et l'app retombe sur le verdict local (sans explication IA).

---

## 1. Prérequis pour tester efficacement

1. **Windows 10/11 x64**, .NET SDK 10+. Lance d'abord `./scripts/setup.ps1`.
2. **Droits administrateur** requis pour : télémétrie **ETW** (comportement), **pare-feu/kill switch**, scan mémoire. Sans admin, ces modules passent en « Indisponible » sans planter (le reste fonctionne).
3. **Windows Defender** supprime le fichier de test EICAR et certains spécimens **avant** que CoreGuard ne les voie. Pour tester sereinement : travaille dans une **VM**, ou ajoute temporairement une exclusion Defender sur le dossier de test, ou utilise les spécimens `demo/` (bénins, pensés pour ne pas être supprimés).
4. **Tout est bénin** : les spécimens `demo/` n'agissent que sous `%TEMP%\CoreGuardDemo`, sur `localhost`, avec données factices et nettoyage. Lance toujours le nettoyage indiqué après chaque essai.

### Les 3 niveaux de test (du plus sûr au plus visuel)

- **Niveau A — Tests automatisés** : `dotnet test AntivirusIA.slnx` → **196 tests** prouvent la logique de chaque moteur/module. C'est la preuve rigoureuse et reproductible.
- **Niveau B — Analyse dans l'UI** : le chemin **entièrement câblé**. On analyse un fichier/dossier → verdict coloré + explication IA. C'est la démo phare.
- **Niveau C — Temps réel & spécimens** : canaris, presse-papiers, persistance, etc. Certains sont actifs (à activer dans Réglages), d'autres ont un détecteur **à venir** (voir statut par user story).

---

## 2. User stories — testables EN DIRECT dès maintenant

Format : **En tant que** … / **Je veux** … / **Afin de** … — puis *Comment tester*, *Résultat attendu*, *Statut*.

### US-01 — Analyser un fichier/dossier à la demande
- **En tant qu'**utilisateur, **je veux** analyser un fichier ou un dossier, **afin de** savoir s'il est sain, suspect ou malveillant.
- **Comment tester :** lancer l'app → page **Analyse** → choisir un fichier ou un dossier → lancer.
- **Résultat attendu :** une pastille de verdict colorée (**vert** Sain / **orange** Suspect / **rouge** Malveillant) par fichier, avec le détail dépliable des indices (signature, heuristique, entropie, PE statique) et le score.
- **Statut : ✅ actif.**

### US-02 — Obtenir une explication en langage clair (IA)
- **…je veux** une explication compréhensible du verdict, **afin de** comprendre pourquoi un fichier est douteux.
- **Comment tester :** app lancée **depuis la racine** (modèle présent) → analyser un fichier **non sain** → lire l'explication sous le verdict.
- **Résultat attendu :** une phrase d'explication générée par le LLM local. Si le modèle est absent, l'app affiche « Verdict établi par les moteurs locaux » (repli propre, **sans planter**).
- **Statut : ✅ actif** (inférence CPU, quelques secondes au 1er appel ; au plus 5 appels IA par lot).

### US-03 — Détecter un malware connu par signature
- **…je veux** qu'un fichier malveillant connu soit reconnu, **afin de** bloquer les menaces répertoriées.
- **Comment tester :** analyser le fichier de test **EICAR** (standard). Comme Defender le supprime souvent, en VM/avec exclusion. Variante fiable : calculer le SHA-256 d'un fichier bénin (`Get-FileHash`), l'ajouter à `AntivirusIA.Engines/Data/signatures.json`, recompiler, puis l'analyser.
- **Résultat attendu :** verdict **Malveillant** (score 100), indice « Signature connue ».
- **Statut : ✅ actif** (attention au préalable Defender).

### US-04 — Repérer un exécutable packé / aux API sensibles (PE statique)
- **…je veux** qu'un `.exe` suspect (packé, imports d'injection) soit signalé, **afin de** détecter des menaces **inconnues** sans signature.
- **Comment tester :** analyser un exécutable packé (ex. compressé UPX) ou un binaire aux imports sensibles.
- **Résultat attendu :** indices « PE statique » (section exécutable à haute entropie, RWX, imports type `VirtualAlloc`/`WriteProcessMemory`/`CreateRemoteThread`), score ↑.
- **Statut : ✅ actif.**

### US-05 — Mettre en quarantaine, restaurer, supprimer
- **…je veux** isoler un fichier dangereux, **afin de** neutraliser la menace tout en pouvant revenir en arrière.
- **Comment tester :** page **Quarantaine** → mettre un fichier en quarantaine → vérifier qu'il disparaît de son emplacement → **Restaurer** → vérifier son retour ; puis **Supprimer**.
- **Résultat attendu :** le fichier est chiffré (AES-256) dans le coffre de quarantaine, restaurable à l'identique.
- **Statut : ✅ actif.**

### US-06 — Consulter l'historique des analyses
- **…je veux** revoir mes analyses passées, **afin de** suivre l'activité.
- **Comment tester :** faire quelques analyses → page **Historique**.
- **Résultat attendu :** liste horodatée (chemin, score, verdict) persistée en SQLite.
- **Statut : ✅ actif.**

### US-07 — Voir le flux d'alertes temps réel
- **…je veux** voir les alertes en direct sur le tableau de bord, **afin de** réagir vite.
- **Comment tester :** page **Tableau de bord** → bouton **« Simuler une alerte »**.
- **Résultat attendu :** une alerte apparaît immédiatement dans le flux (démonstration fiable du rendu temps réel, sans rien exécuter de risqué).
- **Statut : ✅ actif.**

### US-08 — Bloquer un détournement du presse-papiers (crypto-clipper)
- **…je veux** être protégé si un malware remplace une adresse crypto copiée, **afin de** ne pas envoyer mes fonds à un attaquant.
- **Comment tester :** activer la protection presse-papiers (Réglages) → `dotnet run --project .\demo\05-crypto-clipper` → copier du texte.
- **Résultat attendu :** la valeur d'origine est **restaurée**, alerte « détournement du presse-papiers bloqué ». Arrêt : `Ctrl+C` ou 60 s.
- **Statut : ✅ actif** (module `CoreGuard.Privacy`).

### US-09 — Surveiller l'accès caméra/micro (Privacy Guard)
- **…je veux** savoir quel programme utilise ma caméra/micro, **afin de** couper un accès non autorisé.
- **Comment tester :** ouvrir une app caméra (Zoom, Caméra Windows) → observer le badge Privacy Guard.
- **Résultat attendu :** le processus utilisant le capteur est signalé ; hors liste blanche → alerte.
- **Statut : ✅ actif** (lecture du registre `CapabilityAccessManager`).

### US-10 — Détecter une tentative de persistance
- **…je veux** être averti quand un programme s'installe au démarrage, **afin de** l'autoriser ou le bloquer.
- **Comment tester :** `./demo/03-persistance/demo-persistance.ps1` (crée une clé `HKCU\…\Run` + une tâche planifiée de test). **Puis obligatoirement** `./demo/03-persistance/demo-persistance.ps1 -Nettoyer`.
- **Résultat attendu :** le gardien de persistance signale la nouvelle entrée Run/tâche.
- **Statut : ✅ actif** (sondage registre/tâches ; services 7045 via journal Système, admin recommandé).

---

## 3. User stories — attaque OK, détecteur À VENIR / câblage requis

Ces spécimens s'exécutent (côté « attaque »), mais la **capture automatique par CoreGuard** demande soit la Phase 2, soit une activation/branchement supplémentaire. Honnêteté assumée.

### US-11 — Anti-ransomware par canaris
- **Comment tester :** activer les canaris dans **Réglages** (déploie des leurres dans Documents/Bureau/Images). Pour voir le déclenchement, **modifier un de ces leurres**. Le spécimen `demo/02-ransomware-canari` écrit, lui, dans `%TEMP%\CoreGuardDemo\ransomware` (isolé) : pour un test de bout en bout, il faut faire pointer la surveillance **et** le spécimen sur le **même dossier** (alignement des noms de canaris à finaliser).
- **Statut : ⚠️ partiel** — le moteur `CoreGuard.RealTime` fonctionne et est testé, mais l'alignement dossier/noms avec le spécimen reste à câbler. La suppression VSS est **simulée** (jamais exécutée).

### US-12 — AMSI (scripts PowerShell obfusqués)
- **Comment tester :** `demo/01-powershell-amsi/demo-amsi.ps1` (Base64 + `Invoke-Expression`, texte décodé = `DEMO-INOFFENSIF`).
- **Statut : ⚠️ à la demande** — `AmsiScanner` peut analyser un script fourni, mais l'**interception passive** de tout PowerShell (fournisseur AMSI enregistré) n'est pas encore branchée. Le moteur de règles comportementales (parent→enfant, Base64) est testé.

### US-13 — Comportement système via ETW
- **Comment tester (admin) :** déclencher une chaîne Office→PowerShell ou une commande `vssadmin delete shadows`.
- **Statut : ⚠️ nécessite admin** — `EtwProcessMonitor` démarre en admin ; le `BehaviorRuleEngine` (57 tests) couvre toutes les règles. Sans admin, le module se signale « Indisponible ».

### US-14 — Pare-feu applicatif & kill switch réseau
- **Comment tester (admin) :** via l'API `INetworkGuard` (bloquer une app/un port, activer le kill switch) et `PortInspector` pour lister les connexions→PID.
- **Statut : ⚠️ nécessite admin** — logique testée (10 tests) ; pas encore de page UI dédiée (pilotable par code/au branchement service).

### US-15 — Phishing visuel par OCR (extension navigateur)
- **Comment tester :** `./demo/06-phishing-visuel/serve-phishing-demo.ps1` puis ouvrir `http://localhost:8080`. Nécessite de **charger l'extension** (`CoreGuard.Extension/extension/`) dans Chrome/Edge et d'enregistrer l'**hôte Native Messaging** (voir `CoreGuard.Extension/INSTALL.txt`).
- **Statut : ⚠️ câblage requis** — logique OCR/typosquatting/homographes testée (38 tests) ; l'extension doit être installée et l'hôte enregistré pour une démo de bout en bout.

### US-16 — BadUSB (frappe HID anormale)
- **Comment tester :** `dotnet run --project .\demo\04-badusb-hid` (frappe ~1500 car/s dans sa propre fenêtre ; `Échap` pour arrêter).
- **Statut : 🔜 détecteur à venir** — le moniteur HID n'est pas encore implémenté.

### US-17 — Vol d'identifiants navigateur (infostealer)
- **Comment tester :** `./demo/07-vol-identifiants/demo-infostealer.ps1` (ouvre un **faux** `Login Data` sous `%TEMP%`). Nettoyage : `-Nettoyer`.
- **Statut : 🔜 détecteur à venir** — le blocage d'accès par fichier relève du **minifilter noyau (Phase 2)**. En Phase 1 user-mode, pas d'interception fiable avant lecture.

### US-18 — Coffre-fort de mots de passe (Vault)
- **Comment tester :** `dotnet test CoreGuard.Vault.Tests` (11 tests : création, déverrouillage, mauvais mot de passe, round-trip chiffrement, générateur).
- **Statut : ✅ module actif / ⚠️ pas de page UI** — le coffre fonctionne (Argon2id + AES-256-GCM) mais n'a pas encore d'écran dédié dans l'interface.

---

## 4. Récapitulatif des spécimens de démo

Depuis la racine du dépôt. Détails complets : `demo/README.md`.

| Dossier | Lancer | Déclenche | Statut détection | Nettoyage |
|---------|--------|-----------|------------------|-----------|
| `01-powershell-amsi` | `./demo/01-powershell-amsi/demo-amsi.ps1` | AMSI / obfuscation | ⚠️ à la demande | aucun |
| `02-ransomware-canari` | `./demo/02-ransomware-canari/demo-ransomware.ps1` | canaris + vssadmin simulé | ⚠️ partiel | `-Nettoyer` (ou fichier `STOP`) |
| `03-persistance` | `./demo/03-persistance/demo-persistance.ps1` | clé Run + tâche | ✅ actif | **`-Nettoyer` obligatoire** |
| `04-badusb-hid` | `dotnet run --project .\demo\04-badusb-hid` | frappe HID rapide | 🔜 à venir | `Échap` / fermer |
| `05-crypto-clipper` | `dotnet run --project .\demo\05-crypto-clipper` | presse-papiers | ✅ actif | `Ctrl+C` / 60 s |
| `06-phishing-visuel` | `./demo/06-phishing-visuel/serve-phishing-demo.ps1` | OCR phishing | ⚠️ câblage extension | `Ctrl+C` / `/stop` |
| `07-vol-identifiants` | `./demo/07-vol-identifiants/demo-infostealer.ps1` | accès `Login Data` | 🔜 à venir | `-Nettoyer` |

Légende : ✅ actif · ⚠️ nécessite activation/câblage · 🔜 détecteur prévu en Phase 2.

---

## 5. Ordre recommandé pour une démonstration (soutenance)

1. **`dotnet test AntivirusIA.slnx`** → « 196 tests verts » (crédibilité immédiate).
2. Lancer l'app → **Analyse** d'un dossier mêlant fichiers sains + un `.exe` packé → verdicts colorés + **explication IA** (US-01, US-02, US-04).
3. **Signature** : EICAR (ou hash ajouté) → verdict Malveillant (US-03).
4. **Quarantaine** → isoler puis restaurer (US-05), **Historique** (US-06).
5. **Tableau de bord → « Simuler une alerte »** (US-07) et **crypto-clipper** (US-08, visuel et fiable).
6. **Persistance** (US-10) avec nettoyage, puis **Privacy Guard** (US-09).
7. Conclure sur les perspectives **Phase 2** (minifilter noyau) pour transformer les détections « à venir » (HID, infostealer, canaris pré-écriture) en **blocages inviolables**.

> Conseil : fais la démo dans une **VM** avec un **snapshot** préalable, et lance les nettoyages (`-Nettoyer`) après chaque spécimen.
