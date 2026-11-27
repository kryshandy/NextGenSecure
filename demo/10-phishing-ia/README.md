# Spécimen 10 — Anti-phishing : base de confiance, OCR et IA locale

Démonstration **inoffensive** : des pages de laboratoire imitent, par leur seul texte, des marques et institutions
(PayPal, ameli, Orange Money, MTN MoMo, impots.gouv.fr, Netflix), plus des arnaques sans marque (faux frais de colis,
arnaque crypto) et des sites inconnus légitimes. Les formulaires n'envoient rien ; rien ne sort du PC.

## Ce que CoreGuard fait (cascade, de la plus rapide à la plus coûteuse)

1. **Site déclaré de confiance par vous** → sûr. Seul l'utilisateur peut « remonter » un site, après confirmation dans CoreGuard.
2. **Liste noire** (instantané OpenPhish livré + liste personnelle + mise à jour optionnelle) → page d'interception.
3. **Domaine connu** (100 000 domaines les plus visités, Tranco ; domaine enregistrable calculé avec la Public Suffix List)
   → sûr, sans capture. Les hébergeurs où chacun publie (`*.vercel.app`, `sites.google.com`…) n'en profitent jamais.
4. **Règles d'URL** : homographes, typosquatting, marque en sous-domaine, adresse IP, mot de passe en http.
5. **Champ mot de passe sur un site non connu** → capture de l'onglet, **OCR** (Windows.Media.Ocr) + QR :
   marque affichée vs domaine réel.
6. **Zone grise** → l'**IA locale** (Llama 3.2 3B, LLamaSharp, dans l'application) relit les faits et répond en JSON.
   Elle peut **seulement aggraver** le verdict.
7. Affichage : **« CoreGuard n'aime pas ce site »** (page d'interception : Quitter / Je fais confiance / Continuer quand
   même) ou **« CoreGuard doute de ce site »** (fenêtre au centre de la page), avis de l'IA inclus ; alerte dans le
   tableau de bord et bulle Windows si la fenêtre est cachée.

## Démonstration 1 — mesure chiffrée (aucune installation)

```powershell
dotnet run --project .\demo\10-phishing-ia\eval              # règles + IA locale (quelques minutes sur CPU)
dotnet run --project .\demo\10-phishing-ia\eval -- --sans-ia # règles seules
```

Pour chaque cas du `corpus.json` : capture réelle de la page (Edge sans fenêtre), puis la même cascade que l'extension.
Résultat : précision / rappel « règles seules » et « règles + IA », détail par cas dans `resultats.md`.

### Résultats obtenus (19 cas : 11 arnaques, 8 sites légitimes)

| Version | Arnaques détectées | Fausses alertes | Précision | Rappel |
|---|---|---|---|---|
| Règles seules | 9 / 11 | 0 / 8 | 100 % | 82 % |
| Règles + IA, 1re consigne | 11 / 11 | 2 / 8 | 85 % | 100 % |
| Règles + IA, consigne revue | 11 / 11 | 4 / 8 | 73 % | 100 % |
| **Règles + IA + garde-fou « indice objectif »** | **11 / 11** | **0 / 8** | **100 %** | **100 %** |

Ce que ces mesures montrent :
- les règles ratent les arnaques **sans marque** (faux frais de colis, arnaque crypto) ; l'IA locale les rattrape ;
- un petit modèle (Llama 3.2 3B) répond « arnaque » par réflexe sur des sites honnêtes inconnus, même avec une
  consigne détaillée : la consigne seule ne suffit pas ;
- le garde-fou retenu : l'IA n'aggrave que sur **indice objectif** (marque affichée sur un domaine qui n'est pas le
  sien, ou demande de carte / code / phrase de récupération) et jamais une page qui affiche la marque de son propre
  domaine. Les petits sites qui demandent seulement un identifiant ne sont plus soumis au modèle.

Limites, honnêtement : le corpus est petit et a été conçu pour la démonstration ; le garde-fou a été réglé en voyant
ces résultats. La revue par l'IA prend 20 à 90 s sur CPU (le verdict des règles s'affiche tout de suite).

## Démonstration 2 — en direct dans le navigateur

1. Installer l'hôte : `./scripts/install-browser-extension.ps1`. Ouvrir CoreGuard (pour l'IA et la confirmation de confiance).
2. Lancer le laboratoire : `./demo/10-phishing-ia/serve-phishing-lab.ps1`
3. Ouvrir Edge de démonstration (profil temporaire, synchronisation coupée, extension chargée, votre Edge habituel
   n'est pas touché) : `./demo/10-phishing-ia/ouvrir-edge-demo.ps1` — ou charger l'extension à la main
   (`CoreGuard.Extension\extension`, mode développeur) dans Chrome ou Edge. Puis ouvrir :

| Adresse | Attendu |
|---|---|
| `http://ameli-remboursement.localhost:8088/ameli.html` | page d'interception dès le chargement (typosquatting) |
| `http://paypa1-verification.localhost:8088/paypal.html` | OCR : « PayPal » sur un domaine tiers → interception |
| `http://orange-money-cm.localhost:8088/orange-money.html` | OCR : Orange Money → interception |
| `http://suivi-colis-livraison.localhost:8088/colis.html` | zone grise : l'IA locale juge la page, avis affiché |
| `http://club-tennis-lilas.localhost:8088/club.html` | site inconnu légitime : pas d'alerte attendue |
| `http://cadeau-abonnement.localhost:8088/offre.html` puis **Ctrl+Maj+Y** | page sans formulaire : analyse à la demande, fenêtre « CoreGuard doute de ce site » |
| `http://liste-noire-demo.localhost:8088/` | liste noire personnelle → interception immédiate |

4. Sur une page d'interception : « Je fais confiance à ce site » → CoreGuard demande confirmation dans **sa** fenêtre
   (une page web ne peut pas cliquer à votre place) ; Réglages > Anti-phishing permet de tout retirer.
5. Arrêt : `Ctrl+C` ou `http://localhost:8088/stop` (l'entrée de test de la liste noire est retirée), puis
   `./demo/10-phishing-ia/ouvrir-edge-demo.ps1 -Fermer`.

Vérifié en direct (Edge, profil temporaire) : interception au chargement (typosquatting), interception après OCR
(PayPal), arnaque sans marque attrapée par l'IA locale, liste noire personnelle, « Je fais confiance » confirmé dans la
fenêtre CoreGuard (Annuler → rien n'est enregistré), « Quitter ce site », fenêtre « doute » par Ctrl+Maj+Y, alertes
dans le tableau de bord et bulles Windows.

Pages régénérables avec `python generer-pages.py`.
