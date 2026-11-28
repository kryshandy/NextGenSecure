# Tester CoreGuard — procédure précise et résultats observés

Ce guide dit **exactement** quoi lancer, quoi observer et comment nettoyer, pour chaque fonctionnalité. Tous les
« malwares » utilisés sont des **spécimens inoffensifs** écrits pour la démonstration : ils imitent le comportement d'une
attaque (texte encodé, écriture dans un leurre, lecture d'un faux profil…) sans jamais rien abîmer, envoyer ou exécuter
de dangereux. Chacun a un nettoyage.

La colonne **« Observé »** donne le résultat réel de la dernière campagne de test (28/11/2026, Windows 11, service
installé).

---

## 0. Préparer la machine de test

1. Installer CoreGuard avec **`CoreGuard-Setup.exe`** (voir [GUIDE.md](GUIDE.md)) : application, service, AMSI, hôte de
   l'extension. Les spécimens sont copiés dans `C:\Program Files\CoreGuard\Demo`.
   *Depuis le dépôt (développement)* : `./scripts/install-service.ps1` (administrateur), puis
   `dotnet run --project AntivirusIA.UI`.
2. Ouvrir CoreGuard (icône près de l'horloge) : le **tableau de bord** doit afficher « Service connecté » et les modules
   actifs ; les alertes de chaque test y apparaissent dans *Alertes en temps réel*.
3. Ouvrir une console **PowerShell** dans le dossier des spécimens :
   ```powershell
   cd "C:\Program Files\CoreGuard\Demo"
   ```
   (ou `cd demo` à la racine du dépôt). Si PowerShell refuse les scripts : `Set-ExecutionPolicy -Scope Process Bypass`.
4. Pour les spécimens qui doivent être **arrêtés** par CoreGuard, le script se relance dans un processus séparé et
   affiche une ligne **`RÉSULTAT : …`** : c'est elle qui dit si la protection a fonctionné.

## 1. Campagne de test (ordre recommandé)

| # | Fonction testée | Commande | Résultat attendu | Observé |
|---|---|---|---|---|
| 01 | AMSI (script obfusqué) | `powershell -File .\01-powershell-amsi\demo-amsi.ps1` | « Ce script contient du contenu malveillant… bloqué » | ⚠️ détecté par le service mais exécuté (bogue du fournisseur, **corrigé** ; à revérifier après réinstallation) |
| 02 | Anti-ransomware, 1re couche (AMSI) | `powershell -File .\02-ransomware-canari\demo-ransomware.ps1` | script bloqué **avant** exécution | ✅ bloqué au chargement |
| 02b | Anti-ransomware, 2e couche (leurres + audit) | `.\02-ransomware-canari\RansomwareSim\RansomwareSim.exe` | arrêté au **premier** leurre, code `0xC0DE0001` ; leurre restauré | ✅ arrêté au 1er leurre |
| 03 | Persistance | `powershell -File .\03-persistance\demo-persistance.ps1` | 3 fenêtres « Autoriser / Bloquer » ; *Bloquer* retire l'entrée | ✅ |
| 04 | BadUSB (frappe automatique) | `.\04-badusb-hid\BadUsbSim.exe` (ne pas toucher au clavier) | ~30 caractères passent puis **clavier bloqué 10 s** | ✅ 2 000 car. tentés à ~870/s, bloqué |
| 05 | Crypto-clipper | `.\05-crypto-clipper\ClipperSim.exe` | alerte « Presse-papiers détourné : valeur d'origine restaurée » | ✅ |
| 07 | Voleur d'identifiants | `powershell -File .\07-vol-identifiants\demo-infostealer.ps1` | `RÉSULTAT : … ARRÊTÉ par CoreGuard en lisant le faux « Login Data »` | ✅ (2 essais sur 2) |
| 08 | Auto-défense (anti-arrêt) | `powershell -File .\08-anti-kill\demo-anti-kill.ps1` | `taskkill /F` : « Accès refusé » ; service toujours `Running` | ✅ |
| 09 | Injection mémoire (fileless) | `.\09-injection-memoire\MemoryInjectionSim.exe` | arrêté en ≤ 30 s, alerte « Code injecté » | ✅ arrêté à ~20 s (`0xC0DE0001`) |
| 10 | Anti-phishing + IA | voir section 3 | page « CoreGuard n'aime pas ce site », « doute », liste noire | ✅ |
| 11 | Smart Download Guard | `powershell -File .\11-telechargement\demo-telechargement.ps1` | fenêtres vert / orange / rouge avec le site d'origine | ✅ |
| 12 | Mode Paranoïa | activer le mode (tableau de bord), puis `powershell -File .\12-paranoia\demo-paranoia.ps1` | `RÉSULTAT : arrêté par CoreGuard` ; USB bloqué | ✅ (USBSTOR = 4, exécution arrêtée par ETW) |
| 13 | Pare-feu natif WFP | console **administrateur** : `dotnet run --project demo\13-pare-feu-wfp` | curl réussit, puis **bloqué** par le filtre WFP, puis réussit à nouveau | ✅ |

**Nettoyages** : `.\03-persistance\demo-persistance.ps1 -Nettoyer`, `.\07-vol-identifiants\demo-infostealer.ps1 -Nettoyer`,
`.\11-telechargement\demo-telechargement.ps1 -Nettoyer`, `.\12-paranoia\demo-paranoia.ps1 -Nettoyer`,
`Remove-Item -Recurse "$env:USERPROFILE\Documents\CoreGuardDemo"` (fichiers factices du 02). Désactiver le Mode
Paranoïa ensuite (mot de passe de protection) pour libérer l'USB.

## 2. Analyse, quarantaine, IA

1. **Fichier de test EICAR** (fichier standard de test des antivirus, inoffensif) : créer `eicar.txt` contenant
   `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`, puis **Analyse** > choisir le fichier.
   Attendu : **Malveillant** (signature connue + règle), explication de l'IA locale, bouton *Quarantaine*.
2. **Quarantaine** > *Restaurer* : le fichier revient à sa place ; *Supprimer* : définitif.
3. **IA niveau 1 (EMBER / ONNX)** : analyser un `.exe` ; l'indice « IA niveau 1 » n'apparaît que si le modèle le juge
   malveillant. Tests automatiques : `dotnet test AntivirusIA.Tests --filter EmberModelTests`
   (parité avec la référence EMBER, latence, aucun faux positif sur les exécutables Windows). Méthode et chiffres :
   [IA-ENTRAINEMENT.md](IA-ENTRAINEMENT.md).

## 3. Navigateur : anti-phishing, IA, coffre-fort

1. Charger l'extension (`C:\Program Files\CoreGuard\Extension`, mode développeur) et ouvrir CoreGuard.
2. Lancer le laboratoire : `powershell -File .\10-phishing-ia\serve-phishing-lab.ps1`
3. Ouvrir, dans Chrome ou Edge :

| Adresse | Attendu |
|---|---|
| `http://ameli-remboursement.localhost:8088/ameli.html` | interception immédiate (imitation du nom ameli) |
| `http://paypa1-verification.localhost:8088/paypal.html` | capture + OCR : « PayPal » sur un domaine tiers → interception |
| `http://suivi-colis-livraison.localhost:8088/colis.html` | arnaque sans marque : l'IA locale juge, avis affiché (20 à 90 s) |
| `http://cadeau-abonnement.localhost:8088/offre.html` puis **Ctrl+Maj+Y** | fenêtre « CoreGuard doute de ce site » |
| `http://liste-noire-demo.localhost:8088/` | liste noire → interception |
| `http://club-tennis-lilas.localhost:8088/club.html` | site inconnu légitime : aucune alerte |

4. Sur une page d'interception : *Je fais confiance* → CoreGuard demande confirmation **dans sa fenêtre** (Annuler →
   rien n'est enregistré) ; *Quitter ce site* → nouvel onglet.
5. **Mesure chiffrée sans navigateur** : `dotnet run --project demo\10-phishing-ia\eval` (19 cas, précision / rappel avec
   et sans IA ; résultat : 11/11 arnaques, 0 fausse alerte).
6. **Coffre-fort** : *Coffre-fort* > créer, ajouter un identifiant pour un site ; sur sa page de connexion, icône de
   l'extension > *Remplir* ; sur une page d'arnaque, le remplissage est **refusé**.

## 4. Verrouillage et contrôle à distance par téléphone

1. **Verrouillage local** : *Tableau de bord > Verrouiller le PC* : écran CoreGuard, clés USB et nouveaux périphériques
   refusés. Déverrouiller : **Ctrl+R**, puis mot de passe de protection.
2. **Téléphone** : *Réglages > Contrôle à distance* > *Point d'accès mobile de Windows* (l'activer) → connecter le
   téléphone à ce Wi-Fi → *Associer un téléphone* (mot de passe) → scanner le QR code.
3. Sur le téléphone : *Verrouiller le PC* → l'écran de verrouillage apparaît sur le PC ; *Déverrouiller* → il disparaît ;
   *Activer / Désactiver le Mode Paranoïa* → l'état change dans le tableau de bord. Chaque ordre apparaît dans les alertes
   (« Ordre exécuté depuis le téléphone »).
4. Contrôle de sécurité : depuis un autre appareil non associé, ouvrir la même adresse → « Ce téléphone n'est pas
   associé » ; tout ordre forgé est refusé (« Ordre refusé » dans les alertes, blocage après 5 essais).
5. *Révoquer* : le téléphone ne peut plus rien faire.

## 5. Tests automatisés

```powershell
dotnet test AntivirusIA.slnx
```
466 tests (moteurs, IA niveau 1, quarantaine, comportement, réseau et WFP, IPC et relais, service, contrôle à distance,
fournisseur AMSI natif, vie privée, coffre, extension et base de confiance). Le test de blocage WFP réel est ignoré hors
console administrateur (lancé et réussi en administrateur).

## 6. Si un test ne donne pas le résultat attendu

| Symptôme | Cause probable | Vérification |
|---|---|---|
| `RÉSULTAT : … sans être arrêté` (02b, 07) | service non installé ou audit inactif | *Réglages > Service* ; `auditpol /get /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}"` (admin) |
| Script 01 exécuté | fournisseur AMSI non chargé par cette console | ouvrir une **nouvelle** console PowerShell ; *Réglages* : compteur AMSI |
| Pas de fenêtre de téléchargement | module « Surveillance des fichiers » désactivé | tableau de bord |
| Téléphone : « PC injoignable » | pas sur le même réseau, ou point d'accès coupé | *Réglages > Contrôle à distance* : adresses affichées |
| Extension sans effet | hôte non enregistré | réinstaller avec l'option « Hôte de l'extension » |
