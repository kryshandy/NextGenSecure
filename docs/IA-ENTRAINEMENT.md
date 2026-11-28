# Entraîner et évaluer un modèle de détection : comment ça marche, comment le faire bien, et ce que nous avons fait

Ce document explique en détail l'« IA niveau 1 » de CoreGuard : comment un modèle apprend à reconnaître un
exécutable malveillant, comment les éditeurs d'antivirus le font en entreprise, et comment on prouve (chiffres à
l'appui) qu'un modèle est bon. Chaque notion est illustrée sur notre cas réel.

---

## 1. L'idée en une phrase

On montre au modèle des **centaines de milliers d'exemples déjà classés** (« ce fichier est sain », « ce fichier est
malveillant »), décrits par des **mesures chiffrées** (les *caractéristiques*). Il en déduit des règles qui séparent
les deux familles. Ensuite on vérifie ces règles sur des fichiers **qu'il n'a jamais vus** : c'est la seule mesure
honnête de sa qualité.

## 2. Les quatre ingrédients

| Ingrédient | Définition | Dans CoreGuard |
|---|---|---|
| **Données étiquetées** | des exemples avec la bonne réponse | EMBER 2018 : 1 million de fichiers Windows (PE) décrits par des chercheurs, dont 600 000 étiquetés pour l'entraînement (moitié sains, moitié malveillants) et 200 000 pour le test |
| **Caractéristiques** (*features*) | des nombres qui décrivent un fichier | 616 nombres calculés sur les octets : fréquence de chaque octet, « carte » de l'entropie (le désordre) du fichier, statistiques des chaînes de texte (URL, chemins `C:\`, clés de registre, en-têtes `MZ` cachés…) |
| **Algorithme** | la méthode qui apprend | LightGBM : une forêt d'arbres de décision construits les uns après les autres, chacun corrigeant les erreurs des précédents (*gradient boosting*) |
| **Évaluation** | la mesure sur des données jamais vues | jeu de test EMBER séparé, avec AUC, taux de détection et taux de fausses alertes |

### Pourquoi ces caractéristiques ?

Un malware se trahit souvent par sa « texture » plutôt que par son nom :
- **entropie élevée et uniforme** → contenu compressé ou chiffré (programme « packé » pour échapper aux antivirus) ;
- **peu de texte lisible** dans un gros exécutable → code dissimulé ;
- **URL, adresses IP, clés `HKEY_…`, chemins `C:\Users\…\AppData`** → téléchargement, persistance ;
- **plusieurs `MZ`** dans un même fichier → un exécutable caché dans un autre (*dropper*).

Un arbre de décision apprend des règles du type : « si l'entropie dans la zone haute dépasse X **et** qu'il y a moins de
Y chaînes **et** qu'on trouve une URL, alors plutôt malveillant ». Des centaines d'arbres combinés donnent une
**probabilité** entre 0 et 1.

### Pourquoi 616 caractéristiques et pas les 2 381 d'EMBER ?

EMBER décrit aussi l'en-tête, les sections, les fonctions importées… mais ces groupes sont extraits avec la
bibliothèque Python LIEF ; la moindre différence d'analyse en C# fausserait les valeurs, et le modèle se tromperait
sans prévenir (*training/serving skew*, l'erreur classique en production). Nous avons donc gardé les trois groupes qui se
calculent **sur les octets bruts**, que nous recalculons **à l'identique** en C#, et nous le **prouvons** par un test de
parité (section 6). Moins de caractéristiques, mais zéro écart entre l'entraînement et l'utilisation réelle.

## 3. Comment se déroule notre entraînement (concrètement)

Script : `scripts/ml/train_ember_subset.py`.

1. **Lecture en flux** de l'archive officielle EMBER (1,6 Go compressés, ~10 Go de JSON) : aucune décompression sur
   disque, on ne garde que les 616 nombres utiles par fichier. *Le jeu ne contient aucun binaire malveillant, seulement
   des mesures.*
2. **Échantillonnage** : 200 000 fichiers étiquetés pour l'entraînement et 100 000 pour le test (tirage aléatoire à
   graine fixe : le résultat est reproductible). Raison : la mémoire disponible de la machine ; la qualité reste très
   proche du jeu complet pour ce type de modèle.
3. **Séparation entraînement / validation** : 90 % pour apprendre, 10 % mis de côté pour **choisir les seuils**.
4. **Apprentissage** LightGBM : 500 arbres de 64 feuilles, taux d'apprentissage 0,08, sous-échantillonnage des lignes
   (80 %) et des colonnes (60 %) pour éviter d'apprendre « par cœur ».
5. **Choix de deux seuils sur la validation** :
   - seuil **bas** : celui qui ne déclenche que **1 %** de fausses alertes sur des fichiers sains ;
   - seuil **haut** : **0,1 %** de fausses alertes (indice fort).
6. **Mesure finale sur le test** (jamais vu, jamais utilisé pour un réglage) : AUC, détection et fausses alertes
   réelles à chaque seuil.
7. **Export ONNX** (format standard, indépendant de Python) puis **vérification** : ONNX Runtime doit redonner les mêmes
   probabilités que LightGBM.
8. **Fichier de parité** : le script recalcule, avec l'algorithme de référence d'EMBER, les caractéristiques de vrais
   exécutables Windows de la machine (notepad, cmd, kernel32…) ; le test C# compare son propre calcul, valeur par valeur.

Dans CoreGuard (`AntivirusIA.Ml/EmberOnnxEngine.cs`), pour chaque exécutable analysé : lecture des octets → 616
caractéristiques → ONNX Runtime → probabilité → au-dessus du seuil haut **+40 points** de risque, au-dessus du seuil bas
**+20 points**. C'est un indice *heuristique* : il est divisé par 4 si le fichier porte une signature numérique valide.

## 4. Comment on fait un bon entraînement en entreprise

Ce que font les équipes de détection (éditeurs d'antivirus, EDR) — et ce que nous avons appliqué ou non :

| Bonne pratique | Pourquoi | Chez nous |
|---|---|---|
| **Séparation stricte** entraînement / validation / test | Un modèle évalué sur ses propres exemples paraît toujours excellent | ✅ trois ensembles distincts |
| **Séparation temporelle** : tester sur des fichiers *plus récents* que ceux d'entraînement | Les malwares évoluent ; c'est la vraie situation d'un antivirus (*concept drift*) | ✅ par construction d'EMBER : le test est postérieur à l'entraînement (fin 2018) |
| **Dédoublonnage** par empreinte et par famille | Deux variantes quasi identiques de part et d'autre gonflent les scores | ⚠️ fait par les auteurs d'EMBER (empreintes uniques) ; pas de séparation par famille |
| **Étiquettes fiables** (consensus de plusieurs moteurs, délai de maturation) | Une étiquette fausse apprend une erreur | ✅ EMBER : étiquettes issues du consensus VirusTotal |
| **Seuil choisi par le taux de fausses alertes** | Une fausse alerte sur un logiciel courant coûte très cher (clients, support) | ✅ seuils à 1 % et 0,1 % fixés sur la validation |
| **Parité entraînement / production** | Un calcul différent en production rend le modèle aveugle | ✅ test de parité C# / référence |
| **Mesure de latence** | Un antivirus ne doit pas ralentir l'ouverture des fichiers | ✅ budget < 50 ms testé |
| **Versionnage** du modèle, des données et du code | Pouvoir expliquer et reproduire une décision | ✅ graine fixe, métadonnées (`ember-subset.json`), script versionné |
| **Liste de fichiers sains « critiques »** testée à chaque version (Windows, Office, navigateurs…) | Une fausse alerte sur un fichier système est inacceptable | ✅ test : notepad, cmd, ping ne doivent pas être signalés |
| **Combinaison** avec d'autres moteurs, jamais seul | Un modèle statique se contourne (*adversarial*) | ✅ points de risque ajoutés aux signatures, règles, entropie, Authenticode, comportement |
| **Déploiement progressif** (mode silencieux, puis alerte, puis blocage) | Observer les faux positifs réels avant d'agir | ⚠️ pas encore : l'indice agit directement sur le score |
| **Réentraînement régulier** et **surveillance** des performances | Le modèle vieillit en quelques mois | ⚠️ non automatisé (le script se relance à la main) |
| **Données récentes et propres à l'entreprise** (télémétrie clients) | Les jeux publics vieillissent | ❌ hors de portée d'un projet de cours : EMBER 2018 date un peu |

## 5. Évaluer qu'on a réussi : les mesures, expliquées sur un exemple

Imaginons 1 000 fichiers sains et 1 000 malveillants passés au modèle, avec un seuil donné :

| | Le modèle dit « malveillant » | Le modèle dit « sain » |
|---|---|---|
| **Vraiment malveillant** | 950 vrais positifs | 50 faux négatifs (malwares ratés) |
| **Vraiment sain** | 10 faux positifs (fausses alertes) | 990 vrais négatifs |

- **Taux de détection** (rappel, TPR) = 950 / 1 000 = **95 %** : la part des malwares attrapés.
- **Taux de fausses alertes** (FPR) = 10 / 1 000 = **1 %** : la part des fichiers sains accusés à tort.
- **Précision** = 950 / (950 + 10) ≈ **99 %** : quand le modèle alerte, il a raison 99 fois sur 100.
- **AUC** (aire sous la courbe ROC, de 0,5 = hasard à 1 = parfait) : la probabilité qu'un malware pris au hasard
  reçoive une note plus haute qu'un fichier sain pris au hasard. Elle résume le modèle **sur tous les seuils**.

Le piège : sur un vrai PC, il y a des milliers de fichiers sains pour quelques malwares. 1 % de fausses alertes sur
50 000 fichiers = **500 fausses alertes** : inacceptable. C'est pourquoi les éditeurs visent 0,1 % voire 0,01 % et
pourquoi nous avons un **seuil haut** (0,1 %) qui donne le gros des points, et un seuil bas qui ne fait qu'ajouter un
indice parmi d'autres.

### Ce qui prouve que c'est réussi, chez nous

1. **Mesure sur le test EMBER** (fichiers jamais vus, plus récents) : AUC, détection et fausses alertes aux deux seuils
   — voir les résultats ci-dessous et `AntivirusIA.Ml/Models/ember-subset.json`.
2. **Parité** : les 616 valeurs calculées en C# sont identiques à la référence EMBER sur de vrais exécutables, et ONNX
   Runtime en C# redonne la probabilité calculée en Python.
3. **Fausses alertes sur des fichiers critiques** : notepad, cmd, ping ne sont pas signalés.
4. **Latence** : moins de 50 ms par exécutable (test automatisé).

## 6. Résultats obtenus

| Mesure | Résultat | Commentaire |
|---|---|---|
| Fichiers d'entraînement / de test | 199 541 / 100 561 | équilibrés (≈ 50 % malveillants), test plus récent que l'entraînement |
| **AUC sur le test EMBER** | **0,980** | 1 = parfait, 0,5 = hasard |
| Seuil bas (visé : 1 % de fausses alertes) | **84,1 % détectés**, 1,92 % de fausses alertes | +20 points de risque |
| Seuil haut (visé : 0,1 %) | **62,7 % détectés**, 0,23 % de fausses alertes | +40 points de risque |
| Export ONNX | écart max 1,6·10⁻⁷ avec LightGBM | même modèle en C# et en Python |
| Parité C# / référence EMBER | 6 exécutables Windows, 616 valeurs identiques, même probabilité | test automatisé |
| **Fichiers Windows sains de ce PC (System32, 2 177)** | **0 alerte au seuil haut**, 5 au seuil bas (0,23 %) | vraie mesure de fausses alertes sur la machine |
| Temps (Release) | ≈ 17 ms pour 841 Ko, 9,7 ms en moyenne sur System32 | budget 50 ms respecté |

**Lecture honnête.** Les fausses alertes sur le test EMBER (1,92 % et 0,23 %) dépassent les objectifs fixés sur la
validation (1 % et 0,1 %) : les seuils ont été choisis sur des fichiers de la même époque que l'entraînement, alors que
le test est plus récent. C'est exactement le *concept drift* décrit plus haut, et la raison pour laquelle les éditeurs
réentraînent et recalent leurs seuils en continu. Sur les fichiers Windows réels de la machine, en revanche, le seuil haut
ne déclenche aucune alerte, et le seuil bas n'ajoute que 20 points (sous le seuil « suspect » de 30 à lui seul).

## 7. Limites, honnêtement

- Le modèle n'utilise que la « texture » des octets : un malware non packé, au contenu banal, peut passer. C'est pour
  cela qu'il s'ajoute aux autres moteurs (signatures, règles, comportement ETW, AMSI, mémoire) au lieu de les remplacer.
- EMBER 2018 a vieilli : les familles de 2025-2026 ne sont pas représentées. En entreprise, on réentraîne sur la
  télémétrie récente tous les mois.
- Un attaquant qui connaît le modèle peut ajouter des octets pour le tromper (*adversarial padding*) : la signature
  Authenticode, le comportement et la mémoire restent alors les garde-fous.
