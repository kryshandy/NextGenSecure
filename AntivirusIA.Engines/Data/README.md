# Données du moteur de signatures

Ce dossier contient `signatures.json`, la base de signatures SHA-256 utilisée par le moteur de signatures d'`AntivirusIA.Engines`.

> Le fichier JSON ne contient pas de commentaire d'en-tête, car JSON ne permet pas les commentaires. Cette page en tient lieu.

## Format de `signatures.json`

```json
{
  "version": 1,
  "signatures": [
    {
      "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "name": "EICAR-Test-File"
    }
  ]
}
```

| Champ | Type | Rôle |
|-------|------|------|
| `version` | entier | Version de la base de signatures. |
| `signatures` | tableau | Liste des signatures connues. |
| `signatures[].sha256` | chaîne | Empreinte SHA-256 du fichier malveillant, en 64 caractères hexadécimaux. |
| `signatures[].name` | chaîne | Nom lisible de la menace, affiché lors de la détection. |

## Ajouter une signature

1. Calculer l'empreinte SHA-256 du fichier à signer, par exemple :

   ```powershell
   Get-FileHash -Algorithm SHA256 "chemin\vers\fichier"
   ```

2. Ajouter un objet `{ "sha256": "...", "name": "..." }` au tableau `signatures`, en utilisant l'empreinte en minuscules et sans espace.
3. Vérifier que le JSON reste valide (pas de virgule finale, guillemets doubles uniquement).
4. Lancer `dotnet test` pour vérifier que la base se charge correctement.

## Contenu actuel

La seule entrée est la signature du fichier de test standard **EICAR** (`EICAR-Test-File`). Ce fichier est inoffensif : c'est une chaîne de caractères reconnue par tous les antivirus pour vérifier que la détection fonctionne, sans aucune charge malveillante réelle.

## Bases additionnelles (listes SHA-256)

Le moteur charge aussi, s'ils existent :

- le dossier `Data/signatures/` livré avec l'application ;
- le dossier utilisateur `%LocalAppData%\CoreGuard\signatures\`.

Chaque fichier `.json` (format ci-dessus) ou `.txt` / `.sha256` y est chargé. Format texte : une empreinte par ligne, éventuellement suivie d'un nom (`<sha256> <nom>` ou `<sha256>,<nom>`) ; `#` introduit un commentaire et les lignes invalides sont ignorées. Les exports SHA-256 des flux publics (MalwareBazaar par exemple) se déposent tels quels.

## `rules.json` : règles de contenu

`PatternRuleEngine` applique des règles inspirées de YARA aux 32 premiers Mo de chaque fichier :

| Champ | Rôle |
|-------|------|
| `name`, `description` | Identification affichée dans l'indice. |
| `score` | Points ajoutés (0 à 100). |
| `definitive` | `true` : menace identifiée, jamais atténuée par une signature numérique. |
| `condition` | `any`, `all` ou un nombre minimal de motifs trouvés (`"2"`). |
| `strings[]` | Motifs : `text` (ASCII) ou `hex` (`"4D 5A ?? 00"`, `??` = joker), options `noCase` et `wide` (UTF-16LE). |

Les motifs sensibles sont écrits en hexadécimal : sinon, un autre antivirus prendrait `rules.json` lui-même pour un malware.
