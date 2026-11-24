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
