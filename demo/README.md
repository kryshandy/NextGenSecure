# Démonstration CoreGuard (laboratoire)

Ce dossier contiendra les scénarios de démonstration de CoreGuard.

## Principe

Les scénarios utilisent des **spécimens bénins de laboratoire** : des fichiers et scripts conçus uniquement pour déclencher les détecteurs de CoreGuard.

- **Aucune nuisance réelle** : un spécimen ne chiffre, ne vole et ne modifie rien en dehors de son périmètre de test.
- **Exécution isolée** : les scénarios tournent dans un dossier de test dédié, jamais sur des données utilisateur.
- **Kill switch** : chaque scénario peut être interrompu immédiatement, et le kill switch réseau de CoreGuard coupe les communications si besoin.

## Scénarios prévus

| # | Scénario | Cible de détection | Défense attendue |
|---|----------|--------------------|------------------|
| 1 | Ransomware simulé + suppression des copies VSS | Modification massive de fichiers, `vssadmin delete shadows` (ETW) | Canaris anti-ransomware, arrêt du processus, restauration |
| 2 | Désactivation de la protection | Tentative d'arrêt du service ou de l'antivirus | Anti-`taskkill`, réaction immédiate |
| 3 | Script PowerShell malveillant | Contenu du script analysé par AMSI avant exécution | Blocage du script par AMSI |
| 4 | Périphérique BadUSB | Comportement de frappe automatique d'un périphérique HID | Détection comportementale, alerte |
| 5 | Injection mémoire | Relation parent-enfant suspecte et écriture dans un processus tiers (ETW) | Détection comportementale, arrêt du processus |
| 6 | Phishing visuel | Page imitant une page de connexion connue, détectée par OCR | Alerte via l'extension navigateur (OCR) |
| 7 | Vol d'identifiants | Accès aux données de connexion stockées par le navigateur | Anti-infostealer navigateur, alerte |
| 8 | Crypto-clipper | Remplacement d'une adresse de portefeuille dans le presse-papiers | Presse-papiers intelligent, restauration de la valeur |
| 9 | Persistance | Ajout d'une entrée Run/RunOnce, tâche planifiée ou service | Gardien de persistance, signalement et retrait |
| 10 | Accès caméra | Ouverture de la caméra par un processus non autorisé | Privacy Guard, alerte et blocage |

> Les colonnes « Cible » et « Défense » sont à valider avec le document de référence du projet (« CoreGuard — Topo Complet »), qui n'est pas dans le dépôt.
