# =====================================================================
# DÉMO — INOFFENSIF : spécimen 01 (AMSI / règles comportementales)
# Objectif : faire passer par AMSI un script contenant des motifs
# typiques d'obfuscation (Base64 + décodage + invocation dynamique),
# SANS aucune charge utile : la chaîne décodée est "DEMO-INOFFENSIF".
# Aucun téléchargement, aucune exécution du texte décodé, aucun réseau.
# =====================================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Chaîne Base64 anodine : décode vers "DEMO-INOFFENSIF"
$b64 = 'REVNTy1JTk9GRkVOU0lG'

# Motif suspect (obfuscation) : décodage Base64 en mémoire
$octets = [System.Convert]::FromBase64String($b64)
$texte  = [System.Text.Encoding]::UTF8.GetString($octets)

# Motif suspect : invocation dynamique (Invoke-Expression) — mais la
# commande exécutée est un simple Write-Output du texte inoffensif.
$commande = "Write-Output 'Texte decode : $texte'"
Invoke-Expression $commande

# Motif suspect (texte seulement, jamais exécuté) : simple chaîne.
$exemple = 'DownloadString (jamais appele - DEMO INOFFENSIF)'
Write-Output $exemple
Write-Output 'Fin du specimen 01 : rien a nettoyer.'
