# =====================================================================
# DÉMO — INOFFENSIF : spécimen 11 (Smart Download Guard)
# Dépose dans le dossier Téléchargements 4 fichiers de TEST, chacun avec
# une « marque du Web » (flux NTFS Zone.Identifier) identique à celle
# qu'écrit un navigateur après un téléchargement :
#   1. CoreGuardDemo-outil.exe      exécutable NON signé venu d'Internet  -> orange
#   2. CoreGuardDemo-facture.js     script venu d'un faux site de factures -> orange ou rouge
#   3. CoreGuardDemo-cours.pdf      document venu d'Internet              -> vert (alerte simple)
#   4. CoreGuardDemo-restreint.txt  fichier d'un site sur liste restreinte -> rouge
# Aucun fichier ne fait quoi que ce soit (l'exe affiche un message, le
# script n'est jamais lancé). Nettoyage : .\demo-telechargement.ps1 -Nettoyer
# =====================================================================
param([switch]$Nettoyer)
$ErrorActionPreference = 'Stop'

$dl = Join-Path $env:USERPROFILE 'Downloads'
$noms = 'CoreGuardDemo-outil.exe', 'CoreGuardDemo-facture.js', 'CoreGuardDemo-cours.pdf', 'CoreGuardDemo-restreint.txt'

if ($Nettoyer) {
    foreach ($n in $noms) { Remove-Item (Join-Path $dl $n) -Force -ErrorAction SilentlyContinue }
    Write-Output 'Nettoyage termine : fichiers de demonstration retires du dossier Telechargements.'
    return
}

function Ajouter-MarqueDuWeb([string]$chemin, [int]$zone, [string]$hote, [string]$page) {
    # Exactement le format écrit par Edge / Chrome (flux secondaire NTFS)
    $contenu = "[ZoneTransfer]`r`nZoneId=$zone`r`nReferrerUrl=$page`r`nHostUrl=$hote`r`n"
    Set-Content -Path $chemin -Stream 'Zone.Identifier' -Value $contenu -Encoding Ascii
}

# 1) Exécutable non signé, compilé à la volée : affiche seulement un message
$exe = Join-Path $dl $noms[0]
$source = 'public static class Demo { public static void Main() { System.Console.WriteLine("DEMO INOFFENSIF CoreGuard"); } }'
Add-Type -TypeDefinition $source -OutputAssembly $exe -OutputType ConsoleApplication
Ajouter-MarqueDuWeb $exe 3 'https://telechargements-gratuits.example/outil.exe' 'https://telechargements-gratuits.example/'
Write-Output "Depose : $exe"
Start-Sleep -Seconds 4

# 2) Script (jamais exécuté) venu d'un faux site de factures
$js = Join-Path $dl $noms[1]
Set-Content -Path $js -Encoding Ascii -Value "// DEMO INOFFENSIF CoreGuard : ce script ne fait rien`r`nWScript.Echo('demo');"
Ajouter-MarqueDuWeb $js 3 'https://factures-impayees.example/facture.js' 'https://factures-impayees.example/paiement'
Write-Output "Depose : $js"
Start-Sleep -Seconds 4

# 3) Document PDF minimal
$pdf = Join-Path $dl $noms[2]
Set-Content -Path $pdf -Encoding Ascii -Value "%PDF-1.4`n% DEMO INOFFENSIF CoreGuard`n1 0 obj << /Type /Catalog >> endobj`ntrailer << /Root 1 0 R >>`n%%EOF"
Ajouter-MarqueDuWeb $pdf 3 'https://cours-en-ligne.example/cours.pdf' 'https://cours-en-ligne.example/'
Write-Output "Depose : $pdf"
Start-Sleep -Seconds 4

# 4) Fichier texte venu d'un site sur liste restreinte (zone 4)
$txt = Join-Path $dl $noms[3]
Set-Content -Path $txt -Encoding Ascii -Value 'DEMO INOFFENSIF CoreGuard'
Ajouter-MarqueDuWeb $txt 4 'https://site-restreint.example/fichier.txt' 'https://site-restreint.example/'
Write-Output "Depose : $txt"

Write-Output 'Termine. NETTOYAGE : .\demo-telechargement.ps1 -Nettoyer'
