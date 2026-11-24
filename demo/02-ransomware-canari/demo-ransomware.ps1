# =====================================================================
# DÉMO — INOFFENSIF : spécimen 02 (ransomware simulé + canari)
# Tout se passe dans un dossier de TEST créé par ce script, sous %TEMP%.
# Jamais les vrais Documents. Aucun chiffrement réel : les fichiers
# sont simplement écrits puis renommés avec l'extension ".coreguard-demo".
# La commande vssadmin n'est JAMAIS exécutée (mode what-if : affichage).
# Kill switch : créer le fichier STOP dans le dossier de test, ou Ctrl+C.
# Nettoyage   : .\demo-ransomware.ps1 -Nettoyer
# =====================================================================
param(
    [switch]$Nettoyer,
    [int]$NbFichiers = 60,
    # Dossier de test (doit rester sous %TEMP%\CoreGuardDemo, vérifié ci-dessous)
    [string]$Dossier = (Join-Path $env:TEMP 'CoreGuardDemo\ransomware')
)
$ErrorActionPreference = 'Stop'

# Garde-fou : refuse tout dossier hors %TEMP%\CoreGuardDemo
$racine = [IO.Path]::GetFullPath((Join-Path $env:TEMP 'CoreGuardDemo'))
$cible  = [IO.Path]::GetFullPath($Dossier)
if (-not $cible.StartsWith($racine, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Dossier refuse : le specimen reste sous $racine"
}

if ($Nettoyer) {
    if (Test-Path $racine) { Remove-Item $racine -Recurse -Force }
    Write-Output "Nettoyage termine : $racine supprime."
    return
}

New-Item -ItemType Directory -Force -Path $cible | Out-Null
$stop = Join-Path $cible 'STOP'

# 1) Fichiers factices, dont un nom de canari (adapter au canari configuré)
$noms = @('~coreguard_canary.docx', '_aaa_canary.txt') +
        (1..$NbFichiers | ForEach-Object { "document_factice_$_.txt" })
foreach ($n in $noms) {
    Set-Content -Path (Join-Path $cible $n) -Value "DEMO - INOFFENSIF : contenu factice $n" -Encoding UTF8
}
Write-Output "[1/3] $($noms.Count) fichiers factices ecrits dans $cible"

# 2) Rafale de modifications massives : réécriture + renommage rapide
#    (simule le comportement ransomware, sans chiffrer quoi que ce soit)
foreach ($f in Get-ChildItem $cible -File | Where-Object Name -ne 'STOP') {
    if (Test-Path $stop) { Write-Output 'Kill switch STOP detecte : arret.'; break }
    Add-Content -Path $f.FullName -Value 'DEMO-INOFFENSIF'
    Rename-Item -Path $f.FullName -NewName ($f.Name + '.coreguard-demo') -ErrorAction SilentlyContinue
}
Write-Output '[2/3] Rafale de renommages/ecritures terminee.'

# 3) Simulation « what-if » de la suppression des clichés VSS.
#    La commande vssadmin n'est PAS appelée : on lance seulement cmd.exe
#    avec un "echo" dont la ligne de commande contient le texte, ce qui
#    permet de tester une règle ETW basée sur la ligne de commande.
$cmdSimulee = 'vssadmin delete shadows /all /quiet'
Write-Output "[3/3] WHAT-IF (non execute) : $cmdSimulee"
& cmd.exe /c "echo DEMO-INOFFENSIF what-if: $cmdSimulee"

Write-Output "Termine. Nettoyage : .\demo-ransomware.ps1 -Nettoyer"
