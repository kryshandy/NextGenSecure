# =====================================================================
# DÉMO — INOFFENSIF : spécimen 03 (persistance)
# Crée, sans droits admin, une clé Run (HKCU), une tâche planifiée de
# l'utilisateur et un fichier dans son dossier Démarrage, tous pointant
# vers un script de TEST qui ne fait qu'écrire une ligne dans un journal
# de test. Noms préfixés "CoreGuardDemo".
# Attendu : CoreGuard affiche 3 fenêtres « Autoriser / Bloquer » ;
# « Bloquer » supprime la valeur Run et la tâche, et met le fichier du
# dossier Démarrage en quarantaine (restaurable).
# Nettoyage : .\demo-persistance.ps1 -Nettoyer   (à lancer après la démo !)
# =====================================================================
param([switch]$Nettoyer)
$ErrorActionPreference = 'Stop'

$racine  = Join-Path $env:TEMP 'CoreGuardDemo'
$dossier = Join-Path $racine 'persistance'
$script  = Join-Path $dossier 'inoffensif.cmd'
$cleRun  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$nomRun  = 'CoreGuardDemo'
$nomTache = 'CoreGuardDemoTask'
$demarrage = Join-Path ([Environment]::GetFolderPath('Startup')) 'CoreGuardDemo-inoffensif.cmd'

if ($Nettoyer) {
    Remove-ItemProperty -Path $cleRun -Name $nomRun -ErrorAction SilentlyContinue
    $ErrorActionPreference = 'SilentlyContinue'
    & schtasks.exe /Delete /TN $nomTache /F 2>&1 | Out-Null
    Remove-Item $demarrage -Force
    if (Test-Path $racine) { Remove-Item $racine -Recurse -Force }
    Write-Output 'Nettoyage termine : cle Run, tache, fichier Demarrage et dossier de test supprimes.'
    return
}

# Binaire de test inoffensif : écrit une ligne dans un journal de test
New-Item -ItemType Directory -Force -Path $dossier | Out-Null
Set-Content -Path $script -Encoding ASCII -Value @(
    '@echo off',
    'REM DEMO - INOFFENSIF : ecrit une ligne dans un journal de test',
    "echo DEMO-INOFFENSIF %date% %time% >> `"$dossier\journal.txt`""
)

# 1) Clé Run (HKCU)
Set-ItemProperty -Path $cleRun -Name $nomRun -Value "`"$script`""
Write-Output "Cle Run creee : $cleRun\$nomRun"

# 2) Tâche planifiée quotidienne de l'utilisateur courant (ONLOGON exigerait les droits admin)
$ErrorActionPreference = 'Continue'
& schtasks.exe /Create /TN $nomTache /TR "`"$script`"" /SC DAILY /ST 23:59 /F 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Output "Tache planifiee creee : \$nomTache" }
else { Write-Output "Tache planifiee NON creee (code $LASTEXITCODE)" }
$ErrorActionPreference = 'Stop'

# 3) Fichier dans le dossier Démarrage de l'utilisateur
Copy-Item -Path $script -Destination $demarrage -Force
Write-Output "Fichier Demarrage cree : $demarrage"

Write-Output 'Termine. NETTOYAGE OBLIGATOIRE : .\demo-persistance.ps1 -Nettoyer'
