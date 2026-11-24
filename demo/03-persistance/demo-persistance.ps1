# =====================================================================
# DÉMO — INOFFENSIF : spécimen 03 (persistance)
# Crée, sous HKCU uniquement (pas d'admin), une clé Run et une tâche
# planifiée pointant vers un script de TEST qui ne fait qu'écrire une
# ligne dans un journal de test. Noms préfixés "CoreGuardDemo".
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

if ($Nettoyer) {
    Remove-ItemProperty -Path $cleRun -Name $nomRun -ErrorAction SilentlyContinue
    & schtasks.exe /Delete /TN $nomTache /F 2>$null | Out-Null
    if (Test-Path $racine) { Remove-Item $racine -Recurse -Force }
    Write-Output 'Nettoyage termine : cle Run, tache et dossier de test supprimes.'
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

# 2) Tâche planifiée à l'ouverture de session, utilisateur courant
& schtasks.exe /Create /TN $nomTache /TR "`"$script`"" /SC ONLOGON /F | Out-Null
Write-Output "Tache planifiee creee : $nomTache"

Write-Output 'Termine. NETTOYAGE OBLIGATOIRE : .\demo-persistance.ps1 -Nettoyer'
