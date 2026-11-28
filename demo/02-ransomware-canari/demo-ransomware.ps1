# =====================================================================
# DÉMO — INOFFENSIF : spécimen 02 (ransomware simulé + canaris + VSS)
#
# Ce que fait le spécimen, comme un ransomware, mais sans aucun dégât :
#  1. « chiffre » SES PROPRES fichiers factices dans Documents\CoreGuardDemo
#     (simple ajout de texte + renommage en .coreguard-demo) ;
#  2. s'attaque aux fichiers LEURRES de CoreGuard à la racine de Documents,
#     Bureau et Images. Liste blanche stricte : seuls les noms exacts des
#     canaris CoreGuard sont touchés, jamais un autre fichier. Ce sont des
#     faux documents que CoreGuard restaure aussitôt ;
#  3. simule la suppression des clichés VSS : « vssadmin delete shadows »
#     n'est JAMAIS exécuté, seulement affiché via cmd.exe /c echo.
#
# Attendu avec le service CoreGuard installé (audit NTFS actif) : à l'étape 2,
# CoreGuard identifie ce processus PowerShell par l'audit, l'ARRÊTE, et
# restaure le leurre. Le script ne va donc pas au bout : c'est le résultat
# attendu. Il se relance lui-même dans une fenêtre séparée, pour que l'arrêt
# ne ferme pas ta console.
#
# Kill switch : fichier STOP dans Documents\CoreGuardDemo, ou Ctrl+C.
# Nettoyage   : .\demo-ransomware.ps1 -Nettoyer
# =====================================================================
param(
    [switch]$Nettoyer,
    [switch]$Enfant,
    [int]$NbFichiers = 30
)
$ErrorActionPreference = 'Stop'

$documents = [Environment]::GetFolderPath('MyDocuments')
$demo = Join-Path $documents 'CoreGuardDemo'
# Noms EXACTS des canaris CoreGuard (CoreGuard.RealTime/CanaryManager.DefaultCanaryNames)
$canaris = @('!00_confidentiel.docx', '_zz_confidentiel.docx', '~000_backup.xlsx', '!!_comptes_2024.xlsx', '_00_mots_de_passe.txt')

if ($Nettoyer) {
    if (Test-Path $demo) { Remove-Item $demo -Recurse -Force }
    Write-Output "Nettoyage terminé : $demo supprimé (les leurres sont gérés par CoreGuard)."
    return
}

# Relance dans un processus dédié : c'est LUI que CoreGuard arrêtera, pas ta console
if (-not $Enfant) {
    Write-Output "Lancement du spécimen dans un processus séparé..."
    $p = Start-Process -FilePath 'powershell.exe' -PassThru -Wait -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Enfant', '-NbFichiers', $NbFichiers)
    $code = $p.ExitCode
    if ($code -eq [int]0xC0DE0001 -or $code -eq -1059192831) {
        Write-Output "RÉSULTAT : le spécimen (PID $($p.Id)) a été ARRÊTÉ par CoreGuard (code 0xC0DE0001). Protection anti-ransomware opérationnelle."
    } elseif ($code -eq 0) {
        Write-Output "RÉSULTAT : le spécimen est allé au bout sans être arrêté. Vérifiez que le service CoreGuard est installé et que l'audit est actif (scripts/install-service.ps1)."
    } else {
        Write-Output "RÉSULTAT : le spécimen s'est terminé avec le code $code."
    }
    return
}

# ---------- Processus enfant : le « ransomware » ----------
New-Item -ItemType Directory -Force -Path $demo | Out-Null
$stop = Join-Path $demo 'STOP'

# 1) Ses propres fichiers factices, nommés par exécution (aucune collision avec une exécution précédente)
$lot = Get-Date -Format 'yyyyMMdd-HHmmss'
1..$NbFichiers | ForEach-Object {
    Set-Content -Path (Join-Path $demo "document_factice_${lot}_$_.txt") -Value "DEMO - INOFFENSIF : contenu factice $_" -Encoding UTF8
}
foreach ($f in Get-ChildItem $demo -File -Filter "document_factice_${lot}_*.txt") {
    if (Test-Path $stop) { Write-Output 'Kill switch STOP détecté : arrêt.'; exit 0 }
    Add-Content -Path $f.FullName -Value 'DEMO-INOFFENSIF'
    Rename-Item -Path $f.FullName -NewName ($f.Name + '.coreguard-demo')
}
Write-Output "[1/3] $NbFichiers fichiers factices « chiffrés » dans $demo"

# 2) Les leurres CoreGuard (liste blanche : noms exacts, racine des dossiers uniquement)
$dossiers = @($documents, [Environment]::GetFolderPath('DesktopDirectory'), [Environment]::GetFolderPath('MyPictures'))
$touches = 0
foreach ($dossier in $dossiers) {
    foreach ($nom in $canaris) {
        $chemin = Join-Path $dossier $nom
        if (-not (Test-Path -LiteralPath $chemin)) { continue }
        if (Test-Path $stop) { Write-Output 'Kill switch STOP détecté : arrêt.'; exit 0 }
        Write-Output "[2/3] Écriture dans le leurre $chemin ..."
        # Ouverture du fichier existant en écriture, comme un ransomware (fonctionne sur un fichier caché)
        $fs = [IO.File]::Open($chemin, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $octets = [Text.Encoding]::UTF8.GetBytes('DEMO-INOFFENSIF : contenu « chiffré » par le spécimen 02')
            $fs.SetLength(0); $fs.Write($octets, 0, $octets.Length)
        } finally { $fs.Dispose() }
        $touches++
        Start-Sleep -Milliseconds 1500   # laisse à CoreGuard le temps de réagir avant le leurre suivant
    }
}
Write-Output "[2/3] $touches leurre(s) modifié(s) sans arrêt."

# 3) Simulation « what-if » de la suppression des clichés VSS (jamais exécutée)
$cmdSimulee = 'vssadmin delete shadows /all /quiet'
Write-Output "[3/3] WHAT-IF (non exécuté) : $cmdSimulee"
& cmd.exe /c "echo DEMO-INOFFENSIF what-if: $cmdSimulee"
exit 0
