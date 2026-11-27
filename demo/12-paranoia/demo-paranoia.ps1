# =====================================================================
# DÉMO — INOFFENSIF : spécimen 12 (Mode Paranoïa)
# Compile un petit programme NON signé qui ne fait qu'attendre 60 s, le
# dépose dans Téléchargements et le lance, comme le ferait un malware
# téléchargé. Avec le Mode Paranoïa activé dans CoreGuard, il doit être
# arrêté en moins d'une seconde (alerte « Exécution bloquée »).
# Avec le service CoreGuard à jour (droits SYSTEM) : USB bloqué et pare-feu
# WFP durci en plus (voir README).
# Nettoyage : .\demo-paranoia.ps1 -Nettoyer
# =====================================================================
param([switch]$Nettoyer)
$ErrorActionPreference = 'Stop'

$exe = Join-Path (Join-Path $env:USERPROFILE 'Downloads') 'CoreGuardDemo-paranoia.exe'
if ($Nettoyer) {
    Get-Process -Name 'CoreGuardDemo-paranoia' -ErrorAction SilentlyContinue | Stop-Process -Force
    Remove-Item $exe -Force -ErrorAction SilentlyContinue
    Write-Output 'Nettoyage termine.'
    return
}

if (-not (Test-Path $exe)) {
    $source = 'public static class Demo { public static void Main() { System.Console.WriteLine("DEMO INOFFENSIF CoreGuard : attente 60 s"); System.Threading.Thread.Sleep(60000); } }'
    Add-Type -TypeDefinition $source -OutputAssembly $exe -OutputType ConsoleApplication
}

$p = Start-Process -FilePath $exe -WindowStyle Hidden -PassThru
Write-Output "Programme non signe lance depuis Telechargements (PID $($p.Id))..."
Start-Sleep -Seconds 3
if ($p.HasExited) {
    Write-Output "RESULTAT : arrete par CoreGuard (Mode Paranoia) en moins de 3 s."
} else {
    Write-Output "RESULTAT : toujours actif (Mode Paranoia desactive ?). Arret du programme de demo."
    Stop-Process -Id $p.Id -Force
}
