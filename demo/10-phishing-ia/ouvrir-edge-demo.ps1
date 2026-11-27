# =====================================================================
# Ouvre Microsoft Edge dans un PROFIL TEMPORAIRE neuf, avec l'extension
# CoreGuard chargée et la synchronisation de compte coupée : votre profil
# Edge habituel n'est pas touché. Prérequis : ./scripts/install-browser-extension.ps1
# Usage : .\ouvrir-edge-demo.ps1 [-Url http://paypa1-verification.localhost:8088/paypal.html]
# Fermeture et suppression du profil : .\ouvrir-edge-demo.ps1 -Fermer
# =====================================================================
param([string]$Url = 'http://club-tennis-lilas.localhost:8088/club.html', [switch]$Fermer)
$ErrorActionPreference = 'Stop'
$ici = Split-Path -Parent $MyInvocation.MyCommand.Path
$profil = Join-Path $env:TEMP 'CoreGuard-edge-demo'
$extension = (Resolve-Path (Join-Path $ici '..\..\CoreGuard.Extension\extension')).Path
$edge = @('C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe', 'C:\Program Files\Microsoft\Edge\Application\msedge.exe') |
    Where-Object { Test-Path $_ } | Select-Object -First 1

# Ferme uniquement l'Edge de démonstration (profil temporaire), jamais votre Edge habituel
Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object { $_.CommandLine -like '*CoreGuard-edge-demo*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
if (Test-Path $profil) { Remove-Item -Recurse -Force $profil }
if ($Fermer) { Write-Output 'Edge de demonstration ferme, profil temporaire supprime.'; return }
if (-not $edge) { throw 'Microsoft Edge introuvable.' }

New-Item -ItemType Directory -Force $profil | Out-Null
# Profil neuf à chaque lancement : Edge désactive au redémarrage une extension chargée en ligne de commande
Start-Process $edge -ArgumentList @(
    "--user-data-dir=`"$profil`"", '--no-first-run', '--no-default-browser-check', '--disable-sync',
    '--disable-features=DisableLoadExtensionCommandLineSwitch,msImplicitSignin,msEdgeSyncConsent',
    "--load-extension=`"$extension`"", $Url)
Write-Output "Edge de demonstration ouvert (extension CoreGuard chargee). Avertissement « mode developpeur » : « Pas maintenant »."
Write-Output 'Analyse a la demande de la page affichee : Ctrl+Maj+Y.'
