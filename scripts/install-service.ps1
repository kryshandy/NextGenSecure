<#
.SYNOPSIS
  Installe (ou met à jour) le service Windows CoreGuard (compte LocalSystem, démarrage automatique).

.DESCRIPTION
  - publie CoreGuard.Service en Release dans "%ProgramFiles%\CoreGuard\Service"
    (dossier modifiable uniquement par les administrateurs : un programme utilisateur ne peut pas remplacer le binaire) ;
  - crée le service "CoreGuardService" (LocalSystem, démarrage automatique, redémarrage en cas d'arrêt anormal) ;
  - demande le mot de passe de protection à la première installation (exigé ensuite pour tout arrêt) ;
  - le démarre.
  À lancer depuis une console PowerShell **administrateur**, à la racine du dépôt :
      ./scripts/install-service.ps1
  Désinstallation : ./scripts/uninstall-service.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'CoreGuard\Service')
)

$ErrorActionPreference = 'Stop'
$serviceName = 'CoreGuardService'
$displayName = 'CoreGuard - Protection'
$repoRoot = Split-Path -Parent $PSScriptRoot

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Droits administrateur requis : relancez PowerShell en tant qu'administrateur."
}

# Un service existant doit être arrêté avant de remplacer ses fichiers. Il refuse « Stop-Service » :
# l'arrêt passe par le mot de passe de protection.
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host "Arrêt du service existant..."
    # Versions antérieures à l'auto-défense : arrêt classique accepté
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    if ((Get-Service -Name $serviceName).Status -ne 'Stopped') {
        Write-Host "Le service refuse l'arrêt classique : mot de passe de protection requis."
        & (Join-Path $InstallDir 'CoreGuard.Service.exe') --stop
        if ($LASTEXITCODE -ne 0) { throw "Arrêt refusé : mise à jour annulée." }
    }
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

Write-Host "Publication de CoreGuard.Service vers $InstallDir ..."
dotnet publish (Join-Path $repoRoot 'CoreGuard.Service\CoreGuard.Service.csproj') -c Release -r win-x64 --self-contained true -o $InstallDir
if ($LASTEXITCODE -ne 0) { throw "La publication a échoué (code $LASTEXITCODE)." }

$exe = Join-Path $InstallDir 'CoreGuard.Service.exe'
if (-not (Test-Path $exe)) { throw "Exécutable introuvable : $exe" }

if (-not $existing) {
    Write-Host "Création du service $serviceName ..."
    New-Service -Name $serviceName -BinaryPathName "`"$exe`"" -DisplayName $displayName `
        -Description 'CoreGuard : télémétrie comportementale (ETW) et réponse aux menaces.' -StartupType Automatic | Out-Null
}

# Mot de passe de protection : exigé pour tout arrêt du service (défi-réponse HMAC). Demandé à la première
# installation ; conservé lors d'une mise à jour. Réinitialisation : & "$exe" --set-password (administrateur).
$secret = Join-Path $env:ProgramData 'CoreGuard\protection.json'
if (-not (Test-Path $secret)) {
    Write-Host "Définissez le mot de passe de protection (il sera demandé pour désactiver CoreGuard) :"
    & $exe --set-password
    if ($LASTEXITCODE -ne 0) { throw "Mot de passe de protection non défini (code $LASTEXITCODE)." }
}

# Redémarrage automatique après un arrêt anormal : 5 s, 5 s, puis 30 s ; compteur remis à zéro après 1 jour
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
sc.exe failureflag $serviceName 1 | Out-Null

Write-Host "Démarrage du service..."
Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Write-Host "CoreGuard est installé et démarré (auto-défense : processus durci + watchdog)."
Write-Host "Relancez l'interface : le module « Comportement » doit indiquer « Assurée par le service »."
Write-Host "Pour l'arrêter : Réglages > Service et auto-défense > Désactiver, ou & `"$exe`" --stop"
