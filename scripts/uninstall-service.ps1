<#
.SYNOPSIS
  Arrête (mot de passe de protection requis) et supprime le service Windows CoreGuard, puis efface ses fichiers.
  Le secret %ProgramData%\CoreGuard\protection.json est conservé ; supprimez-le à la main si besoin.
  La stratégie d'audit « Système de fichiers » activée à l'installation est laissée telle quelle ; pour la désactiver :
      auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:disable
  À lancer depuis une console PowerShell **administrateur** : ./scripts/uninstall-service.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'CoreGuard\Service')
)

$ErrorActionPreference = 'Stop'
$serviceName = 'CoreGuardService'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Droits administrateur requis : relancez PowerShell en tant qu'administrateur."
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        # Versions antérieures à l'auto-défense : arrêt classique ; sinon arrêt authentifié par mot de passe
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        if ((Get-Service -Name $serviceName).Status -ne 'Stopped') {
            & (Join-Path $InstallDir 'CoreGuard.Service.exe') --stop
            if ($LASTEXITCODE -ne 0) { throw "Arrêt refusé : désinstallation annulée." }
        }
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    sc.exe delete $serviceName | Out-Null
    Write-Host "Service $serviceName supprimé."
} else {
    Write-Host "Service $serviceName absent."
}

if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
    Write-Host "Fichiers supprimés : $InstallDir"
}
