<#
.SYNOPSIS
  Arrête et supprime le service Windows CoreGuard, puis efface ses fichiers.
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
        Stop-Service -Name $serviceName -Force
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
