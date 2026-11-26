<#
.SYNOPSIS
  Installe l'hôte Native Messaging de l'extension CoreGuard pour Chrome, Edge, Brave et Chromium (utilisateur courant).

.DESCRIPTION
  - publie l'hôte (CoreGuard.Extension.exe : anti-phishing OCR/QR, accès au coffre) dans
    %LOCALAPPDATA%\CoreGuard\BrowserHost ;
  - écrit son manifeste « com.coreguard.host.json » : chemin absolu de l'exe et UNE seule extension autorisée,
    celle de CoreGuard (ID fixe dkmnbfljkgocbdiileppcmlcphbjbimi, dérivé de la clé publique du manifeste) ;
  - déclare l'hôte auprès de chaque navigateur (clés HKCU\...\NativeMessagingHosts, sans droits administrateur).
  Il reste ensuite à charger l'extension : chrome://extensions (ou edge://extensions, brave://extensions) >
  « Mode développeur » > « Charger l'extension non empaquetée » > dossier CoreGuard.Extension\extension.

      ./scripts/install-browser-extension.ps1
      ./scripts/install-browser-extension.ps1 -Uninstall
#>
[CmdletBinding()]
param([switch]$Uninstall)
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$hostName = 'com.coreguard.host'
$extensionId = 'dkmnbfljkgocbdiileppcmlcphbjbimi'
$installDir = Join-Path $env:LOCALAPPDATA 'CoreGuard\BrowserHost'
$registryRoots = @(
    'HKCU:\Software\Google\Chrome\NativeMessagingHosts',
    'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts',
    'HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts',
    'HKCU:\Software\Chromium\NativeMessagingHosts'
)

if ($Uninstall) {
    foreach ($root in $registryRoots) { Remove-Item -Path (Join-Path $root $hostName) -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $installDir) { Remove-Item -Recurse -Force $installDir -ErrorAction SilentlyContinue }
    Write-Host "Hôte de l'extension CoreGuard désinstallé (pensez à retirer l'extension dans le navigateur)."
    return
}

Write-Host "Publication de l'hôte vers $installDir ..."
dotnet publish (Join-Path $repoRoot 'CoreGuard.Extension\CoreGuard.Extension.csproj') -c Release -o $installDir
if ($LASTEXITCODE -ne 0) { throw "La publication de l'hôte a échoué (code $LASTEXITCODE)." }
$exe = Join-Path $installDir 'CoreGuard.Extension.exe'
if (-not (Test-Path $exe)) { throw "Exécutable introuvable : $exe" }

$manifestPath = Join-Path $installDir "$hostName.json"
$manifest = [ordered]@{
    name            = $hostName
    description     = 'Hôte Native Messaging CoreGuard (anti-phishing, coffre-fort)'
    path            = $exe
    type            = 'stdio'
    allowed_origins = @("chrome-extension://$extensionId/")
}
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))

foreach ($root in $registryRoots) {
    $key = Join-Path $root $hostName
    New-Item -Path $key -Force | Out-Null
    Set-Item -Path $key -Value $manifestPath
}

Write-Host ""
Write-Host "Hôte installé et déclaré pour Chrome, Edge, Brave et Chromium."
Write-Host "Chargez maintenant l'extension (une seule fois) :"
Write-Host "  1. ouvrez chrome://extensions (edge://extensions, brave://extensions)"
Write-Host "  2. activez le « Mode développeur »"
Write-Host "  3. « Charger l'extension non empaquetée » > $(Join-Path $repoRoot 'CoreGuard.Extension\extension')"
Write-Host "  L'ID affiché doit être $extensionId."
Write-Host "Pour l'auto-remplissage : ouvrez CoreGuard > Coffre-fort, créez/déverrouillez le coffre et ajoutez vos identifiants."
