#requires -Version 5.1
<#
.SYNOPSIS
    Construit l'installateur complet et HORS LIGNE de CoreGuard : artifacts\CoreGuard-Setup\
.DESCRIPTION
    Produit un dossier autonome à copier sur n'importe quel PC Windows 10/11 x64 (aucun .NET, aucun téléchargement) :
      CoreGuard-Setup.exe         assistant d'installation (droits administrateur)
      payload\App                 application CoreGuard (runtime .NET inclus) + modèle IA local (GGUF) + modèle EMBER/ONNX
      payload\Service             service de protection SYSTEM
      payload\Amsi                fournisseur AMSI natif (NativeAOT)
      payload\BrowserHost         hôte Native Messaging de l'extension (avec sa base anti-phishing)
      payload\Extension           extension navigateur (Manifest V3)
      payload\Docs                guide d'utilisation, guide de test, documentation
      payload\Demo                spécimens de démonstration INOFFENSIFS (scripts et programmes compilés)
    Prérequis pour CONSTRUIRE (pas pour installer) : SDK .NET 10, outils C++ de Visual Studio (fournisseur AMSI),
    modèle models\Llama-3.2-3B-Instruct-Q4_K_M.gguf présent dans le dépôt.
.EXAMPLE
    ./scripts/build-setup.ps1
#>
param(
    [string]$OutDir = (Join-Path $PSScriptRoot '..\artifacts\CoreGuard-Setup'),
    [switch]$SansAmsi
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$OutDir = [IO.Path]::GetFullPath($OutDir)
$payload = Join-Path $OutDir 'payload'
$rid = 'win-x64'

function Publier([string]$projet, [string]$destination, [string[]]$extra = @()) {
    Write-Host "  publication de $projet..." -ForegroundColor DarkGray
    & dotnet publish (Join-Path $root $projet) -c Release -r $rid --self-contained true -o $destination -v quiet --nologo @extra
    if ($LASTEXITCODE -ne 0) { throw "Publication de $projet échouée (code $LASTEXITCODE)." }
}

Write-Host "=== CoreGuard — construction de l'installateur hors ligne ===" -ForegroundColor Cyan
if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force $payload | Out-Null

Write-Host "[1/8] Application (runtime .NET inclus)" -ForegroundColor Cyan
Publier 'AntivirusIA.UI\AntivirusIA.UI.csproj' (Join-Path $payload 'App')

Write-Host "[2/8] Modèle d'IA local (~2 Go)" -ForegroundColor Cyan
$modele = Join-Path $root 'models\Llama-3.2-3B-Instruct-Q4_K_M.gguf'
if (-not (Test-Path $modele)) { throw "Modèle absent : $modele (scripts/download-model.ps1 une fois, puis relancer)." }
New-Item -ItemType Directory -Force (Join-Path $payload 'App\models') | Out-Null
Copy-Item $modele (Join-Path $payload 'App\models\')
if (-not (Test-Path (Join-Path $payload 'App\Models\ember-subset.onnx'))) { throw "Modèle EMBER/ONNX absent de la publication." }

Write-Host "[3/8] Service de protection" -ForegroundColor Cyan
Publier 'CoreGuard.Service\CoreGuard.Service.csproj' (Join-Path $payload 'Service')

Write-Host "[4/8] Fournisseur AMSI natif" -ForegroundColor Cyan
if ($SansAmsi) {
    Write-Warning "Fournisseur AMSI ignoré (-SansAmsi)."
} else {
    & (Join-Path $root 'scripts\build-amsi-provider.ps1')
    New-Item -ItemType Directory -Force (Join-Path $payload 'Amsi') | Out-Null
    Copy-Item (Join-Path $root 'CoreGuard.AmsiProvider\bin\publish\CoreGuard.AmsiProvider.dll') (Join-Path $payload 'Amsi\')
}

Write-Host "[5/8] Hôte et extension navigateur" -ForegroundColor Cyan
Publier 'CoreGuard.Extension\CoreGuard.Extension.csproj' (Join-Path $payload 'BrowserHost')
Copy-Item -Recurse (Join-Path $root 'CoreGuard.Extension\extension') (Join-Path $payload 'Extension')

Write-Host "[6/8] Documentation" -ForegroundColor Cyan
New-Item -ItemType Directory -Force (Join-Path $payload 'Docs') | Out-Null
foreach ($doc in 'docs\GUIDE.md', 'docs\TESTING.md', 'docs\IA-ENTRAINEMENT.md', 'docs\CoreGuard-Phase1-Explication.html', 'README.md') {
    if (Test-Path (Join-Path $root $doc)) { Copy-Item (Join-Path $root $doc) (Join-Path $payload 'Docs\') }
}

Write-Host "[7/8] Spécimens de démonstration inoffensifs" -ForegroundColor Cyan
$demo = Join-Path $payload 'Demo'
robocopy (Join-Path $root 'demo') $demo /E /XD bin obj eval /NFL /NDL /NJH /NJS /NP | Out-Null
foreach ($p in @(
        @{ Projet = 'demo\02-ransomware-canari\RansomwareSim\RansomwareSim.csproj'; Dossier = '02-ransomware-canari\RansomwareSim' },
        @{ Projet = 'demo\04-badusb-hid\BadUsbSim.csproj'; Dossier = '04-badusb-hid' },
        @{ Projet = 'demo\05-crypto-clipper\ClipperSim.csproj'; Dossier = '05-crypto-clipper' },
        @{ Projet = 'demo\09-injection-memoire\MemoryInjectionSim.csproj'; Dossier = '09-injection-memoire' })) {
    Publier $p.Projet (Join-Path $demo $p.Dossier) @('-p:PublishSingleFile=true', '-p:IncludeNativeLibrariesForSelfExtract=true')
}

Write-Host "[8/8] Assistant d'installation" -ForegroundColor Cyan
Publier 'CoreGuard.Setup\CoreGuard.Setup.csproj' $OutDir @('-p:PublishSingleFile=true', '-p:IncludeNativeLibrariesForSelfExtract=true')
Get-ChildItem $OutDir -Filter '*.pdb' | Remove-Item

$taille = (Get-ChildItem $OutDir -Recurse -File | Measure-Object Length -Sum).Sum / 1GB
Write-Host ""
Write-Host ("Installateur prêt : {0} ({1:N1} Go)" -f $OutDir, $taille) -ForegroundColor Green
Write-Host "Copiez le dossier entier sur le PC cible, puis lancez CoreGuard-Setup.exe (droits administrateur)."
