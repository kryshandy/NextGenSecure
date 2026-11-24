#requires -Version 5.1
<#
.SYNOPSIS
    Produit une version AUTONOME de CoreGuard embarquant TOUT.
.DESCRIPTION
    Publie l'UI WPF en self-contained win-x64 (le runtime .NET est inclus,
    aucune installation de .NET requise sur la machine cible), puis copie
    le modèle IA local à côté de l'exécutable. Résultat : un dossier unique
    `publish/CoreGuard` qui fonctionne tel quel, hors-ligne.
.NOTES
    Le dossier final pèse ~2,3 Go (runtime .NET + modèle GGUF ~2 Go).
#>
param(
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [string]$OutDir = (Join-Path $PSScriptRoot '..\publish\CoreGuard'),
    [switch]$SkipModel
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
Push-Location $root
try {
    Write-Host "=== CoreGuard — publication autonome ($Runtime) ===" -ForegroundColor Cyan

    # 1. S'assurer que le modèle est présent (sauf -SkipModel)
    if (-not $SkipModel) {
        & (Join-Path $PSScriptRoot 'download-model.ps1')
    }

    # 2. Publication self-contained de l'UI (embarque le runtime .NET)
    Write-Host "[..] Publication self-contained de l'interface..." -ForegroundColor Cyan
    & dotnet publish AntivirusIA.UI/AntivirusIA.UI.csproj `
        -c $Configuration -r $Runtime --self-contained true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -o "$OutDir"

    # 3. Embarquer le modèle IA à côté de l'exécutable
    if (-not $SkipModel) {
        $modelSrc = Join-Path $root 'models'
        $modelDst = Join-Path $OutDir 'models'
        New-Item -ItemType Directory -Force -Path $modelDst | Out-Null
        Write-Host "[..] Copie du modèle IA dans la distribution..." -ForegroundColor Cyan
        Copy-Item (Join-Path $modelSrc '*.gguf') $modelDst -Force
    }

    Write-Host ""
    Write-Host "=== Distribution autonome prête ===" -ForegroundColor Green
    Write-Host "    $OutDir" -ForegroundColor Green
    Write-Host "    Lance CoreGuard en double-cliquant AntivirusIA.UI.exe (aucun .NET requis)." -ForegroundColor Green
}
finally {
    Pop-Location
}
