#requires -Version 5.1
<#
.SYNOPSIS
    Installe CoreGuard de bout en bout : paquets, modele IA, compilation.
.DESCRIPTION
    A lancer apres un clone. Rend le depot auto-suffisant :
      1. Verifie le SDK .NET
      2. Restaure les paquets NuGet
      3. Telecharge le modele IA local (~2 Go) s'il manque
      4. Compile la solution
#>
param(
    [switch]$SkipModel  # pour installer sans telecharger le modele (dev rapide)
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location $root
try {
    Write-Host "=== CoreGuard — installation ===" -ForegroundColor Cyan

    # 1. SDK .NET
    $sdk = (& dotnet --version) 2>$null
    if (-not $sdk) { throw "Le SDK .NET est introuvable. Installe .NET SDK 10+ : https://dotnet.microsoft.com/download" }
    Write-Host "[OK] SDK .NET $sdk" -ForegroundColor Green

    # 2. Restauration NuGet
    Write-Host "[..] Restauration des paquets NuGet..." -ForegroundColor Cyan
    & dotnet restore AntivirusIA.slnx

    # 3. Modele IA
    if ($SkipModel) {
        Write-Host "[--] Telechargement du modele ignore (-SkipModel)." -ForegroundColor Yellow
    } else {
        & (Join-Path $PSScriptRoot 'download-model.ps1')
    }

    # 4. Compilation
    Write-Host "[..] Compilation de la solution..." -ForegroundColor Cyan
    & dotnet build AntivirusIA.slnx -c Debug

    Write-Host ""
    Write-Host "=== Termine. Lance l'application avec : ===" -ForegroundColor Green
    Write-Host "    dotnet run --project AntivirusIA.UI" -ForegroundColor Green
}
finally {
    Pop-Location
}
