<#
.SYNOPSIS
  Compile le fournisseur AMSI CoreGuard en DLL native (NativeAOT, win-x64).

.DESCRIPTION
  Prérequis : Visual Studio (ou Build Tools) avec la charge de travail « Développement Desktop en C++ »
  (linker MSVC) et le SDK Windows. Le dossier de vswhere.exe est ajouté au PATH, car la chaîne NativeAOT
  le cherche à cet endroit.
  Sortie : CoreGuard.AmsiProvider\bin\publish\CoreGuard.AmsiProvider.dll

      ./scripts/build-amsi-provider.ps1
#>
[CmdletBinding()]
param(
    [string]$Output
)
$ErrorActionPreference = 'Stop'
# $PSScriptRoot n'est pas fiable dans les valeurs par défaut des paramètres sous Windows PowerShell 5.1
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Output) { $Output = Join-Path $repoRoot 'CoreGuard.AmsiProvider\bin\publish' }

$installer = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
if (-not (Test-Path (Join-Path $installer 'vswhere.exe'))) {
    throw "vswhere.exe introuvable : installez Visual Studio ou les Build Tools avec les outils C++."
}
$env:PATH = "$installer;$env:PATH"

dotnet publish (Join-Path $repoRoot 'CoreGuard.AmsiProvider\CoreGuard.AmsiProvider.csproj') -c Release -r win-x64 -o $Output
if ($LASTEXITCODE -ne 0) { throw "Compilation NativeAOT du fournisseur AMSI échouée (code $LASTEXITCODE)." }

$dll = Join-Path $Output 'CoreGuard.AmsiProvider.dll'
if (-not (Test-Path $dll)) { throw "DLL introuvable : $dll" }
Write-Host "Fournisseur AMSI compilé : $dll"
