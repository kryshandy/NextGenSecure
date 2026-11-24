#requires -Version 5.1
<#
.SYNOPSIS
    Télécharge le modèle IA local (GGUF) de CoreGuard s'il est absent.
.DESCRIPTION
    Le modèle (~2 Go) n'est pas versionné dans git (limite GitHub 100 Mo).
    Ce script le télécharge dans models/ et vérifie sa taille.
#>
param(
    [string]$ModelDir = (Join-Path $PSScriptRoot '..\models'),
    [string]$FileName = 'Llama-3.2-3B-Instruct-Q4_K_M.gguf',
    [string]$Url = 'https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf',
    [long]$ExpectedBytes = 2019377696
)

$ErrorActionPreference = 'Stop'
$ModelDir = [System.IO.Path]::GetFullPath($ModelDir)
New-Item -ItemType Directory -Force -Path $ModelDir | Out-Null
$target = Join-Path $ModelDir $FileName

if (Test-Path $target) {
    $size = (Get-Item $target).Length
    if ($size -eq $ExpectedBytes) {
        Write-Host "[OK] Modele deja present et complet ($size octets)." -ForegroundColor Green
        return
    }
    Write-Host "[..] Fichier incomplet ($size octets), reprise du telechargement..." -ForegroundColor Yellow
}

Write-Host "[..] Telechargement du modele IA (~2 Go) depuis Hugging Face..." -ForegroundColor Cyan
# curl gere la reprise (-C -) et les redirections (-L)
curl.exe -L -C - --retry 3 -o "$target" "$Url"

$size = (Get-Item $target).Length
if ($size -ne $ExpectedBytes) {
    Write-Warning "Taille inattendue : $size octets (attendu $ExpectedBytes). Relance le script pour reprendre."
    exit 1
}
Write-Host "[OK] Modele telecharge et verifie ($size octets)." -ForegroundColor Green
