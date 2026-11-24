# =====================================================================
# DÉMO — INOFFENSIF : spécimen 07 (accès aux identifiants navigateur)
# Crée un FAUX profil de navigateur sous %TEMP% avec un faux fichier
# "Login Data" (texte factice), puis l'OUVRE et le LIT, comme le ferait
# un infostealer. Jamais le vrai profil Chrome/Edge. Aucun réseau.
# Si la règle anti-infostealer surveille les accès par nom de fichier
# ("Login Data"), l'ouverture ci-dessous doit la déclencher.
# Nettoyage : .\demo-infostealer.ps1 -Nettoyer
# =====================================================================
param([switch]$Nettoyer)
$ErrorActionPreference = 'Stop'

$racine = Join-Path $env:TEMP 'CoreGuardDemo'
$profil = Join-Path $racine 'faux-profil-chrome\Default'

if ($Nettoyer) {
    if (Test-Path $racine) { Remove-Item $racine -Recurse -Force }
    Write-Output "Nettoyage termine : $racine supprime."
    return
}

New-Item -ItemType Directory -Force -Path $profil | Out-Null
$faux = Join-Path $profil 'Login Data'
Set-Content -Path $faux -Encoding UTF8 -Value 'DEMO-INOFFENSIF : faux fichier Login Data, aucun identifiant reel.'

# Ouverture en lecture avec partage, comme un voleur copiant la base
$fs = [IO.File]::Open($faux, 'Open', 'Read', 'ReadWrite')
try {
    $lecteur = New-Object IO.StreamReader($fs)
    $contenu = $lecteur.ReadToEnd()
    Write-Output "Lu $($contenu.Length) caracteres depuis le FAUX fichier : $faux"
} finally { $fs.Dispose() }

# Copie vers un autre emplacement de TEST (motif « copie de la base »)
Copy-Item $faux (Join-Path $racine 'copie_login_data.tmp') -Force
Write-Output 'Termine. Nettoyage : .\demo-infostealer.ps1 -Nettoyer'
