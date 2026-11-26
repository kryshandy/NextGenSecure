# =====================================================================
# DÉMO — INOFFENSIF : spécimen 07 (vol d'identifiants navigateur)
#
# Imite un « infostealer » : il cherche les bases de mots de passe des navigateurs et lit celle de Chromium.
# Il ne lit QUE le profil LEURRE déposé par CoreGuard dans %LOCALAPPDATA%\Chromium\User Data : avant toute
# lecture, il vérifie la présence du marqueur « CoreGuard-HONEYPOT ». Il ne touche jamais aux vrais profils
# Chrome, Edge, Brave ou Firefox, n'envoie rien, n'écrit rien en dehors de son dossier de test.
#
# Attendu avec le service CoreGuard installé (audit NTFS actif) : dès la lecture du faux « Login Data »,
# CoreGuard identifie ce processus PowerShell et l'ARRÊTE (alerte « Vol d'identifiants bloqué »).
# Il se relance lui-même dans un processus séparé, pour que l'arrêt ne ferme pas ta console.
#
# Nettoyage : .\demo-infostealer.ps1 -Nettoyer
# =====================================================================
param([switch]$Nettoyer, [switch]$Enfant)
$ErrorActionPreference = 'Stop'

$leurre = Join-Path $env:LOCALAPPDATA 'Chromium\User Data'
$etat = Join-Path $leurre 'Local State'
$base = Join-Path $leurre 'Default\Login Data'
$test = Join-Path $env:TEMP 'CoreGuardDemo\infostealer'

if ($Nettoyer) {
    if (Test-Path $test) { Remove-Item $test -Recurse -Force }
    Write-Output "Nettoyage terminé : $test supprimé (le profil leurre est géré par CoreGuard)."
    return
}

if (-not $Enfant) {
    if (-not (Test-Path -LiteralPath $etat) -or -not ((Get-Content -LiteralPath $etat -Raw) -match 'CoreGuard-HONEYPOT')) {
        Write-Output "Profil leurre CoreGuard introuvable : installez/démarrez le service CoreGuard (scripts/install-service.ps1)."
        Write-Output "Par sécurité, ce spécimen ne lit jamais un profil de navigateur qui n'est pas le leurre."
        return
    }
    Write-Output "Lancement du spécimen dans un processus séparé..."
    $p = Start-Process -FilePath 'powershell.exe' -PassThru -Wait -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Enfant')
    if ($p.ExitCode -eq -1059192831) {
        Write-Output "RÉSULTAT : le spécimen (PID $($p.Id)) a été ARRÊTÉ par CoreGuard en lisant le faux « Login Data ». Anti-infostealer opérationnel."
    } elseif ($p.ExitCode -eq 0) {
        Write-Output "RÉSULTAT : lecture effectuée sans arrêt. Vérifiez que le service CoreGuard est installé et que l'audit est actif."
    } else {
        Write-Output "RÉSULTAT : le spécimen s'est terminé avec le code $($p.ExitCode)."
    }
    return
}

# ---------- Processus enfant : le « voleur » ----------
# Garde-fou : uniquement le leurre CoreGuard
if (-not ((Get-Content -LiteralPath $etat -Raw) -match 'CoreGuard-HONEYPOT')) { exit 3 }

# 1) Comme un vrai voleur : passe en revue les chemins de navigateurs connus (existence seulement, aucune lecture)
foreach ($chemin in @('Google\Chrome\User Data', 'Microsoft\Edge\User Data', 'BraveSoftware\Brave-Browser\User Data', 'Chromium\User Data')) {
    Write-Output ("[1/2] {0} : {1}" -f $chemin, $(if (Test-Path (Join-Path $env:LOCALAPPDATA $chemin)) { 'présent' } else { 'absent' }))
}

# 2) Lit la clé (Local State) puis la base de mots de passe du LEURRE, comme on copie la base pour la déchiffrer ailleurs
New-Item -ItemType Directory -Force -Path $test | Out-Null
$cle = [IO.File]::ReadAllText($etat)
$fs = [IO.File]::Open($base, 'Open', 'Read', 'ReadWrite')
try {
    $octets = New-Object byte[] $fs.Length
    [void]$fs.Read($octets, 0, $octets.Length)
} finally { $fs.Dispose() }
[IO.File]::WriteAllBytes((Join-Path $test 'copie_login_data.tmp'), $octets)
Write-Output "[2/2] Faux « Login Data » lu ($($octets.Length) octets) sans être arrêté."
exit 0
