# =====================================================================
# DÉMO — INOFFENSIF : spécimen 10 (anti-phishing : base de confiance, OCR, IA)
# Sert les pages de laboratoire (pages\) sur le port 8088 de CETTE machine
# uniquement (127.0.0.1). Les adresses *.localhost pointent toujours vers la
# machine locale : http://paypa1-verification.localhost:8088/paypal.html
# Les formulaires n'envoient rien. Aucune donnée ne sort du PC.
# Ajoute aussi une entrée de TEST à la liste noire personnelle de CoreGuard
# (liste-noire-demo.localhost), retirée à l'arrêt.
# Arrêt : Ctrl+C, ou ouvrir http://localhost:8088/stop
# Nettoyage seul : .\serve-phishing-lab.ps1 -Nettoyer
# =====================================================================
param([switch]$Nettoyer, [int]$Port = 8088)
$ErrorActionPreference = 'Stop'

$ici = Split-Path -Parent $MyInvocation.MyCommand.Path
$pages = Join-Path $ici 'pages'
$listeNoire = Join-Path $env:LOCALAPPDATA 'CoreGuard\phishing\blocklist-local.txt'
$entreeDemo = "http://liste-noire-demo.localhost:$Port/"

function Retirer-EntreeDemo {
    if (Test-Path $listeNoire) {
        $reste = @(Get-Content $listeNoire | Where-Object { $_ -notlike '*liste-noire-demo.localhost*' -and $_ -notlike '# CoreGuard demo 10*' })
        if ($reste.Count -eq 0) { Remove-Item $listeNoire -Force } else { Set-Content -Path $listeNoire -Value $reste -Encoding UTF8 }
    }
}

if ($Nettoyer) {
    Retirer-EntreeDemo
    Write-Output 'Nettoyage termine : entree de test retiree de la liste noire personnelle.'
    return
}

# Entrée de test dans la liste noire personnelle (lue par l'hôte du navigateur à chaque vérification)
New-Item -ItemType Directory -Force -Path (Split-Path $listeNoire) | Out-Null
Retirer-EntreeDemo
Add-Content -Path $listeNoire -Value @('# CoreGuard demo 10 (retiree a l''arret du serveur)', $entreeDemo) -Encoding UTF8

$liste = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), $Port
$liste.Start()
Write-Output "Laboratoire anti-phishing sur le port $Port (machine locale uniquement). Pages :"
Get-ChildItem $pages -Filter *.html | ForEach-Object { Write-Output "  http://<nom-au-choix>.localhost:$Port/$($_.Name)" }
Write-Output "Exemples : http://paypa1-verification.localhost:$Port/paypal.html  (marque + domaine tiers)"
Write-Output "           http://ameli-remboursement.localhost:$Port/ameli.html   (typosquatting)"
Write-Output "           http://suivi-colis-livraison.localhost:$Port/colis.html (zone grise : IA locale)"
Write-Output "           http://club-tennis-lilas.localhost:$Port/club.html      (site inconnu legitime)"
Write-Output "           $entreeDemo                     (liste noire)"
Write-Output "Arret : Ctrl+C ou http://localhost:$Port/stop"

try {
    while ($true) {
        $client = $liste.AcceptTcpClient()
        try {
            $flux = $client.GetStream()
            $lecteur = New-Object System.IO.StreamReader($flux)
            $ligne = $lecteur.ReadLine()
            while (($l = $lecteur.ReadLine()) -ne $null -and $l -ne '') { }   # en-têtes ignorés
            $chemin = if ($ligne -match '^GET (\S+) ') { [Uri]::UnescapeDataString(($Matches[1] -split '\?')[0]) } else { '/' }

            if ($chemin -eq '/stop') {
                $corps = [Text.Encoding]::UTF8.GetBytes('Serveur arrete.')
                $type = 'text/plain; charset=utf-8'; $statut = '200 OK'; $arreter = $true
            } else {
                $nom = [IO.Path]::GetFileName($chemin.TrimStart('/'))       # aucun accès hors du dossier pages\
                if ([string]::IsNullOrEmpty($nom)) { $nom = 'club.html' }
                $fichier = Join-Path $pages $nom
                if (Test-Path $fichier -PathType Leaf) {
                    $corps = [IO.File]::ReadAllBytes($fichier); $type = 'text/html; charset=utf-8'; $statut = '200 OK'
                } else {
                    $corps = [Text.Encoding]::UTF8.GetBytes('Page de laboratoire introuvable.'); $type = 'text/plain; charset=utf-8'; $statut = '404 Not Found'
                }
                $arreter = $false
            }
            $entete = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $statut`r`nContent-Type: $type`r`nContent-Length: $($corps.Length)`r`nConnection: close`r`nCache-Control: no-store`r`n`r`n")
            $flux.Write($entete, 0, $entete.Length)
            $flux.Write($corps, 0, $corps.Length)
            $flux.Flush()
        } catch {
            # client parti : on continue
        } finally {
            $client.Close()
        }
        if ($arreter) { break }
    }
} finally {
    $liste.Stop()
    Retirer-EntreeDemo
    Write-Output 'Serveur arrete, entree de test retiree de la liste noire personnelle.'
}
