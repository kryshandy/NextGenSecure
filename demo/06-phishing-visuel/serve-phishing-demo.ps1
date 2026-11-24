# =====================================================================
# DÉMO — INOFFENSIF : spécimen 06 (phishing visuel pour OCR)
# Sert sur http://localhost:8080/ une page locale avec un faux
# « Sign in to Microsoft » rendu EN IMAGE (le texte n'est pas dans le
# HTML, seul l'OCR peut le lire). Le formulaire n'existe pas : aucune
# donnée n'est collectée ni transmise. Écoute localhost uniquement.
# Arrêt : Ctrl+C, ou ouvrir http://localhost:8080/stop
# =====================================================================
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

# Génère l'image de la fausse page de connexion (PNG en mémoire)
$bmp = New-Object System.Drawing.Bitmap 520, 360
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'
$g.TextRenderingHint = 'AntiAliasGridFit'
$g.Clear([System.Drawing.Color]::White)
$g.DrawRectangle([System.Drawing.Pens]::LightGray, 0, 0, 519, 359)

function Nouvelle-Police([float]$taille, [string]$style) {
    New-Object System.Drawing.Font('Segoe UI', $taille, [System.Drawing.FontStyle]$style)
}
$noir = [System.Drawing.Brushes]::Black
$gris = [System.Drawing.Brushes]::DimGray
$bleu = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(0, 103, 184))

$g.FillRectangle([System.Drawing.Brushes]::OrangeRed, 40, 36, 14, 14)
$g.FillRectangle([System.Drawing.Brushes]::LimeGreen, 56, 36, 14, 14)
$g.FillRectangle([System.Drawing.Brushes]::DodgerBlue, 40, 52, 14, 14)
$g.FillRectangle([System.Drawing.Brushes]::Gold, 56, 52, 14, 14)
$g.DrawString('Microsoft', (Nouvelle-Police 16 'Regular'), $gris, 78, 38)
$g.DrawString('Sign in', (Nouvelle-Police 24 'Bold'), $noir, 40, 90)
$g.DrawString('Email, phone, or Skype', (Nouvelle-Police 12 'Regular'), $gris, 40, 150)
$g.DrawLine([System.Drawing.Pens]::Gray, 40, 178, 480, 178)
$g.DrawString('Password', (Nouvelle-Police 12 'Regular'), $gris, 40, 200)
$g.DrawLine([System.Drawing.Pens]::Gray, 40, 228, 480, 228)
$g.DrawString('Forgot your password?', (Nouvelle-Police 10 'Regular'), $bleu, 40, 245)
$g.FillRectangle($bleu, 380, 290, 100, 36)
$g.DrawString('Sign in', (Nouvelle-Police 12 'Regular'), [System.Drawing.Brushes]::White, 407, 297)
$g.Dispose()
$ms = New-Object IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$png = $ms.ToArray()
$bmp.Dispose(); $ms.Dispose()

$html = @'
<!doctype html><html><head><meta charset="utf-8"><title>Sign in to your account</title></head>
<body style="font-family:sans-serif;background:#f2f2f2;text-align:center;padding-top:40px">
<!-- DEMO - INOFFENSIF : page locale, aucun formulaire, rien n'est envoye -->
<img src="/login.png" alt="" width="520" height="360"><br>
<small style="color:#777">Page de demonstration CoreGuard (localhost) - aucune donnee collectee.</small>
</body></html>
'@
$htmlOctets = [Text.Encoding]::UTF8.GetBytes($html)

$ecouteur = New-Object System.Net.HttpListener
$ecouteur.Prefixes.Add('http://localhost:8080/')   # localhost uniquement
$ecouteur.Start()
Write-Output 'Specimen 06 sur http://localhost:8080/  (Ctrl+C ou /stop pour arreter)'
try {
    while ($ecouteur.IsListening) {
        $ctx = $ecouteur.GetContext()
        $chemin = $ctx.Request.Url.AbsolutePath
        $arreter = $false
        if ($chemin -eq '/login.png') { $ctx.Response.ContentType = 'image/png'; $oct = $png }
        elseif ($chemin -eq '/stop')  { $oct = [Text.Encoding]::UTF8.GetBytes('Arret.'); $arreter = $true }
        else { $ctx.Response.ContentType = 'text/html; charset=utf-8'; $oct = $htmlOctets }
        $ctx.Response.OutputStream.Write($oct, 0, $oct.Length)
        $ctx.Response.Close()
        if ($arreter) { $ecouteur.Stop() }
    }
} finally {
    if ($ecouteur.IsListening) { $ecouteur.Stop() }
    Write-Output 'Serveur arrete.'
}
