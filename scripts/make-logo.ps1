#requires -Version 5.1
<#
.SYNOPSIS
    Génère le logo CoreGuard (bouclier + coche) : .ico multi-tailles pour l'app
    WPF et PNG (16/32/48/128/256) pour l'extension navigateur et l'UI.
.NOTES
    Rendu vectoriel par GDI+ (System.Drawing), sans dépendance externe.
    Palette : indigo #4F46E5 -> cyan #06B6D4, coche blanche.
#>
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$root     = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$uiAssets = Join-Path $root 'AntivirusIA.UI\Assets'
$extIcons = Join-Path $root 'CoreGuard.Extension\extension\icons'
New-Item -ItemType Directory -Force -Path $uiAssets, $extIcons | Out-Null

function New-LogoBitmap([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode   = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    $k = $s / 256.0
    function P([double]$x, [double]$y) { New-Object System.Drawing.PointF([single]($x*$k), [single]($y*$k)) }

    # --- Bouclier (haut plat, base en pointe) ---
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddLine((P 48 54), (P 208 54))
    $path.AddLine((P 208 54), (P 208 126))
    $path.AddBezier((P 208 126), (P 206 180), (P 176 206), (P 128 216))
    $path.AddBezier((P 128 216), (P 80 206), (P 50 180), (P 48 126))
    $path.CloseFigure()

    $rect = New-Object System.Drawing.RectangleF(0, 0, [single]$s, [single]$s)
    $c1 = [System.Drawing.Color]::FromArgb(255, 79, 70, 229)   # indigo
    $c2 = [System.Drawing.Color]::FromArgb(255, 6, 182, 212)   # cyan
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $c1, $c2, [single]90)
    $g.FillPath($brush, $path)

    # Reflet léger sur la moitié haute
    $g.SetClip($path)
    $hl = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $rect,
        [System.Drawing.Color]::FromArgb(60, 255, 255, 255),
        [System.Drawing.Color]::FromArgb(0, 255, 255, 255), [single]90)
    $g.FillRectangle($hl, 0, 0, $s, [single]($s*0.5))
    $g.ResetClip()

    # --- Coche blanche (protection vérifiée) ---
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, [single](22*$k))
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $g.DrawLines($pen, @((P 94 130), (P 118 156), (P 170 98)))

    $pen.Dispose(); $brush.Dispose(); $hl.Dispose(); $path.Dispose(); $g.Dispose()
    return $bmp
}

function Save-Png([int]$s, [string]$dest) {
    $b = New-LogoBitmap $s
    $b.Save($dest, [System.Drawing.Imaging.ImageFormat]::Png)
    $b.Dispose()
    Write-Host "  PNG $s -> $dest"
}

# PNG pour l'UI et l'extension
Save-Png 256 (Join-Path $uiAssets 'coreguard-256.png')
foreach ($sz in 16, 32, 48, 128) { Save-Png $sz (Join-Path $extIcons ("icon$sz.png")) }

# --- Assemblage du .ico multi-tailles (PNG embarqué) ---
$sizes = 256, 48, 32, 16
$blobs = @{}
foreach ($sz in $sizes) {
    $b = New-LogoBitmap $sz
    $ms = New-Object System.IO.MemoryStream
    $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $blobs[$sz] = $ms.ToArray(); $ms.Dispose(); $b.Dispose()
}
$icoPath = Join-Path $uiAssets 'coreguard.ico'
$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
foreach ($sz in $sizes) {
    $dim = if ($sz -ge 256) { 0 } else { $sz }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$blobs[$sz].Length); $bw.Write([uint32]$offset)
    $offset += $blobs[$sz].Length
}
foreach ($sz in $sizes) { $bw.Write($blobs[$sz]) }
$bw.Flush(); $bw.Close(); $fs.Dispose()
Write-Host "  ICO -> $icoPath ($($sizes.Count) tailles)"

Write-Host "Logo CoreGuard généré." -ForegroundColor Green
