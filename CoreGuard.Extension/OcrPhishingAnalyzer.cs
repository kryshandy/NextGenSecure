using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Graphics.Imaging;
using Windows.Media.Ocr;
using Windows.Storage.Streams;

namespace CoreGuard.Extension;

/// <summary>Résultat complet de l'analyse d'une capture d'écran.</summary>
public sealed record CaptureAnalysis(
    PhishingVerdict Verdict,
    IReadOnlyList<string> Reasons,
    string ExtractedText,
    string? QrUrl);

/// <summary>
/// Analyse anti-phishing d'une capture : OCR (Windows.Media.Ocr) + QR (ZXing)
/// puis corrélation via <see cref="PhishingLogic"/>. L'image est une donnée NON FIABLE.
/// </summary>
public sealed class OcrPhishingAnalyzer
{
    /// <summary>Plafond de texte conservé (évite de renvoyer/stocker un volume arbitraire).</summary>
    private const int MaxTextLength = 20_000;

    /// <summary>Analyse une image PNG/JPEG associée à l'URL de la page.</summary>
    public async Task<CaptureAnalysis> AnalyzeAsync(byte[] imageBytes, string? pageUrl, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(imageBytes);

        using var bitmap = await DecodeAsync(imageBytes).ConfigureAwait(false);

        var texte = await ExtractTextAsync(bitmap).ConfigureAwait(false);
        var evaluation = PhishingLogic.Assess(texte, pageUrl);

        var verdict = evaluation.Verdict;
        var raisons = new List<string>(evaluation.Reasons);

        // Quishing : un QR code visible peut cacher une URL malveillante.
        string? urlQr = null;
        var pixels = CopyBgra(bitmap);
        urlQr = QrCodeScanner.DecodeUrl(pixels, bitmap.PixelWidth, bitmap.PixelHeight);
        if (urlQr is not null)
        {
            var evalQr = PhishingLogic.AssessUrl(urlQr);
            if (evalQr.Verdict > verdict) verdict = evalQr.Verdict;
            raisons.AddRange(evalQr.Reasons.Select(r => "[QR] " + r));
            if (evalQr.Verdict == PhishingVerdict.Safe)
                raisons.Add("[QR] URL cachée détectée : " + urlQr);
        }

        ct.ThrowIfCancellationRequested();
        return new CaptureAnalysis(verdict, raisons, texte, urlQr);
    }

    /// <summary>Lit seulement la capture : texte (OCR) et URL d'un éventuel QR code. La décision revient à l'appelant.</summary>
    public async Task<(string Text, string? QrUrl)> ReadAsync(byte[] imageBytes, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(imageBytes);
        using var bitmap = await DecodeAsync(imageBytes).ConfigureAwait(false);
        var texte = await ExtractTextAsync(bitmap).ConfigureAwait(false);
        var urlQr = QrCodeScanner.DecodeUrl(CopyBgra(bitmap), bitmap.PixelWidth, bitmap.PixelHeight);
        ct.ThrowIfCancellationRequested();
        return (texte, urlQr);
    }

    // Décode l'image en bitmap BGRA8 (format attendu par l'OCR et ZXing).
    private static async Task<SoftwareBitmap> DecodeAsync(byte[] imageBytes)
    {
        using var flux = new InMemoryRandomAccessStream();
        await flux.WriteAsync(imageBytes.AsBuffer());
        flux.Seek(0);
        var decodeur = await BitmapDecoder.CreateAsync(flux);
        return await decodeur.GetSoftwareBitmapAsync(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied);
    }

    private static async Task<string> ExtractTextAsync(SoftwareBitmap bitmap)
    {
        // Image trop grande pour le moteur OCR : on refuse plutôt que de planter.
        if (bitmap.PixelWidth > OcrEngine.MaxImageDimension || bitmap.PixelHeight > OcrEngine.MaxImageDimension)
            throw new InvalidOperationException("Image trop grande pour l'OCR.");

        var moteur = OcrEngine.TryCreateFromUserProfileLanguages()
            ?? throw new InvalidOperationException("Aucune langue OCR installée sur le système.");
        var resultat = await moteur.RecognizeAsync(bitmap);
        var texte = resultat.Text ?? string.Empty;
        return texte.Length > MaxTextLength ? texte[..MaxTextLength] : texte;
    }

    private static byte[] CopyBgra(SoftwareBitmap bitmap)
    {
        var tampon = new Windows.Storage.Streams.Buffer((uint)(bitmap.PixelWidth * bitmap.PixelHeight * 4));
        bitmap.CopyToBuffer(tampon);
        return tampon.ToArray();
    }
}
