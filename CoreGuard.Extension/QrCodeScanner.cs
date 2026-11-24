using ZXing;

namespace CoreGuard.Extension;

/// <summary>Lecture de QR codes (quishing) via ZXing.Net, sans dépendance à System.Drawing.</summary>
public static class QrCodeScanner
{
    /// <summary>
    /// Décode un QR code dans une image BGRA32 brute. Retourne l'URL http(s) contenue,
    /// ou null si aucun QR n'est trouvé ou si le contenu n'est pas une URL web.
    /// Le contenu du QR est NON FIABLE : il n'est jamais ouvert, seulement évalué.
    /// </summary>
    public static string? DecodeUrl(byte[] pixelsBgra, int width, int height)
    {
        if (width <= 0 || height <= 0 || pixelsBgra.Length < width * height * 4) return null;

        var lecteur = new BarcodeReaderGeneric
        {
            AutoRotate = true,
            Options = new ZXing.Common.DecodingOptions
            {
                PossibleFormats = [BarcodeFormat.QR_CODE],
                TryHarder = true
            }
        };
        var source = new RGBLuminanceSource(pixelsBgra, width, height, RGBLuminanceSource.BitmapFormat.BGRA32);
        var resultat = lecteur.Decode(source);
        return resultat is null ? null : NormalizeUrl(resultat.Text);
    }

    /// <summary>Ne conserve que les URL http(s) absolues et de taille raisonnable.</summary>
    public static string? NormalizeUrl(string? contenu)
    {
        if (string.IsNullOrWhiteSpace(contenu) || contenu.Length > 2048) return null;
        return Uri.TryCreate(contenu.Trim(), UriKind.Absolute, out var uri) &&
               (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
            ? uri.AbsoluteUri
            : null;
    }
}
