using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Engines;

/// <summary>
/// Vérifie la signature Authenticode intégrée d'un fichier via WinVerifyTrust (Windows uniquement).
/// Aucune requête réseau : la révocation n'est pas vérifiée en ligne (pas de blocage du scan hors connexion).
/// LIMITE : les fichiers système signés par catalogue (sans signature intégrée) sont vus comme non signés,
/// ils perdent donc simplement l'atténuation, sans être pénalisés.
/// </summary>
public sealed partial class AuthenticodeVerifier : IFileTrustProvider
{
    public Task<FileTrust> EvaluateAsync(string path, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows() || !File.Exists(path)) return Task.FromResult(FileTrust.Unsigned);
        return Task.Run(() => Verify(path), ct);
    }

    private static FileTrust Verify(string path)
    {
        int status = WinVerifyTrustFile(path);
        if (status == TrustENoSignature || status == TrustESubjectFormUnknown || status == TrustEProviderUnknown)
            return FileTrust.Unsigned;

        bool valid = status == 0;
        return new FileTrust(IsSigned: true, IsValid: valid, Publisher: valid ? TryGetPublisher(path) : null);
    }

    private static string? TryGetPublisher(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // seul moyen managé d'extraire le certificat d'un fichier signé
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            string name = cert.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrWhiteSpace(name) ? null : name;
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or IOException)
        {
            return null;
        }
    }

    // ---------- P/Invoke WinVerifyTrust ----------

    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustEProviderUnknown = unchecked((int)0x800B0001);

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [LibraryImport("wintrust.dll")]
    private static partial int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WinTrustData pWVTData);

    private static int WinVerifyTrustFile(string path)
    {
        IntPtr pathPtr = Marshal.StringToHGlobalUni(path);
        IntPtr filePtr = IntPtr.Zero;
        try
        {
            var fileInfo = new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = pathPtr
            };
            filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, filePtr, false);

            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pFile = filePtr,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdCacheOnlyUrlRetrieval
            };

            Guid action = GenericVerifyV2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            data.dwStateAction = WtdStateActionClose; // libère l'état alloué par la vérification
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return result;
        }
        finally
        {
            if (filePtr != IntPtr.Zero) Marshal.FreeHGlobal(filePtr);
            Marshal.FreeHGlobal(pathPtr);
        }
    }
}
