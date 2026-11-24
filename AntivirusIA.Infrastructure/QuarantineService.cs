using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Infrastructure;

public sealed class QuarantineService : IQuarantineService
{
    private static readonly JsonSerializerOptions OptionsJson = new() { WriteIndented = true };

    private readonly string _dossier;
    private readonly string _indexPath;
    private readonly byte[] _cle;
    private readonly List<QuarantineEntry> _entrees;
    private readonly SemaphoreSlim _verrou = new(1, 1);

    public QuarantineService(string dossier)
    {
        _dossier = dossier;
        Directory.CreateDirectory(_dossier);

        _indexPath = Path.Combine(_dossier, "index.json");
        _cle = ChargerOuCreerCle(Path.Combine(_dossier, "quarantine.key"));

        _entrees = File.Exists(_indexPath)
            ? JsonSerializer.Deserialize<List<QuarantineEntry>>(File.ReadAllText(_indexPath)) ?? new()
            : new();
    }

    public IReadOnlyList<QuarantineEntry> List()
    {
        lock (_entrees)
            return _entrees.ToList();
    }

    public async Task<QuarantineEntry> QuarantineAsync(string cheminFichier, string raison, CancellationToken ct = default)
    {
        var info = new FileInfo(cheminFichier);
        if (!info.Exists)
            throw new FileNotFoundException("Fichier introuvable", cheminFichier);

        await _verrou.WaitAsync(ct);
        try
        {
            var entree = new QuarantineEntry(Guid.NewGuid(), info.FullName, raison, DateTime.UtcNow, info.Length);
            string cible = CheminStocke(entree.Id);

            await ChiffrerAsync(info.FullName, cible, ct);
            try
            {
                File.Delete(info.FullName);
            }
            catch
            {
                // Impossible de supprimer l'original : on annule la mise en quarantaine
                File.Delete(cible);
                throw;
            }

            lock (_entrees) _entrees.Add(entree);
            SauvegarderIndex();
            return entree;
        }
        finally
        {
            _verrou.Release();
        }
    }

    public async Task RestoreAsync(Guid id, CancellationToken ct = default)
    {
        await _verrou.WaitAsync(ct);
        try
        {
            QuarantineEntry entree = Trouver(id);

            string? dossierOrigine = Path.GetDirectoryName(entree.OriginalPath);
            if (!string.IsNullOrEmpty(dossierOrigine))
                Directory.CreateDirectory(dossierOrigine);

            await DechiffrerAsync(CheminStocke(id), entree.OriginalPath, ct);

            File.Delete(CheminStocke(id));
            lock (_entrees) _entrees.Remove(entree);
            SauvegarderIndex();
        }
        finally
        {
            _verrou.Release();
        }
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await _verrou.WaitAsync(ct);
        try
        {
            QuarantineEntry entree = Trouver(id);

            File.Delete(CheminStocke(id));
            lock (_entrees) _entrees.Remove(entree);
            SauvegarderIndex();
        }
        finally
        {
            _verrou.Release();
        }
    }

    // ---------- Méthodes internes ----------

    private string CheminStocke(Guid id) => Path.Combine(_dossier, id + ".quar");

    private QuarantineEntry Trouver(Guid id)
    {
        lock (_entrees)
            return _entrees.FirstOrDefault(e => e.Id == id)
                   ?? throw new KeyNotFoundException($"Aucune entrée de quarantaine avec l'identifiant {id}");
    }

    private void SauvegarderIndex()
    {
        List<QuarantineEntry> copie;
        lock (_entrees) copie = _entrees.ToList();
        File.WriteAllText(_indexPath, JsonSerializer.Serialize(copie, OptionsJson));
    }

    // ---------- Clé de chiffrement ----------
    // Format v2 : "CGK2" + clé protégée par DPAPI (portée utilisateur courant). Une copie du dossier de quarantaine
    // vers une autre machine ou un autre compte est inexploitable. Une ancienne clé brute (32 octets) est migrée.
    // LIMITE : un programme exécuté sous le même compte peut aussi appeler DPAPI ; seule une exécution en
    // service système (Phase 2) l'en empêchera.
    internal static readonly byte[] MagicCle = "CGK2"u8.ToArray();
    private static readonly byte[] EntropieDpapi = "CoreGuard.Quarantine.v2"u8.ToArray();

    internal static byte[] ChargerOuCreerCle(string chemin)
    {
        if (File.Exists(chemin))
        {
            byte[] contenu = File.ReadAllBytes(chemin);
            if (contenu.AsSpan().StartsWith(MagicCle))
                return Deproteger(contenu[MagicCle.Length..]);

            if (contenu.Length == 32)
            {
                EcrireCle(chemin, contenu); // migration de l'ancienne clé stockée en clair
                return contenu;
            }
            throw new InvalidDataException("Clé de quarantaine illisible");
        }

        byte[] cle = RandomNumberGenerator.GetBytes(32); // AES-256
        EcrireCle(chemin, cle);
        return cle;
    }

    private static void EcrireCle(string chemin, byte[] cle)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.WriteAllBytes(chemin, cle); // pas de DPAPI hors Windows
            return;
        }
        byte[] protegee = ProtectedData.Protect(cle, EntropieDpapi, DataProtectionScope.CurrentUser);
        string temp = chemin + ".tmp";
        File.WriteAllBytes(temp, [.. MagicCle, .. protegee]);
        File.Move(temp, chemin, overwrite: true);
    }

    private static byte[] Deproteger(byte[] protegee)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Clé protégée par DPAPI : Windows requis");
        try
        {
            return ProtectedData.Unprotect(protegee, EntropieDpapi, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidDataException("Clé de quarantaine inutilisable (autre compte ou autre machine)", ex);
        }
    }

    // ---------- Format des fichiers .quar ----------
    // v2 (authentifié) : "CGQ2" | taille de bloc (int32) | nonce de base (12 o) | blocs [chiffré | tag GCM 16 o]
    // Chaque bloc est chiffré en AES-256-GCM avec un nonce dérivé de son index ; l'en-tête, l'index et un
    // indicateur « dernier bloc » sont authentifiés (AAD) : toute modification, troncature ou permutation de
    // blocs est détectée, et la restauration échoue sans rien écrire à l'emplacement d'origine.
    // v1 (ancien, AES-CBC non authentifié) : IV (16 o) | chiffré. Accepté en lecture seule, pour restaurer
    // les fichiers mis en quarantaine avant la v2.
    internal static readonly byte[] MagicFichier = "CGQ2"u8.ToArray();
    private const int TailleBloc = 1024 * 1024;
    private const int TailleTag = 16;
    private const int TailleNonce = 12;
    private const int TailleEntete = 4 + 4 + TailleNonce;

    private async Task ChiffrerAsync(string source, string destination, CancellationToken ct)
    {
        byte[] nonceBase = RandomNumberGenerator.GetBytes(TailleNonce);
        byte[] entete = new byte[TailleEntete];
        MagicFichier.CopyTo(entete, 0);
        BinaryPrimitives.WriteInt32LittleEndian(entete.AsSpan(4), TailleBloc);
        nonceBase.CopyTo(entete, 8);

        await using var sortie = new FileStream(destination, FileMode.Create, FileAccess.Write,
            FileShare.None, 81920, useAsync: true);
        await using var entree = new FileStream(source, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, 81920, useAsync: true);
        await sortie.WriteAsync(entete, ct);

        using var gcm = new AesGcm(_cle, TailleTag);
        byte[] courant = new byte[TailleBloc], suivant = new byte[TailleBloc];
        byte[] chiffre = new byte[TailleBloc], tag = new byte[TailleTag];
        int lus = await entree.ReadAtLeastAsync(courant, TailleBloc, throwOnEndOfStream: false, ct);
        long index = 0;
        while (true)
        {
            // Lecture anticipée : le bloc courant est le dernier si rien ne le suit
            int lusSuivant = lus == TailleBloc
                ? await entree.ReadAtLeastAsync(suivant, TailleBloc, throwOnEndOfStream: false, ct)
                : 0;
            bool dernier = lusSuivant == 0;

            gcm.Encrypt(Nonce(nonceBase, index), courant.AsSpan(0, lus), chiffre.AsSpan(0, lus), tag,
                Aad(entete, index, dernier));
            await sortie.WriteAsync(chiffre.AsMemory(0, lus), ct);
            await sortie.WriteAsync(tag, ct);

            if (dernier) break;
            (courant, suivant) = (suivant, courant);
            lus = lusSuivant;
            index++;
        }
        await sortie.FlushAsync(ct);
    }

    private async Task DechiffrerAsync(string source, string destination, CancellationToken ct)
    {
        // Déchiffrement vers un fichier temporaire : rien n'apparaît à l'emplacement d'origine
        // tant que l'intégrité de TOUS les blocs n'a pas été vérifiée
        string temp = destination + "." + Guid.NewGuid().ToString("N")[..8] + ".cgrestore";
        try
        {
            await using (var entree = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true))
            await using (var sortie = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                var magic = new byte[4];
                int n = await entree.ReadAtLeastAsync(magic, 4, throwOnEndOfStream: false, ct);
                if (n == 4 && magic.AsSpan().SequenceEqual(MagicFichier))
                {
                    await DechiffrerV2Async(entree, sortie, ct);
                }
                else
                {
                    entree.Position = 0;
                    await DechiffrerV1Async(entree, sortie, ct);
                }
            }
            File.Move(temp, destination, overwrite: false);
        }
        catch (CryptographicException ex)
        {
            throw new IOException("Fichier de quarantaine altéré ou corrompu : restauration refusée", ex);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    private async Task DechiffrerV2Async(FileStream entree, FileStream sortie, CancellationToken ct)
    {
        byte[] entete = new byte[TailleEntete];
        MagicFichier.CopyTo(entete, 0);
        await entree.ReadExactlyAsync(entete.AsMemory(4), ct);
        int tailleBloc = BinaryPrimitives.ReadInt32LittleEndian(entete.AsSpan(4));
        if (tailleBloc is <= 0 or > 16 * 1024 * 1024)
            throw new CryptographicException("En-tête de quarantaine invalide");
        byte[] nonceBase = entete[8..];

        using var gcm = new AesGcm(_cle, TailleTag);
        byte[] bloc = new byte[tailleBloc + TailleTag];
        byte[] clair = new byte[tailleBloc];
        long index = 0;
        while (true)
        {
            int lus = await entree.ReadAtLeastAsync(bloc, bloc.Length, throwOnEndOfStream: false, ct);
            if (lus < TailleTag) throw new CryptographicException("Fichier de quarantaine tronqué");
            bool dernier = entree.Position == entree.Length;
            if (!dernier && lus != bloc.Length) throw new CryptographicException("Bloc de quarantaine incomplet");

            int taille = lus - TailleTag;
            gcm.Decrypt(Nonce(nonceBase, index), bloc.AsSpan(0, taille), bloc.AsSpan(taille, TailleTag),
                clair.AsSpan(0, taille), Aad(entete, index, dernier));
            await sortie.WriteAsync(clair.AsMemory(0, taille), ct);

            if (dernier) break;
            index++;
        }
    }

    private async Task DechiffrerV1Async(FileStream entree, FileStream sortie, CancellationToken ct)
    {
        var iv = new byte[16];
        await entree.ReadExactlyAsync(iv, ct);

        using var aes = Aes.Create();
        aes.Key = _cle;
        aes.IV = iv;

        await using var crypto = new CryptoStream(entree, aes.CreateDecryptor(), CryptoStreamMode.Read, leaveOpen: true);
        await crypto.CopyToAsync(sortie, ct);
    }

    private static byte[] Nonce(byte[] nonceBase, long index)
    {
        byte[] nonce = (byte[])nonceBase.Clone();
        Span<byte> compteur = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(compteur, index);
        for (int i = 0; i < 8; i++) nonce[TailleNonce - 8 + i] ^= compteur[i];
        return nonce;
    }

    private static byte[] Aad(byte[] entete, long index, bool dernier)
    {
        byte[] aad = new byte[entete.Length + 9];
        entete.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(entete.Length), index);
        aad[^1] = dernier ? (byte)1 : (byte)0;
        return aad;
    }
}
