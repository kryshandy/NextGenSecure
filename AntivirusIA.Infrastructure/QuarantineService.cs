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

    private static byte[] ChargerOuCreerCle(string chemin)
    {
        if (File.Exists(chemin))
            return File.ReadAllBytes(chemin);

        byte[] cle = RandomNumberGenerator.GetBytes(32); // AES-256
        File.WriteAllBytes(chemin, cle);
        return cle;
    }

    // Fichier produit : 16 octets de vecteur d'initialisation, puis le contenu chiffré
    private async Task ChiffrerAsync(string source, string destination, CancellationToken ct)
    {
        using var aes = Aes.Create();
        aes.Key = _cle;
        aes.GenerateIV();

        await using var sortie = new FileStream(destination, FileMode.Create, FileAccess.Write,
            FileShare.None, 81920, useAsync: true);
        await sortie.WriteAsync(aes.IV, ct);

        await using var crypto = new CryptoStream(sortie, aes.CreateEncryptor(), CryptoStreamMode.Write);
        await using var entree = new FileStream(source, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, 81920, useAsync: true);

        await entree.CopyToAsync(crypto, ct);
        await crypto.FlushFinalBlockAsync(ct);
    }

    private async Task DechiffrerAsync(string source, string destination, CancellationToken ct)
    {
        await using var entree = new FileStream(source, FileMode.Open, FileAccess.Read,
            FileShare.Read, 81920, useAsync: true);

        var iv = new byte[16];
        await entree.ReadExactlyAsync(iv, ct);

        using var aes = Aes.Create();
        aes.Key = _cle;
        aes.IV = iv;

        await using var crypto = new CryptoStream(entree, aes.CreateDecryptor(), CryptoStreamMode.Read);
        await using var sortie = new FileStream(destination, FileMode.CreateNew, FileAccess.Write,
            FileShare.None, 81920, useAsync: true);

        await crypto.CopyToAsync(sortie, ct);
    }
}