using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace CoreGuard.RealTime;

/// <summary>
/// Gère des fichiers leurres (canaris) : déploiement, surveillance, restauration depuis une copie AES en mémoire.
/// Détection POST-écriture (user-mode) : l'alerte survient après la modification, la restauration répare.
/// </summary>
public sealed class CanaryManager : IDisposable
{
    /// <summary>
    /// Noms de la spécification (préfixes « ! », « _ », « ~ » : rencontrés en premier par un ransomware qui
    /// parcourt les dossiers dans l'ordre alphabétique, ou en dernier selon le tri), plus deux leurres « appâts ».
    /// </summary>
    public static readonly string[] DefaultCanaryNames =
    [
        "!00_confidentiel.docx", "_zz_confidentiel.docx", "~000_backup.xlsx", "!!_comptes_2024.xlsx", "_00_mots_de_passe.txt"
    ];

    private sealed record CanaryEntry(byte[] Cipher, byte[] Iv);

    private readonly IThreatResponder _responder;
    private readonly Func<int?> _pidResolver;
    private readonly ConcurrentDictionary<string, CanaryEntry> _canaries = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _selfWrites = new(StringComparer.OrdinalIgnoreCase);
    // Une écriture produit plusieurs notifications (troncature, écriture, fermeture) : une seule alerte par rafale
    private readonly ConcurrentDictionary<string, DateTime> _lastTrigger = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan TriggerCoalesce = TimeSpan.FromMilliseconds(1500);
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32); // clé éphémère, jamais écrite sur disque
    private readonly CancellationTokenSource _cts = new();
    private readonly object _gate = new();
    private bool _disposed;

    /// <summary>Levé à chaque canari touché.</summary>
    public event EventHandler<CanaryAlert>? CanaryTriggered;

    /// <summary>Restaurer automatiquement le canari après alerte (défaut : true).</summary>
    public bool AutoRestore { get; init; } = true;

    /// <summary>Déposer les canaris avec l'attribut « caché » (défaut : true), pour que l'utilisateur ne les ouvre pas.</summary>
    public bool Hidden { get; init; } = true;

    /// <summary>Levé après chaque écriture d'un canari par le gestionnaire (dépôt ou restauration) : chemin écrit.</summary>
    public event EventHandler<string>? CanaryWritten;

    /// <summary>Levé pour un incident non fatal (tampon du watcher saturé, dossier disparu…).</summary>
    public event EventHandler<string>? Warning;

    /// <summary>Vrai si le chemin est un canari déployé.</summary>
    public bool IsCanary(string path) => _canaries.ContainsKey(path);

    public CanaryManager(IThreatResponder responder, Func<int?>? pidResolver = null)
    {
        _responder = responder ?? throw new ArgumentNullException(nameof(responder));
        _pidResolver = pidResolver ?? (() => PidResolver.FindSuspectPid());
    }

    /// <summary>Chemins des canaris actuellement déployés.</summary>
    public IReadOnlyCollection<string> CanaryPaths => _canaries.Keys.ToArray();

    /// <summary>Dossiers par défaut : Documents, Bureau, Images de l'utilisateur.</summary>
    public static IEnumerable<string> DefaultFolders() =>
    [
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)
    ];

    /// <summary>
    /// Déploie les canaris dans les dossiers donnés et démarre leur surveillance.
    /// Les dossiers inexistants ou inaccessibles sont ignorés. Retourne les chemins créés.
    /// </summary>
    public IReadOnlyList<string> Deploy(IEnumerable<string> folders, IEnumerable<string>? names = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var nameList = (names ?? DefaultCanaryNames).ToArray();
        var created = new List<string>();

        foreach (var folder in folders.Where(f => !string.IsNullOrWhiteSpace(f)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(folder)) continue;
            var deployedHere = false;
            foreach (var name in nameList)
            {
                var path = Path.Combine(folder, name);
                try
                {
                    var content = GenerateFakeContent(name);
                    WriteCanaryWithRetry(path, content);
                    _canaries[path] = Encrypt(content);
                    created.Add(path);
                    deployedHere = true;
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
                {
                    // Pas de droits / verrouillé : on passe au suivant.
                }
            }
            if (deployedHere) StartWatcher(folder);
        }
        return created;
    }

    /// <summary>Restaure un canari depuis sa copie chiffrée en mémoire. False si inconnu ou échec.</summary>
    public Task<bool> RestoreAsync(string path, CancellationToken ct = default)
    {
        if (!_canaries.TryGetValue(path, out var entry)) return Task.FromResult(false);
        return Task.Run(() =>
        {
            try
            {
                var content = Decrypt(entry);
                var dir = Path.GetDirectoryName(path);
                if (dir is not null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

                WriteCanaryWithRetry(path, content);
                return true;
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                return false;
            }
        }, ct);
    }

    /// <summary>Supprime les canaris du disque et arrête la surveillance.</summary>
    public void Remove()
    {
        StopWatchers();
        foreach (var path in _canaries.Keys)
        {
            try
            {
                if (File.Exists(path)) File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
            }
            catch { /* best-effort */ }
        }
        _canaries.Clear();
    }

    // Le fichier peut être tenu un instant (antivirus, indexeur, le ransomware lui-même) : on insiste ~3 s
    private void WriteCanaryWithRetry(string path, byte[] content)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                WriteCanary(path, content);
                return;
            }
            catch (IOException) when (attempt < 30 && !_disposed)
            {
                Thread.Sleep(100);
            }
        }
    }

    // Un fichier caché ne peut pas être réécrit tel quel (accès refusé) : attributs remis à zéro, écriture, puis caché
    private void WriteCanary(string path, byte[] content)
    {
        MarkSelfWrite(path);
        if (File.Exists(path)) File.SetAttributes(path, FileAttributes.Normal);
        File.WriteAllBytes(path, content);
        if (Hidden) File.SetAttributes(path, FileAttributes.Hidden);
        try { CanaryWritten?.Invoke(this, path); } catch { /* un abonné fautif ne bloque pas le dépôt */ }
    }

    private void StartWatcher(string folder)
    {
        try
        {
            var w = new FileSystemWatcher(folder)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.Attributes,
                IncludeSubdirectories = false,
                InternalBufferSize = 64 * 1024
            };
            w.Changed += (_, e) => Handle(e.FullPath, "Modified");
            w.Deleted += (_, e) => Handle(e.FullPath, "Deleted");
            w.Renamed += (_, e) =>
            {
                if (_canaries.ContainsKey(e.OldFullPath)) Handle(e.OldFullPath, "Renamed");
                else Handle(e.FullPath, "Renamed"); // renommé VERS un nom de canari (écrasement)
            };
            // Tampon saturé (rafale d'écritures, typique d'un ransomware) : des événements ont pu être perdus.
            // On recrée le watcher et on vérifie l'intégrité de chaque canari du dossier.
            w.Error += (_, e) => OnWatcherError(folder, w, e.GetException());
            w.EnableRaisingEvents = true;
            lock (_gate) _watchers.Add(w);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            // Dossier disparu / inaccessible : surveillance impossible, on ignore.
        }
    }

    private void OnWatcherError(string folder, FileSystemWatcher failed, Exception error)
    {
        if (_disposed) return;
        try { Warning?.Invoke(this, $"Surveillance de {folder} interrompue ({error.GetType().Name}) : redémarrage et vérification des canaris."); }
        catch { /* abonné fautif */ }

        lock (_gate)
        {
            _watchers.Remove(failed);
            try { failed.Dispose(); } catch { /* déjà libéré */ }
        }
        StartWatcher(folder);
        _ = Task.Run(() => VerifyFolder(folder));
    }

    /// <summary>Compare chaque canari du dossier à sa copie : tout écart déclenche l'alerte comme une modification.</summary>
    private void VerifyFolder(string folder)
    {
        foreach (var (path, entry) in _canaries.ToArray())
        {
            if (!string.Equals(Path.GetDirectoryName(path), Path.TrimEndingDirectorySeparator(folder), StringComparison.OrdinalIgnoreCase)) continue;
            bool intact;
            try { intact = File.Exists(path) && File.ReadAllBytes(path).AsSpan().SequenceEqual(Decrypt(entry)); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { intact = false; }
            if (!intact) Handle(path, File.Exists(path) ? "Modified" : "Deleted");
        }
    }

    private void Handle(string path, string operation)
    {
        if (_disposed || !_canaries.ContainsKey(path)) return;
        // Ignore l'écho de nos propres écritures (déploiement / restauration).
        if (_selfWrites.TryGetValue(path, out var until) && DateTime.UtcNow < until) return;

        DateTime now = DateTime.UtcNow;
        if (_lastTrigger.TryGetValue(path, out var last) && now - last < TriggerCoalesce) return;
        _lastTrigger[path] = now;

        var alert = new CanaryAlert(path, operation, DateTime.UtcNow, SafeResolvePid());
        try { CanaryTriggered?.Invoke(this, alert); } catch { /* un abonné fautif ne doit pas casser la détection */ }

        _ = Task.Run(async () =>
        {
            try
            {
                await _responder.OnCanaryTriggeredAsync(alert, _cts.Token).ConfigureAwait(false);
                if (AutoRestore) await RestoreAsync(path).ConfigureAwait(false);
            }
            catch { /* le responder ne doit jamais faire planter le watcher */ }
        });
    }

    private int? SafeResolvePid()
    {
        try { return _pidResolver(); } catch { return null; }
    }

    // Fenêtre pendant laquelle les événements du watcher sur ce chemin sont attribués à nous-mêmes.
    private void MarkSelfWrite(string path) => _selfWrites[path] = DateTime.UtcNow.AddMilliseconds(750);

    private CanaryEntry Encrypt(byte[] plain)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.GenerateIV();
        return new CanaryEntry(aes.EncryptCbc(plain, aes.IV), aes.IV);
    }

    private byte[] Decrypt(CanaryEntry e)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        return aes.DecryptCbc(e.Cipher, e.Iv);
    }

    /// <summary>Contenu factice : signature ZIP pour OOXML + remplissage réaliste.</summary>
    private static byte[] GenerateFakeContent(string name)
    {
        var ext = Path.GetExtension(name).ToLowerInvariant();
        using var ms = new MemoryStream();
        if (ext is ".docx" or ".xlsx")
            ms.Write([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]); // en-tête ZIP
        var text = "Document confidentiel - Direction financière\r\nRéf. " + Guid.NewGuid().ToString("N")[..8] +
                   "\r\nBudget prévisionnel, identifiants, relevés de comptes.\r\n";
        ms.Write(Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat(text, 40))));
        return ms.ToArray();
    }

    private void StopWatchers()
    {
        lock (_gate)
        {
            foreach (var w in _watchers) { w.EnableRaisingEvents = false; w.Dispose(); }
            _watchers.Clear();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        StopWatchers();
        _cts.Dispose();
    }
}
