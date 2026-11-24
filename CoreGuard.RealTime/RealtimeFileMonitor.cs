namespace CoreGuard.RealTime;

/// <summary>
/// Surveille des dossiers et signale les nouveaux fichiers (créés ou renommés vers le dossier),
/// afin de brancher un scan à la volée côté service.
/// </summary>
public sealed class RealtimeFileMonitor : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly object _gate = new();
    private bool _disposed;

    /// <summary>Levé pour chaque nouveau fichier (chemin complet).</summary>
    public event EventHandler<string>? NewFileDetected;

    /// <summary>Démarre la surveillance ; retourne la liste des dossiers effectivement surveillés.</summary>
    public IReadOnlyList<string> Start(IEnumerable<string> folders, bool includeSubdirectories = true)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var watched = new List<string>();
        foreach (var folder in folders)
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) continue;
            try
            {
                var w = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = includeSubdirectories,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
                    InternalBufferSize = 64 * 1024
                };
                w.Created += (_, e) => Raise(e.FullPath);
                w.Renamed += (_, e) => Raise(e.FullPath);
                w.EnableRaisingEvents = true;
                lock (_gate) _watchers.Add(w);
                watched.Add(folder);
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
            {
                // Dossier inaccessible : ignoré.
            }
        }
        return watched;
    }

    private void Raise(string path)
    {
        if (Directory.Exists(path)) return; // on ne signale que les fichiers
        try { NewFileDetected?.Invoke(this, path); } catch { /* protège le watcher */ }
    }

    public void Stop()
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
        Stop();
    }
}
