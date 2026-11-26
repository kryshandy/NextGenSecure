using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CoreGuard.Service;

/// <summary>Configuration du verrouillage à distance (aucun secret en clair : empreinte PBKDF2 du code).</summary>
public sealed record RemoteLockConfig(IReadOnlyList<string> Folders, string Salt, int Iterations, string CodeHash)
{
    public const int MinCodeLength = 10;
    public const string CommandFilePrefix = "CoreGuard-VERROUILLER";

    public static RemoteLockConfig Create(IReadOnlyList<string> folders, string code, int iterations = 200_000)
    {
        if (string.IsNullOrWhiteSpace(code) || code.Trim().Length < MinCodeLength)
            throw new ArgumentException($"Le code de verrouillage à distance doit contenir au moins {MinCodeLength} caractères.", nameof(code));
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        return new RemoteLockConfig(folders, Convert.ToBase64String(salt), iterations, Convert.ToBase64String(Hash(code.Trim(), salt, iterations)));
    }

    /// <summary>Le contenu du fichier-ordre est-il le bon code ? (comparaison en temps constant)</summary>
    public bool Verify(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return false;
        byte[] expected = Convert.FromBase64String(CodeHash);
        byte[] actual = Hash(candidate.Trim(), Convert.FromBase64String(Salt), Iterations);
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    private static byte[] Hash(string code, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(code), salt, iterations, HashAlgorithmName.SHA256, 32);

    public static RemoteLockConfig? Load(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<RemoteLockConfig>(File.ReadAllText(path)) : null; }
        catch (Exception ex) when (ex is IOException or JsonException) { return null; }
    }

    /// <summary>Écrit la configuration ; <paramref name="restrictToAdmins"/> : ACL réservée à SYSTEM et aux Administrateurs.</summary>
    public void Save(string path, bool restrictToAdmins)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        if (restrictToAdmins && OperatingSystem.IsWindows())
        {
            var acl = new System.Security.AccessControl.FileSecurity();
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in new[] { System.Security.Principal.WellKnownSidType.LocalSystemSid, System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid })
                acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(sid, null),
                    System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
            new FileInfo(temp).SetAccessControl(acl);
        }
        File.Move(temp, path, overwrite: true);
    }
}

/// <summary>
/// Déclencheur de verrouillage À DISTANCE par dossier synchronisé (OneDrive, Google Drive…), sans aucun port
/// réseau ni serveur CoreGuard. Depuis son téléphone, le propriétaire crée dans ce dossier un fichier
/// « CoreGuard-VERROUILLER….txt » contenant son code ; dès que le PC le reçoit, CoreGuard vérifie le code et
/// verrouille. Le fichier est ensuite renommé (« .traite » ou « .refuse ») pour ne pas être rejoué.
/// Le déverrouillage, lui, se fait uniquement devant le PC avec le mot de passe de protection.
/// Inactif tant qu'aucune configuration n'existe (opt-in).
/// </summary>
public sealed class RemoteLockWatcher(RemoteLockConfig config, Action<string> engage, Action<string, string> publish, ILogger logger) : IDisposable
{
    private static readonly TimeSpan Poll = TimeSpan.FromSeconds(30); // la synchronisation cloud ne déclenche pas toujours d'événement
    private readonly List<FileSystemWatcher> _watchers = [];
    private Timer? _timer;
    private int _scanning;

    public void Start()
    {
        foreach (string folder in config.Folders.Where(Directory.Exists))
        {
            try
            {
                var w = new FileSystemWatcher(folder, RemoteLockConfig.CommandFilePrefix + "*.txt")
                { NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite };
                w.Created += (_, _) => Scan();
                w.Renamed += (_, _) => Scan();
                w.Changed += (_, _) => Scan();
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
            {
                logger.LogWarning("Dossier de verrouillage à distance inaccessible : {Folder}", folder);
            }
        }
        _timer = new Timer(_ => Scan(), null, TimeSpan.FromSeconds(5), Poll);
        logger.LogInformation("Verrouillage à distance actif sur {Count} dossier(s).", config.Folders.Count);
    }

    public void Scan()
    {
        if (Interlocked.Exchange(ref _scanning, 1) == 1) return;
        try
        {
            foreach (string folder in config.Folders.Where(Directory.Exists))
                foreach (string file in Directory.GetFiles(folder, RemoteLockConfig.CommandFilePrefix + "*.txt"))
                    if (!file.Contains(".traite-", StringComparison.OrdinalIgnoreCase) && !file.Contains(".refuse-", StringComparison.OrdinalIgnoreCase))
                        Handle(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // dossier en cours de synchronisation : nouvel essai au prochain passage
        }
        finally
        {
            Interlocked.Exchange(ref _scanning, 0);
        }
    }

    private void Handle(string file)
    {
        string content;
        try
        {
            if (new FileInfo(file).Length > 1024) { Rename(file, "refuse"); return; }
            content = File.ReadAllText(file);
        }
        catch (IOException) { return; } // encore en cours d'écriture par le client de synchronisation

        if (config.Verify(content))
        {
            Rename(file, "traite");
            logger.LogWarning("Ordre de verrouillage à distance reçu : {File}", Path.GetFileName(file));
            engage("ordre à distance (" + Path.GetFileName(file) + ")");
        }
        else
        {
            Rename(file, "refuse");
            publish("Verrouillage à distance refusé", $"{Path.GetFileName(file)} : code incorrect.");
        }
    }

    private static void Rename(string file, string suffix)
    {
        // Sans extension .txt : le fichier renommé ne correspond plus au motif et ne peut pas être rejoué
        try { File.Move(file, Path.ChangeExtension(file, $".{suffix}-{DateTime.UtcNow:yyyyMMddHHmmss}")); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* au mieux */ }
    }

    public void Dispose()
    {
        _timer?.Dispose();
        foreach (var w in _watchers) w.Dispose();
        _watchers.Clear();
    }
}
