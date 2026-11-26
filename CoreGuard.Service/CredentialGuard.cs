using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Engines;
using CoreGuard.RealTime;

namespace CoreGuard.Service;

/// <summary>
/// Anti-infostealer : surveille la LECTURE des fichiers d'identifiants des navigateurs (mots de passe, cookies de
/// session, cartes) par l'audit NTFS (événement 4663 = PID exact), et arrête tout lecteur qui n'est pas un
/// navigateur signé (ou Defender / l'indexation). Un profil leurre Chromium attire les voleurs qui essaient tous
/// les chemins connus.
/// LIMITE (mode utilisateur) : impossible d'interdire la lecture à l'avance — le navigateur et le voleur tournent
/// sous le même compte, une ACL ne peut pas les distinguer. La lecture a lieu, puis le voleur est arrêté : le
/// fichier a pu être copié, d'où le conseil de changer les mots de passe. Le driver Ring 0 permettra de bloquer avant.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CredentialGuard(
    IKernelActionProvider actions,
    Action<string, string, string, string> publish,
    ILogger logger) : IDisposable
{
    private static readonly TimeSpan Refresh = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan AllowCache = TimeSpan.FromMinutes(10);

    private readonly ConcurrentDictionary<string, CredentialFile> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, DateTime> _allowedPids = new();
    private readonly ConcurrentDictionary<int, DateTime> _stoppedPids = new();
    private readonly ConcurrentDictionary<string, SignerInfo> _signers = new(StringComparer.OrdinalIgnoreCase);
    private readonly AuthenticodeVerifier _authenticode = new();
    private readonly List<string> _profiles = [];
    private CanaryAuditWatcher? _audit;
    private Timer? _timer;
    private int _auditFailures;

    public int WatchedFiles => _files.Count;
    public bool Listening => _audit is not null;
    public int Stopped { get; private set; }

    public string StatusText
    {
        get
        {
            if (_files.IsEmpty) return "Aucun fichier d'identifiants trouvé";
            var browsers = _files.Values.Select(f => f.Browser).Distinct().Order();
            string state = Listening && _auditFailures == 0 ? "attribution par audit : arrêt du voleur" : "audit indisponible : surveillance inactive";
            return $"{_files.Count} fichiers surveillés ({string.Join(", ", browsers)}), {state} ; {Stopped} voleur(s) arrêté(s)";
        }
    }

    public void Start()
    {
        _profiles.AddRange(ServiceHost.IsWindowsService
            ? UserProfiles.ProfileRoots()
            : [Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)]);

        var audit = new CanaryAuditWatcher(path => _files.ContainsKey(path), CanaryAuditWatcher.IsReadAccess);
        audit.Warning += (_, w) => logger.LogWarning("{Warning}", w);
        audit.Access += (_, a) => OnRead(a);
        if (audit.Start()) _audit = audit; else audit.Dispose();

        RefreshTargets();
        _timer = new Timer(_ => RefreshTargets(), null, Refresh, Refresh);
        logger.LogInformation("Anti-infostealer : {Status}", StatusText);
    }

    // Nouveaux fichiers (navigateur installé, profil créé) et SACL perdues (fichier remplacé par le navigateur)
    private void RefreshTargets()
    {
        try
        {
            int failures = 0;
            var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string profile in _profiles)
            {
                CredentialTargets.EnsureHoneypot(profile);
                foreach (var file in CredentialTargets.Enumerate(profile))
                {
                    current.Add(file.Path);
                    _files[file.Path] = file;
                    if (!CanaryAuditWatcher.TryEnableAudit(file.Path, FileSystemRights.ReadData, out _)) failures++;
                }
            }
            foreach (string gone in _files.Keys.Where(k => !current.Contains(k)).ToList()) _files.TryRemove(gone, out _);
            if (failures > 0 && _auditFailures == 0)
                logger.LogWarning("Audit NTFS impossible sur {Count} fichier(s) d'identifiants (droits administrateur requis).", failures);
            _auditFailures = failures;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogWarning("Inventaire des fichiers d'identifiants impossible : {Message}", ex.Message);
        }
    }

    private void OnRead(CanaryAccess access)
    {
        if (access.Pid == Environment.ProcessId) return;
        DateTime now = DateTime.UtcNow;
        if (_allowedPids.TryGetValue(access.Pid, out DateTime ok) && now - ok < AllowCache) return;
        if (_stoppedPids.ContainsKey(access.Pid)) return;
        if (!_files.TryGetValue(access.Path, out CredentialFile? file)) return;

        SignerInfo signer = _signers.GetOrAdd(access.ProcessName, path =>
        {
            try
            {
                var trust = _authenticode.EvaluateAsync(path).GetAwaiter().GetResult();
                return new SignerInfo(trust.IsTrusted, trust.Publisher);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return new SignerInfo(false, null);
            }
        });

        if (CredentialAccessPolicy.Decide(access.ProcessName, file.Honeypot, signer) == CredentialDecision.Allow)
        {
            _allowedPids[access.Pid] = now;
            return;
        }

        _stoppedPids[access.Pid] = now;
        string image = Path.GetFileName(access.ProcessName);
        string target = $"{Path.GetFileName(access.Path)} ({file.Browser})";
        _ = Task.Run(async () =>
        {
            ActionResult result = await actions.TerminateProcessAsync(access.Pid, $"lecture de {target} : vol d'identifiants");
            if (result.Success) Stopped++;
            string advice = file.Honeypot
                ? "Il a lu le profil leurre Chromium : comportement typique d'un voleur d'identifiants."
                : "Le fichier a pu être copié avant l'arrêt : changez les mots de passe enregistrés dans ce navigateur.";
            publish(result.Success ? "Critical" : "Warning", "Anti-infostealer",
                result.Success ? $"Vol d'identifiants bloqué : {image}" : $"Vol d'identifiants : {image} (arrêt impossible)",
                $"{image} (PID {access.Pid}) a lu {target}. {result.Message} {advice}");
            logger.LogWarning("Lecture de {Target} par {Image} (PID {Pid}) : {Message}", target, image, access.Pid, result.Message);
        });
    }

    public void Dispose()
    {
        _timer?.Dispose();
        _audit?.Dispose();
        _audit = null;
        foreach (string profile in _profiles) CredentialTargets.RemoveHoneypot(profile);
    }
}
