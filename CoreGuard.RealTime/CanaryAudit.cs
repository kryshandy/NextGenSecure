using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CoreGuard.RealTime;

/// <summary>Accès en écriture à un canari, attribué par l'audit NTFS de Windows (événement de sécurité 4663).</summary>
public sealed record CanaryAccess(string Path, int Pid, string ProcessName, uint AccessMask, DateTime WhenUtc);

/// <summary>
/// Attribution fiable d'une écriture sur un canari, sans driver : une règle d'audit (SACL) est posée sur chaque
/// canari, et Windows journalise dans le journal Sécurité (événement 4663) le PID exact et l'exécutable de tout
/// processus qui écrit, ajoute ou supprime (renommage compris) le fichier.
/// Prérequis : droits SYSTEM ou administrateur (SeSecurityPrivilege pour poser la SACL, lecture du journal Sécurité)
/// et sous-catégorie d'audit « Système de fichiers » activée en succès (scripts/install-service.ps1 le fait).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class CanaryAuditWatcher : IDisposable
{
    // Accès audités : WriteData, AppendData, DELETE (un renommage exige DELETE). Pas la lecture ni les attributs :
    // l'indexation, l'antivirus ou l'Explorateur qui lisent un fichier ne doivent pas être pris pour un ransomware.
    internal const uint WriteData = 0x2, AppendData = 0x4, Delete = 0x10000;
    private const FileSystemRights AuditedRights = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete;

    // Sous-catégorie « Système de fichiers » (indépendante de la langue de Windows)
    public static readonly Guid FileSystemAuditSubcategory = new("0CCE921D-69AE-11D9-BED3-505054503030");

    private static readonly EventLogPropertySelector Selector = new(
    [
        "Event/EventData/Data[@Name='ObjectName']",
        "Event/EventData/Data[@Name='ProcessId']",
        "Event/EventData/Data[@Name='ProcessName']",
        "Event/EventData/Data[@Name='AccessMask']"
    ]);

    private readonly Func<string, bool> _isCanary;
    private EventLogWatcher? _watcher;

    /// <param name="isCanary">Filtre : seuls les accès aux canaris sont remontés.</param>
    public CanaryAuditWatcher(Func<string, bool> isCanary) => _isCanary = isCanary;

    public event EventHandler<CanaryAccess>? Access;
    public event EventHandler<string>? Warning;

    /// <summary>Pose la règle d'audit sur un canari. Faux (avec la raison) si le privilège manque.</summary>
    public static bool TryEnableAudit(string path, out string? error)
    {
        try
        {
            var security = new FileSecurity();
            security.AddAuditRule(new FileSystemAuditRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                AuditedRights, AuditFlags.Success));
            new FileInfo(path).SetAccessControl(security); // seule la SACL est modifiée (DACL intacte)
            error = null;
            return true;
        }
        catch (Exception ex) when (ex is PrivilegeNotHeldException or UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            error = ex.GetType().Name;
            return false;
        }
    }

    /// <summary>
    /// Vrai si l'audit « Système de fichiers » est activé en succès, faux s'il est désactivé, null si la
    /// stratégie n'a pas pu être lue (droits insuffisants).
    /// </summary>
    public static bool? IsFileSystemAuditEnabled()
    {
        Guid sub = FileSystemAuditSubcategory;
        if (!AuditQuerySystemPolicy(in sub, 1, out IntPtr ptr) || ptr == IntPtr.Zero) return null;
        try
        {
            var info = Marshal.PtrToStructure<AuditPolicyInformation>(ptr);
            return (info.AuditingInformation & 0x1) != 0; // POLICY_AUDIT_EVENT_SUCCESS
        }
        finally
        {
            AuditFree(ptr);
        }
    }

    /// <summary>Démarre l'écoute du journal Sécurité. Faux si le journal est inaccessible (droits).</summary>
    public bool Start()
    {
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4663)]]");
            var watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += OnRecord;
            watcher.Enabled = true;
            _watcher = watcher;
            return true;
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or InvalidOperationException)
        {
            Warning?.Invoke(this, $"Journal Sécurité inaccessible : {ex.GetType().Name}");
            return false;
        }
    }

    private void OnRecord(object? sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            if (e.EventRecord is not EventLogRecord record) return;
            using (record)
            {
                var access = Parse(record.GetPropertyValues(Selector), record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow, _isCanary);
                if (access is not null) Access?.Invoke(this, access);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Un événement illisible ne doit pas arrêter l'écoute
        }
    }

    /// <summary>Interprète les champs d'un événement 4663 ; null si ce n'est pas une écriture sur un canari.</summary>
    internal static CanaryAccess? Parse(IList<object?> values, DateTime whenUtc, Func<string, bool> isCanary)
    {
        if (values.Count < 4 || values[0] is not string path || !isCanary(path)) return null;

        uint mask = ToUInt32(values[3]);
        if (!IsWriteAccess(mask)) return null;

        long pid = ToInt64(values[1]);
        if (pid <= 0 || pid > int.MaxValue) return null;

        return new CanaryAccess(path, (int)pid, values[2] as string ?? "?", mask, whenUtc);
    }

    internal static bool IsWriteAccess(uint mask) => (mask & (WriteData | AppendData | Delete)) != 0;

    // Les champs « HexInt » arrivent selon les versions en nombre ou en chaîne « 0x… »
    private static long ToInt64(object? value) => value switch
    {
        ulong u => unchecked((long)u),
        long l => l,
        uint u => u,
        int i => i,
        string s when s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                      long.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long h) => h,
        string s when long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out long d) => d,
        _ => -1
    };

    private static uint ToUInt32(object? value)
    {
        long v = ToInt64(value);
        return v is >= 0 and <= uint.MaxValue ? (uint)v : 0;
    }

    public void Dispose()
    {
        if (_watcher is null) return;
        _watcher.Enabled = false;
        _watcher.Dispose();
        _watcher = null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AuditQuerySystemPolicy(in Guid subCategoryGuids, uint policyCount, out IntPtr auditPolicy);

    [LibraryImport("advapi32.dll")]
    private static partial void AuditFree(IntPtr buffer);
}
