using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using AntivirusIA.Core.Interfaces;

namespace CoreGuard.Response;

/// <summary>
/// Actions de réponse en mode utilisateur (aucun driver) : Win32 / NT natif, ACL NTFS et DACL de processus.
/// LIMITES (levées par le futur driver) :
/// - un processus élevé ne peut être arrêté que si CoreGuard l'est aussi ;
/// - un administrateur disposant de SeDebugPrivilege contourne la DACL d'un processus ;
/// - l'arrêt intervient après le démarrage du processus, pas avant.
/// </summary>
public sealed class UserModeActionProvider : IKernelActionProvider
{
    // Processus dont l'arrêt planterait ou paralyserait Windows : jamais touchés, quel que soit le verdict.
    private static readonly HashSet<string> CriticalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "Secure System", "Memory Compression", "smss", "csrss", "wininit",
        "winlogon", "services", "lsass", "lsaiso", "svchost", "fontdrvhost", "dwm", "explorer", "MsMpEng",
        "NisSrv", "SecurityHealthService", "sihost", "ctfmon", "taskhostw", "RuntimeBroker"
    };

    private readonly Func<string, string, bool>? _blockApplication;
    private readonly HashSet<int> _protectedPids = [];
    private readonly object _gate = new();

    /// <param name="blockApplication">
    /// Blocage réseau d'un exécutable (nom de règle, chemin) → vrai si la règle a été posée.
    /// Fourni par la composition root (pare-feu), pour que ce module ne dépende que de Core.
    /// </param>
    public UserModeActionProvider(Func<string, string, bool>? blockApplication = null)
    {
        _blockApplication = blockApplication;
        _protectedPids.Add(Environment.ProcessId);
    }

    public string Name => "Mode utilisateur";

    public bool IsKernelBacked => false;

    /// <summary>Ajoute un processus à ne jamais arrêter (ex. watchdog CoreGuard).</summary>
    public void AddProtectedProcess(int pid)
    {
        lock (_gate) _protectedPids.Add(pid);
    }

    // ---------- Processus ----------

    public Task<ActionResult> TerminateProcessAsync(int pid, string reason, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            if (CheckTarget(pid) is { } refus) return refus;

            using var h = Native.OpenProcess(Native.ProcessTerminate | Native.Synchronize | Native.ProcessQueryLimitedInformation, false, pid);
            if (h.IsInvalid) return OpenFailure(pid);

            if (!Native.TerminateProcess(h, Native.ExitCodeTerminatedByCoreGuard))
                return ActionResult.Fail($"Arrêt du PID {pid} refusé (erreur {Native.LastError}).");

            Native.WaitForSingleObject(h, 3000);
            return ActionResult.Ok($"Processus {pid} arrêté : {reason}");
        }, ct);

    public Task<ActionResult> SuspendProcessAsync(int pid, CancellationToken ct = default) =>
        Task.Run(() => SuspendOrResume(pid, suspend: true), ct);

    public Task<ActionResult> ResumeProcessAsync(int pid, CancellationToken ct = default) =>
        Task.Run(() => SuspendOrResume(pid, suspend: false), ct);

    private ActionResult SuspendOrResume(int pid, bool suspend)
    {
        if (CheckTarget(pid) is { } refus) return refus;

        using var h = Native.OpenProcess(Native.ProcessSuspendResume, false, pid);
        if (h.IsInvalid) return OpenFailure(pid);

        int status = suspend ? Native.NtSuspendProcess(h) : Native.NtResumeProcess(h);
        return status == 0
            ? ActionResult.Ok($"Processus {pid} {(suspend ? "suspendu" : "repris")}.")
            : ActionResult.Fail($"{(suspend ? "Suspension" : "Reprise")} du PID {pid} impossible (NTSTATUS 0x{status:X8}).");
    }

    /// <summary>Refus des cibles interdites : null si l'action est permise.</summary>
    internal ActionResult? CheckTarget(int pid)
    {
        if (pid <= 4) return ActionResult.Fail($"PID {pid} : processus système, action refusée.");
        lock (_gate)
            if (_protectedPids.Contains(pid)) return ActionResult.Fail($"PID {pid} : processus CoreGuard protégé, action refusée.");

        string name;
        try
        {
            using var p = Process.GetProcessById(pid);
            name = p.ProcessName;
        }
        catch (ArgumentException)
        {
            return ActionResult.Fail($"PID {pid} : processus introuvable (déjà terminé ?).");
        }
        catch (InvalidOperationException)
        {
            return ActionResult.Fail($"PID {pid} : processus déjà terminé.");
        }

        if (CriticalNames.Contains(name))
            return ActionResult.Fail($"{name} (PID {pid}) est un processus critique de Windows : action refusée.");

        // Processus marqué critique par Windows : l'arrêter provoquerait un écran bleu
        using var q = Native.OpenProcess(Native.ProcessQueryLimitedInformation, false, pid);
        if (!q.IsInvalid && Native.IsProcessCritical(q, out bool critical) && critical)
            return ActionResult.Fail($"{name} (PID {pid}) est marqué critique par Windows : action refusée.");

        return null;
    }

    private static ActionResult OpenFailure(int pid) =>
        Native.LastError == Native.ErrorAccessDenied
            ? ActionResult.Fail($"Accès refusé au PID {pid} (processus élevé ou protégé : CoreGuard doit être administrateur).")
            : ActionResult.Fail($"Ouverture du PID {pid} impossible (erreur {Native.LastError}).");

    // ---------- Réseau ----------

    public Task<ActionResult> BlockNetworkAsync(int pid, string? imagePath, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            if (_blockApplication is null)
                return ActionResult.Fail("Aucun pare-feu disponible pour le blocage réseau.");

            string? path = string.IsNullOrWhiteSpace(imagePath) ? Native.GetImagePath(pid) : imagePath;
            if (string.IsNullOrWhiteSpace(path))
                return ActionResult.Fail($"Chemin de l'exécutable du PID {pid} introuvable.");

            try
            {
                string rule = $"Block-{Path.GetFileNameWithoutExtension(path)}-{pid}";
                return _blockApplication(rule, path)
                    ? ActionResult.Ok($"Connexions sortantes de {Path.GetFileName(path)} bloquées.")
                    : ActionResult.Fail($"Blocage réseau de {Path.GetFileName(path)} refusé (droits administrateur requis ?).");
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return ActionResult.Fail($"Blocage réseau impossible : {ex.GetType().Name}");
            }
        }, ct);

    // ---------- Fichiers ----------

    public Task<ActionResult> ProtectFileAsync(string path, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            try
            {
                var file = new FileInfo(path);
                if (!file.Exists) return ActionResult.Fail("Fichier introuvable.");
                file.SetAccessControl(BuildQuarantineAcl());
                return ActionResult.Ok($"Droits NTFS restreints sur {file.Name}.");
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PrivilegeNotHeldException)
            {
                return ActionResult.Fail($"Restriction NTFS impossible : {ex.GetType().Name}");
            }
        }, ct);

    /// <summary>
    /// ACL d'un fichier isolé : héritage coupé ; SYSTEM et Administrateurs en contrôle total ; l'utilisateur garde
    /// lecture / écriture / suppression (restauration possible) ; l'exécution est refusée à tous.
    /// </summary>
    internal static FileSecurity BuildQuarantineAcl()
    {
        var acl = new FileSecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var user = WindowsIdentity.GetCurrent().User!;

        acl.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.ExecuteFile, AccessControlType.Deny));
        acl.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(user,
            FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete, AccessControlType.Allow));
        return acl;
    }

    // ---------- Auto-protection ----------

    public Task<ActionResult> ProtectSelfAsync(CancellationToken ct = default) =>
        Task.Run(() => ProtectProcess(Environment.ProcessId), ct);

    /// <summary>
    /// Remplace la DACL du processus : SYSTEM garde tous les droits, tous les autres (propriétaire compris, via
    /// « OWNER RIGHTS ») ne gardent que la consultation. Arrêt, suspension, écriture mémoire, création de thread
    /// distant et modification de la DACL deviennent impossibles sans SeDebugPrivilege.
    /// </summary>
    internal static ActionResult ProtectProcess(int pid)
    {
        using var h = Native.OpenProcess(Native.WriteDac, false, pid);
        if (h.IsInvalid) return OpenFailure(pid);

        byte[] dacl = BuildProcessDacl();
        uint err = Native.SetSecurityInfo(h, Native.SeKernelObject, Native.DaclSecurityInformation,
            IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
        return err == 0
            ? ActionResult.Ok($"Processus {pid} protégé contre l'arrêt et l'injection.")
            : ActionResult.Fail($"Durcissement du PID {pid} impossible (erreur {err}).");
    }

    internal static byte[] BuildProcessDacl()
    {
        const int limited = Native.ProcessQueryLimitedInformation | Native.Synchronize | Native.ReadControl;

        var acl = new RawAcl(GenericAcl.AclRevision, 3);
        acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, Native.ProcessAllAccess,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), false, null));
        // OWNER RIGHTS : retire au propriétaire les droits implicites READ_CONTROL / WRITE_DAC
        acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, limited,
            new SecurityIdentifier("S-1-3-4"), false, null));
        acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, limited,
            new SecurityIdentifier(WellKnownSidType.WorldSid, null), false, null));

        var bytes = new byte[acl.BinaryLength];
        acl.GetBinaryForm(bytes, 0);
        return bytes;
    }
}
