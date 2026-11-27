using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CoreGuard.Network;

/// <summary>
/// Pare-feu natif Windows Filtering Platform (WFP, <c>fwpuclnt.dll</c>) : filtres posés directement dans le moteur
/// de filtrage du noyau, sans passer par le pare-feu Windows (COM). Les filtres CoreGuard vivent dans une sous-couche
/// dédiée, de poids élevé, et sont identifiés par l'AppId Windows de l'exécutable (<c>FwpmGetAppIdFromFileName0</c>).
/// <list type="bullet">
/// <item>Session dynamique : les filtres disparaissent d'eux-mêmes quand le moteur est fermé ou quand le processus
///       meurt (Mode Paranoïa, essais) — impossible de laisser la machine bloquée par erreur.</item>
/// <item>Session persistante : les filtres survivent au redémarrage (isolement d'un programme malveillant).</item>
/// </list>
/// Exige les droits administrateur (service SYSTEM ou console élevée).
/// </summary>
public sealed class WfpFirewall : IDisposable
{
    /// <summary>Sous-couche CoreGuard (clé fixe : les filtres persistants restent identifiables).</summary>
    public static readonly Guid SubLayerKey = new("6d9a3b3e-6f1c-4c2a-9a55-2c0f6c0e7a41");

    // Couches et conditions WFP (fwpmu.h)
    public static readonly Guid LayerConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    public static readonly Guid LayerConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    public static readonly Guid LayerRecvAcceptV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    public static readonly Guid LayerRecvAcceptV6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");
    private static readonly Guid ConditionAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    private static readonly Guid ConditionFlags = new("632ce23b-5167-435c-86d7-e903684aa80c");

    private const uint RpcAuthnWinNt = 10;
    private const uint SessionFlagDynamic = 0x1;
    private const uint ActionBlock = 0x1001;   // FWP_ACTION_BLOCK | FWP_ACTION_FLAG_TERMINATING
    private const uint ActionPermit = 0x1002;  // FWP_ACTION_PERMIT | FWP_ACTION_FLAG_TERMINATING
    private const uint FilterFlagPersistent = 0x1;
    private const uint SubLayerFlagPersistent = 0x1;
    private const uint TypeEmpty = 0, TypeUint8 = 1, TypeUint32 = 3, TypeByteBlob = 12;
    private const uint MatchEqual = 0, MatchFlagsAllSet = 6;
    private const uint FlagIsLoopback = 0x1;
    private const uint ErrorAlreadyExists = 0x80320009;

    private IntPtr _engine;
    private readonly bool _dynamic;

    /// <summary>Ouvre une session sur le moteur WFP local. Lève <see cref="NetworkGuardException"/> sans droits suffisants.</summary>
    public WfpFirewall(bool dynamic = true)
    {
        _dynamic = dynamic;
        var session = new FWPM_SESSION0
        {
            displayData = new FWPM_DISPLAY_DATA0 { name = "CoreGuard", description = "Pare-feu natif CoreGuard" },
            flags = dynamic ? SessionFlagDynamic : 0,
            txnWaitTimeoutInMSec = 5000
        };
        Check(FwpmEngineOpen0(null, RpcAuthnWinNt, IntPtr.Zero, ref session, out _engine), "ouverture du moteur WFP");
    }

    private bool _subLayerReady;

    public bool IsDynamic => _dynamic;

    /// <summary>Vrai si une couche existe dans le moteur (vérifie les identifiants sans rien modifier).</summary>
    public bool LayerExists(Guid layerKey) => LayerStatus(layerKey) == 0;

    /// <summary>Code de retour de la lecture d'une couche (0 = trouvée, 0x80320002 = absente, 5 = accès refusé).</summary>
    public uint LayerStatus(Guid layerKey)
    {
        uint rc = FwpmLayerGetByKey0(_engine, ref layerKey, out IntPtr layer);
        if (rc == 0) FwpmFreeMemory0(ref layer);
        return rc;
    }

    /// <summary>Bloque toutes les connexions sortantes d'un exécutable (IPv4 et IPv6). Renvoie les identifiants des filtres.</summary>
    public IReadOnlyList<ulong> BlockApplicationOutbound(string exePath, string name)
    {
        IntPtr appId = IntPtr.Zero;
        Check(FwpmGetAppIdFromFileName0(exePath, out appId), "AppId de " + Path.GetFileName(exePath));
        try
        {
            var blob = Marshal.PtrToStructure<FWP_BYTE_BLOB>(appId);
            var condition = new FWPM_FILTER_CONDITION0
            {
                fieldKey = ConditionAppId,
                matchType = MatchEqual,
                conditionValue = new FWP_VALUE0 { type = TypeByteBlob, value = appId }
            };
            _ = blob; // l'AppId est passé par pointeur, tel que renvoyé par WFP
            return InTransaction(() =>
            [
                AddFilter(name + " (IPv4)", LayerConnectV4, ActionBlock, 10, [condition]),
                AddFilter(name + " (IPv6)", LayerConnectV6, ActionBlock, 10, [condition])
            ]);
        }
        finally
        {
            FwpmFreeMemory0(ref appId);
        }
    }

    /// <summary>
    /// Mode bouclier : refuse toute connexion entrante non sollicitée (IPv4 et IPv6), sauf le trafic local (loopback),
    /// indispensable aux applications de la machine. Les réponses aux connexions sortantes ne sont pas concernées.
    /// </summary>
    public IReadOnlyList<ulong> BlockAllInbound(string name)
    {
        var loopback = new FWPM_FILTER_CONDITION0
        {
            fieldKey = ConditionFlags,
            matchType = MatchFlagsAllSet,
            conditionValue = new FWP_VALUE0 { type = TypeUint32, value = (IntPtr)FlagIsLoopback }
        };
        return InTransaction(() =>
        [
            AddFilter(name + " : local autorisé (IPv4)", LayerRecvAcceptV4, ActionPermit, 15, [loopback]),
            AddFilter(name + " : local autorisé (IPv6)", LayerRecvAcceptV6, ActionPermit, 15, [loopback]),
            AddFilter(name + " (IPv4)", LayerRecvAcceptV4, ActionBlock, 5, []),
            AddFilter(name + " (IPv6)", LayerRecvAcceptV6, ActionBlock, 5, [])
        ]);
    }

    /// <summary>Retire des filtres (absents : ignorés).</summary>
    public void Remove(IEnumerable<ulong> filterIds)
    {
        foreach (ulong id in filterIds) FwpmFilterDeleteById0(_engine, id);
    }

    private IReadOnlyList<ulong> InTransaction(Func<ulong[]> work)
    {
        if (!_subLayerReady) { EnsureSubLayer(); _subLayerReady = true; }
        Check(FwpmTransactionBegin0(_engine, 0), "début de transaction WFP");
        try
        {
            ulong[] ids = work();
            Check(FwpmTransactionCommit0(_engine), "validation de la transaction WFP");
            return ids;
        }
        catch
        {
            FwpmTransactionAbort0(_engine);
            throw;
        }
    }

    private ulong AddFilter(string name, Guid layer, uint action, byte weight, FWPM_FILTER_CONDITION0[] conditions)
    {
        int size = Marshal.SizeOf<FWPM_FILTER_CONDITION0>();
        IntPtr array = conditions.Length == 0 ? IntPtr.Zero : Marshal.AllocHGlobal(size * conditions.Length);
        try
        {
            for (int i = 0; i < conditions.Length; i++) Marshal.StructureToPtr(conditions[i], array + i * size, false);
            var filter = new FWPM_FILTER0
            {
                displayData = new FWPM_DISPLAY_DATA0 { name = "CoreGuard — " + name, description = "Filtre posé par CoreGuard" },
                flags = _dynamic ? 0 : FilterFlagPersistent,
                layerKey = layer,
                subLayerKey = SubLayerKey,
                weight = new FWP_VALUE0 { type = TypeUint8, value = (IntPtr)weight },
                numFilterConditions = (uint)conditions.Length,
                filterCondition = array,
                action = new FWPM_ACTION0 { type = action }
            };
            Check(FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out ulong id), "ajout du filtre « " + name + " »");
            return id;
        }
        finally
        {
            if (array != IntPtr.Zero) Marshal.FreeHGlobal(array);
        }
    }

    private void EnsureSubLayer()
    {
        var subLayer = new FWPM_SUBLAYER0
        {
            subLayerKey = SubLayerKey,
            displayData = new FWPM_DISPLAY_DATA0 { name = "CoreGuard", description = "Filtres de l'antivirus CoreGuard" },
            flags = _dynamic ? 0 : SubLayerFlagPersistent,
            weight = 0xFFFF // prioritaire sur les autres sous-couches
        };
        uint rc = FwpmSubLayerAdd0(_engine, ref subLayer, IntPtr.Zero);
        if (rc != 0 && rc != ErrorAlreadyExists) Check(rc, "création de la sous-couche CoreGuard");
    }

    private static void Check(uint rc, string what)
    {
        if (rc == 0) return;
        string detail = rc == 5 || rc == 0x80070005 ? "droits administrateur requis" : $"code 0x{rc:X8}";
        throw new NetworkGuardException($"WFP : {what} impossible ({detail}).", new Win32Exception(unchecked((int)rc)));
    }

    public void Dispose()
    {
        if (_engine == IntPtr.Zero) return;
        FwpmEngineClose0(_engine); // session dynamique : tous ses filtres sont retirés ici
        _engine = IntPtr.Zero;
    }

    // ---------------------------------------------------------------- Interop (fwpmu.h, x64)

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FWPM_DISPLAY_DATA0
    {
        public string? name;
        public string? description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_BYTE_BLOB
    {
        public uint size;
        public IntPtr data;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FWPM_SESSION0
    {
        public Guid sessionKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public uint txnWaitTimeoutInMSec;
        public uint processId;
        public IntPtr sid;
        public IntPtr username;
        public int kernelMode;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    /// <summary>FWP_VALUE0 et FWP_CONDITION_VALUE0 : type + union de 8 octets (valeur ou pointeur).</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_VALUE0
    {
        public uint type;
        public IntPtr value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public uint matchType;
        public FWP_VALUE0 conditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_ACTION0
    {
        public uint type;
        public Guid filterTypeOrCalloutKey;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION0 action;
        public ulong providerContext0;   // union { UINT64 rawContext; GUID providerContextKey; } : 16 octets
        public ulong providerContext1;
        public IntPtr reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity, ref FWPM_SESSION0 session, out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr layer);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr p);
}
