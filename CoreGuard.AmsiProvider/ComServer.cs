using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CoreGuard.AmsiProvider;

/// <summary>
/// Serveur COM minimal écrit à la main (pas de ComWrappers : compatible NativeAOT, aucune réflexion).
/// Deux objets statiques et sans état : la fabrique de classe et le fournisseur AMSI. Leur durée de vie n'a
/// pas besoin de compteur de références (AddRef/Release renvoient une valeur fixe, DllCanUnloadNow répond
/// toujours « non ») : la DLL reste chargée jusqu'à la fin du processus hôte, comme les fournisseurs AMSI usuels.
/// RÈGLE ABSOLUE : aucune exception ne doit sortir d'une méthode [UnmanagedCallersOnly] (le processus hôte
/// planterait) ; tout est intercepté et, en cas de doute, le contenu est déclaré « non détecté ».
/// </summary>
public static unsafe class ComServer
{
    // Doit correspondre à CoreGuard.Ipc.AmsiProviderInfo.Clsid et aux scripts d'enregistrement
    internal static readonly Guid Clsid = new("6B3C2F1E-8A4D-4C7B-9E21-C0A5E9F4D317");
    private static readonly Guid IidUnknown = new("00000000-0000-0000-C000-000000000046");
    private static readonly Guid IidClassFactory = new("00000001-0000-0000-C000-000000000046");
    private static readonly Guid IidAntimalwareProvider = new("B2CABFE3-FE04-42B1-A5DF-08D483D4D125");

    private const int S_OK = 0;
    private const int S_FALSE = 1;
    private const int E_NOINTERFACE = unchecked((int)0x80004002);
    private const int E_POINTER = unchecked((int)0x80004003);
    private const int E_FAIL = unchecked((int)0x80004005);
    private const int CLASS_E_NOAGGREGATION = unchecked((int)0x80040110);
    private const int CLASS_E_CLASSNOTAVAILABLE = unchecked((int)0x80040111);

    private const int AmsiResultNotDetected = 1;
    private const int AmsiResultDetected = 32768;

    private static readonly object Gate = new();
    private static void* s_factory;
    private static void* s_provider;

    // Un objet COM = un pointeur vers sa table de méthodes (vtable)
    private static void EnsureObjects()
    {
        if (s_provider is not null) return;
        lock (Gate)
        {
            if (s_provider is not null) return;

            var factoryVtbl = (void**)NativeMemory.Alloc(5, (nuint)sizeof(void*));
            factoryVtbl[0] = (delegate* unmanaged<void*, Guid*, void**, int>)&FactoryQueryInterface;
            factoryVtbl[1] = (delegate* unmanaged<void*, uint>)&AddRef;
            factoryVtbl[2] = (delegate* unmanaged<void*, uint>)&Release;
            factoryVtbl[3] = (delegate* unmanaged<void*, void*, Guid*, void**, int>)&CreateInstance;
            factoryVtbl[4] = (delegate* unmanaged<void*, int, int>)&LockServer;

            var providerVtbl = (void**)NativeMemory.Alloc(6, (nuint)sizeof(void*));
            providerVtbl[0] = (delegate* unmanaged<void*, Guid*, void**, int>)&ProviderQueryInterface;
            providerVtbl[1] = (delegate* unmanaged<void*, uint>)&AddRef;
            providerVtbl[2] = (delegate* unmanaged<void*, uint>)&Release;
            providerVtbl[3] = (delegate* unmanaged<void*, void*, int*, int>)&Scan;
            providerVtbl[4] = (delegate* unmanaged<void*, ulong, void>)&CloseSession;
            providerVtbl[5] = (delegate* unmanaged<void*, char**, int>)&DisplayName;

            var factory = (void**)NativeMemory.Alloc(1, (nuint)sizeof(void*));
            *factory = factoryVtbl;
            var provider = (void**)NativeMemory.Alloc(1, (nuint)sizeof(void*));
            *provider = providerVtbl;

            s_factory = factory;
            s_provider = provider; // publié en dernier : EnsureObjects est idempotent
        }
    }

    // ---------- Exports de la DLL ----------

    [UnmanagedCallersOnly(EntryPoint = "DllGetClassObject")]
    private static int DllGetClassObject(Guid* clsid, Guid* iid, void** ppv)
    {
        try
        {
            if (ppv is null) return E_POINTER;
            *ppv = null;
            if (clsid is null || iid is null || *clsid != Clsid) return CLASS_E_CLASSNOTAVAILABLE;
            EnsureObjects();
            if (*iid != IidClassFactory && *iid != IidUnknown) return E_NOINTERFACE;
            *ppv = s_factory;
            return S_OK;
        }
        catch
        {
            return E_FAIL;
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "DllCanUnloadNow")]
    private static int DllCanUnloadNow() => S_FALSE;

    // ---------- IUnknown (commun) ----------

    [UnmanagedCallersOnly]
    private static uint AddRef(void* self) => 2;

    [UnmanagedCallersOnly]
    private static uint Release(void* self) => 1;

    // ---------- IClassFactory ----------

    [UnmanagedCallersOnly]
    private static int FactoryQueryInterface(void* self, Guid* iid, void** ppv)
    {
        if (ppv is null) return E_POINTER;
        if (iid is not null && (*iid == IidUnknown || *iid == IidClassFactory)) { *ppv = self; return S_OK; }
        *ppv = null;
        return E_NOINTERFACE;
    }

    [UnmanagedCallersOnly]
    private static int CreateInstance(void* self, void* outer, Guid* iid, void** ppv)
    {
        try
        {
            if (ppv is null) return E_POINTER;
            *ppv = null;
            if (outer is not null) return CLASS_E_NOAGGREGATION;
            EnsureObjects();
            if (iid is null || (*iid != IidUnknown && *iid != IidAntimalwareProvider)) return E_NOINTERFACE;
            *ppv = s_provider;
            return S_OK;
        }
        catch
        {
            return E_FAIL;
        }
    }

    [UnmanagedCallersOnly]
    private static int LockServer(void* self, int fLock) => S_OK;

    // ---------- IAntimalwareProvider ----------

    [UnmanagedCallersOnly]
    private static int ProviderQueryInterface(void* self, Guid* iid, void** ppv)
    {
        if (ppv is null) return E_POINTER;
        if (iid is not null && (*iid == IidUnknown || *iid == IidAntimalwareProvider)) { *ppv = self; return S_OK; }
        *ppv = null;
        return E_NOINTERFACE;
    }

    [UnmanagedCallersOnly]
    private static int Scan(void* self, void* stream, int* result)
    {
        if (result is null) return E_POINTER;
        *result = AmsiResultNotDetected;
        try
        {
            if (stream is null) return S_OK;
            var content = AmsiStream.Read(stream, out string app, out string? contentName);
            if (content.Length > 0 && ScanClient.IsMalicious(app, contentName, content))
                *result = AmsiResultDetected;
        }
        catch
        {
            // Fail-open : une erreur du fournisseur ne doit jamais casser PowerShell
            *result = AmsiResultNotDetected;
        }
        return S_OK;
    }

    [UnmanagedCallersOnly]
    private static void CloseSession(void* self, ulong session) { }

    [UnmanagedCallersOnly]
    private static int DisplayName(void* self, char** name)
    {
        if (name is null) return E_POINTER;
        try
        {
            *name = (char*)Marshal.StringToCoTaskMemUni("CoreGuard");
            return S_OK;
        }
        catch
        {
            *name = null;
            return E_FAIL;
        }
    }
}

/// <summary>Lecture d'un IAmsiStream (attributs et contenu) via sa vtable.</summary>
internal static unsafe class AmsiStream
{
    private const int AttrAppName = 0, AttrContentName = 1, AttrContentSize = 2, AttrContentAddress = 3;
    public const int MaxContentBytes = 512 * 1024;

    // vtable IAmsiStream : 0 QI, 1 AddRef, 2 Release, 3 GetAttribute, 4 Read
    public static byte[] Read(void* stream, out string app, out string? contentName)
    {
        void** vtbl = *(void***)stream;
        var getAttribute = (delegate* unmanaged<void*, int, uint, byte*, uint*, int>)vtbl[3];
        var read = (delegate* unmanaged<void*, ulong, uint, byte*, uint*, int>)vtbl[4];

        app = ReadString(stream, getAttribute, AttrAppName) ?? "?";
        contentName = ReadString(stream, getAttribute, AttrContentName);

        ulong size = 0;
        uint ret = 0;
        if (getAttribute(stream, AttrContentSize, sizeof(ulong), (byte*)&size, &ret) != 0 || size == 0) return [];
        int length = (int)Math.Min(size, MaxContentBytes);

        void* address = null;
        if (getAttribute(stream, AttrContentAddress, (uint)sizeof(void*), (byte*)&address, &ret) == 0 && address is not null)
            return new ReadOnlySpan<byte>(address, length).ToArray();

        // Pas d'adresse directe : lecture par le flux
        var buffer = new byte[length];
        fixed (byte* p = buffer)
        {
            uint total = 0;
            while (total < length)
            {
                uint got = 0;
                if (read(stream, total, (uint)length - total, p + total, &got) != 0 || got == 0) break;
                total += got;
            }
            return total == length ? buffer : buffer[..(int)total];
        }
    }

    private static string? ReadString(void* stream, delegate* unmanaged<void*, int, uint, byte*, uint*, int> getAttribute, int attribute)
    {
        const int max = 1024;
        byte* buffer = stackalloc byte[max];
        uint ret = 0;
        if (getAttribute(stream, attribute, max, buffer, &ret) != 0 || ret < 2) return null;
        return new string((char*)buffer, 0, (int)Math.Min(ret, max) / 2).TrimEnd('\0');
    }
}
