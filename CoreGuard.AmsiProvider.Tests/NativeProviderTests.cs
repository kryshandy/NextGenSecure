using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using CoreGuard.Ipc;

// Les variables d'environnement lues par le fournisseur sont globales au processus : tests en série
[assembly: DoNotParallelize]

namespace CoreGuard.AmsiProvider.Tests;

/// <summary>
/// Teste la VRAIE DLL native (sortie NativeAOT) comme le ferait amsi.dll : DllGetClassObject, fabrique de classe,
/// IAntimalwareProvider::Scan sur un faux IAmsiStream. Ignoré (Inconclusive) si la DLL n'a pas été compilée
/// (scripts/build-amsi-provider.ps1).
/// </summary>
[TestClass]
public sealed class NativeProviderTests
{
    private static readonly Guid Clsid = new(AmsiProviderInfo.Clsid);
    private static readonly Guid IidClassFactory = new("00000001-0000-0000-C000-000000000046");
    private static readonly Guid IidAntimalwareProvider = new("B2CABFE3-FE04-42B1-A5DF-08D483D4D125");
    private const int AmsiNotDetected = 1, AmsiDetected = 32768;

    private static IntPtr s_library;
    private static unsafe void* s_provider;

    [ClassInitialize]
    public static void Load(TestContext _)
    {
        string dll = Path.Combine(RepoRoot(), "CoreGuard.AmsiProvider", "bin", "publish", "CoreGuard.AmsiProvider.dll");
        if (!File.Exists(dll)) return;
        s_library = NativeLibrary.Load(dll);
    }

    private static unsafe void* Provider()
    {
        if (s_library == IntPtr.Zero) Assert.Inconclusive("DLL NativeAOT absente : lancez scripts/build-amsi-provider.ps1.");
        if (s_provider is not null) return s_provider;

        var getClassObject = (delegate* unmanaged<Guid*, Guid*, void**, int>)NativeLibrary.GetExport(s_library, "DllGetClassObject");
        Guid clsid = Clsid, iidFactory = IidClassFactory, iidProvider = IidAntimalwareProvider;
        void* factory;
        Assert.AreEqual(0, getClassObject(&clsid, &iidFactory, &factory));

        var createInstance = (delegate* unmanaged<void*, void*, Guid*, void**, int>)(*(void***)factory)[3];
        void* provider;
        Assert.AreEqual(0, createInstance(factory, null, &iidProvider, &provider));
        return s_provider = provider;
    }

    private static unsafe int Scan(string app, byte[] content)
    {
        void* provider = Provider();
        using var stream = new FakeAmsiStream(app, content);
        var scan = (delegate* unmanaged<void*, void*, int*, int>)(*(void***)provider)[3];
        int result = -1;
        Assert.AreEqual(0, scan(provider, stream.Pointer, &result));
        return result;
    }

    private static string NewPipe() => "CoreGuard.Test.Amsi." + Guid.NewGuid().ToString("N");

    private static void UseDevPipe(string? pipe)
    {
        Environment.SetEnvironmentVariable("COREGUARD_DEV_SERVICE", pipe is null ? null : "1");
        Environment.SetEnvironmentVariable("COREGUARD_AMSI_PIPE", pipe);
    }

    [TestCleanup]
    public void Reset() => UseDevPipe(null);

    [TestMethod]
    public unsafe void Un_clsid_inconnu_est_refuse()
    {
        if (s_library == IntPtr.Zero) Assert.Inconclusive("DLL NativeAOT absente.");
        var getClassObject = (delegate* unmanaged<Guid*, Guid*, void**, int>)NativeLibrary.GetExport(s_library, "DllGetClassObject");
        Guid other = Guid.NewGuid(), iid = IidClassFactory;
        void* ppv;
        Assert.AreEqual(unchecked((int)0x80040111), getClassObject(&other, &iid, &ppv)); // CLASS_E_CLASSNOTAVAILABLE
    }

    [TestMethod]
    public unsafe void Le_fournisseur_se_presente_sous_le_nom_CoreGuard()
    {
        void* provider = Provider();
        var displayName = (delegate* unmanaged<void*, char**, int>)(*(void***)provider)[5];
        char* name;
        Assert.AreEqual(0, displayName(provider, &name));
        try { Assert.AreEqual("CoreGuard", new string(name)); }
        finally { Marshal.FreeCoTaskMem((IntPtr)name); }
    }

    [TestMethod]
    public void Sans_service_le_script_passe_rapidement()
    {
        UseDevPipe(NewPipe()); // pipe que personne n'écoute
        var sw = Stopwatch.StartNew();
        Assert.AreEqual(AmsiNotDetected, Scan("powershell", Encoding.Unicode.GetBytes("Write-Output 1")));
        Assert.IsLessThan(1000, sw.ElapsedMilliseconds, "fail-open rapide attendu");

        sw.Restart(); // second appel : service mémorisé comme absent, aucun délai
        Assert.AreEqual(AmsiNotDetected, Scan("powershell", Encoding.Unicode.GetBytes("Write-Output 2")));
        Assert.IsLessThan(100, sw.ElapsedMilliseconds);
    }

    [TestMethod]
    public async Task Le_verdict_du_service_bloque_ou_laisse_passer()
    {
        string pipe = NewPipe();
        var received = new List<AmsiScanRequest>();
        IpcEnvelope? Handle(IpcEnvelope r)
        {
            if (r.Type != IpcContract.Types.AmsiScan || r.Amsi is null) return null;
            lock (received) received.Add(r.Amsi);
            string text = Encoding.Unicode.GetString(Convert.FromBase64String(r.Amsi.Content));
            bool bad = text.Contains("MARQUEUR-MALVEILLANT");
            return new IpcEnvelope(IpcContract.Types.AmsiResult, AmsiVerdict: new AmsiVerdict(bad, bad ? 100 : 0, "test"));
        }

        await using var server = new PipeServer(pipe,
            () => new ServiceStatus(1, Environment.ProcessId, DateTime.UtcNow, "x", false, false, []), null, Handle);
        server.Start();
        UseDevPipe(pipe);

        Assert.AreEqual(AmsiDetected, Scan("powershell.exe", Encoding.Unicode.GetBytes("Write-Output 'MARQUEUR-MALVEILLANT'")));
        Assert.AreEqual(AmsiNotDetected, Scan("powershell.exe", Encoding.Unicode.GetBytes("Get-Date")));

        Assert.HasCount(2, received);
        Assert.AreEqual("powershell.exe", received[0].App);
        Assert.AreEqual("demo.ps1", received[0].ContentName);
    }

    [TestMethod]
    public async Task Chaine_complete_le_specimen_01_est_bloque_par_l_analyseur_du_service()
    {
        // DLL native -> pipe -> analyseur réel du service (règles Data/rules.json), comme en production
        var scanner = new CoreGuard.Service.ScriptScanner(
            new AntivirusIA.Engines.PatternRuleEngine(Path.Combine(AppContext.BaseDirectory, "Data", "rules.json")));
        string pipe = NewPipe();
        await using var server = new PipeServer(pipe,
            () => new ServiceStatus(1, Environment.ProcessId, DateTime.UtcNow, "x", false, false, []), null,
            r => r.Type == IpcContract.Types.AmsiScan
                ? new IpcEnvelope(IpcContract.Types.AmsiResult, AmsiVerdict: scanner.Evaluate(r.Amsi))
                : null);
        server.Start();
        UseDevPipe(pipe);

        string demo = File.ReadAllText(Path.Combine(RepoRoot(), "demo", "01-powershell-amsi", "demo-amsi.ps1"));
        Assert.AreEqual(AmsiDetected, Scan("powershell.exe", Encoding.Unicode.GetBytes(demo)));
        Assert.AreEqual(AmsiNotDetected, Scan("powershell.exe", Encoding.Unicode.GetBytes("Get-Process | Select-Object -First 5")));
    }

    [TestMethod]
    public async Task Une_reponse_invalide_du_serveur_laisse_passer()
    {
        string pipe = NewPipe();
        await using var server = new PipeServer(pipe,
            () => new ServiceStatus(1, Environment.ProcessId, DateTime.UtcNow, "x", false, false, []), null,
            _ => new IpcEnvelope(IpcContract.Types.Error, Error: "refus"));
        server.Start();
        UseDevPipe(pipe);

        Assert.AreEqual(AmsiNotDetected, Scan("powershell.exe", Encoding.Unicode.GetBytes("Get-Date")));
    }

    [TestMethod]
    public void En_production_un_faux_service_hors_session_0_est_ignore()
    {
        // Sans le mode développement, le fournisseur vise le pipe de production et exige la session 0.
        // Un serveur lancé ici (session utilisateur) sur ce nom serait rejeté ; on vérifie au moins qu'un
        // pipe de production absent ou non authentique ne bloque jamais le script.
        UseDevPipe(null);
        Assert.AreEqual(AmsiNotDetected, Scan("powershell.exe", Encoding.Unicode.GetBytes("Get-Date")));
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AntivirusIA.slnx"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Racine du dépôt introuvable");
    }
}

/// <summary>Faux IAmsiStream (vtable native) : nom d'application, nom de contenu, taille et adresse du contenu.</summary>
internal sealed unsafe class FakeAmsiStream : IDisposable
{
    private static readonly void** Vtbl = CreateVtbl();
    private readonly GCHandle _self;
    private readonly IntPtr _object;
    private readonly IntPtr _content;
    private readonly int _length;
    private readonly string _app;

    public FakeAmsiStream(string app, byte[] content)
    {
        _app = app;
        _length = content.Length;
        _content = Marshal.AllocHGlobal(Math.Max(1, content.Length));
        Marshal.Copy(content, 0, _content, content.Length);
        _self = GCHandle.Alloc(this);
        // Objet natif : [vtable][handle vers l'instance managée]
        _object = Marshal.AllocHGlobal(2 * sizeof(void*));
        ((void**)_object)[0] = Vtbl;
        ((IntPtr*)_object)[1] = GCHandle.ToIntPtr(_self);
    }

    public void* Pointer => (void*)_object;

    private static void** CreateVtbl()
    {
        var v = (void**)NativeMemory.Alloc(5, (nuint)sizeof(void*));
        v[0] = (delegate* unmanaged<void*, Guid*, void**, int>)&QueryInterface;
        v[1] = (delegate* unmanaged<void*, uint>)&AddRef;
        v[2] = (delegate* unmanaged<void*, uint>)&Release;
        v[3] = (delegate* unmanaged<void*, int, uint, byte*, uint*, int>)&GetAttribute;
        v[4] = (delegate* unmanaged<void*, ulong, uint, byte*, uint*, int>)&Read;
        return v;
    }

    private static FakeAmsiStream From(void* self) => (FakeAmsiStream)GCHandle.FromIntPtr(((IntPtr*)self)[1]).Target!;

    [UnmanagedCallersOnly] private static int QueryInterface(void* self, Guid* iid, void** ppv) { *ppv = null; return unchecked((int)0x80004002); }
    [UnmanagedCallersOnly] private static uint AddRef(void* self) => 1;
    [UnmanagedCallersOnly] private static uint Release(void* self) => 1;

    [UnmanagedCallersOnly]
    private static int GetAttribute(void* self, int attribute, uint size, byte* data, uint* retData)
    {
        var s = From(self);
        switch (attribute)
        {
            case 0: return WriteString(s._app, size, data, retData);          // APP_NAME
            case 1: return WriteString("demo.ps1", size, data, retData);      // CONTENT_NAME
            case 2: *(ulong*)data = (ulong)s._length; *retData = 8; return 0; // CONTENT_SIZE
            case 3: *(IntPtr*)data = s._content; *retData = (uint)sizeof(IntPtr); return 0; // CONTENT_ADDRESS
            default: return unchecked((int)0x80070057);                       // E_INVALIDARG
        }
    }

    [UnmanagedCallersOnly]
    private static int Read(void* self, ulong position, uint size, byte* buffer, uint* read) { *read = 0; return unchecked((int)0x80004005); }

    private static int WriteString(string value, uint size, byte* data, uint* retData)
    {
        byte[] bytes = Encoding.Unicode.GetBytes(value + "\0");
        *retData = (uint)bytes.Length;
        if (bytes.Length > size) return unchecked((int)0x8007007A); // E_NOT_SUFFICIENT_BUFFER
        bytes.CopyTo(new Span<byte>(data, bytes.Length));
        return 0;
    }

    public void Dispose()
    {
        Marshal.FreeHGlobal(_object);
        Marshal.FreeHGlobal(_content);
        _self.Free();
    }
}
