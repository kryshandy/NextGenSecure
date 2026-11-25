using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using CoreGuard.Ipc;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace CoreGuard.Ipc.Tests;

[TestClass]
public sealed class PipeTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private static string NewPipeName() => "CoreGuard.Test." + Guid.NewGuid().ToString("N");

    private static ServiceStatus Status(string behaviorState = "Active") =>
        new(IpcContract.ProtocolVersion, Environment.ProcessId, DateTime.UtcNow, "Mode utilisateur", false, false,
            [new ModuleStatus(ServiceModules.Behavior, behaviorState, "test")]);

    private static async Task<T> WithTimeout<T>(Task<T> task) =>
        await task.WaitAsync(Timeout);

    // Le serveur de test n'est pas un service (session utilisateur) : vérification de session désactivée
    private static ServiceClient DevClient(string pipe) => new(pipe, requireServiceSession: false);

    [TestMethod]
    public async Task Le_client_recoit_l_etat_a_la_connexion()
    {
        string name = NewPipeName();
        await using var server = new PipeServer(name, () => Status(), null);
        server.Start();

        await using var client = DevClient(name);
        var received = new TaskCompletionSource<ServiceStatus>();
        client.StatusReceived += (_, s) => received.TrySetResult(s);

        Assert.IsTrue(await client.ConnectAsync(Timeout));
        var status = await WithTimeout(received.Task);

        Assert.IsTrue(status.IsModuleActive(ServiceModules.Behavior));
        Assert.AreEqual(Environment.ProcessId, client.ServerProcessId);
    }

    [TestMethod]
    public async Task Les_alertes_sont_diffusees_a_tous_les_clients()
    {
        string name = NewPipeName();
        await using var server = new PipeServer(name, () => Status(), null);
        server.Start();

        await using var a = DevClient(name);
        await using var b = DevClient(name);
        var gotA = new TaskCompletionSource<ServiceAlert>();
        var gotB = new TaskCompletionSource<ServiceAlert>();
        var readyA = new TaskCompletionSource();
        var readyB = new TaskCompletionSource();
        a.AlertReceived += (_, x) => gotA.TrySetResult(x);
        b.AlertReceived += (_, x) => gotB.TrySetResult(x);
        a.StatusReceived += (_, _) => readyA.TrySetResult();
        b.StatusReceived += (_, _) => readyB.TrySetResult();

        Assert.IsTrue(await a.ConnectAsync(Timeout));
        Assert.IsTrue(await b.ConnectAsync(Timeout));
        await readyA.Task.WaitAsync(Timeout);
        await readyB.Task.WaitAsync(Timeout);
        Assert.AreEqual(2, server.ClientCount);

        server.Broadcast(new ServiceAlert("Critical", "Comportement", "SHADOW_COPY_DELETE", "vssadmin delete shadows", DateTime.UtcNow));

        Assert.AreEqual("SHADOW_COPY_DELETE", (await WithTimeout(gotA.Task)).Title);
        Assert.AreEqual("Critical", (await WithTimeout(gotB.Task)).Severity);
    }

    [TestMethod]
    public async Task Un_changement_d_etat_est_pousse_aux_clients()
    {
        string name = NewPipeName();
        string state = "Unavailable";
        await using var server = new PipeServer(name, () => Status(state), null);
        server.Start();

        await using var client = DevClient(name);
        var first = new TaskCompletionSource();
        var active = new TaskCompletionSource();
        client.StatusReceived += (_, s) =>
        {
            first.TrySetResult();
            if (s.IsModuleActive(ServiceModules.Behavior)) active.TrySetResult();
        };
        Assert.IsTrue(await client.ConnectAsync(Timeout));
        await first.Task.WaitAsync(Timeout);

        state = "Active";
        server.BroadcastStatus();
        await active.Task.WaitAsync(Timeout);
    }

    [TestMethod]
    public async Task Le_canal_refuse_toute_commande()
    {
        string name = NewPipeName();
        await using var server = new PipeServer(name, () => Status(), null);
        server.Start();

        await using var raw = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        await raw.ConnectAsync((int)Timeout.TotalMilliseconds);
        await IpcContract.WriteAsync(raw, new IpcEnvelope("terminateProcess"));

        var reply = await WithTimeout(IpcContract.ReadAsync(raw));
        Assert.AreEqual(IpcContract.Types.Error, reply!.Type);
    }

    [TestMethod]
    public async Task Une_trame_trop_grande_ferme_la_connexion()
    {
        string name = NewPipeName();
        await using var server = new PipeServer(name, () => Status(), null);
        server.Start();

        await using var raw = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        await raw.ConnectAsync((int)Timeout.TotalMilliseconds);
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, IpcContract.MaxMessageBytes + 1);
        await raw.WriteAsync(header);
        await raw.FlushAsync();

        var buffer = new byte[16];
        int read = await raw.ReadAsync(buffer).AsTask().WaitAsync(Timeout);
        Assert.AreEqual(0, read, "le serveur doit fermer la connexion");
    }

    [TestMethod]
    public async Task Un_faux_service_hors_session_0_est_rejete()
    {
        // Un serveur lancé dans la session de l'utilisateur (comme le ferait un programme malveillant
        // qui imite le pipe) ne doit pas être accepté par un client en mode production
        string name = NewPipeName();
        await using var server = new PipeServer(name, () => Status(), null);
        server.Start();

        await using var client = new ServiceClient(name, requireServiceSession: true);
        Assert.IsFalse(await client.ConnectAsync(Timeout));
        Assert.IsFalse(client.IsConnected);
    }

    [TestMethod]
    public async Task L_arret_du_service_est_signale()
    {
        string name = NewPipeName();
        var server = new PipeServer(name, () => Status(), null);
        server.Start();

        await using var client = DevClient(name);
        var ready = new TaskCompletionSource();
        var lost = new TaskCompletionSource();
        client.StatusReceived += (_, _) => ready.TrySetResult();
        client.Disconnected += (_, _) => lost.TrySetResult();
        Assert.IsTrue(await client.ConnectAsync(Timeout));
        await ready.Task.WaitAsync(Timeout);

        await server.DisposeAsync();
        await lost.Task.WaitAsync(Timeout);
        Assert.IsNull(client.LastStatus);
    }

    [TestMethod]
    public async Task Service_absent_echoue_rapidement()
    {
        await using var client = DevClient(NewPipeName());
        Assert.IsFalse(await client.ConnectAsync(TimeSpan.FromMilliseconds(300)));
    }

    [TestMethod]
    public async Task Le_cadrage_aller_retour_conserve_le_message()
    {
        using var ms = new MemoryStream();
        var alert = new ServiceAlert("Warning", "Réponse", "Arrêt impossible", "accès refusé — é", DateTime.UtcNow);
        await IpcContract.WriteAsync(ms, new IpcEnvelope(IpcContract.Types.Alert, Alert: alert));
        ms.Position = 0;

        var back = await IpcContract.ReadAsync(ms);
        Assert.AreEqual(alert, back!.Alert);
        Assert.IsNull(await IpcContract.ReadAsync(ms), "fin de flux = null");
    }

    [TestMethod]
    public async Task Un_json_invalide_est_rejete()
    {
        using var ms = new MemoryStream();
        byte[] body = Encoding.UTF8.GetBytes("{pas du json");
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, body.Length);
        ms.Write(header);
        ms.Write(body);
        ms.Position = 0;

        await Assert.ThrowsExactlyAsync<InvalidDataException>(() => IpcContract.ReadAsync(ms));
    }

    [TestMethod]
    public void L_acl_du_pipe_refuse_le_reseau()
    {
        var security = PipeServer.CreateServiceSecurity();
        var rules = security.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<PipeAccessRule>().ToList();
        var network = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.NetworkSid, null);
        Assert.IsTrue(rules.Any(r => r.IdentityReference.Equals(network) && r.AccessControlType == System.Security.AccessControl.AccessControlType.Deny));
    }
}

[TestClass]
public sealed class SecuredPipeTests
{
    [TestMethod]
    public async Task Le_pipe_avec_l_acl_du_service_accepte_plusieurs_clients()
    {
        string name = "CoreGuard.Test." + Guid.NewGuid().ToString("N");
        Exception? error = null;
        await using var server = new PipeServer(name,
            () => new ServiceStatus(1, Environment.ProcessId, DateTime.UtcNow, "x", false, false, []),
            PipeServer.CreateServiceSecurity());
        server.Error += (_, e) => error = e;
        server.Start();

        // Deux clients simultanés : le serveur doit pouvoir créer une seconde instance du pipe sécurisé
        await using var client = new ServiceClient(name, requireServiceSession: false);
        await using var second = new ServiceClient(name, requireServiceSession: false);
        Assert.IsTrue(await client.ConnectAsync(TimeSpan.FromSeconds(5)), $"connexion refusée ; erreur serveur : {error}");
        Assert.IsTrue(await second.ConnectAsync(TimeSpan.FromSeconds(5)), $"seconde connexion refusée ; erreur serveur : {error}");
        Assert.IsNull(error, $"erreur serveur : {error}");
    }
}
