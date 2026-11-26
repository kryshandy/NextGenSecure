using CoreGuard.Ipc;

namespace CoreGuard.Ipc.Tests;

[TestClass]
public sealed class StopAuthenticationTests
{
    // Itérations réduites pour la vitesse des tests (le produit utilise 600 000)
    private const int FastIterations = 1_000;
    private const string Password = "Correct-Horse-42";

    private sealed class ManualTime(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static (StopAuthenticator auth, ManualTime time) Create()
    {
        var time = new ManualTime(new DateTimeOffset(2026, 11, 26, 10, 0, 0, TimeSpan.Zero));
        return (new StopAuthenticator(ProtectionSecret.Create(Password, FastIterations), time), time);
    }

    private static StopRequest Answer(StopChallenge c, string password) => new(c.Nonce, StopProtocol.Answer(password, c));

    [TestMethod]
    public void Le_bon_mot_de_passe_est_accepte()
    {
        var (auth, _) = Create();
        var challenge = auth.IssueChallenge()!;
        Assert.IsTrue(auth.Verify(Answer(challenge, Password)).Accepted);
    }

    [TestMethod]
    public void Un_mauvais_mot_de_passe_est_refuse()
    {
        var (auth, _) = Create();
        var result = auth.Verify(Answer(auth.IssueChallenge()!, "mauvais-mdp"));
        Assert.IsFalse(result.Accepted);
        StringAssert.Contains(result.Message, "incorrect");
    }

    [TestMethod]
    public void Une_reponse_capturee_ne_peut_pas_etre_rejouee()
    {
        var (auth, _) = Create();
        var request = Answer(auth.IssueChallenge()!, Password);
        Assert.IsTrue(auth.Verify(request).Accepted);
        Assert.IsFalse(auth.Verify(request).Accepted, "nonce à usage unique");
    }

    [TestMethod]
    public void Un_defi_expire_est_refuse()
    {
        var (auth, time) = Create();
        var request = Answer(auth.IssueChallenge()!, Password);
        time.Now += StopAuthenticator.NonceLifetime + TimeSpan.FromSeconds(1);
        Assert.IsFalse(auth.Verify(request).Accepted);
    }

    [TestMethod]
    public void Un_nonce_invente_est_refuse()
    {
        var (auth, _) = Create();
        var forged = new StopChallenge(Convert.ToBase64String(new byte[32]), Convert.ToBase64String(new byte[16]), FastIterations);
        Assert.IsFalse(auth.Verify(Answer(forged, Password)).Accepted);
    }

    [TestMethod]
    public void Cinq_echecs_verrouillent_meme_le_bon_mot_de_passe()
    {
        var (auth, time) = Create();
        for (int i = 0; i < StopAuthenticator.MaxFailures; i++)
            Assert.IsFalse(auth.Verify(Answer(auth.IssueChallenge()!, "faux" + i)).Accepted);

        var locked = auth.Verify(Answer(auth.IssueChallenge()!, Password));
        Assert.IsFalse(locked.Accepted, "verrouillé");
        StringAssert.Contains(locked.Message, "essais");

        time.Now += StopAuthenticator.Lockout + TimeSpan.FromSeconds(1);
        Assert.IsTrue(auth.Verify(Answer(auth.IssueChallenge()!, Password)).Accepted, "déverrouillé après le délai");
    }

    [TestMethod]
    public void Sans_mot_de_passe_configure_aucun_arret_n_est_possible()
    {
        var auth = new StopAuthenticator(null);
        Assert.IsNull(auth.IssueChallenge());
        Assert.IsFalse(auth.Verify(new StopRequest("x", "y")).Accepted);
    }

    [TestMethod]
    public void Preuve_mal_formee_comptee_comme_echec()
    {
        var (auth, _) = Create();
        var c = auth.IssueChallenge()!;
        Assert.IsFalse(auth.Verify(new StopRequest(c.Nonce, "pas-du-base64!")).Accepted);
    }

    [TestMethod]
    public void Mot_de_passe_trop_court_refuse()
    {
        Assert.ThrowsExactly<ArgumentException>(() => ProtectionSecret.Create("court"));
    }

    [TestMethod]
    public void Le_secret_ne_contient_pas_le_mot_de_passe_et_se_recharge()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "protection.json");
        try
        {
            ProtectionSecret.Create(Password, FastIterations).Save(path, restrictToAdmins: false);
            StringAssert.DoesNotMatch(File.ReadAllText(path), new System.Text.RegularExpressions.Regex(Password));

            var auth = new StopAuthenticator(ProtectionSecret.Load(path));
            Assert.IsTrue(auth.Verify(Answer(auth.IssueChallenge()!, Password)).Accepted);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, true);
        }
    }

    [TestMethod]
    public async Task Arret_de_bout_en_bout_par_le_pipe()
    {
        string name = "CoreGuard.Test." + Guid.NewGuid().ToString("N");
        var auth = new StopAuthenticator(ProtectionSecret.Create(Password, FastIterations));
        bool stopped = false;

        IpcEnvelope? Handle(IpcEnvelope r) => r.Type switch
        {
            IpcContract.Types.Challenge => new IpcEnvelope(IpcContract.Types.Challenge, Challenge: auth.IssueChallenge()),
            IpcContract.Types.StopRequest => Verdict(auth.Verify(r.Stop)),
            _ => null
        };
        IpcEnvelope Verdict(StopResult v) { stopped |= v.Accepted; return new IpcEnvelope(IpcContract.Types.StopResult, StopResult: v); }

        await using var server = new PipeServer(name,
            () => new ServiceStatus(1, Environment.ProcessId, DateTime.UtcNow, "x", false, false, []), null, Handle);
        server.Start();

        await using var client = new ServiceClient(name, requireServiceSession: false);
        Assert.IsTrue(await client.ConnectAsync(TimeSpan.FromSeconds(5)));

        Assert.IsFalse((await client.RequestStopAsync("mauvais-mdp")).Accepted);
        Assert.IsFalse(stopped);
        Assert.IsTrue((await client.RequestStopAsync(Password)).Accepted);
        Assert.IsTrue(stopped);
    }
}
