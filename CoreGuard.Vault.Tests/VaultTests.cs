using Microsoft.Data.Sqlite;

namespace CoreGuard.Vault.Tests;

[TestClass]
public sealed class VaultTests
{
    private string _path = "";

    [TestInitialize]
    public void Init() => _path = Path.Combine(Path.GetTempPath(), $"cgvault-{Guid.NewGuid():N}.cgdb");

    [TestCleanup]
    public void Cleanup()
    {
        SqliteConnection.ClearAllPools();
        try { File.Delete(_path); } catch (IOException) { }
    }

    // Paramètres Argon2 réduits pour garder les tests rapides.
    private Vault NewVault() => new(new VaultOptions { FilePath = _path, MemorySizeKb = 1024, Iterations = 1, DegreeOfParallelism = 1 });

    [TestMethod]
    public async Task Create_Then_Unlock_Succeeds()
    {
        using var v = NewVault();
        await v.CreateAsync("master-pass");
        Assert.IsFalse(v.IsUnlocked);
        Assert.IsTrue(await v.UnlockAsync("master-pass"));
        Assert.IsTrue(v.IsUnlocked);
    }

    [TestMethod]
    public async Task Unlock_WrongPassword_ReturnsFalse_NoException()
    {
        using var v = NewVault();
        await v.CreateAsync("good");
        Assert.IsFalse(await v.UnlockAsync("bad"));
        Assert.IsFalse(v.IsUnlocked);
    }

    [TestMethod]
    public async Task Unlock_MissingFile_ReturnsFalse()
    {
        using var v = NewVault();
        Assert.IsFalse(await v.UnlockAsync("x"));
    }

    [TestMethod]
    public async Task Create_Twice_Throws()
    {
        using var v = NewVault();
        await v.CreateAsync("a");
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => v.CreateAsync("a"));
    }

    [TestMethod]
    public async Task Operations_WhileLocked_Throw()
    {
        using var v = NewVault();
        await v.CreateAsync("a");
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => v.ListAsync());
    }

    [TestMethod]
    public async Task Crud_RoundTrip()
    {
        using var v = NewVault();
        await v.CreateAsync("pw");
        await v.UnlockAsync("pw");

        var e = await v.AddAsync("Github", "krys", "https://github.com", "s3cret!é");
        var list = await v.ListAsync();
        Assert.AreEqual(1, list.Count);
        Assert.AreEqual("Github", list[0].Title);
        Assert.AreEqual("s3cret!é", await v.GetSecretAsync(e.Id));

        Assert.IsTrue(await v.UpdateAsync(e.Id, "GH", "krys2", "https://gh.io", null));
        Assert.AreEqual("s3cret!é", await v.GetSecretAsync(e.Id)); // secret conservé
        Assert.AreEqual("GH", (await v.GetAsync(e.Id))!.Title);

        Assert.IsTrue(await v.UpdateAsync(e.Id, "GH", "krys2", "https://gh.io", "nouveau"));
        Assert.AreEqual("nouveau", await v.GetSecretAsync(e.Id));

        Assert.IsTrue(await v.DeleteAsync(e.Id));
        Assert.IsFalse(await v.DeleteAsync(e.Id));
        Assert.AreEqual(0, (await v.ListAsync()).Count);
        Assert.IsNull(await v.GetSecretAsync(e.Id));
    }

    [TestMethod]
    public async Task Persistence_AcrossInstances()
    {
        Guid id;
        using (var v = NewVault())
        {
            await v.CreateAsync("pw");
            await v.UnlockAsync("pw");
            id = (await v.AddAsync("t", "u", "url", "secret")).Id;
        }
        using var v2 = NewVault();
        Assert.IsTrue(await v2.UnlockAsync("pw"));
        Assert.AreEqual("secret", await v2.GetSecretAsync(id));
    }

    [TestMethod]
    public async Task Secret_IsNotStoredInClear_AndNoncesDiffer()
    {
        using var v = NewVault();
        await v.CreateAsync("pw");
        await v.UnlockAsync("pw");
        var a = await v.AddAsync("a", "", "", "same-secret-value");
        var b = await v.AddAsync("b", "", "", "same-secret-value");
        v.Lock();

        SqliteConnection.ClearAllPools();
        var raw = await File.ReadAllBytesAsync(_path);
        Assert.IsFalse(System.Text.Encoding.UTF8.GetString(raw).Contains("same-secret-value"));

        await using var conn = new SqliteConnection($"Data Source={_path};Pooling=False");
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT nonce, ciphertext FROM entries ORDER BY title";
        await using var r = await cmd.ExecuteReaderAsync();
        await r.ReadAsync(); var n1 = (byte[])r["nonce"]; var c1 = (byte[])r["ciphertext"];
        await r.ReadAsync(); var n2 = (byte[])r["nonce"]; var c2 = (byte[])r["ciphertext"];
        CollectionAssert.AreNotEqual(n1, n2);
        CollectionAssert.AreNotEqual(c1, c2);
    }

    [TestMethod]
    public async Task TamperedCiphertext_IsDetected()
    {
        Guid id;
        using (var v = NewVault())
        {
            await v.CreateAsync("pw");
            await v.UnlockAsync("pw");
            id = (await v.AddAsync("t", "u", "url", "secret")).Id;
        }

        await using (var conn = new SqliteConnection($"Data Source={_path};Pooling=False"))
        {
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE entries SET ciphertext = x'00112233445566'";
            await cmd.ExecuteNonQueryAsync();
        }

        using var v2 = NewVault();
        await v2.UnlockAsync("pw");
        await Assert.ThrowsExactlyAsync<InvalidDataException>(() => v2.GetSecretAsync(id));
    }

    [TestMethod]
    public void GeneratePassword_RespectsLengthAndCategories()
    {
        var p = Vault.GeneratePassword(32);
        Assert.AreEqual(32, p.Length);
        Assert.IsTrue(p.Any(char.IsLower) && p.Any(char.IsUpper) && p.Any(char.IsDigit) && p.Any(c => !char.IsLetterOrDigit(c)));

        var digits = Vault.GeneratePassword(20, new PasswordOptions(false, false, true, false));
        Assert.IsTrue(digits.All(char.IsDigit));

        Assert.AreNotEqual(Vault.GeneratePassword(24), Vault.GeneratePassword(24));
    }

    [TestMethod]
    public void GeneratePassword_InvalidArgs_Throw()
    {
        Assert.ThrowsExactly<ArgumentException>(() => Vault.GeneratePassword(10, new PasswordOptions(false, false, false, false)));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Vault.GeneratePassword(2));
    }
}
