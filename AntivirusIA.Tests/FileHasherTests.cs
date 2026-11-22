using AntivirusIA.Engines;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class FileHasherTests
{
    [TestMethod]
    public async Task Sha256_de_abc_est_correct()
    {
        string path = Path.GetTempFileName();
        await File.WriteAllTextAsync(path, "abc");

        string hash = await FileHasher.ComputeSha256Async(path);
        File.Delete(path);

        Assert.AreEqual(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            hash);
    }
}