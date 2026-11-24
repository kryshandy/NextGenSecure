using AntivirusIA.AI;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class LLamaSharpProviderTests
{
    [TestMethod]
    public void ResolveModelPath_CheminAbsolu_EstConserve()
    {
        string absolu = Path.Combine(Path.GetTempPath(), "x.gguf");
        Assert.AreEqual(absolu, LLamaSharpProvider.ResolveModelPath(absolu));
    }

    [TestMethod]
    public void ResolveModelPath_Relatif_ExistantDansRepertoireCourant_EstTrouve()
    {
        string dir = Directory.CreateTempSubdirectory().FullName;
        string ancien = Directory.GetCurrentDirectory();
        try
        {
            File.WriteAllText(Path.Combine(dir, "m-test.gguf"), "x");
            Directory.SetCurrentDirectory(dir);
            Assert.AreEqual(Path.Combine(dir, "m-test.gguf"), LLamaSharpProvider.ResolveModelPath("m-test.gguf"));
        }
        finally
        {
            Directory.SetCurrentDirectory(ancien);
            Directory.Delete(dir, true);
        }
    }

    [TestMethod]
    public void ResolveModelPath_Introuvable_RenvoiePremierCandidatDeLExecutable()
    {
        string resolu = LLamaSharpProvider.ResolveModelPath("inexistant-xyz.gguf");
        Assert.AreEqual(Path.Combine(AppContext.BaseDirectory, "inexistant-xyz.gguf"), resolu);
    }

    [TestMethod]
    public void BuildChatPrompt_UtiliseLeFormatLlama3()
    {
        string p = LLamaSharpProvider.BuildChatPrompt("SYS", "USR");
        StringAssert.Contains(p, "<|start_header_id|>system<|end_header_id|>\n\nSYS<|eot_id|>");
        StringAssert.Contains(p, "<|start_header_id|>user<|end_header_id|>\n\nUSR<|eot_id|>");
        Assert.IsTrue(p.EndsWith("<|start_header_id|>assistant<|end_header_id|>\n\n"));
    }

    [TestMethod]
    public async Task CompleteAsync_ModeleAbsent_LeveFileNotFoundException()
    {
        using var provider = new LLamaSharpProvider(new AiOptions { ModelPath = "models/absent-xyz.gguf" });
        await Assert.ThrowsExactlyAsync<FileNotFoundException>(() => provider.CompleteAsync("s", "u"));
    }

    [TestMethod]
    public void AiOptions_ValeursParDefaut()
    {
        var o = new AiOptions();
        Assert.AreEqual("models/Llama-3.2-3B-Instruct-Q4_K_M.gguf", o.ModelPath);
        Assert.AreEqual(512, o.MaxTokens);
        Assert.AreEqual(0.2f, o.Temperature);
    }
}
