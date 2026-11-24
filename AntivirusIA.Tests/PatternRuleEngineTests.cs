using System.Text;
using AntivirusIA.Core.Models;
using AntivirusIA.Engines;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class PatternRuleEngineTests
{
    private static string RulesPath => Path.Combine(AppContext.BaseDirectory, "Data", "rules.json");

    private static IReadOnlyList<Indicator> Eval(PatternRule rule, byte[] content) =>
        new PatternRuleEngine([rule]).Evaluate(content);

    private static PatternRule Rule(string condition, params PatternString[] strings) =>
        new("Test", "règle de test", 50, [.. strings], condition);

    [TestMethod]
    public void Texte_exact_est_trouve()
    {
        var r = Rule("any", new PatternString(Text: "malveillant"));
        Assert.AreEqual(1, Eval(r, Encoding.ASCII.GetBytes("xx malveillant yy")).Count);
        Assert.AreEqual(0, Eval(r, Encoding.ASCII.GetBytes("xx MALVEILLANT yy")).Count);
    }

    [TestMethod]
    public void Option_nocase_ignore_la_casse()
    {
        var r = Rule("any", new PatternString(Text: "Invoke-Expression", NoCase: true));
        Assert.AreEqual(1, Eval(r, Encoding.ASCII.GetBytes("INVOKE-EXPRESSION $x")).Count);
    }

    [TestMethod]
    public void Option_wide_cherche_l_utf16()
    {
        var r = Rule("any", new PatternString(Text: "secret", Wide: true));
        Assert.AreEqual(1, Eval(r, Encoding.Unicode.GetBytes("un secret ici")).Count);
        Assert.AreEqual(0, Eval(r, Encoding.ASCII.GetBytes("un secret ici")).Count);
    }

    [TestMethod]
    public void Motif_hexadecimal_avec_jokers()
    {
        var r = Rule("any", new PatternString(Hex: "4D 5A ?? ?? 50 45"));
        Assert.AreEqual(1, Eval(r, [0x00, 0x4D, 0x5A, 0x90, 0x00, 0x50, 0x45, 0x00]).Count);
        Assert.AreEqual(0, Eval(r, [0x00, 0x4D, 0x5A, 0x90, 0x00, 0x50, 0x46, 0x00]).Count);
    }

    [TestMethod]
    public void Motif_hexadecimal_commencant_par_un_joker()
    {
        var r = Rule("any", new PatternString(Hex: "?? 41 42"));
        Assert.AreEqual(1, Eval(r, Encoding.ASCII.GetBytes("zAB")).Count);
        Assert.AreEqual(0, Eval(r, Encoding.ASCII.GetBytes("AB")).Count, "le joker exige un octet avant");
    }

    [TestMethod]
    public void Conditions_all_et_nombre_minimal()
    {
        var a = new PatternString(Text: "alpha");
        var b = new PatternString(Text: "beta");
        var c = new PatternString(Text: "gamma");
        byte[] deux = Encoding.ASCII.GetBytes("alpha ... beta");

        Assert.AreEqual(0, Eval(Rule("all", a, b, c), deux).Count);
        Assert.AreEqual(1, Eval(Rule("2", a, b, c), deux).Count);
        Assert.AreEqual(0, Eval(Rule("3", a, b, c), deux).Count);
        Assert.AreEqual(1, Eval(Rule("any", a, b, c), deux).Count);
    }

    [TestMethod]
    public void Motifs_invalides_sont_ignores_sans_exception()
    {
        var engine = new PatternRuleEngine([
            Rule("any", new PatternString(Hex: "ZZ")),
            Rule("any", new PatternString(Hex: "?? ??")),
            Rule("any", new PatternString())
        ]);
        Assert.AreEqual(0, engine.Count);
    }

    [TestMethod]
    public void Definitive_est_propage_a_l_indice()
    {
        var r = new PatternRule("X", "d", 100, [new PatternString(Text: "abc")], "any", Definitive: true);
        Assert.IsTrue(Eval(r, Encoding.ASCII.GetBytes("abc")).Single().Definitive);
    }

    [TestMethod]
    public void La_base_livree_se_charge()
    {
        var engine = new PatternRuleEngine(RulesPath);
        Assert.IsTrue(engine.Count >= 8);
    }

    [TestMethod]
    public void La_base_livree_detecte_un_script_de_suppression_des_cliches()
    {
        var engine = new PatternRuleEngine(RulesPath);
        var indices = engine.Evaluate(Encoding.ASCII.GetBytes("@echo off\r\nVSSADMIN Delete Shadows /all /quiet\r\n"));
        Assert.IsTrue(indices.Any(i => i.Description.Contains("Ransom-ShadowCopyDelete")));
    }

    [TestMethod]
    public void La_base_livree_detecte_l_eicar_sans_le_hash()
    {
        // Variante EICAR reconstituée en mémoire (jamais écrite sur disque) suivie d'octets : le hash change, la règle reste
        // string.Concat sur un tableau : le compilateur ne fusionne pas les morceaux, la DLL de test ne contient jamais la chaîne complète
        string eicar = string.Concat(new[] { "X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-", "TEST-FILE!$H+H*" });
        var indices = new PatternRuleEngine(RulesPath).Evaluate(Encoding.ASCII.GetBytes(eicar + "\r\n   "));
        var hit = indices.Single(i => i.Description.Contains("EICAR"));
        Assert.IsTrue(hit.Definitive);
        Assert.AreEqual(100, hit.Points);
    }

    [TestMethod]
    public void La_base_livree_ne_signale_pas_un_texte_banal()
    {
        var indices = new PatternRuleEngine(RulesPath).Evaluate(Encoding.UTF8.GetBytes("Compte rendu de réunion : budget, planning, décisions."));
        Assert.AreEqual(0, indices.Count);
    }

    [TestMethod]
    public async Task Analyse_d_un_fichier_sur_disque()
    {
        string chemin = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        await File.WriteAllBytesAsync(chemin, Encoding.ASCII.GetBytes("debut ReflectiveLoader fin"));
        try
        {
            var report = new FileReport { FullPath = chemin, SizeBytes = new FileInfo(chemin).Length };
            var indices = await new PatternRuleEngine(RulesPath).AnalyzeAsync(report);
            Assert.IsTrue(indices.Any(i => i.Description.Contains("Loader-ReflectiveDll")));
        }
        finally
        {
            File.Delete(chemin);
        }
    }
}
