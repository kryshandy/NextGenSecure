using AntivirusIA.Ai;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class AiResponseParserTests
{
    [TestMethod]
    public void Un_json_propre_est_lu_correctement()
    {
        const string json = """{"verdict":"Malveillant","confidence":88,"family":"Dropper","explanation":"Ce programme télécharge du code."}""";

        var analyse = AiResponseParser.TryParse(json);

        Assert.IsNotNull(analyse);
        Assert.AreEqual(Verdict.Malveillant, analyse.Verdict);
        Assert.AreEqual(88, analyse.Confidence);
        Assert.AreEqual("Dropper", analyse.Family);
    }

    [TestMethod]
    public void Un_json_entoure_de_balises_markdown_est_lu()
    {
        const string reponse = "Voici mon analyse :\n```json\n{\"verdict\":\"Suspect\",\"confidence\":60,\"family\":null,\"explanation\":\"Comportement louche.\"}\n```";

        var analyse = AiResponseParser.TryParse(reponse);

        Assert.IsNotNull(analyse);
        Assert.AreEqual(Verdict.Suspect, analyse.Verdict);
        Assert.IsNull(analyse.Family);
    }

    [TestMethod]
    public void Les_verdicts_en_anglais_sont_acceptes()
    {
        var analyse = AiResponseParser.TryParse("""{"verdict":"malicious","confidence":90}""");

        Assert.IsNotNull(analyse);
        Assert.AreEqual(Verdict.Malveillant, analyse.Verdict);
    }

    [TestMethod]
    public void Une_confiance_hors_limites_est_ramenee_a_100()
    {
        var analyse = AiResponseParser.TryParse("""{"verdict":"Sain","confidence":150}""");

        Assert.IsNotNull(analyse);
        Assert.AreEqual(100, analyse.Confidence);
    }

    [TestMethod]
    public void Un_verdict_inconnu_est_refuse()
    {
        Assert.IsNull(AiResponseParser.TryParse("""{"verdict":"peut-etre","confidence":50}"""));
    }

    [TestMethod]
    public void Un_texte_sans_json_est_refuse()
    {
        Assert.IsNull(AiResponseParser.TryParse("Je ne peux pas répondre à cette demande."));
    }
}