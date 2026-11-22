using AntivirusIA.Core.Models;
using AntivirusIA.Core.Services;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class ScoringServiceTests
{
    [TestMethod]
    [DataRow(0, Verdict.Sain)]
    [DataRow(29, Verdict.Sain)]
    [DataRow(30, Verdict.Suspect)]
    [DataRow(69, Verdict.Suspect)]
    [DataRow(70, Verdict.Malveillant)]
    [DataRow(100, Verdict.Malveillant)]
    public void Le_verdict_depend_du_score(int score, Verdict attendu)
    {
        Assert.AreEqual(attendu, new ScoringService().Evaluate(score));
    }
}