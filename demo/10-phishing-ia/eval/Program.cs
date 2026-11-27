// Évaluation de l'anti-phishing CoreGuard sur le corpus de démonstration (100 % local).
// Pour chaque cas : capture réelle de la page de labo (Edge sans fenêtre), puis la MÊME cascade que l'extension :
// base de confiance → règles d'URL → OCR + corrélation marque/domaine → revue par l'IA locale (qui ne peut qu'aggraver).
// Résultat : tableau par cas + précision / rappel « règles seules » et « règles + IA », écrit dans resultats.md.
//
// Usage : dotnet run --project demo/10-phishing-ia/eval [-- --sans-ia]
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using AntivirusIA.AI;
using CoreGuard.Extension;
using CoreGuard.Ipc;

string demoDir = FindDemoDir();
string repo = Path.GetFullPath(Path.Combine(demoDir, "..", ".."));
bool withAi = !args.Contains("--sans-ia");

var corpus = JsonDocument.Parse(File.ReadAllText(Path.Combine(demoDir, "corpus.json"))).RootElement.GetProperty("cases")
    .EnumerateArray()
    .Select(c => (Url: c.GetProperty("url").GetString()!, Page: c.GetProperty("page").GetString()!,
                  Expected: c.GetProperty("expected").GetString()!, Note: c.GetProperty("note").GetString()!))
    .ToList();

// Base livrée uniquement (pas les sites de confiance ni la liste personnelle de l'utilisateur) : résultat reproductible
string data = Path.Combine(AppContext.BaseDirectory, "Data");
var trust = new TrustBase(PublicSuffixList.Load(Path.Combine(data, "public_suffix_list.dat")),
    File.ReadLines(Path.Combine(data, "top-domains.txt")), File.ReadLines(Path.Combine(data, "phishing-blocklist.txt")), []);
PhishingLogic.Suffixes = trust.Suffixes;
var sites = new SiteAnalyzer(trust);
var ocr = new OcrPhishingAnalyzer();
using var ai = withAi ? new LLamaSharpProvider(new AiOptions { ModelPath = Path.Combine(repo, AiOptions.DefaultModelPath), MaxTokens = 120 }) : null;

Console.WriteLine($"Base : {trust.KnownCount} domaines connus, {trust.BlockedCount} entrées de liste noire, {trust.Suffixes.Count} suffixes publics.");
Console.WriteLine(withAi ? "IA locale : Llama 3.2 3B (revue des cas de la zone grise)." : "IA locale désactivée (--sans-ia).");

// 1) Captures réelles des pages de labo
string shots = Path.Combine(Path.GetTempPath(), "CoreGuardPhishingEval");
Directory.CreateDirectory(shots);
foreach (string page in corpus.Select(c => c.Page).Distinct())
{
    string png = Path.Combine(shots, Path.ChangeExtension(page, ".png"));
    if (!File.Exists(png)) Render(Path.Combine(demoDir, "pages", page), png);
}

// 2) Cascade sur chaque cas
var rows = new List<(string Url, string Note, string Expected, string Rules, string Final, string Trust, string Ai, double Seconds, string Why)>();
foreach (var c in corpus)
{
    var sw = Stopwatch.StartNew();
    var d = sites.CheckNavigation(c.Url, hasPassword: true);
    if (d.NeedsCapture)
    {
        var (text, _) = await ocr.ReadAsync(await File.ReadAllBytesAsync(Path.Combine(shots, Path.ChangeExtension(c.Page, ".png"))));
        d = sites.CheckPage(c.Url, text, hasPassword: true) is var p ? p with { Reasons = p.Reasons } : d;
        string rules = d.Verdict.ToString();
        string final = rules, aiText = d.NeedsReview ? "—" : "non sollicitée";
        if (d.NeedsReview && ai is not null)
        {
            var facts = new SiteFacts(c.Url, d.Domain, rules, d.Reasons.Take(12).ToList(), d.Brands.Take(12).ToList(), d.LoginPage, false,
                SiteAnalyzer.Excerpt(text));
            string answer = await ai.CompleteAsync(SiteReview.SystemPrompt, SiteReview.UserPrompt(facts));
            var (aiVerdict, reason) = SiteReview.ParseAnswer(answer);
            final = SiteReview.Merge(rules, aiVerdict);
            aiText = $"{aiVerdict ?? "illisible"} : {reason}";
        }
        rows.Add((c.Url, c.Note, c.Expected, rules, final, d.Trust.ToString(), aiText, sw.Elapsed.TotalSeconds, string.Join(" ; ", d.Reasons)));
    }
    else
    {
        rows.Add((c.Url, c.Note, c.Expected, d.Verdict.ToString(), d.Verdict.ToString(), d.Trust.ToString(), "non sollicitée", sw.Elapsed.TotalSeconds, string.Join(" ; ", d.Reasons)));
    }
    var r = rows[^1];
    Console.WriteLine($"{(Alert(r.Final) == (r.Expected == "alerte") ? "OK " : "ERR")} {r.Final,-10} (règles {r.Rules,-10}) {r.Url}  [{r.Seconds:0.0} s]");
    Console.WriteLine($"      {r.Why}");
}

// 3) Mesures
string Metrics(Func<(string Url, string Note, string Expected, string Rules, string Final, string Trust, string Ai, double Seconds, string Why), string> pick)
{
    int tp = rows.Count(r => r.Expected == "alerte" && Alert(pick(r)));
    int fn = rows.Count(r => r.Expected == "alerte" && !Alert(pick(r)));
    int fp = rows.Count(r => r.Expected == "sur" && Alert(pick(r)));
    int tn = rows.Count(r => r.Expected == "sur" && !Alert(pick(r)));
    double precision = tp + fp == 0 ? 1 : (double)tp / (tp + fp);
    double recall = tp + fn == 0 ? 1 : (double)tp / (tp + fn);
    return $"{tp} arnaques détectées / {tp + fn}, {fp} fausse(s) alerte(s) / {fp + tn} sites sûrs — précision {precision:P0}, rappel {recall:P0}";
}

var md = new StringBuilder();
md.AppendLine("# Résultats de l'évaluation anti-phishing CoreGuard");
md.AppendLine();
md.AppendLine($"Généré le {DateTime.Now:dd/MM/yyyy HH:mm} par `dotnet run --project demo/10-phishing-ia/eval`{(withAi ? "" : " -- --sans-ia")}. Analyse 100 % locale : captures réelles des pages de labo, OCR Windows, base de confiance livrée{(withAi ? ", IA locale Llama 3.2 3B" : "")}.");
md.AppendLine();
md.AppendLine($"- **Règles seules** : {Metrics(r => r.Rules)}");
if (withAi) md.AppendLine($"- **Règles + IA** : {Metrics(r => r.Final)}");
md.AppendLine();
md.AppendLine("| Attendu | Règles | Final | Base | Adresse | Cas | Raisons des règles | Avis de l'IA | Durée |");
md.AppendLine("|---|---|---|---|---|---|---|---|---|");
foreach (var r in rows)
    md.AppendLine($"| {r.Expected} | {r.Rules} | **{r.Final}** | {r.Trust} | `{r.Url}` | {r.Note} | {r.Why.Replace("|", "/")} | {r.Ai.Replace("|", "/")} | {r.Seconds:0.0} s |");
string output = Path.Combine(demoDir, withAi ? "resultats.md" : "resultats-sans-ia.md");
File.WriteAllText(output, md.ToString());
Console.WriteLine();
Console.WriteLine("Règles seules : " + Metrics(r => r.Rules));
if (withAi) Console.WriteLine("Règles + IA   : " + Metrics(r => r.Final));
Console.WriteLine("Détail : " + output);

static bool Alert(string verdict) => verdict is "Suspicious" or "Phishing";

static void Render(string html, string png)
{
    string edge = new[] { @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", @"C:\Program Files\Microsoft\Edge\Application\msedge.exe" }
        .FirstOrDefault(File.Exists) ?? throw new FileNotFoundException("Microsoft Edge est requis pour les captures.");
    string profile = Path.Combine(Path.GetTempPath(), "CoreGuardPhishingEval", "edge-profile");
    var psi = new ProcessStartInfo(edge)
    {
        ArgumentList = { "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run", $"--user-data-dir={profile}",
                         "--window-size=1100,800", $"--screenshot={png}", new Uri(html).AbsoluteUri },
        UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true
    };
    using var p = Process.Start(psi)!;
    p.WaitForExit(60_000);
    if (!File.Exists(png)) throw new InvalidOperationException("Capture impossible : " + html);
}

static string FindDemoDir()
{
    for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
    {
        string candidate = Path.Combine(dir.FullName, "demo", "10-phishing-ia");
        if (File.Exists(Path.Combine(candidate, "corpus.json"))) return candidate;
        if (File.Exists(Path.Combine(dir.FullName, "corpus.json"))) return dir.FullName;
    }
    throw new DirectoryNotFoundException("corpus.json introuvable.");
}
