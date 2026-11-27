using System.Net.Http;
using System.Windows;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.UI.Models;
using AntivirusIA.UI.Views;
using CoreGuard.Ipc;

namespace AntivirusIA.UI.Services;

/// <summary>
/// Côté application de l'anti-phishing (étape 11) :
/// - journal : chaque verdict non sûr du navigateur arrive dans le tableau de bord (bulle Windows si la fenêtre est cachée) ;
/// - revue : l'IA locale examine les sites de la zone grise et peut seulement AGGRAVER le verdict des règles ;
/// - confiance : « Je fais confiance à ce site » n'est enregistré qu'après confirmation dans CoreGuard (une page web
///   ne peut pas cliquer à la place de l'utilisateur) ;
/// - liste noire : mise à jour optionnelle depuis OpenPhish (désactivée par défaut).
/// </summary>
public sealed class PhishingReviewService : IDisposable
{
    public const string FeedUrl = "https://openphish.com/feed.txt";
    private static readonly TimeSpan AiTimeout = TimeSpan.FromSeconds(40);
    private static readonly TimeSpan FeedInterval = TimeSpan.FromHours(12);
    private const int MaxFeedBytes = 5 * 1024 * 1024;

    private readonly AppSettings _settings;
    private readonly SettingsStore _store;
    private readonly AlertHub _alerts;
    private readonly IAiProvider _ai;
    private readonly SemaphoreSlim _aiGate = new(1, 1);
    private readonly Dictionary<string, DateTime> _recentReports = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _feedTimer;

    public PhishingReviewService(AppSettings settings, SettingsStore store, AlertHub alerts, IAiProvider ai)
    {
        _settings = settings;
        _store = store;
        _alerts = alerts;
        _ai = ai;
        Handlers = new SiteHandlers(ReportAsync, ReviewAsync, TrustAsync);
        _settings.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName != nameof(AppSettings.PhishingFeedUpdates)) return;
            _store.Save(_settings);
            ScheduleFeed();
        };
    }

    public SiteHandlers Handlers { get; }

    /// <summary>Levé (thread quelconque) quand la liste de confiance ou la liste noire change.</summary>
    public event Action? ListsChanged;

    public void Start() => ScheduleFeed();

    // ---------------------------------------------------------------- Journal

    private Task ReportAsync(SiteFacts f)
    {
        // checkUrl puis analyse de la capture signalent souvent le même site : un seul message par minute
        string key = f.Verdict + "|" + f.Domain;
        lock (_recentReports)
        {
            if (_recentReports.TryGetValue(key, out var last) && DateTime.UtcNow - last < TimeSpan.FromMinutes(1)) return Task.CompletedTask;
            _recentReports[key] = DateTime.UtcNow;
        }
        Publish(f.Verdict, f.Domain, f.Reasons, null);
        return Task.CompletedTask;
    }

    private void Publish(string verdict, string domain, IEnumerable<string> reasons, string? aiExplanation)
    {
        bool phishing = verdict == "Phishing";
        string detail = string.Join(" · ", reasons.Take(3)) + (aiExplanation is null ? "" : " · IA : " + aiExplanation);
        _alerts.Publish(phishing ? AlertSeverity.Critical : AlertSeverity.Warning, "Anti-phishing",
            phishing ? $"Site d'arnaque probable : {domain}" : $"CoreGuard doute de ce site : {domain}", detail);
    }

    // ---------------------------------------------------------------- Revue par l'IA

    private async Task<SiteReply> ReviewAsync(SiteFacts f)
    {
        if (!_settings.UseAi) return new SiteReply(f.Verdict, null, false, true);

        // Une revue à la fois : le modèle local est partagé
        if (!await _aiGate.WaitAsync(TimeSpan.FromSeconds(5))) return new SiteReply(f.Verdict, null, false, true);
        try
        {
            using var cts = new CancellationTokenSource(AiTimeout);
            string answer = await _ai.CompleteAsync(SiteReview.SystemPrompt, SiteReview.UserPrompt(f), cts.Token);
            var (aiVerdict, reason) = SiteReview.ParseAnswer(answer);
            if (aiVerdict is null) return new SiteReply(f.Verdict, null, false, true);

            // L'IA ne peut qu'aggraver : seul l'utilisateur peut « remonter » un site
            string final = SiteReview.Merge(f.Verdict, aiVerdict);
            if (SiteReview.Rank(final) > SiteReview.Rank(f.Verdict)) Publish(final, f.Domain, f.Reasons, reason); // aggravé par l'IA
            return new SiteReply(final, reason, true, true);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return new SiteReply(f.Verdict, null, false, true); // modèle absent ou trop lent : verdict des règles
        }
        finally
        {
            _aiGate.Release();
        }
    }

    // ---------------------------------------------------------------- Confiance de l'utilisateur

    private async Task<SiteReply> TrustAsync(SiteFacts f)
    {
        string domain = f.Domain.Trim().ToLowerInvariant();
        if (domain.Length == 0 || domain.Contains(' ') || domain.Contains('/')) return new SiteReply(f.Verdict, null, false, false);

        var asked = new TaskCompletionSource<bool>();
        UiThread.Post(() =>
        {
            var dialog = new ConfirmDialog("Faire confiance à ce site ?",
                $"Vous déclarez « {domain} » de confiance. CoreGuard ne vous alertera plus pour ce site, même s'il ressemble " +
                "à une arnaque. Ne le faites que si vous êtes certain de l'adresse.", "Faire confiance", danger: true)
            {
                Topmost = true,
                WindowStartupLocation = WindowStartupLocation.CenterScreen
            };
            dialog.Activate();
            asked.TrySetResult(dialog.ShowDialog() == true);
        });
        bool yes = await asked.Task;
        if (!yes) return new SiteReply(f.Verdict, null, false, false);

        Directory.CreateDirectory(PhishingFiles.Directory);
        var existing = TrustedSites();
        if (!existing.Contains(domain)) await File.AppendAllTextAsync(PhishingFiles.TrustedSites, domain + Environment.NewLine);
        _alerts.Publish(AlertSeverity.Info, "Anti-phishing", $"Site déclaré de confiance : {domain}", "Retirable dans Réglages > Anti-phishing.");
        ListsChanged?.Invoke();
        return new SiteReply("Safe", null, false, true);
    }

    public static IReadOnlyList<string> TrustedSites() =>
        File.Exists(PhishingFiles.TrustedSites)
            ? File.ReadAllLines(PhishingFiles.TrustedSites).Select(l => l.Trim()).Where(l => l.Length > 0).Distinct().ToList()
            : [];

    public void ClearTrustedSites()
    {
        if (File.Exists(PhishingFiles.TrustedSites)) File.Delete(PhishingFiles.TrustedSites);
        _alerts.Publish(AlertSeverity.Info, "Anti-phishing", "Sites de confiance retirés", "Tous les sites seront à nouveau analysés.");
        ListsChanged?.Invoke();
    }

    // ---------------------------------------------------------------- Liste noire (option Internet)

    public static DateTime? FeedUpdatedAt => File.Exists(PhishingFiles.BlocklistUpdate) ? File.GetLastWriteTime(PhishingFiles.BlocklistUpdate) : null;

    private void ScheduleFeed()
    {
        _feedTimer?.Dispose();
        _feedTimer = null;
        if (!_settings.PhishingFeedUpdates) return;
        var due = FeedUpdatedAt is { } at && DateTime.Now - at < FeedInterval ? FeedInterval - (DateTime.Now - at) : TimeSpan.Zero;
        _feedTimer = new Timer(_ => _ = UpdateFeedAsync(), null, due, FeedInterval);
    }

    /// <summary>Télécharge le flux OpenPhish (URL fixe, HTTPS), le valide et le remplace de façon atomique.</summary>
    public async Task<string> UpdateFeedAsync()
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("CoreGuard-Antivirus/1.0");
            using var response = await http.GetAsync(FeedUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength > MaxFeedBytes) return "Liste trop volumineuse, ignorée.";
            string body = await response.Content.ReadAsStringAsync();
            if (body.Length > MaxFeedBytes) return "Liste trop volumineuse, ignorée.";

            var urls = body.Split('\n').Select(l => l.Trim())
                .Where(l => l.Length < 2048 && Uri.TryCreate(l, UriKind.Absolute, out var u) && (u.Scheme == "http" || u.Scheme == "https"))
                .Distinct().ToList();
            if (urls.Count == 0) return "Liste vide ou illisible, ancienne liste conservée.";

            Directory.CreateDirectory(PhishingFiles.Directory);
            string temp = PhishingFiles.BlocklistUpdate + ".tmp";
            await File.WriteAllTextAsync(temp, $"# OpenPhish {DateTime.Now:yyyy-MM-dd HH:mm}\n" + string.Join('\n', urls) + "\n");
            File.Move(temp, PhishingFiles.BlocklistUpdate, overwrite: true);
            ListsChanged?.Invoke();
            string message = $"{urls.Count} adresses de phishing à jour.";
            _alerts.Publish(AlertSeverity.Info, "Anti-phishing", "Liste noire mise à jour", message);
            return message;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or UnauthorizedAccessException)
        {
            return "Mise à jour impossible (hors ligne ?) : l'instantané livré reste actif.";
        }
    }

    public void Dispose() => _feedTimer?.Dispose();
}
