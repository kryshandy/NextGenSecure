using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using AntivirusIA.UI.Models;
using Microsoft.Win32;
using Forms = System.Windows.Forms;

namespace AntivirusIA.UI.Services;

/// <summary>
/// Mode arrière-plan : icône dans la zone de notification (menu Ouvrir / Verrouiller / Quitter), fermeture de la
/// fenêtre = masquage (les modules hébergés par l'application continuent : BadUSB, presse-papiers, capteurs,
/// téléchargements, coffre, extension navigateur, persistance), bulles pour les alertes importantes quand la
/// fenêtre est cachée, et lancement automatique à l'ouverture de session (valeur HKCU Run « CoreGuard »).
/// </summary>
public sealed class BackgroundHost : IDisposable
{
    public const string AutoStartValueName = "CoreGuard";
    public const string BackgroundArgument = "--background";
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    private readonly AppSettings _settings;
    private readonly SettingsStore _store;
    private readonly AlertHub _alerts;
    private readonly LockdownUiController _lockdown;
    private readonly IDialogService _dialogs;
    private Forms.NotifyIcon? _icon;
    private Window? _window;
    private bool _exiting;
    private bool _hintShown;

    public BackgroundHost(AppSettings settings, SettingsStore store, AlertHub alerts, LockdownUiController lockdown, IDialogService dialogs)
    {
        _settings = settings;
        _store = store;
        _alerts = alerts;
        _lockdown = lockdown;
        _dialogs = dialogs;
    }

    /// <summary>Chemin de l'exécutable courant, tel qu'il est inscrit au démarrage.</summary>
    public static string ExePath => Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "AntivirusIA.UI.exe");

    /// <summary>Commande inscrite dans la clé Run (reconnue par le gardien de persistance comme étant CoreGuard).</summary>
    public static string AutoStartCommand => $"\"{ExePath}\" {BackgroundArgument}";

    public void Attach(Window window)
    {
        _window = window;
        window.Closing += OnWindowClosing;

        _icon = new Forms.NotifyIcon
        {
            Icon = LoadIcon(),
            Text = "CoreGuard - protection active",
            Visible = true,
            ContextMenuStrip = BuildMenu()
        };
        _icon.MouseClick += (_, e) => { if (e.Button == Forms.MouseButtons.Left) ShowWindow(); };
        _icon.BalloonTipClicked += (_, _) => ShowWindow();

        _alerts.Published += OnAlert;
        _settings.PropertyChanged += OnSettingChanged;
        ApplyAutoStart(_settings.StartWithWindows);
    }

    public void ShowWindow()
    {
        if (_window is null) return;
        _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
        _window.Topmost = true;  // ramène au premier plan même si une autre application a le focus
        _window.Topmost = false;
        _window.Focus();
    }

    private Forms.ContextMenuStrip BuildMenu()
    {
        var menu = new Forms.ContextMenuStrip { ShowImageMargin = false };
        var status = new Forms.ToolStripMenuItem("CoreGuard : protection active") { Enabled = false };
        menu.Items.Add(status);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Ouvrir CoreGuard", null, (_, _) => ShowWindow());
        menu.Items.Add("Verrouiller le PC maintenant", null, (_, _) => _ = LockAsync());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Quitter CoreGuard", null, (_, _) => Quit());
        ((Forms.ToolStripMenuItem)menu.Items[2]).Font = new System.Drawing.Font(menu.Font, System.Drawing.FontStyle.Bold);
        return menu;
    }

    private async Task LockAsync()
    {
        if (!_dialogs.Confirm("Verrouiller le PC",
                "Écran CoreGuard, clés USB bloquées, nouveaux périphériques refusés"
                + (_settings.LockdownCutsNetwork ? ", réseau coupé" : "")
                + ". Seul le mot de passe de protection permettra de déverrouiller.", "Verrouiller", danger: true))
            return;
        await _lockdown.LockNowAsync("verrouillage depuis la zone de notification", _settings.LockdownCutsNetwork);
    }

    private void Quit()
    {
        if (!_dialogs.Confirm("Quitter CoreGuard",
                "Les protections hébergées par l'application s'arrêtent (BadUSB, presse-papiers, caméra/micro, téléchargements, " +
                "persistance, coffre et extension navigateur). Le service système, s'il est installé, continue.", "Quitter", danger: true))
            return;
        _exiting = true;
        Application.Current.Shutdown();
    }

    private void OnWindowClosing(object? sender, CancelEventArgs e)
    {
        if (_exiting || !_settings.RunInBackground)
        {
            _exiting = true;
            Application.Current.Shutdown();
            return;
        }
        e.Cancel = true;
        _window!.Hide();
        if (!_hintShown)
        {
            _hintShown = true;
            _icon?.ShowBalloonTip(4000, "CoreGuard reste actif",
                "La protection continue en arrière-plan. Icône CoreGuard près de l'horloge pour rouvrir ou quitter.", Forms.ToolTipIcon.Info);
        }
    }

    // Bulle Windows pour les alertes importantes pendant que la fenêtre est cachée
    private void OnAlert(AlertItem item)
    {
        if (_icon is null || _window is null || (_window.IsVisible && _window.WindowState != WindowState.Minimized)) return;
        if (item.Severity is not (AlertSeverity.Critical or AlertSeverity.Warning)) return;
        _icon.ShowBalloonTip(5000, $"CoreGuard - {item.Source}", Clip($"{item.Title}\n{item.Detail}", 250),
            item.Severity == AlertSeverity.Critical ? Forms.ToolTipIcon.Error : Forms.ToolTipIcon.Warning);
    }

    private void OnSettingChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AppSettings.StartWithWindows))
        {
            ApplyAutoStart(_settings.StartWithWindows);
            _store.Save(_settings);
        }
        else if (e.PropertyName == nameof(AppSettings.RunInBackground))
        {
            _store.Save(_settings);
        }
    }

    /// <summary>Inscrit (ou retire) CoreGuard au démarrage de la session, sans droits administrateur.</summary>
    public static void ApplyAutoStart(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true);
            if (enabled)
            {
                if (key.GetValue(AutoStartValueName) as string != AutoStartCommand) key.SetValue(AutoStartValueName, AutoStartCommand);
            }
            else if (key.GetValue(AutoStartValueName) is not null)
            {
                key.DeleteValue(AutoStartValueName);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            Trace.WriteLine($"[CoreGuard] Démarrage automatique non modifiable : {ex.Message}");
        }
    }

    /// <summary>Vrai si la commande est celle de CoreGuard lui-même (pas de question au gardien de persistance).</summary>
    public static bool IsOwnCommand(string command) =>
        command.Contains(ExePath, StringComparison.OrdinalIgnoreCase);

    private static System.Drawing.Icon LoadIcon()
    {
        try
        {
            return System.Drawing.Icon.ExtractAssociatedIcon(ExePath) ?? System.Drawing.SystemIcons.Shield;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException)
        {
            return System.Drawing.SystemIcons.Shield;
        }
    }

    private static string Clip(string text, int max) => text.Length > max ? text[..max] + "…" : text;

    public void Dispose()
    {
        _alerts.Published -= OnAlert;
        _settings.PropertyChanged -= OnSettingChanged;
        if (_icon is not null)
        {
            _icon.Visible = false;
            _icon.Dispose();
            _icon = null;
        }
    }
}
