using AntivirusIA.AI;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AntivirusIA.UI.Models;

/// <summary>Réglages utilisateur observables, persistés en JSON par <c>SettingsStore</c>.</summary>
public sealed partial class AppSettings : ObservableObject
{
    [ObservableProperty] private bool _darkTheme = true;
    [ObservableProperty] private int _thresholdSuspect = 30;
    [ObservableProperty] private int _thresholdMalicious = 70;
    [ObservableProperty] private bool _autoQuarantine;
    [ObservableProperty] private bool _useAi = true;
    [ObservableProperty] private string _modelPath = AiOptions.DefaultModelPath;

    // Modules de protection temps réel
    [ObservableProperty] private bool _monitorDownloads = true;
    [ObservableProperty] private bool _canariesEnabled;
    [ObservableProperty] private bool _behaviorEnabled = true;
    [ObservableProperty] private bool _persistenceEnabled = true;
    [ObservableProperty] private bool _clipboardEnabled = true;
    [ObservableProperty] private bool _sensorsEnabled = true;
    [ObservableProperty] private bool _paranoiaEnabled;
    [ObservableProperty] private bool _badUsbEnabled = true;
    [ObservableProperty] private bool _lockOnBadUsb;
    [ObservableProperty] private bool _lockdownCutsNetwork;

    // Mode arrière-plan : fermer la fenêtre la masque ; lancement automatique à l'ouverture de session
    [ObservableProperty] private bool _runInBackground = true;
    [ObservableProperty] private bool _startWithWindows = true;

    /// <summary>Entrées de démarrage autorisées par l'utilisateur (empreintes : on redemande si la commande change).</summary>
    public List<string> AllowedPersistence { get; set; } = [];

    // Les seuils restent cohérents : suspect < malveillant, bornés à 1..100
    partial void OnThresholdSuspectChanged(int value)
    {
        int v = Math.Clamp(value, 1, 99);
        if (v != value) { ThresholdSuspect = v; return; }
        if (ThresholdMalicious <= v) ThresholdMalicious = v + 1;
    }

    partial void OnThresholdMaliciousChanged(int value)
    {
        int v = Math.Clamp(value, 2, 100);
        if (v != value) { ThresholdMalicious = v; return; }
        if (ThresholdSuspect >= v) ThresholdSuspect = v - 1;
    }
}
