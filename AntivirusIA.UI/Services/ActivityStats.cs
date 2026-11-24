using CommunityToolkit.Mvvm.ComponentModel;

namespace AntivirusIA.UI.Services;

/// <summary>Compteurs de la session affichés (et animés) sur le tableau de bord. Modifiés sur le thread UI uniquement.</summary>
public sealed partial class ActivityStats : ObservableObject
{
    [ObservableProperty] private int _filesScanned;
    [ObservableProperty] private int _threatsFound;
    [ObservableProperty] private int _quarantined;
    [ObservableProperty] private int _alertCount;
}
