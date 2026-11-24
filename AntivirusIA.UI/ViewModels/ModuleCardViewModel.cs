using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using AntivirusIA.UI.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AntivirusIA.UI.ViewModels;

/// <summary>
/// Carte d'un module de protection sur le tableau de bord : reflète l'état du <see cref="ProtectionModule"/>
/// (Actif / Désactivé / Indisponible) et expose l'interrupteur lié au réglage correspondant.
/// L'état réel reste piloté par <c>ProtectionService</c> : cette classe ne fait que présenter et déclencher l'application.
/// </summary>
public sealed class ModuleCardViewModel : ObservableObject
{
    private readonly ProtectionModule _module;
    private readonly Func<bool>? _read;
    private readonly Action<bool>? _write;

    /// <param name="read">Lecture du réglage associé ; null si le module n'a pas d'interrupteur.</param>
    /// <param name="write">Écriture du réglage + application (enregistrement, redémarrage des modules).</param>
    public ModuleCardViewModel(ProtectionModule module, string iconKey, Func<bool>? read, Action<bool>? write)
    {
        _module = module;
        _read = read;
        _write = write;
        Icon = Application.Current?.TryFindResource(iconKey) as Geometry;

        // Relais des changements du module (états et libellés modifiés par ProtectionService sur le thread UI)
        _module.PropertyChanged += OnModulePropertyChanged;
    }

    public string Name => _module.Name;
    public string Description => _module.Description;
    public Geometry? Icon { get; }
    public ModuleState State => _module.State;
    public string StatusText => _module.StatusText;

    /// <summary>Libellé court de l'état, affiché dans la pastille.</summary>
    public string StateLabel => _module.State switch
    {
        ModuleState.Active => "Actif",
        ModuleState.Unavailable => "Indisponible",
        _ => "Désactivé"
    };

    /// <summary>Faux pour les modules sans réglage (ex. Réseau : toujours en inspection).</summary>
    public bool CanToggle => _read is not null;

    /// <summary>Infobulle : description du module et, le cas échéant, l'indication d'utilisation de l'interrupteur.</summary>
    public string ToolTipText => CanToggle ? $"{Description}\nUtilisez l'interrupteur pour activer ou désactiver ce module." : Description;

    /// <summary>État de l'interrupteur (le réglage, pas l'état réel : un module activé peut être indisponible).</summary>
    public bool IsOn
    {
        get => _read?.Invoke() ?? _module.State == ModuleState.Active;
        set
        {
            if (_write is null || value == IsOn) return;
            _write(value);
            OnPropertyChanged();
        }
    }

    /// <summary>Appelé quand le réglage a changé ailleurs (page Réglages) pour resynchroniser l'interrupteur.</summary>
    public void RefreshSetting() => OnPropertyChanged(nameof(IsOn));

    private void OnModulePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(ProtectionModule.State):
                OnPropertyChanged(nameof(State));
                OnPropertyChanged(nameof(StateLabel));
                break;
            case nameof(ProtectionModule.StatusText):
                OnPropertyChanged(nameof(StatusText));
                break;
        }
    }
}
