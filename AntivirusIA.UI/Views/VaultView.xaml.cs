using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using AntivirusIA.UI.ViewModels;

namespace AntivirusIA.UI.Views;

/// <summary>
/// Les PasswordBox ne se lient pas (par conception WPF) : leurs valeurs sont passées directement au ViewModel,
/// puis effacées. Le mot de passe ne reste dans aucune propriété de l'interface.
/// </summary>
public partial class VaultView : UserControl
{
    public VaultView()
    {
        InitializeComponent();
        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is INotifyPropertyChanged old) old.PropertyChanged -= OnVmChanged;
            if (e.NewValue is INotifyPropertyChanged vm) vm.PropertyChanged += OnVmChanged;
            ApplyState();
        };
    }

    private VaultViewModel? Vm => DataContext as VaultViewModel;

    private void OnVmChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(VaultViewModel.State)) ApplyState();
    }

    private void ApplyState()
    {
        var state = Vm?.State ?? VaultState.Locked;
        CreatePanel.Visibility = state == VaultState.NeedsCreation ? Visibility.Visible : Visibility.Collapsed;
        UnlockPanel.Visibility = state == VaultState.Locked ? Visibility.Visible : Visibility.Collapsed;
        OpenPanel.Visibility = state == VaultState.Unlocked ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void OnCreate(object sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        string a = CreateMaster.Password, b = CreateConfirm.Password;
        CreateMaster.Clear();
        CreateConfirm.Clear();
        await Vm.CreateAsync(a, b);
    }

    private async void OnUnlock(object sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        string master = UnlockMaster.Password;
        UnlockMaster.Clear();
        await Vm.UnlockAsync(master);
    }

    private void OnUnlockKey(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) OnUnlock(sender, e);
    }

    private void OnGenerate(object sender, RoutedEventArgs e) => NewPassword.Password = VaultViewModel.Generate();

    private async void OnAdd(object sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (await Vm.AddAsync(NewPassword.Password)) NewPassword.Clear();
    }
}
