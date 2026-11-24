using System.Windows;
using System.Windows.Controls;
using AntivirusIA.UI.ViewModels;

namespace AntivirusIA.UI.Views;

public partial class ScanView : UserControl
{
    public ScanView() => InitializeComponent();

    // Indication visuelle de dépôt : voile accentué au-dessus de la zone de résultats
    private void OnDragEnter(object sender, DragEventArgs e) =>
        DropOverlay.Visibility = e.Data.GetDataPresent(DataFormats.FileDrop) ? Visibility.Visible : Visibility.Collapsed;

    private void OnDragLeave(object sender, DragEventArgs e) =>
        DropOverlay.Visibility = Visibility.Collapsed;

    // Glisser-déposer : le chemin est une donnée externe, il est validé par ScanService (existence du fichier/dossier)
    private async void OnDrop(object sender, DragEventArgs e)
    {
        DropOverlay.Visibility = Visibility.Collapsed;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths && DataContext is ScanViewModel vm)
            await vm.ScanPathAsync(paths[0]);
    }
}
