using System.Windows;
using System.Windows.Controls;
using AntivirusIA.UI.ViewModels;

namespace AntivirusIA.UI.Views;

public partial class ScanView : UserControl
{
    public ScanView() => InitializeComponent();

    private void OnDragEnter(object sender, DragEventArgs e) =>
        DropOutline.SetResourceReference(System.Windows.Shapes.Shape.StrokeProperty, "AccentBrush");

    private void OnDragLeave(object sender, DragEventArgs e) =>
        DropOutline.SetResourceReference(System.Windows.Shapes.Shape.StrokeProperty, "BorderBrush");

    // Glisser-déposer : le chemin est une donnée externe, il est validé par ScanService (existence du fichier/dossier)
    private async void OnDrop(object sender, DragEventArgs e)
    {
        OnDragLeave(sender, e);
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths && DataContext is ScanViewModel vm)
            await vm.ScanPathAsync(paths[0]);
    }
}
