using System.Windows.Controls;
using System.Windows.Input;

namespace AntivirusIA.UI.Views;

public partial class DashboardView : UserControl
{
    public DashboardView() => InitializeComponent();

    // Le flux d'alertes a son propre défilement : en butée, la molette doit faire défiler la page entière
    private void OnAlertsWheel(object sender, MouseWheelEventArgs e)
    {
        if (sender is not ScrollViewer inner) return;

        bool atTop = inner.VerticalOffset <= 0 && e.Delta > 0;
        bool atBottom = inner.VerticalOffset >= inner.ScrollableHeight && e.Delta < 0;
        if (inner.ScrollableHeight <= 0 || atTop || atBottom)
        {
            e.Handled = true;
            PageScroll.ScrollToVerticalOffset(PageScroll.VerticalOffset - e.Delta);
        }
    }
}
