using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace AntivirusIA.UI.Controls;

/// <summary>
/// État vide illustré : médaillon vectoriel (cercles concentriques + icône), titre et description.
/// Le rendu est défini par le style par défaut (Styles.xaml).
/// </summary>
public sealed class EmptyState : Control
{
    public static readonly DependencyProperty IconProperty =
        DependencyProperty.Register(nameof(Icon), typeof(Geometry), typeof(EmptyState));
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(nameof(Title), typeof(string), typeof(EmptyState), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty DescriptionProperty =
        DependencyProperty.Register(nameof(Description), typeof(string), typeof(EmptyState), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty ToneBrushProperty =
        DependencyProperty.Register(nameof(ToneBrush), typeof(Brush), typeof(EmptyState));
    public static readonly DependencyProperty ToneSoftBrushProperty =
        DependencyProperty.Register(nameof(ToneSoftBrush), typeof(Brush), typeof(EmptyState));

    public Geometry? Icon { get => (Geometry?)GetValue(IconProperty); set => SetValue(IconProperty, value); }
    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    public string Description { get => (string)GetValue(DescriptionProperty); set => SetValue(DescriptionProperty, value); }
    public Brush? ToneBrush { get => (Brush?)GetValue(ToneBrushProperty); set => SetValue(ToneBrushProperty, value); }
    public Brush? ToneSoftBrush { get => (Brush?)GetValue(ToneSoftBrushProperty); set => SetValue(ToneSoftBrushProperty, value); }

    static EmptyState() =>
        DefaultStyleKeyProperty.OverrideMetadata(typeof(EmptyState), new FrameworkPropertyMetadata(typeof(EmptyState)));
}
