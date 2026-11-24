using System.Windows;
using System.Windows.Controls;

namespace AntivirusIA.UI.Controls;

/// <summary>
/// Ligne de réglage : libellé + description à gauche, contrôle (interrupteur, curseur...) à droite via <c>Content</c>.
/// </summary>
public sealed class SettingRow : ContentControl
{
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(nameof(Title), typeof(string), typeof(SettingRow), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty DescriptionProperty =
        DependencyProperty.Register(nameof(Description), typeof(string), typeof(SettingRow), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty ShowSeparatorProperty =
        DependencyProperty.Register(nameof(ShowSeparator), typeof(bool), typeof(SettingRow), new PropertyMetadata(true));

    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    public string Description { get => (string)GetValue(DescriptionProperty); set => SetValue(DescriptionProperty, value); }
    public bool ShowSeparator { get => (bool)GetValue(ShowSeparatorProperty); set => SetValue(ShowSeparatorProperty, value); }

    static SettingRow() =>
        DefaultStyleKeyProperty.OverrideMetadata(typeof(SettingRow), new FrameworkPropertyMetadata(typeof(SettingRow)));
}
