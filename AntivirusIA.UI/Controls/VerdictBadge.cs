using System.Windows;
using System.Windows.Controls;
using AntivirusIA.Core.Models;

namespace AntivirusIA.UI.Controls;

/// <summary>
/// Pastille de verdict : Sain = vert, Suspect = orange, Malveillant = rouge.
/// Le rendu (couleurs, texte, pulsation) est entièrement défini dans le template de Styles.xaml.
/// </summary>
public sealed class VerdictBadge : Control
{
    public static readonly DependencyProperty VerdictProperty =
        DependencyProperty.Register(nameof(Verdict), typeof(Verdict), typeof(VerdictBadge),
            new FrameworkPropertyMetadata(Verdict.Sain));

    public Verdict Verdict
    {
        get => (Verdict)GetValue(VerdictProperty);
        set => SetValue(VerdictProperty, value);
    }

    static VerdictBadge() =>
        DefaultStyleKeyProperty.OverrideMetadata(typeof(VerdictBadge), new FrameworkPropertyMetadata(typeof(VerdictBadge)));
}
