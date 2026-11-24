using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace AntivirusIA.UI.Controls;

/// <summary>Carte de section : pastille d'icône, titre, sous-titre et contenu libre.</summary>
public sealed class SectionCard : ContentControl
{
    public static readonly DependencyProperty IconProperty =
        DependencyProperty.Register(nameof(Icon), typeof(Geometry), typeof(SectionCard));
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(nameof(Title), typeof(string), typeof(SectionCard), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty SubtitleProperty =
        DependencyProperty.Register(nameof(Subtitle), typeof(string), typeof(SectionCard), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty HeaderContentProperty =
        DependencyProperty.Register(nameof(HeaderContent), typeof(object), typeof(SectionCard));

    public Geometry? Icon { get => (Geometry?)GetValue(IconProperty); set => SetValue(IconProperty, value); }
    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    public string Subtitle { get => (string)GetValue(SubtitleProperty); set => SetValue(SubtitleProperty, value); }

    /// <summary>Contenu optionnel aligné à droite de l'en-tête (bouton d'action...).</summary>
    public object? HeaderContent { get => GetValue(HeaderContentProperty); set => SetValue(HeaderContentProperty, value); }

    static SectionCard() =>
        DefaultStyleKeyProperty.OverrideMetadata(typeof(SectionCard), new FrameworkPropertyMetadata(typeof(SectionCard)));
}
