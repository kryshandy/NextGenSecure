using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;

namespace AntivirusIA.UI.Controls;

/// <summary>
/// TextBlock qui anime son entier affiché (compteur « count-up ») à chaque changement de <see cref="Value"/>.
/// </summary>
public sealed class CountUpTextBlock : TextBlock
{
    public static readonly DependencyProperty ValueProperty =
        DependencyProperty.Register(nameof(Value), typeof(int), typeof(CountUpTextBlock),
            new PropertyMetadata(0, OnValueChanged));

    // Valeur intermédiaire animée (double pour obtenir une interpolation fluide)
    private static readonly DependencyProperty DisplayProperty =
        DependencyProperty.Register(nameof(Display), typeof(double), typeof(CountUpTextBlock),
            new PropertyMetadata(0d, OnDisplayChanged));

    public int Value
    {
        get => (int)GetValue(ValueProperty);
        set => SetValue(ValueProperty, value);
    }

    private double Display
    {
        get => (double)GetValue(DisplayProperty);
        set => SetValue(DisplayProperty, value);
    }

    public CountUpTextBlock() => Text = "0";

    private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var ctl = (CountUpTextBlock)d;
        var animation = new DoubleAnimation
        {
            To = (int)e.NewValue,
            Duration = TimeSpan.FromMilliseconds(800),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        ctl.BeginAnimation(DisplayProperty, animation);
    }

    private static void OnDisplayChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) =>
        ((CountUpTextBlock)d).Text = Math.Round((double)e.NewValue).ToString("N0", CultureInfo.CurrentCulture);
}
