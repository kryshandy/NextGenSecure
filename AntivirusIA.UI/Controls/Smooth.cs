using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Media.Animation;

namespace AntivirusIA.UI.Controls;

/// <summary>Propriété attachée : anime la valeur d'une ProgressBar au lieu de la faire sauter.</summary>
public static class Smooth
{
    public static readonly DependencyProperty ValueProperty =
        DependencyProperty.RegisterAttached("Value", typeof(double), typeof(Smooth), new PropertyMetadata(0d, OnValueChanged));

    public static double GetValue(DependencyObject d) => (double)d.GetValue(ValueProperty);
    public static void SetValue(DependencyObject d, double v) => d.SetValue(ValueProperty, v);

    private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not RangeBase bar) return;
        bar.BeginAnimation(RangeBase.ValueProperty, new DoubleAnimation
        {
            To = (double)e.NewValue,
            Duration = TimeSpan.FromMilliseconds(300),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        });
    }
}
