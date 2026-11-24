using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace AntivirusIA.UI.Controls;

/// <summary>
/// Anneau de progression (0 à 100) dessiné directement : piste + arc arrondi qui s'anime en douceur
/// à chaque changement de <see cref="Value"/>. Utilisé pour le score de protection et l'avancement des analyses.
/// </summary>
public sealed class ArcProgress : FrameworkElement
{
    public static readonly DependencyProperty ValueProperty =
        DependencyProperty.Register(nameof(Value), typeof(double), typeof(ArcProgress),
            new PropertyMetadata(0d, OnValueChanged));

    // Valeur réellement dessinée (interpolée par l'animation)
    private static readonly DependencyProperty DisplayValueProperty =
        DependencyProperty.Register(nameof(DisplayValue), typeof(double), typeof(ArcProgress),
            new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ThicknessProperty =
        DependencyProperty.Register(nameof(Thickness), typeof(double), typeof(ArcProgress),
            new FrameworkPropertyMetadata(10d, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty TrackBrushProperty =
        DependencyProperty.Register(nameof(TrackBrush), typeof(Brush), typeof(ArcProgress),
            new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ProgressBrushProperty =
        DependencyProperty.Register(nameof(ProgressBrush), typeof(Brush), typeof(ArcProgress),
            new FrameworkPropertyMetadata(Brushes.DodgerBlue, FrameworkPropertyMetadataOptions.AffectsRender));

    public double Value { get => (double)GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public double Thickness { get => (double)GetValue(ThicknessProperty); set => SetValue(ThicknessProperty, value); }
    public Brush TrackBrush { get => (Brush)GetValue(TrackBrushProperty); set => SetValue(TrackBrushProperty, value); }
    public Brush ProgressBrush { get => (Brush)GetValue(ProgressBrushProperty); set => SetValue(ProgressBrushProperty, value); }

    private double DisplayValue { get => (double)GetValue(DisplayValueProperty); set => SetValue(DisplayValueProperty, value); }

    private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var ctl = (ArcProgress)d;
        double target = Math.Clamp((double)e.NewValue, 0, 100);
        ctl.BeginAnimation(DisplayValueProperty, new DoubleAnimation
        {
            To = target,
            Duration = TimeSpan.FromMilliseconds(650),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        });
    }

    protected override void OnRender(DrawingContext dc)
    {
        double size = Math.Min(ActualWidth, ActualHeight);
        if (size <= Thickness) return;

        var center = new Point(ActualWidth / 2, ActualHeight / 2);
        double radius = (size - Thickness) / 2;

        dc.DrawEllipse(null, new Pen(TrackBrush, Thickness), center, radius, radius);

        double value = Math.Clamp(DisplayValue, 0, 100);
        if (value <= 0.05) return;

        var pen = new Pen(ProgressBrush, Thickness) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };

        if (value >= 99.95)
        {
            dc.DrawEllipse(null, pen, center, radius, radius);
            return;
        }

        // Départ à midi, sens horaire
        double sweep = value / 100 * 360;
        double endRad = (sweep - 90) * Math.PI / 180;
        var start = new Point(center.X, center.Y - radius);
        var end = new Point(center.X + radius * Math.Cos(endRad), center.Y + radius * Math.Sin(endRad));

        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(start, false, false);
            ctx.ArcTo(end, new Size(radius, radius), 0, sweep > 180, SweepDirection.Clockwise, true, false);
        }
        geometry.Freeze();
        dc.DrawGeometry(null, pen, geometry);
    }
}
