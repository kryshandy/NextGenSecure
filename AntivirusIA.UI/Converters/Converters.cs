using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace AntivirusIA.UI.Converters;

/// <summary>Vrai -> Collapsed, Faux -> Visible (inverse du convertisseur standard).</summary>
public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Visible quand un entier vaut zéro (état vide d'une liste).</summary>
public sealed class ZeroToVisibleConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is int n && n == 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Visible quand une chaîne est non vide.</summary>
public sealed class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        string.IsNullOrWhiteSpace(value as string) ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Inverse d'un booléen (pour IsEnabled).</summary>
public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;
}

/// <summary>Visible quand un entier est strictement positif (pastille de compteur, bandeau...).</summary>
public sealed class NonZeroToVisibleConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is int n && n > 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Vrai quand la valeur (enum ou texte) correspond au paramètre ; à l'inverse, un clic sur une puce
/// (RadioButton) réécrit la valeur d'énumération. Permet de lier des filtres à une propriété d'énumération.
/// </summary>
public sealed class EnumEqualsConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is not null && string.Equals(value.ToString(), parameter?.ToString(), StringComparison.Ordinal);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true && parameter is not null
            ? Enum.Parse(targetType, parameter.ToString()!)
            : Binding.DoNothing;
}
