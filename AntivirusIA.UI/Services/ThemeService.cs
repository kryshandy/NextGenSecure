using System.Windows;

namespace AntivirusIA.UI.Services;

/// <summary>Bascule thème sombre / clair en remplaçant le dictionnaire de palette (les styles utilisent DynamicResource).</summary>
public sealed class ThemeService
{
    private static readonly Uri Dark = new("Themes/Dark.xaml", UriKind.Relative);
    private static readonly Uri Light = new("Themes/Light.xaml", UriKind.Relative);

    public void Apply(bool dark)
    {
        var merged = Application.Current.Resources.MergedDictionaries;
        var target = dark ? Dark : Light;

        for (int i = 0; i < merged.Count; i++)
        {
            string? source = merged[i].Source?.OriginalString;
            if (source is not null && (source.EndsWith("Dark.xaml", StringComparison.OrdinalIgnoreCase) ||
                                       source.EndsWith("Light.xaml", StringComparison.OrdinalIgnoreCase)))
            {
                merged[i] = new ResourceDictionary { Source = target };
                return;
            }
        }
        merged.Insert(0, new ResourceDictionary { Source = target });
    }
}
