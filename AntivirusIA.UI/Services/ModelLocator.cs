namespace AntivirusIA.UI.Services;

/// <summary>
/// Résout le chemin du modèle IA : absolu tel quel ; relatif cherché depuis le répertoire courant
/// (<c>dotnet run --project AntivirusIA.UI</c> depuis la racine du dépôt), puis en remontant depuis l'exécutable.
/// </summary>
public static class ModelLocator
{
    public static string Resolve(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return path;
        if (Path.IsPathRooted(path)) return path;

        string cwd = Path.Combine(Directory.GetCurrentDirectory(), path);
        if (File.Exists(cwd)) return cwd;

        // Lancement depuis Visual Studio : le répertoire courant est bin\Debug\... on remonte jusqu'à trouver models\
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, path);
            if (File.Exists(candidate)) return candidate;
        }
        return cwd;
    }
}
