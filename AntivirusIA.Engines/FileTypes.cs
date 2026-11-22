namespace AntivirusIA.Engines;

internal static class FileTypes
{
    public static readonly HashSet<string> Executables = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".sys", ".com", ".msi"
    };

    public static readonly HashSet<string> Scripts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".vbs", ".js", ".bat", ".cmd", ".wsf", ".hta"
    };

    public static readonly HashSet<string> Documents = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip"
    };
}