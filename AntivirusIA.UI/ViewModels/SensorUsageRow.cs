namespace AntivirusIA.UI.ViewModels;

/// <summary>Ligne « application qui utilise un capteur » du tableau de bord.</summary>
public sealed class SensorUsageRow(CoreGuard.Privacy.SensorUsage usage)
{
    public CoreGuard.Privacy.SensorUsage Usage { get; } = usage;

    public string SensorLabel => Usage.Sensor switch
    {
        "webcam" => "Caméra",
        "microphone" => "Micro",
        _ => Usage.Sensor
    };

    public string AppName => CoreGuard.Privacy.SensorControl.IsDesktopApp(Usage.Process)
        ? Path.GetFileName(Usage.Process)
        : Usage.Process.Split('_')[0];

    public string Detail => Usage.Process;

    public string IconKey => Usage.Sensor == "webcam" ? "Icon.Camera" : "Icon.Eye";
}
