namespace CoreGuard.RealTime;

/// <summary>
/// Alerte levée lorsqu'un fichier canari est touché (modifié, supprimé ou renommé).
/// </summary>
/// <param name="CanaryPath">Chemin complet du canari touché.</param>
/// <param name="OperationType">Type d'opération : "Modified", "Deleted" ou "Renamed".</param>
/// <param name="WhenUtc">Horodatage UTC de la détection.</param>
/// <param name="SuspectPid">PID suspect (best-effort, peut être null : voir <see cref="PidResolver"/>).</param>
public sealed record CanaryAlert(string CanaryPath, string OperationType, DateTime WhenUtc, int? SuspectPid);
