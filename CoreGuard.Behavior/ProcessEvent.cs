namespace CoreGuard.Behavior;

/// <summary>Événement de création de processus (réel ETW ou synthétique pour les tests).</summary>
public sealed record ProcessEvent(int Pid, int ParentPid, string Image, string CommandLine, DateTime WhenUtc);

/// <summary>Alerte comportementale. Severity : 0 (info) à 100 (maximum).</summary>
public sealed record BehaviorAlert(string Rule, string Detail, int Severity, int? Pid);
