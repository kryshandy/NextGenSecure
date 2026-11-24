namespace CoreGuard.Network;

/// <summary>Une connexion ou un socket d'écoute TCP/UDP observé sur la machine.</summary>
public sealed record Connection(
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string? RemoteAddress,
    int? RemotePort,
    string State,
    int Pid,
    string? ProcessName);
