namespace CoreGuard.Network;

/// <summary>Erreur claire levée quand le pare-feu ne peut pas être piloté (droits, COM indisponible...).</summary>
public sealed class NetworkGuardException : Exception
{
    public NetworkGuardException(string message) : base(message) { }
    public NetworkGuardException(string message, Exception inner) : base(message, inner) { }
}
