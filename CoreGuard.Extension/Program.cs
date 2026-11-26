using CoreGuard.Extension;

// Hôte Native Messaging CoreGuard : boucle stdin -> routeur -> stdout.
// IMPORTANT : stdout est réservé au protocole ; aucun Console.WriteLine ailleurs.
using var entree = Console.OpenStandardInput();
using var sortie = Console.OpenStandardOutput();

// Identifiants : coffre CoreGuard via l'interface (refus si cet hôte n'a pas été lancé par un navigateur signé)
var routeur = new HostRouter(new OcrPhishingAnalyzer(), new VaultCredentialProvider());

while (true)
{
    try
    {
        using var message = await NativeMessagingProtocol.ReadAsync(entree);
        if (message is null) break; // le navigateur a fermé le flux

        var reponse = await routeur.HandleAsync(message.RootElement);
        await NativeMessagingProtocol.WriteAsync(sortie, reponse);
    }
    catch (InvalidDataException e)
    {
        // Flux corrompu : on signale l'erreur puis on s'arrête (resynchronisation impossible).
        await NativeMessagingProtocol.WriteAsync(sortie, new { ok = false, error = e.Message });
        break;
    }
}
