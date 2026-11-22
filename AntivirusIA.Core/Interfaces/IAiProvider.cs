namespace AntivirusIA.Core.Interfaces;

// Un fournisseur d'IA (Gemini, DeepSeek...) : il reçoit un prompt et renvoie le texte brut
public interface IAiProvider
{
    string Name { get; }

    Task<string> CompleteAsync(string systemPrompt, string userPrompt, CancellationToken ct = default);
}