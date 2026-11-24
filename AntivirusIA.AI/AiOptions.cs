namespace AntivirusIA.AI;

// Options du fournisseur LLM local (LLamaSharp)
public sealed record AiOptions
{
    // Chemin par défaut du modèle, relatif à l'exécutable ou au répertoire courant
    public const string DefaultModelPath = "models/Llama-3.2-3B-Instruct-Q4_K_M.gguf";

    public string ModelPath { get; init; } = DefaultModelPath;

    // Nombre maximal de tokens générés par réponse
    public int MaxTokens { get; init; } = 512;

    // Température basse : réponses plus déterministes pour un verdict de sécurité
    public float Temperature { get; init; } = 0.2f;

    // Taille du contexte (prompt + réponse)
    public uint ContextSize { get; init; } = 4096;
}
