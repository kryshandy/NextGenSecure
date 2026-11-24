using System.Text;
using AntivirusIA.Core.Interfaces;
using LLama;
using LLama.Common;
using LLama.Sampling;

namespace AntivirusIA.AI;

// Fournisseur d'IA local basé sur LLamaSharp (backend CPU) et un modèle GGUF Llama 3
public sealed class LLamaSharpProvider : IAiProvider, IDisposable
{
    private const string EotToken = "<|eot_id|>";

    private readonly AiOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private LLamaWeights? _weights;
    private bool _disposed;

    public LLamaSharpProvider(AiOptions? options = null)
    {
        _options = options ?? new AiOptions();
    }

    public string Name => "LLamaSharp (Llama 3.2 3B local)";

    // Résout le chemin du modèle : absolu tel quel, sinon répertoire de l'exécutable puis répertoire courant.
    // Si introuvable, renvoie le premier candidat (utile pour le message d'erreur).
    public static string ResolveModelPath(string modelPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(modelPath);

        if (Path.IsPathRooted(modelPath))
            return modelPath;

        string[] candidats =
        [
            Path.Combine(AppContext.BaseDirectory, modelPath),
            Path.Combine(Directory.GetCurrentDirectory(), modelPath),
        ];

        return candidats.FirstOrDefault(File.Exists) ?? candidats[0];
    }

    // Assemble system + user au format de chat Llama 3.
    // Le jeton <|begin_of_text|> est ajouté par l'exécuteur : on ne le duplique pas.
    public static string BuildChatPrompt(string systemPrompt, string userPrompt) =>
        $"<|start_header_id|>system<|end_header_id|>\n\n{systemPrompt}{EotToken}" +
        $"<|start_header_id|>user<|end_header_id|>\n\n{userPrompt}{EotToken}" +
        "<|start_header_id|>assistant<|end_header_id|>\n\n";

    public async Task<string> CompleteAsync(string systemPrompt, string userPrompt, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(systemPrompt);
        ArgumentNullException.ThrowIfNull(userPrompt);

        string path = ResolveModelPath(_options.ModelPath);
        if (!File.Exists(path))
            throw new FileNotFoundException(
                $"Modèle GGUF introuvable : '{path}'. Placez le fichier dans le dossier 'models' (aucun téléchargement automatique).", path);

        // Un seul appel d'inférence à la fois (le modèle chargé est partagé)
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var parametres = new ModelParams(path) { ContextSize = _options.ContextSize };

            // Chargement paresseux au premier appel, hors du thread appelant
            _weights ??= await Task.Run(() => LLamaWeights.LoadFromFile(parametres), ct).ConfigureAwait(false);

            var executeur = new StatelessExecutor(_weights, parametres);
            var inference = new InferenceParams
            {
                MaxTokens = _options.MaxTokens,
                AntiPrompts = [EotToken],
                SamplingPipeline = new DefaultSamplingPipeline { Temperature = _options.Temperature },
            };

            var sb = new StringBuilder();
            await foreach (string morceau in executeur.InferAsync(BuildChatPrompt(systemPrompt, userPrompt), inference, ct)
                               .ConfigureAwait(false))
            {
                sb.Append(morceau);
            }

            return sb.ToString().Replace(EotToken, string.Empty).Trim();
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _weights?.Dispose();
        _gate.Dispose();
    }
}
