using AntivirusIA.Core.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AntivirusIA.AI;

public static class ServiceCollectionExtensions
{
    // Enregistre le fournisseur d'IA local (LLamaSharp) en singleton ; le modèle n'est chargé qu'au premier appel
    public static IServiceCollection AddCoreGuardAi(this IServiceCollection services, AiOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var opts = options ?? new AiOptions();
        services.TryAddSingleton(opts);
        services.TryAddSingleton<LLamaSharpProvider>(_ => new LLamaSharpProvider(opts));
        services.TryAddSingleton<IAiProvider>(sp => sp.GetRequiredService<LLamaSharpProvider>());
        return services;
    }
}
