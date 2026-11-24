using System.Windows;

namespace AntivirusIA.UI.Services;

/// <summary>Marshalling vers le thread UI : les événements temps réel arrivent sur des threads d'arrière-plan.</summary>
public static class UiThread
{
    public static void Post(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.HasShutdownStarted) return;

        if (dispatcher.CheckAccess()) action();
        else dispatcher.BeginInvoke(action);
    }
}
