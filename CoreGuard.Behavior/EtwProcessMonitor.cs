using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace CoreGuard.Behavior;

/// <summary>
/// Écoute les créations de processus via le fournisseur kernel ETW et les confie au
/// <see cref="BehaviorRuleEngine"/>. Nécessite les droits administrateur ; sinon dégrade
/// en émettant un avertissement.
/// </summary>
public sealed class EtwProcessMonitor : IProcessTelemetry
{
    private const string SessionName = "CoreGuard-Behavior-Process";

    private readonly BehaviorRuleEngine _engine;
    private readonly object _lock = new();
    private TraceEventSession? _session;
    private Thread? _thread;

    public EtwProcessMonitor(BehaviorRuleEngine engine) =>
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));

    public bool IsRunning { get; private set; }
    public event EventHandler<BehaviorAlert>? AlertRaised;
    public event EventHandler<string>? Warning;

    public bool Start()
    {
        lock (_lock)
        {
            if (IsRunning) return true;
            try
            {
                if (TraceEventSession.IsElevated() != true)
                {
                    Warning?.Invoke(this, "Surveillance ETW des processus désactivée : droits administrateur requis.");
                    return false;
                }

                var session = new TraceEventSession(SessionName) { StopOnDispose = true };
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);
                session.Source.Kernel.ProcessStart += data =>
                    OnProcessStart(data.ProcessID, data.ParentID, data.ImageFileName, data.CommandLine, data.TimeStamp);

                _session = session;
                _thread = new Thread(() => RunSession(session)) { IsBackground = true, Name = "CoreGuard.EtwProcess" };
                _thread.Start();
                IsRunning = true;
                return true;
            }
            catch (Exception ex)
            {
                CleanupSession();
                Warning?.Invoke(this, $"Impossible de démarrer la session ETW : {ex.GetType().Name}");
                return false;
            }
        }
    }

    private void RunSession(TraceEventSession session)
    {
        try { session.Source.Process(); }
        catch (Exception ex) { Warning?.Invoke(this, $"Session ETW interrompue : {ex.GetType().Name}"); }
        finally { IsRunning = false; }
    }

    private void OnProcessStart(int pid, int parentPid, string? image, string? commandLine, DateTime when)
    {
        try
        {
            var evt = new ProcessEvent(pid, parentPid, image ?? string.Empty, commandLine ?? string.Empty, when.ToUniversalTime());
            foreach (var alert in _engine.Evaluate(evt))
                AlertRaised?.Invoke(this, alert);
        }
        catch
        {
            // Un abonné défaillant ne doit jamais tuer le thread de trace.
        }
    }

    public void Stop()
    {
        Thread? thread;
        lock (_lock)
        {
            thread = _thread;
            CleanupSession();
            IsRunning = false;
        }
        thread?.Join(TimeSpan.FromSeconds(3));
    }

    private void CleanupSession()
    {
        try { _session?.Dispose(); } catch { /* arrêt best-effort */ }
        _session = null;
        _thread = null;
    }

    public void Dispose() => Stop();
}
