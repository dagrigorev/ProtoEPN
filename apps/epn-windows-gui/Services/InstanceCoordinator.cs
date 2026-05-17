namespace Epn.WindowsGui.Services;

public sealed class InstanceCoordinator : IDisposable
{
    private const string MutexName = @"Local\EPN.WindowsGui.ActiveOwner";
    private const string ShutdownEventName = @"Local\EPN.WindowsGui.ShutdownPrevious";

    private readonly EventWaitHandle shutdownEvent;
    private readonly CancellationTokenSource cts = new();
    private Mutex? ownerMutex;
    private Task? watcher;

    public event Action? ShutdownRequested;

    public bool IsLatestOwner { get; private set; }

    public InstanceCoordinator()
    {
        shutdownEvent = new EventWaitHandle(
            initialState: false,
            mode: EventResetMode.AutoReset,
            name: ShutdownEventName);
    }

    public async Task BecomeLatestAsync()
    {
        shutdownEvent.Set();
        await Task.Delay(700, cts.Token);
        AcquireOwnerMutex();
        watcher = Task.Run(WatchShutdownRequestsAsync);
    }

    private void AcquireOwnerMutex()
    {
        ownerMutex?.Dispose();
        ownerMutex = new Mutex(initiallyOwned: true, name: MutexName, out var createdNew);
        if (!createdNew)
        {
            try
            {
                IsLatestOwner = ownerMutex.WaitOne(TimeSpan.Zero);
            }
            catch (AbandonedMutexException)
            {
                IsLatestOwner = true;
            }
        }
        else
        {
            IsLatestOwner = true;
        }
    }

    private void WatchShutdownRequestsAsync()
    {
        while (!cts.IsCancellationRequested)
        {
            if (!shutdownEvent.WaitOne(500))
            {
                continue;
            }

            if (!IsLatestOwner)
            {
                continue;
            }

            IsLatestOwner = false;
            ShutdownRequested?.Invoke();
            return;
        }
    }

    public void Dispose()
    {
        cts.Cancel();
        try
        {
            if (IsLatestOwner)
            {
                ownerMutex?.ReleaseMutex();
            }
        }
        catch
        {
            // Mutex may already be abandoned during process shutdown.
        }
        ownerMutex?.Dispose();
        shutdownEvent.Dispose();
        cts.Dispose();
    }
}
