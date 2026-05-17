using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace Epn.WindowsGui.Services;

public sealed class InstanceCoordinator : IDisposable
{
    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "EPN",
        "instances");
    private static readonly string LatestPath = Path.Combine(StateDir, "latest.json");

    private readonly int currentPid = Environment.ProcessId;
    private readonly string currentToken = Guid.NewGuid().ToString("N");

    public bool IsLatestOwner => ReadLatest()?.Pid == currentPid &&
                                 ReadLatest()?.Token == currentToken;

    public async Task BecomeLatestAsync()
    {
        Directory.CreateDirectory(StateDir);
        var previous = ReadLatest();
        WriteLatest(new InstanceState(currentPid, currentToken));

        if (previous is not null && previous.Pid != currentPid)
        {
            await ClosePreviousAsync(previous.Pid);
        }
    }

    private static async Task ClosePreviousAsync(int pid)
    {
        Process? process = null;

        try
        {
            process = Process.GetProcessById(pid);
            if (process.ProcessName.Equals("epn-windows-gui", StringComparison.OrdinalIgnoreCase))
            {
                process.CloseMainWindow();
                for (var i = 0; i < 20 && !process.HasExited; i++)
                {
                    await Task.Delay(100);
                    process.Refresh();
                }

                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync();
                }
            }
        }
        catch
        {
            // The previous process may already be gone.
        }
        finally
        {
            process?.Dispose();
        }
    }

    public void Dispose()
    {
        if (IsLatestOwner)
        {
            TryDeleteLatest();
        }
    }

    private static InstanceState? ReadLatest()
    {
        try
        {
            return File.Exists(LatestPath)
                ? JsonSerializer.Deserialize<InstanceState>(File.ReadAllText(LatestPath))
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static void WriteLatest(InstanceState state)
    {
        File.WriteAllText(LatestPath, JsonSerializer.Serialize(state));
    }

    private static void TryDeleteLatest()
    {
        try { File.Delete(LatestPath); } catch { }
    }

    private sealed record InstanceState(int Pid, string Token);
}
