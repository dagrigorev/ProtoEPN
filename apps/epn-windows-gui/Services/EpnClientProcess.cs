using System.Diagnostics;
using System.IO;

namespace Epn.WindowsGui.Services;

public sealed class EpnClientProcess
{
    private Process? process;

    public event Action<string>? OutputReceived;
    public event Action<int>? Exited;

    public async Task StartAsync(string host, int discoveryPort, int socksPort, CancellationToken cancellationToken)
    {
        if (process is { HasExited: false })
        {
            throw new InvalidOperationException("EPN client is already running.");
        }

        var exe = ResolveClientExe();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var failed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = $"socks --disc-host {Quote(host)} --disc-port {discoveryPort} --socks-port {socksPort} --debug",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(exe)!
            },
            EnableRaisingEvents = true
        };

        process.OutputDataReceived += (_, e) => HandleLine(e.Data, ready, failed);
        process.ErrorDataReceived += (_, e) => HandleLine(e.Data, ready, failed);
        process.Exited += (_, _) =>
        {
            if (!ready.Task.IsCompleted)
            {
                failed.TrySetResult($"EPN client exited with code {process.ExitCode}.");
            }
            Exited?.Invoke(process.ExitCode);
        };

        if (!process.Start())
        {
            throw new InvalidOperationException("Failed to start epn-win-client.exe.");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        await using var reg = cancellationToken.Register(() => failed.TrySetCanceled(cancellationToken));
        var completed = await Task.WhenAny(ready.Task, failed.Task);
        await completed;

        if (completed == failed.Task)
        {
            await StopAsync();
            throw new InvalidOperationException(await failed.Task);
        }
    }

    public async Task StopAsync()
    {
        if (process is null)
        {
            return;
        }

        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
        catch
        {
            // The process may have exited between HasExited and Kill.
        }
        finally
        {
            process.Dispose();
            process = null;
        }
    }

    private void HandleLine(string? line, TaskCompletionSource ready, TaskCompletionSource<string> failed)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return;
        }

        OutputReceived?.Invoke(line);

        if (line.Contains("SOCKS5 proxy running", StringComparison.OrdinalIgnoreCase))
        {
            ready.TrySetResult();
        }
        else if (line.Contains("[FAIL]", StringComparison.OrdinalIgnoreCase) ||
                 line.Contains("Cannot establish", StringComparison.OrdinalIgnoreCase))
        {
            failed.TrySetResult(line);
        }
    }

    private static string ResolveClientExe()
    {
        var baseDir = AppContext.BaseDirectory;
        var candidates = new List<string>
        {
            Path.Combine(baseDir, "epn-win-client.exe"),
            Path.Combine(baseDir, "..", "epn-win-client", "epn-win-client.exe")
        };

        var cursor = new DirectoryInfo(baseDir);
        for (var i = 0; i < 8 && cursor is not null; i++, cursor = cursor.Parent)
        {
            candidates.Add(Path.Combine(cursor.FullName, "build-windows", "apps", "epn-win-client", "epn-win-client.exe"));
        }

        foreach (var candidate in candidates)
        {
            var full = Path.GetFullPath(candidate);
            if (File.Exists(full))
            {
                return full;
            }
        }

        throw new FileNotFoundException("epn-win-client.exe was not found next to the GUI application.");
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
    }
}
