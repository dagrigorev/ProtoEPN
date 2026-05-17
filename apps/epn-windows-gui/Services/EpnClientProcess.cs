using System.Diagnostics;
using System.IO;
using System.Net.Sockets;

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

        var readyFromLog = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var failed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        OutputReceived?.Invoke($"[GUI] Launching: {exe}");

        process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = $"socks --disc-host {Quote(host)} --disc-port {discoveryPort} --socks-port {socksPort} --debug",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(exe)!
            },
            EnableRaisingEvents = true
        };

        process.OutputDataReceived += (_, e) => HandleLine(e.Data, readyFromLog, failed);
        process.ErrorDataReceived += (_, e) => HandleLine(e.Data, readyFromLog, failed);

        process.Exited += (_, _) =>
        {
            var currentProcess = process;
            if (currentProcess is null)
            {
                return;
            }

            int exitCode;

            try
            {
                exitCode = currentProcess.ExitCode;
            }
            catch
            {
                exitCode = -1;
            }

            if (!readyFromLog.Task.IsCompleted)
            {
                failed.TrySetResult($"EPN client exited before SOCKS was ready. Exit code: {exitCode}.");
            }

            Exited?.Invoke(exitCode);
        };

        if (!process.Start())
        {
            throw new InvalidOperationException("Failed to start epn-win-client.exe.");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        await using var reg = cancellationToken.Register(() =>
        {
            failed.TrySetCanceled(cancellationToken);
        });

        var readyFromPort = WaitForTcpPortAsync("127.0.0.1", socksPort, cancellationToken);

        var completed = await Task.WhenAny(
            readyFromLog.Task,
            readyFromPort,
            failed.Task);

        if (completed == failed.Task)
        {
            await StopAsync();
            throw new InvalidOperationException(await failed.Task);
        }

        await completed;
    }

    public async Task StopAsync()
    {
        var currentProcess = process;
        if (currentProcess is null)
        {
            return;
        }

        process = null;

        try
        {
            if (!currentProcess.HasExited)
            {
                try
                {
                    currentProcess.StandardInput.Close();
                }
                catch
                {
                    // ignored
                }

                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));

                try
                {
                    await currentProcess.WaitForExitAsync(timeoutCts.Token);
                }
                catch (OperationCanceledException)
                {
                    if (!currentProcess.HasExited)
                    {
                        currentProcess.Kill(entireProcessTree: true);
                        await currentProcess.WaitForExitAsync();
                    }
                }
            }
        }
        catch
        {
            // The process may have exited between checks.
        }
        finally
        {
            currentProcess.Dispose();
        }
    }

    private static async Task WaitForTcpPortAsync(string host, int port, CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var tcp = new TcpClient();

                var connectTask = tcp.ConnectAsync(host, port, cancellationToken).AsTask();
                var timeoutTask = Task.Delay(5000, cancellationToken);

                var completed = await Task.WhenAny(connectTask, timeoutTask);

                if (completed == connectTask && tcp.Connected)
                {
                    return;
                }
            }
            catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException)
            {
                lastError = ex;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new OperationCanceledException(
            $"SOCKS port {host}:{port} did not become ready. Last error: {lastError?.Message}",
            cancellationToken);
    }

    private void HandleLine(
    string? line,
    TaskCompletionSource ready,
    TaskCompletionSource<string> failed)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return;
        }

        OutputReceived?.Invoke(line);

        if (line.Contains("SOCKS5 proxy running", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("EpnTunnel: established", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("Tunnel: established", StringComparison.OrdinalIgnoreCase))
        {
            ready.TrySetResult();
            return;
        }

        if (line.Contains("[FAIL]", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("Cannot establish", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("error", StringComparison.OrdinalIgnoreCase))
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
