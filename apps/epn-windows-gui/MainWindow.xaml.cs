using System.ComponentModel;
using System.IO;
using System.Windows;
using Epn.WindowsGui.Services;
using Forms = System.Windows.Forms;
using Media = System.Windows.Media;

namespace Epn.WindowsGui;

public partial class MainWindow : Window
{
    private readonly EpnClientProcess client = new();
    private readonly InstanceCoordinator instances;
    private readonly Forms.NotifyIcon trayIcon;
    private bool exitRequested;
    private bool closeInsteadOfTray;

    private CancellationTokenSource? connectCts;
    private int connectionGeneration;
    private bool disconnectInProgress;

    public MainWindow(InstanceCoordinator instances)
    {
        InitializeComponent();
        this.instances = instances;

        trayIcon = new Forms.NotifyIcon
        {
            Icon = new System.Drawing.Icon(Path.Combine(AppContext.BaseDirectory, "Assets", "epn.ico")),
            Text = "EPN Client",
            Visible = true,
            ContextMenuStrip = BuildTrayMenu()
        };
        trayIcon.DoubleClick += (_, _) => RestoreFromTray();

        client.OutputReceived += line => Dispatcher.Invoke(() => ObserveClientOutput(line));
        client.Exited += code => Dispatcher.Invoke(() => OnClientExited(code));

        LoadSettings();
        SetDisconnected("Ready.");
    }

    private Forms.ContextMenuStrip BuildTrayMenu()
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open", null, (_, _) => RestoreFromTray());
        menu.Items.Add("Disconnect", null, async (_, _) => await DisconnectAsync());
        menu.Items.Add("Exit", null, async (_, _) =>
        {
            exitRequested = true;
            await DisconnectAsync();
            trayIcon.Visible = false;
            trayIcon.Dispose();
            System.Windows.Application.Current.Shutdown();
        });
        return menu;
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        await ConnectAsync();
    }

    private async void DisconnectButton_Click(object sender, RoutedEventArgs e)
    {
        await DisconnectAsync();
    }

    private async Task ConnectAsync()
    {
        var generation = ++connectionGeneration;

        connectCts?.Cancel();
        connectCts?.Dispose();
        connectCts = null;

        try
        {
            var endpoint = EndpointParser.Parse(EndpointBox.Text);
            var socksPort = ParsePort(SocksPortBox.Text, "SOCKS port");
            var timeout = ParseTimeout(TimeoutBox.Text);

            SaveSettings();
            SetConnecting($"Discovering {endpoint.Host}:{endpoint.Port}...");

            connectCts = new CancellationTokenSource(timeout);
            var token = connectCts.Token;

            await client.StartAsync(endpoint.Host, endpoint.Port, socksPort, token);

            if (token.IsCancellationRequested || generation != connectionGeneration)
            {
                return;
            }

            SetConnecting("Testing tunneled web access...");
            await SocksProbe.VerifyHttpAsync(socksPort, token);

            if (token.IsCancellationRequested || generation != connectionGeneration)
            {
                return;
            }

            SystemProxy.EnablePac("127.0.0.1", socksPort, allowDirectFallback: false);

            if (token.IsCancellationRequested || generation != connectionGeneration)
            {
                await RunCleanupAsync();
                return;
            }

            SetConnected($"System proxy: PAC → SOCKS5 127.0.0.1:{socksPort}");
            trayIcon.Text = "EPN connected";
            trayIcon.ShowBalloonTip(1500, "EPN", "Connected", Forms.ToolTipIcon.Info);
        }
        catch (OperationCanceledException)
        {
            if (generation == connectionGeneration && !disconnectInProgress)
            {
                await DisconnectAsync();
                SetDisconnected("Connection timeout.");
            }
        }
        catch (Exception ex)
        {
            if (generation == connectionGeneration && !disconnectInProgress)
            {
                await DisconnectAsync();
                SetDisconnected(ex.Message);
            }
        }
    }

    private async Task DisconnectAsync()
    {
        if (disconnectInProgress)
        {
            return;
        }

        disconnectInProgress = true;

        try
        {
            connectionGeneration++;

            connectCts?.Cancel();

            await client.StopAsync();
            await RunCleanupAsync();

            SetDisconnected("Proxy disabled.");
            trayIcon.Text = "EPN disconnected";
        }
        finally
        {
            connectCts?.Dispose();
            connectCts = null;
            disconnectInProgress = false;
        }
    }

    private static int ParsePort(string value, string name)
    {
        if (!int.TryParse(value.Trim(), out var port) || port is < 1 or > 65535)
        {
            throw new InvalidOperationException($"{name} must be between 1 and 65535.");
        }
        return port;
    }

    private static TimeSpan ParseTimeout(string value)
    {
        if (!int.TryParse(value.Trim(), out var seconds) || seconds is < 3 or > 300)
        {
            throw new InvalidOperationException("Timeout must be between 3 and 300 seconds.");
        }
        return TimeSpan.FromSeconds(seconds);
    }

    private void ObserveClientOutput(string line)
    {
        DetailsText.Text = line;

        if (disconnectInProgress)
        {
            return;
        }

        if (line.Contains("SOCKS5 proxy running", StringComparison.OrdinalIgnoreCase))
        {
            SetConnected("SOCKS5 proxy is running.");
        }
        else if (line.Contains("route built", StringComparison.OrdinalIgnoreCase))
        {
            DetailsText.Text = line;
        }
        else if (line.Contains("tunnel established", StringComparison.OrdinalIgnoreCase))
        {
            SetConnecting("Tunnel established. Starting local SOCKS proxy...");
        }
        else if (line.Contains("Stopped. Goodbye", StringComparison.OrdinalIgnoreCase))
        {
            SetDisconnected("EPN client stopped.");
        }
        else if (line.Contains("Cannot establish", StringComparison.OrdinalIgnoreCase) ||
                 line.Contains("[FAIL]", StringComparison.OrdinalIgnoreCase))
        {
            SetDisconnected(line);
        }
    }

    private void OnClientExited(int code)
    {
        if (exitRequested || disconnectInProgress)
        {
            return;
        }

        _ = RunCleanupAsync();
        SetDisconnected(code == 0
            ? "EPN process stopped."
            : $"EPN process exited with code {code}.");
    }

    private async Task RunCleanupAsync()
    {
        try
        {
            await client.CleanupAsync();
        }
        catch (Exception ex)
        {
            SystemProxy.Disable();
            DetailsText.Text = $"Cleanup fallback used: {ex.Message}";
        }
    }

    private void SetConnecting(string details)
    {
        ConnectButton.IsEnabled = false;
        DisconnectButton.IsEnabled = true;
        EndpointBox.IsEnabled = false;
        SocksPortBox.IsEnabled = false;
        TimeoutBox.IsEnabled = false;
        StatusDot.Fill = Media.Brushes.Goldenrod;
        StatusText.Text = "Connecting";
        DetailsText.Text = details;
    }

    private void SetConnected(string details)
    {
        ConnectButton.IsEnabled = false;
        DisconnectButton.IsEnabled = true;
        EndpointBox.IsEnabled = false;
        SocksPortBox.IsEnabled = false;
        TimeoutBox.IsEnabled = false;
        StatusDot.Fill = (Media.Brush)FindResource("GoodBrush");
        StatusText.Text = "Connected";
        DetailsText.Text = details;
    }

    private void SetDisconnected(string details)
    {
        ConnectButton.IsEnabled = true;
        DisconnectButton.IsEnabled = false;
        EndpointBox.IsEnabled = true;
        SocksPortBox.IsEnabled = true;
        TimeoutBox.IsEnabled = true;
        StatusDot.Fill = Media.Brushes.SlateGray;
        StatusText.Text = "Disconnected";
        DetailsText.Text = details;
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (exitRequested || closeInsteadOfTray)
        {
            return;
        }

        if (!instances.IsLatestOwner)
        {
            closeInsteadOfTray = true;
            exitRequested = true;
            return;
        }

        e.Cancel = true;
        Hide();
        trayIcon.ShowBalloonTip(1500, "EPN", "Still running in the tray.", Forms.ToolTipIcon.Info);
    }

    private void LoadSettings()
    {
        EndpointBox.Text = UserSettings.Get("Endpoint", EndpointBox.Text);
        SocksPortBox.Text = UserSettings.Get("SocksPort", SocksPortBox.Text);
        TimeoutBox.Text = UserSettings.Get("Timeout", TimeoutBox.Text);
    }

    private void SaveSettings()
    {
        UserSettings.Set("Endpoint", EndpointBox.Text.Trim());
        UserSettings.Set("SocksPort", SocksPortBox.Text.Trim());
        UserSettings.Set("Timeout", TimeoutBox.Text.Trim());
    }
}
