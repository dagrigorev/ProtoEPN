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
    private readonly Forms.NotifyIcon trayIcon;
    private bool exitRequested;

    public MainWindow()
    {
        InitializeComponent();

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
        try
        {
            var endpoint = EndpointParser.Parse(EndpointBox.Text);
            var socksPort = ParsePort(SocksPortBox.Text, "SOCKS port");
            var timeout = ParseTimeout(TimeoutBox.Text);

            SaveSettings();
            SetConnecting($"Discovering {endpoint.Host}:{endpoint.Port}...");

            using var cts = new CancellationTokenSource(timeout);
            await client.StartAsync(endpoint.Host, endpoint.Port, socksPort, cts.Token);
            SystemProxy.EnableSocks("127.0.0.1", socksPort);

            SetConnected($"System proxy: socks=127.0.0.1:{socksPort}");
            trayIcon.Text = "EPN connected";
            trayIcon.ShowBalloonTip(1500, "EPN", "Connected", Forms.ToolTipIcon.Info);
        }
        catch (OperationCanceledException)
        {
            await DisconnectAsync();
            SetDisconnected("Connection timeout.");
        }
        catch (Exception ex)
        {
            await DisconnectAsync();
            SetDisconnected(ex.Message);
        }
    }

    private async Task DisconnectAsync()
    {
        SystemProxy.Disable();
        await client.StopAsync();
        SetDisconnected("Proxy disabled.");
        trayIcon.Text = "EPN disconnected";
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
        if (line.Contains("route built", StringComparison.OrdinalIgnoreCase))
        {
            DetailsText.Text = line;
        }
        else if (line.Contains("tunnel established", StringComparison.OrdinalIgnoreCase))
        {
            SetConnected("Tunnel established.");
        }
        else if (line.Contains("Cannot establish", StringComparison.OrdinalIgnoreCase) ||
                 line.Contains("[FAIL]", StringComparison.OrdinalIgnoreCase))
        {
            SetDisconnected(line);
        }
    }

    private void OnClientExited(int code)
    {
        if (!exitRequested && code != 0)
        {
            SystemProxy.Disable();
            SetDisconnected($"EPN process exited with code {code}.");
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
        if (exitRequested)
        {
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
