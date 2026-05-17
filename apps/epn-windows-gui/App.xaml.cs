using Epn.WindowsGui.Services;

namespace Epn.WindowsGui;

public partial class App : System.Windows.Application
{
    private InstanceCoordinator? instances;

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        base.OnStartup(e);
        instances = new InstanceCoordinator();
        var window = new MainWindow(instances);
        MainWindow = window;
        window.Show();
        _ = instances.BecomeLatestAsync();
    }

    protected override void OnExit(System.Windows.ExitEventArgs e)
    {
        instances?.Dispose();
        base.OnExit(e);
    }
}
