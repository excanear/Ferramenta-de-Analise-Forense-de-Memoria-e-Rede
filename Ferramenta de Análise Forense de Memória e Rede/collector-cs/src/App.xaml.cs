using System.Windows;

namespace ForensicCollector.UI;

public partial class App : Application
{
    protected void OnStartup(object sender, StartupEventArgs e)
    {
        MainWindow mainWindow = new MainWindow();
        mainWindow.Show();
    }
}
