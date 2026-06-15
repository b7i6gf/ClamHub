using System.Diagnostics;
using System.Reflection;
using System.Windows;
using System.Windows.Input;
using System.Windows.Navigation;
using ClamAVGui.Core;

namespace ClamAVGui;

/// <summary>
/// Small modal About dialog. Shows the app version (read from the assembly),
/// the ClamAV engine version and each signature database file with its version,
/// plus a clickable link to the GitHub repository. Opened from the About button.
/// </summary>
public partial class AboutWindow : Window
{
    /// <summary>
    /// Creates the About dialog from the collected version info (or null when
    /// the ClamAV binaries were not found). Called from: MainWindow.About_Click.
    /// </summary>
    public AboutWindow(UpdateManager.VersionInfo? info)
    {
        InitializeComponent();

        // App version comes from the assembly so it stays in sync with the csproj.
        var asm = Assembly.GetExecutingAssembly().GetName().Version;
        string appVersion = asm != null ? $"{asm.Major}.{asm.Minor}.{asm.Build}" : "1.0.0";

        HeaderVersionLine.Text = $"App Version {appVersion}     |     {info?.Engine ?? "ClamAV not found"}";

        if (info == null)
        {
            DbHeaderLine.Text = "Database Versions: not available";
            DbListLine.Text = "";
            return;
        }

        DbHeaderLine.Text = string.IsNullOrWhiteSpace(info.BuildTime)
            ? "Database Versions:"
            : $"Database Versions: last updated {info.BuildTime}";

        DbListLine.Text = string.Join("\n", new[]
        {
            FormatDb("daily", info.Daily),
            FormatDb("main", info.Main),
            FormatDb("bytecode", info.Bytecode)
        });
    }

    /// <summary>
    /// Formats one database line as "file - version", or "name - not found"
    /// when the file is missing. Called from: the constructor.
    /// </summary>
    private static string FormatDb(string name, UpdateManager.DbVersion? db)
        => db != null ? $"{db.File} - {db.Version}" : $"{name} - not found";

    /// <summary>
    /// Opens the clicked hyperlink in the default browser.
    /// Called from: the GitHub Hyperlink RequestNavigate event.
    /// </summary>
    private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = e.Uri.AbsoluteUri,
                UseShellExecute = true
            });
        }
        catch
        {
            // Ignore: if no browser is available there is nothing useful to do.
        }
        e.Handled = true;
    }

    /// <summary>Allows dragging the borderless dialog. Called from: window MouseLeftButtonDown.</summary>
    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    /// <summary>Closes the dialog. Called from: Close button.</summary>
    private void Close_Click(object sender, RoutedEventArgs e)
        => Close();
}
