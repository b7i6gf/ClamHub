using System.Windows;
using ClamHub.Core;

namespace ClamHub;

/// <summary>
/// Application entry point. Runs the startup sequence before MainWindow opens:
/// 1. Create the portable folder layout (AppPaths.EnsureDirectories)
/// 2. Load or create settings.json (SettingsManager.Load)
/// 3. Generate missing freshclam.conf / clamd.conf (ConfigManager.EnsureConfigs)
/// The result is stored in StartupCheck and shown by MainWindow.
/// </summary>
public partial class App : Application
{
    /// <summary>Result of the config check, read by MainWindow for the status panel.</summary>
    public static ConfigManager.ConfigCheckResult? StartupCheck { get; private set; }

    /// <summary>
    /// Path passed via "--scan &lt;path&gt;" from the context menu, or null.
    /// Read by MainWindow.InitializeAsync to start a scan automatically.
    /// </summary>
    public static string? StartupScanPath { get; private set; }

    /// <summary>
    /// Startup hook. Called by: WPF runtime before StartupUri window is created.
    /// </summary>
    protected override void OnStartup(StartupEventArgs e)
    {
        ParseArguments(e.Args);

        // If another ClamHub is already running, hand it our scan request (or a
        // plain activate) and exit instead of opening a second window.
        if (!SingleInstance.ClaimPrimary())
        {
            SingleInstance.SendToPrimary(
                string.IsNullOrWhiteSpace(StartupScanPath)
                    ? SingleInstance.ActivateMessage
                    : StartupScanPath);
            Shutdown();
            return;
        }

        AppPaths.EnsureDirectories();
        SettingsManager.Load();
        StartupCheck = ConfigManager.EnsureConfigs();
        base.OnStartup(e);
    }

    /// <summary>
    /// Shutdown hook. Ensures clamd and any other bundled ClamAV process is
    /// terminated whenever the app exits, even through close paths that do not
    /// go through the main window. Safe to run after the window already cleaned
    /// up (it simply finds nothing left).
    /// Called by: WPF runtime when the application shuts down.
    /// </summary>
    protected override void OnExit(ExitEventArgs e)
    {
        DaemonController.KillAllOwned();
        base.OnExit(e);
    }

    /// <summary>
    /// Extracts the "--scan &lt;path&gt;" argument from the command line.
    /// Called from: OnStartup.
    /// </summary>
    private static void ParseArguments(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], "--scan", StringComparison.OrdinalIgnoreCase))
            {
                StartupScanPath = args[i + 1];
                return;
            }
        }
    }
}
