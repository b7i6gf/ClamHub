using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
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
        // Install crash handlers before anything else so an unexpected exception is
        // logged (and, on the UI thread, shown) instead of silently killing the app.
        InstallGlobalExceptionHandlers();

        ParseArguments(e.Args);

        // Remove a leftover "<name>.old.exe" from a previous self-upgrade, in the
        // background so it never blocks startup (no-op when there is none).
        _ = Task.Run(SelfUpdater.CleanupOldExe);

        // Settings drive the elevation choice, so load them first.
        SettingsManager.Load();

        // Optionally relaunch elevated before anything else (and before claiming the
        // single-instance mutex), so the elevated copy becomes the primary instance.
        if (SettingsManager.Current.AlwaysStartAsAdmin && !IsElevated() && TryRelaunchElevated())
        {
            Shutdown();
            return;
        }

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

        // Re-apply a previously chosen ClamAV folder (if it still has the binaries)
        // before folders and configs are created, so they target the right place.
        var savedClamAv = SettingsManager.Current.ClamAvPath;
        if (!string.IsNullOrWhiteSpace(savedClamAv) && AppPaths.ContainsClamAvBinaries(savedClamAv))
            AppPaths.SetClamAvDir(savedClamAv);

        AppPaths.EnsureDirectories();
        StartupCheck = ConfigManager.EnsureConfigs();
        base.OnStartup(e);
    }

    /// <summary>True when the process already runs with administrator rights. Called from: OnStartup.</summary>
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Relaunches the app elevated via the UAC prompt, forwarding any scan path.
    /// Returns true if the elevated copy was started (so this one should exit), or
    /// false if the prompt was declined or the path is unknown (continue normally).
    /// Called from: OnStartup when AlwaysStartAsAdmin is set.
    /// </summary>
    private static bool TryRelaunchElevated()
    {
        var exe = Environment.ProcessPath;
        if (exe == null) return false;
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = true,
                Verb = "runas",
                Arguments = string.IsNullOrWhiteSpace(StartupScanPath) ? "" : $"--scan \"{StartupScanPath}\""
            });
            return true;
        }
        catch (Win32Exception)
        {
            // UAC declined: fall back to running without elevation.
            return false;
        }
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
    /// Installs process-wide handlers so an unexpected exception is logged and (for a
    /// UI-thread error) shown in a dialog instead of crashing the whole app. Called
    /// from: OnStartup (first thing).
    /// </summary>
    private void InstallGlobalExceptionHandlers()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    /// <summary>
    /// UI-thread exceptions: log, tell the user the action was stopped, and keep the
    /// app running (the failed operation is abandoned). Called by: the WPF dispatcher.
    /// </summary>
    private void OnDispatcherUnhandledException(
        object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
    {
        LogCrash("UI", e.Exception);
        try
        {
            new MessageDialog(
                "ClamHub - unexpected error",
                "Something went wrong and the last action was stopped. "
                + "The application will keep running.\n\n" + e.Exception.Message,
                "OK", null).ShowDialog();
        }
        catch { /* never let the error dialog itself bring the app down */ }
        e.Handled = true;
    }

    /// <summary>
    /// Background task exceptions: log and mark observed so they cannot tear the
    /// process down later. Called by: the task scheduler.
    /// </summary>
    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        LogCrash("Task", e.Exception);
        e.SetObserved();
    }

    /// <summary>
    /// Last-resort handler for otherwise fatal exceptions; only logs, since the
    /// process is already going down. Called by: the runtime.
    /// </summary>
    private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex) LogCrash("Fatal", ex);
    }

    /// <summary>
    /// Appends one entry to crash.log next to the app. Best effort: logging must
    /// never throw. Called from: the global exception handlers.
    /// </summary>
    private static void LogCrash(string source, Exception ex)
    {
        try
        {
            var path = System.IO.Path.Combine(AppPaths.LogsDir, "crash.log");
            System.IO.File.AppendAllText(path,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {source}: {ex}\n\n");
        }
        catch { /* logging must never throw */ }
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
