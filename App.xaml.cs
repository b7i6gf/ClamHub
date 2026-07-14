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
    /// Id of the context menu action requested via "--action &lt;id&gt; &lt;path&gt;"
    /// (or "scan" for the legacy "--scan &lt;path&gt;"), or null. Read by
    /// MainWindow.InitializeAsync to run the action automatically.
    /// </summary>
    public static string? StartupActionId { get; private set; }

    /// <summary>
    /// Path passed with the startup action, or null. Read by
    /// MainWindow.InitializeAsync together with StartupActionId.
    /// </summary>
    public static string? StartupActionPath { get; private set; }

    /// <summary>
    /// Infected-file action passed with a scan request via "--infected
    /// &lt;report|quarantine|remove&gt;", or null to use the app default. Read by
    /// MainWindow.InitializeAsync.
    /// </summary>
    public static string? StartupInfectedAction { get; private set; }

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

        // If another ClamHub is already running, hand it our request (or a plain
        // activate) and exit instead of opening a second window.
        if (!SingleInstance.ClaimPrimary())
        {
            SingleInstance.SendToPrimary(
                string.IsNullOrWhiteSpace(StartupActionPath)
                    ? SingleInstance.ActivateMessage
                    : SingleInstance.FormatRequest(StartupActionId ?? "scan", StartupActionPath, StartupInfectedAction));
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

        // Make the Windows context menu match the saved selection (adds/removes
        // entries and repairs a moved-folder path). Primary instance only.
        ContextMenuManager.SyncToSettings();

        base.OnStartup(e);
    }

    /// <summary>True when the process already runs with administrator rights. Called from: OnStartup.</summary>
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Relaunches the app elevated via the UAC prompt, forwarding any pending
    /// context action + path. Returns true if the elevated copy was started (so
    /// this one should exit), or false if the prompt was declined or there is
    /// nothing to forward (continue normally). Called from: OnStartup when
    /// AlwaysStartAsAdmin is set.
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
                Arguments = BuildForwardArgs()
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
    /// Builds the command-line arguments that forward the current context action
    /// to a relaunched instance, or "" when there is nothing to forward.
    /// Called from: TryRelaunchElevated.
    /// </summary>
    private static string BuildForwardArgs()
    {
        if (string.IsNullOrWhiteSpace(StartupActionPath)) return "";
        string infected = string.IsNullOrWhiteSpace(StartupInfectedAction)
            ? "" : $"--infected {StartupInfectedAction} ";
        // A drive root ends in a backslash which would escape the closing quote
        // ("M:\" arrives as M:"); double it so the relaunched instance parses the
        // path back correctly.
        string path = StartupActionPath;
        if (path.EndsWith("\\", StringComparison.Ordinal)) path += "\\";
        return $"--action {StartupActionId ?? "scan"} {infected}--path \"{path}\"";
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
        // During an update restart, deliberately leave clamd running so the fresh
        // instance finds it already up (no gap/race with its own auto-start).
        // Otherwise stop every bundled ClamAV process.
        if (!SelfUpdater.RestartingForUpdate)
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
    /// Extracts the startup context action from the command line. Supports the
    /// current form "--action &lt;id&gt; [--infected &lt;a&gt;] --path &lt;path&gt;"
    /// in any order, plus two legacy fallbacks: a bare path right after the id, and
    /// "--scan &lt;path&gt;" (treated as the "scan" action). Called from: OnStartup.
    /// </summary>
    private static void ParseArguments(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--action" when i + 1 < args.Length:
                    StartupActionId = args[i + 1];
                    // Legacy: a bare path could follow the id directly (no --path flag).
                    if (i + 2 < args.Length && !args[i + 2].StartsWith("--"))
                        StartupActionPath = args[i + 2];
                    break;
                case "--infected" when i + 1 < args.Length:
                    StartupInfectedAction = args[i + 1];
                    break;
                case "--path" when i + 1 < args.Length:
                    StartupActionPath = args[i + 1];
                    break;
                case "--scan" when i + 1 < args.Length:
                    StartupActionId = "scan";
                    StartupActionPath = args[i + 1];
                    break;
            }
        }
        StartupActionPath = NormalizeContextPath(StartupActionPath);
    }

    /// <summary>
    /// Repairs a path mangled by shell command-line quoting. Explorer expands %1
    /// for a drive to "M:\": inside the registry command --path "M:\" the trailing
    /// backslash escapes the closing quote and the app receives M:" instead, so a
    /// drive scan from the context menu silently did nothing (the existence check
    /// failed). Undoes that escape and turns a bare drive letter ("M:") into its
    /// root ("M:\"). Called from: ParseArguments.
    /// </summary>
    private static string? NormalizeContextPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return path;
        var p = path.Trim();
        if (p.EndsWith("\"", StringComparison.Ordinal))
            p = p[..^1] + "\\";
        if (p.Length == 2 && char.IsLetter(p[0]) && p[1] == ':')
            p += "\\";
        return p;
    }
}
