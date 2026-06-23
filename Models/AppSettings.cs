namespace ClamHub.Models;

/// <summary>
/// Where the output console is shown: docked at the bottom (default), docked on
/// the right (the window widens so the main area keeps its width), or in a
/// separate window. Chosen via the title bar view buttons.
/// </summary>
public enum ConsolePosition
{
    Bottom,
    Right,
    Window
}

/// <summary>
/// Action applied to infected files during a scan.
/// Used by: AppSettings, later by ScanEngine to build the command line.
/// </summary>
public enum InfectedFileAction
{
    ReportOnly,
    Quarantine,
    Remove
}

/// <summary>
/// User configurable settings, persisted as settings.json next to the EXE.
/// Loaded and saved by: Core.SettingsManager. Consumed by all modules.
/// </summary>
public class AppSettings
{
    /// <summary>Prefer clamdscan via the daemon. Falls back to clamscan when clamd is not running.</summary>
    public bool UseDaemon { get; set; } = true;

    /// <summary>Start clamd automatically when the GUI starts.</summary>
    public bool AutoStartDaemon { get; set; } = true;

    /// <summary>Pass --multiscan to clamdscan so the daemon scans with multiple threads.</summary>
    public bool MultiScan { get; set; } = true;

    /// <summary>TCP port clamd listens on. Must match clamd.conf (ConfigManager keeps them in sync).</summary>
    public int ClamdPort { get; set; } = 3310;

    /// <summary>Max worker threads for clamd. 0 means use the number of logical CPU cores.</summary>
    public int MaxThreads { get; set; } = 0;

    /// <summary>Default action for infected files.</summary>
    public InfectedFileAction DefaultAction { get; set; } = InfectedFileAction.ReportOnly;

    /// <summary>Last window width in pixels (0 = use the default start size). Restored on launch.</summary>
    public double WindowWidth { get; set; }

    /// <summary>Last window height in pixels (0 = use the default start size). Restored on launch.</summary>
    public double WindowHeight { get; set; }

    /// <summary>Last window left position (screen px). Restored only when still on a visible monitor.</summary>
    public double WindowLeft { get; set; }

    /// <summary>Last window top position (screen px). Restored only when still on a visible monitor.</summary>
    public double WindowTop { get; set; }

    /// <summary>Whether the window was maximized when last closed.</summary>
    public bool WindowMaximized { get; set; }

    /// <summary>Where the output console is docked. Set via the title bar view buttons.</summary>
    public ConsolePosition ConsolePosition { get; set; } = ConsolePosition.Bottom;

    /// <summary>Run freshclam automatically on GUI startup so the database is always current.</summary>
    public bool UpdateOnStart { get; set; } = true;

    /// <summary>Play a notification sound whenever a scan reports an infected file.</summary>
    public bool SoundOnDetection { get; set; } = true;

    /// <summary>
    /// Count the files in the scan target for daemon scans, since clamdscan does
    /// not report a scanned-file count. The count runs after the scan on a
    /// background thread, so it never slows the scan itself. Can be disabled for
    /// very large targets where counting would take noticeable time.
    /// </summary>
    public bool CountFilesOnDaemonScan { get; set; } = true;

    /// <summary>
    /// Personal VirusTotal API key, stored only in this local settings.json and
    /// never embedded in code. Empty string disables the VirusTotal lookup.
    /// </summary>
    public string VirusTotalApiKey { get; set; } = "";

    /// <summary>
    /// Folder where ClamAV is installed, when the user pointed the app at an
    /// existing install (folder picker). Empty/null means use the default
    /// BaseDir\ClamAV. Re-applied on startup via AppPaths.SetClamAvDir.
    /// </summary>
    public string? ClamAvPath { get; set; }

    /// <summary>
    /// When true, the app relaunches itself elevated on startup (UAC prompt) so it
    /// always runs as administrator. If the prompt is declined it continues without
    /// elevation. Applied in App.OnStartup.
    /// </summary>
    public bool AlwaysStartAsAdmin { get; set; }

    /// <summary>
    /// Directories excluded from every scan. Applied to clamscan via
    /// --exclude-dir and to the daemon via a managed ExcludePath block in
    /// clamd.conf. Absolute paths.
    /// </summary>
    public List<string> ExcludeDirectories { get; set; } = new();

    /// <summary>
    /// File extensions excluded from every scan (without dot, e.g. "iso").
    /// Applied to clamscan via --exclude and to the daemon via ExcludePath.
    /// </summary>
    public List<string> ExcludeExtensions { get; set; } = new();

    /// <summary>Resolved thread count. Called from ConfigManager when writing clamd.conf.</summary>
    public int EffectiveMaxThreads()
        => MaxThreads > 0 ? MaxThreads : Environment.ProcessorCount;
}
