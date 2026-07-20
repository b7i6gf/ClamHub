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
/// How multiple ClamHub context menu entries are laid out in the Windows
/// right-click menu: nested under a single cascading "ClamHub" submenu, or listed
/// one under another directly in the menu. With only one applicable entry the
/// distinction is ignored (a single flat entry is written). Chosen in Settings;
/// consumed by Core.ContextMenuManager when registering.
/// </summary>
public enum ContextMenuGrouping
{
    Submenu,
    Inline
}

/// <summary>
/// User configurable settings, persisted as settings.json next to the EXE.
/// Loaded and saved by: Core.SettingsManager. Consumed by all modules.
/// </summary>
public class AppSettings
{
    /// <summary>"Prefer daemon for scans" (shown in the context menu settings section). Scans only:
    /// use clamdscan and start clamd first if needed; falls back to clamscan if the daemon cannot start.</summary>
    public bool UseDaemon { get; set; } = true;

    /// <summary>"Start daemon on startup": start clamd in the background on launch, independent of UseDaemon.</summary>
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
    /// Default folder for History "Export" (one entry to a .txt). Empty means
    /// the app's Logs folder is offered. When AlwaysExport is off this folder is
    /// only the starting location of the save dialog; when on, the file is
    /// written here without a dialog.
    /// </summary>
    public string HistoryExportPath { get; set; } = "";

    /// <summary>When true, History "Export" writes straight to
    /// HistoryExportPath without opening the save dialog.</summary>
    public bool HistoryAlwaysExportToPath { get; set; }

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
    /// When true, a silent GitHub update check (ClamHub + ClamAV) runs at startup,
    /// prints exactly one console line with the outcome and lights the About-button
    /// dot when an update exists. Used by MainWindow.CheckForUpdatesOnStartupAsync.
    /// Default: false.
    /// </summary>
    public bool CheckUpdatesOnStartup { get; set; }

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

    /// <summary>
    /// Individual files excluded from every scan (absolute paths). Applied to
    /// clamscan via an anchored --exclude regex. The daemon ignores per-scan
    /// excludes, so any exclusion forces the scan onto clamscan.
    /// </summary>
    public List<string> ExcludeFiles { get; set; } = new();

    /// <summary>
    /// File names (e.g. "daily.cvd", "rfxn.ndb") of signature databases the user disabled
    /// via the Signatures table context menu. Disabling MOVES the file from the database
    /// folder to AppPaths.DisabledDatabaseDir: clamd and clamscan only load the database
    /// folder, so the database is not scanned, and freshclam neither sees nor deletes it
    /// there (a disabled file kept inside the database folder was pruned by freshclam,
    /// which is how databases went missing). Updates are additionally suppressed via the
    /// freshclam ExcludeDatabase block (official/mirror databases) or by parking the
    /// DatabaseCustomURL line (see DisabledCustomUrls). This list is the durable record:
    /// ConfigManager.EnforceDatabaseDisables re-applies the move if a file re-appears, and
    /// PruneStaleExclusions drops entries whose database no longer exists at all. The
    /// custom blacklist/whitelist are never listed here. Case-insensitive.
    /// </summary>
    public List<string> ExcludedDatabases { get; set; } = new();

    /// <summary>
    /// Custom-URL databases (freshclam DatabaseCustomURL) that are currently disabled,
    /// keyed by their local file name (e.g. "rfxn.ndb" -> the download URL). freshclam's
    /// ExcludeDatabase does NOT suppress DatabaseCustomURL downloads, so while such a
    /// database is disabled its URL is "parked" here and REMOVED from freshclam.conf so
    /// freshclam has nothing to download; enabling restores the line. Kept in sync with
    /// ExcludedDatabases by ConfigManager.SyncCustomUrlDownloads. Case-insensitive keys.
    /// </summary>
    public Dictionary<string, string> DisabledCustomUrls { get; set; }
        = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Layout of multiple context menu entries: a cascading "ClamHub" submenu
    /// (default) or an inline list. Ignored when only one entry applies. Applied by
    /// Core.ContextMenuManager.Register.
    /// </summary>
    public ContextMenuGrouping ContextMenuGrouping { get; set; } = ContextMenuGrouping.Submenu;

    /// <summary>
    /// Ids of the context menu actions the user has switched ON (opt-in). Empty by
    /// default, so a fresh install adds nothing until the user picks entries in
    /// Settings. Only actions listed here are registered (the VirusTotal entry also
    /// needs an API key). Consumed by ContextMenuManager.
    /// </summary>
    public List<string> ContextMenuEnabledActions { get; set; } = new();

    /// <summary>
    /// File-Verifier tab: whether the "Hashes" check box was ticked last time.
    /// Saved on every Inspect click, restored by InitializeFileVerifierTab.
    /// </summary>
    public bool FileVerifierIncludeHashes { get; set; } = true;

    /// <summary>
    /// File-Verifier tab: whether the "File system (owner, ACLs, ADS)" check box
    /// was ticked last time. Saved on every Inspect click, restored by
    /// InitializeFileVerifierTab.
    /// </summary>
    public bool FileVerifierIncludeFileSystem { get; set; } = true;

    /// <summary>
    /// File-Verifier tab: whether the "PE analysis" check box was ticked last
    /// time. Saved on every Inspect click, restored by InitializeFileVerifierTab.
    /// </summary>
    public bool FileVerifierIncludePe { get; set; } = true;

    /// <summary>
    /// File-Verifier tab: whether the "Document analysis" check box was ticked
    /// last time (Office/PDF/RTF/LNK/script/archive structure). On by default;
    /// it only reads structure and self-skips for other file kinds.
    /// </summary>
    public bool FileVerifierIncludeDocument { get; set; } = true;

    /// <summary>File-Verifier "Signature" checkbox: verify the Authenticode
    /// signature (embedded or catalog) offline.</summary>
    public bool FileVerifierIncludeSignature { get; set; } = true;

    /// <summary>File-Verifier "ClamAV" checkbox: report-only single-file scan.
    /// Off by default: it needs downloaded signatures and adds scan time.</summary>
    public bool FileVerifierIncludeClamAv { get; set; }

    /// <summary>File-Verifier "VirusTotal" checkbox: SHA256 lookup. Off by
    /// default because the hash is sent to a third party.</summary>
    public bool FileVerifierIncludeVirusTotal { get; set; }

    /// <summary>File-Verifier "Strings/IOCs" checkbox: extract indicator
    /// strings (URLs, IPs, registry Run keys, shell commands). Off by default;
    /// it is a second full read of the file.</summary>
    public bool FileVerifierIncludeStrings { get; set; }

    /// <summary>
    /// File-Verifier tab: the hash algorithm selected last time ("All", "MD5",
    /// "SHA256", ...). Persisted like the check boxes so the tab AND the context
    /// menu "Create Integrity Report" reuse the user's choice after a restart.
    /// </summary>
    public string FileVerifierHashAlgo { get; set; } = "All";

    /// <summary>
    /// When true, the "Scan with ClamHub" context entry becomes a submenu offering
    /// Report / Quarantine / Remove (the infected-file action for that one scan);
    /// when false it is a single entry that uses the app default action. Consumed by
    /// ContextMenuManager (menu shape) and MainWindow (dispatch).
    /// </summary>
    public bool ContextMenuScanActionSelectable { get; set; } = false;

    /// <summary>Resolved thread count. Called from ConfigManager when writing clamd.conf.</summary>
    public int EffectiveMaxThreads()
        => MaxThreads > 0 ? MaxThreads : Environment.ProcessorCount;
}
