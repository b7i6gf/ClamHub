using System.IO;

namespace ClamHub.Core;

/// <summary>
/// Defines all paths of the portable folder layout relative to the EXE location.
/// Called from: App.xaml.cs (startup), ConfigManager, SettingsManager and later
/// from DaemonController, ScanEngine and LogManager.
/// </summary>
public static class AppPaths
{
    /// <summary>Folder that contains ClamHub.exe. Everything is relative to this.</summary>
    public static string BaseDir { get; } = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);

    /// <summary>The ClamAV executables that must be present for the app to work.</summary>
    public static readonly string[] RequiredBinaries =
        { "clamd.exe", "clamscan.exe", "clamdscan.exe", "freshclam.exe" };

    private static string? _clamAvDir;

    /// <summary>The built-in default ClamAV folder, next to the EXE.</summary>
    public static string DefaultClamAvDir => Path.Combine(BaseDir, "ClamAV");

    /// <summary>
    /// Folder with the portable ClamAV binaries (clamd.exe, clamscan.exe, ...).
    /// Defaults to BaseDir\ClamAV but can be repointed to an existing ClamAV folder
    /// the user selected (persisted as settings.ClamAvPath, re-applied on startup).
    /// </summary>
    public static string ClamAvDir => _clamAvDir ?? DefaultClamAvDir;

    /// <summary>
    /// Repoints ClamAvDir (and everything derived from it) to the given folder, or
    /// back to the default BaseDir\ClamAV when null/empty. Called from:
    /// App.OnStartup (saved path) and MainWindow.LocateClamAvFolderAsync.
    /// </summary>
    public static void SetClamAvDir(string? path)
        => _clamAvDir = string.IsNullOrWhiteSpace(path)
            ? null
            : path!.TrimEnd(Path.DirectorySeparatorChar);

    /// <summary>
    /// True only when the active ClamAV folder resolves to a DIFFERENT path than the
    /// default BaseDir\ClamAV. Pointing the override at the default folder (e.g. the
    /// user copied ClamAV into the local folder and selected it) is NOT custom, so
    /// the update window shows "Reinstall" instead of "Install locally".
    /// </summary>
    public static bool ClamAvDirIsCustom =>
        _clamAvDir != null
        && !string.Equals(
            Path.GetFullPath(_clamAvDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            Path.GetFullPath(DefaultClamAvDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when the folder contains every required ClamAV executable. Used to
    /// validate a saved path or a folder the user picked. Called from:
    /// App.OnStartup and MainWindow.LocateClamAvFolderAsync.
    /// </summary>
    public static bool ContainsClamAvBinaries(string dir)
    {
        try { return RequiredBinaries.All(e => File.Exists(Path.Combine(dir, e))); }
        catch { return false; }
    }

    /// <summary>Folder for the virus signature database used by freshclam and clamd.</summary>
    public static string DatabaseDir => Path.Combine(ClamAvDir, "database");

    /// <summary>
    /// Parking folder for databases the user disabled. It sits NEXT TO DatabaseDir, never
    /// inside it, which is the whole point: freshclam prunes files it does not recognise
    /// from its DatabaseDirectory, so a disabled database kept there (previously renamed to
    /// "name.disabled") was DELETED on the next update and, being excluded from downloads,
    /// never came back. Outside that folder the file is untouched by freshclam and simply
    /// not seen by clamd/clamscan, which only load DatabaseDir. Enabling moves it back.
    /// </summary>
    public static string DisabledDatabaseDir => Path.Combine(ClamAvDir, "database-disabled");

    /// <summary>
    /// ClamHub's own blacklist: SHA256 hash signatures (.hsb) that make the scanner
    /// DETECT chosen files. Lives in DatabaseDir so clamscan/clamd load it like the
    /// official databases. Managed by Core.CustomSignatureManager.
    /// </summary>
    public static string CustomBlacklistDb => Path.Combine(DatabaseDir, "clamhub-custom.hsb");

    /// <summary>
    /// ClamHub's own allow-list: SHA256 false-positive hashes (.sfp) that make the
    /// scanner IGNORE chosen files. Lives in DatabaseDir alongside the databases.
    /// Managed by Core.CustomSignatureManager.
    /// </summary>
    public static string CustomWhitelistDb => Path.Combine(DatabaseDir, "clamhub-whitelist.sfp");

    /// <summary>Folder for all log files (scan logs, daemon log, update log).</summary>
    public static string LogsDir => Path.Combine(BaseDir, "Logs");

    /// <summary>Folder where infected files are moved when quarantine mode is used.</summary>
    public static string QuarantineDir => Path.Combine(BaseDir, "Quarantine");

    // ClamAV executables
    public static string ClamdExe => Path.Combine(ClamAvDir, "clamd.exe");
    public static string ClamdScanExe => Path.Combine(ClamAvDir, "clamdscan.exe");
    public static string ClamScanExe => Path.Combine(ClamAvDir, "clamscan.exe");
    public static string FreshClamExe => Path.Combine(ClamAvDir, "freshclam.exe");

    /// <summary>ClamAV configuration/diagnostics tool. Optional (not in RequiredBinaries).</summary>
    public static string ClamConfExe => Path.Combine(ClamAvDir, "clamconf.exe");

    /// <summary>ClamAV signature/database tool (sigtool). Optional (not in RequiredBinaries).</summary>
    public static string SigToolExe => Path.Combine(ClamAvDir, "sigtool.exe");

    // Config files (auto generated by ConfigManager when missing)
    public static string FreshClamConf => Path.Combine(ClamAvDir, "freshclam.conf");
    public static string ClamdConf => Path.Combine(ClamAvDir, "clamd.conf");

    // GUI settings and log outputs
    public static string SettingsFile => Path.Combine(BaseDir, "settings.json");
    public static string ProfilesFile => Path.Combine(BaseDir, "profiles.json");
    public static string QueueProfilesFile => Path.Combine(BaseDir, "queues.json");
    public static string HistoryFile => Path.Combine(LogsDir, "history.json");
    public static string QuarantineIndexFile => Path.Combine(QuarantineDir, "quarantine.json");
    public static string ScanLogFile => Path.Combine(LogsDir, "clamd-scan.log");
    public static string ClamdLogFile => Path.Combine(LogsDir, "clamd.log");
    public static string FreshClamLogFile => Path.Combine(LogsDir, "freshclam.log");
    public static string InfectedFilesReport => Path.Combine(LogsDir, "INFECTED_FILES.txt");

    /// <summary>Application icon, shipped next to the EXE for the context menu entry.</summary>
    public static string IconFile => Path.Combine(BaseDir, "ClamHub.ico");

    /// <summary>
    /// Creates all required folders if they do not exist yet.
    /// Called from: App.xaml.cs on startup, before any other component runs.
    /// </summary>
    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(ClamAvDir);
        Directory.CreateDirectory(DatabaseDir);
        Directory.CreateDirectory(DisabledDatabaseDir);
        Directory.CreateDirectory(LogsDir);
        Directory.CreateDirectory(QuarantineDir);
    }
}
