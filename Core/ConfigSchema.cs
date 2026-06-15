namespace ClamAVGui.Core;

/// <summary>
/// Typed schema of clamd.conf and freshclam.conf parameters, audited against
/// the official man pages (ClamAV 1.4.x). Bool parameters render as yes/no
/// dropdowns, the rest as text fields; Header entries render as group titles.
///
/// Deliberately excluded:
/// - Unix-only options (LocalSocket*, User, DatabaseOwner, LogSyslog/LogFacility,
///   PidFile, Foreground) - meaningless on Windows
/// - OnAccess* - relies on Linux fanotify, not available on Windows
/// - VirusEvent / OnUpdateExecute / OnErrorExecute / BytecodeUnsigned - execute
///   arbitrary commands or unsigned code; excluded for the same reason the GUI
///   has no free command mode. Still editable via "Open file" deliberately.
/// - Debug/LeaveTemporaryFiles/GenerateMetadataJson - debugging only
/// Parameters not listed stay untouched in the files (ClamConfFile preserves them).
/// Called from: MainWindow.Settings.cs when building the config editor rows.
/// </summary>
public static class ConfigSchema
{
    public enum ParamType { Bool, Text, Header }

    /// <summary>One editable parameter: key, control type and tooltip hint.</summary>
    public record ConfParam(string Key, ParamType Type, string Hint);

    private static ConfParam Header(string title) => new(title, ParamType.Header, "");
    private static ConfParam B(string key, string hint) => new(key, ParamType.Bool, hint);
    private static ConfParam T(string key, string hint) => new(key, ParamType.Text, hint);

    /// <summary>Editable clamd.conf parameters (official defaults in brackets).</summary>
    public static readonly ConfParam[] ClamdParams =
    {
        Header("Daemon"),
        T("TCPSocket", "TCP port the daemon listens on [disabled]. The GUI follows this port automatically."),
        T("TCPAddr", "Bind address [all interfaces]. Keep 127.0.0.1 so the daemon is never exposed to the network."),
        T("MaxThreads", "Worker threads for parallel scans [10]. Recommended: number of CPU cores."),
        T("MaxQueue", "Queued scan jobs including running ones [100]. Keep at least 2x MaxThreads."),
        T("IdleTimeout", "Seconds a worker waits for a new job [30]."),
        T("SelfCheck", "Database self check interval in seconds [600]."),
        B("ConcurrentDatabaseReload", "Load the new database in parallel during reloads [yes]. 'no' halves RAM usage but blocks scans briefly."),
        T("TemporaryDirectory", "Override the temp directory [system temp]."),

        Header("File system"),
        T("ExcludePath", "Paths skipped during daemon scans. Click Manage list to add folders and file extensions (same dialog as the scan Exclusions button)."),
        B("CrossFilesystems", "Scan across file system boundaries [yes]."),
        B("FollowDirectorySymlinks", "Follow directory symlinks [no]."),
        B("FollowFileSymlinks", "Follow file symlinks [no]."),

        Header("Logging"),
        B("LogTime", "Prefix log entries with a timestamp [no]."),
        B("LogVerbose", "Verbose daemon logging [no]."),
        B("LogClean", "Also log clean files [no]. Massively grows the log."),
        T("LogFileMaxSize", "Max log size, e.g. 5M [1M]. 0 disables the limit."),
        B("LogRotate", "Rotate the log when LogFileMaxSize is reached [no]."),
        B("ExtendedDetectionInfo", "Log size and hash of infected files next to the virus name [no]."),

        Header("Detection"),
        B("DetectPUA", "Also detect potentially unwanted applications like adware or cracks [no]."),
        B("HeuristicAlerts", "Algorithmic detection for complex malware [yes]."),
        B("HeuristicScanPrecedence", "Stop at the first heuristic match instead of scanning on [no]."),
        B("Bytecode", "Load bytecode signatures, strongly recommended [yes]."),
        B("PhishingSignatures", "Signature based phishing detection in mails [yes]."),
        B("PhishingScanURLs", "URL based phishing detection in mails [yes]."),

        Header("File types"),
        B("ScanPE", "Deep analysis of Windows executables incl. UPX unpacking [yes]."),
        B("ScanELF", "Deep analysis of Linux/Unix executables [yes]."),
        B("ScanOLE2", "Office documents, .msi and OLE2 containers [yes]."),
        B("ScanPDF", "Scan inside PDF files [yes]."),
        B("ScanSWF", "Scan inside Flash files [yes]."),
        B("ScanHTML", "HTML/JavaScript normalisation and decryption [yes]."),
        B("ScanMail", "Parse mail files and their attachments [yes]."),
        B("ScanXMLDOCS", "XML based documents (docx, xlsx, ...) [yes]."),
        B("ScanOneNote", "OneNote files [yes]."),
        B("ScanImage", "Image files [yes]."),
        B("ScanImageFuzzyHash", "Detection via image fuzzy hashes [yes]."),
        B("ScanArchive", "Scan inside archives (zip, rar, 7z, ...) [yes]."),

        Header("Extra alerts"),
        B("AlertEncrypted", "Alert on encrypted archives AND documents [no]."),
        B("AlertEncryptedArchive", "Alert on encrypted archives (zip, 7z, rar) [no]."),
        B("AlertEncryptedDoc", "Alert on encrypted documents (pdf) [no]."),
        B("AlertOLE2Macros", "Alert on Office files containing VBA macros [no]."),
        B("AlertBrokenExecutables", "Alert on broken PE/ELF executables [no]."),
        B("AlertBrokenMedia", "Alert on broken image files [no]."),
        B("AlertExceedsMax", "Alert on files skipped due to size limits [no]."),

        Header("Limits"),
        T("MaxScanTime", "Max milliseconds per file [120000]. 0 disables (DoS risk)."),
        T("MaxScanSize", "Max data scanned per file incl. archive content, e.g. 400M [400M]."),
        T("MaxFileSize", "Skip files larger than this, e.g. 100M [100M]. Hard limit: 2G."),
        T("MaxRecursion", "Max nesting depth of archives in archives [17]."),
        T("MaxFiles", "Max files scanned per archive/container [10000]."),
        T("MaxDirectoryRecursion", "Max folder nesting depth [15]."),
        T("MaxEmbeddedPE", "Max file size checked for embedded executables [40M]."),

        Header("Cache"),
        B("DisableCache", "Disable the clean file cache [no]. Slows large scans."),
        T("CacheSize", "Cache entries for known clean files [65536]."),
    };

    /// <summary>Editable freshclam.conf parameters (official defaults in brackets).</summary>
    public static readonly ConfParam[] FreshClamParams =
    {
        Header("Update source"),
        T("DatabaseMirror", "Signature mirror [database.clamav.net]."),
        T("PrivateMirror", "Private mirror URL, overrides DatabaseMirror [disabled]."),
        T("DatabaseCustomURL", "Additional database from a custom URL [disabled]. Multiple entries: edit via Open file."),
        T("ExtraDatabase", "Additional 3rd party database via ClamAV mirrors [disabled]. Multiple entries: edit via Open file."),
        T("ExcludeDatabase", "Skip a standard database [disabled]. Multiple entries: edit via Open file."),
        B("ScriptedUpdates", "Incremental updates instead of full downloads, keep enabled [yes]."),
        B("Bytecode", "Download bytecode signatures, recommended [yes]."),

        Header("Connection"),
        T("ConnectTimeout", "Connect timeout in seconds [10]."),
        T("ReceiveTimeout", "Max seconds per download, 0 = no limit [0]. Too low aborts the first full database download."),
        T("MaxAttempts", "Download attempts per mirror [3]."),
        T("HTTPProxyServer", "Proxy, optionally with scheme like socks5:// [disabled]."),
        T("HTTPProxyPort", "Proxy port [disabled]."),
        T("HTTPProxyUsername", "Proxy user [disabled]."),
        T("HTTPProxyPassword", "Proxy password, stored in plain text in the conf [disabled]."),

        Header("Behaviour"),
        B("TestDatabases", "Verify downloaded databases before activating them [yes]."),
        B("CompressLocalDatabase", "Store local databases compressed [no]. Saves disk, slows loading."),
        T("NotifyClamd", "Path to clamd.conf; a running daemon reloads signatures after updates [disabled]."),

        Header("Logging"),
        B("LogTime", "Prefix log entries with a timestamp [no]."),
        B("LogVerbose", "Verbose update logging [no]."),
        T("LogFileMaxSize", "Max log size, e.g. 5M [1M]. CAUTION: when exceeded without LogRotate, logging silently stops."),
        B("LogRotate", "Rotate the log when LogFileMaxSize is reached [no]."),
    };
}
