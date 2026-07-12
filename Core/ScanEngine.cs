using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Builds and runs ClamAV scans. Prefers clamdscan (daemon, parallel via
/// --multiscan, --fdpass) and falls back to clamscan when the daemon is not
/// running or the scan mode needs clamscan-only options (--include, --memory).
/// Replaces FILESCAN/FOLDERSCAN/REMOVE/MOVE/MEMORY/TYPESCAN of the old scripts.
/// Called from: MainWindow scan buttons; results are consumed by LogManager (stage 4).
/// </summary>
public static class ScanEngine
{
    /// <summary>What to scan. Path covers files, folders and whole drives.</summary>
    public enum ScanMode { Path, Memory }

    /// <summary>
    /// How a scan should treat the clamd daemon: Auto = use it only if it already
    /// runs (never start it), EnsureDaemon = start it first if needed (context menu
    /// "Scan with ClamHub" with prefer on), Standalone = always clamscan ("Scan w/o
    /// daemon", the only way per-scan exclusions take effect).
    /// </summary>
    public enum DaemonUsage { Auto, EnsureDaemon, Standalone }

    /// <summary>All parameters for one scan run. Built by the UI from its inputs.</summary>
    public record ScanOptions(
        ScanMode Mode,
        string? TargetPath,
        InfectedFileAction Action,
        bool MultiScan,
        IReadOnlyList<string>? IncludeExtensions,
        bool StopInfectedProcesses,
        IReadOnlyList<string>? ExcludeDirectories = null,
        IReadOnlyList<string>? ExcludeExtensions = null,
        IReadOnlyList<string>? ExcludeFiles = null,
        DaemonUsage DaemonMode = DaemonUsage.Auto);

    /// <summary>Outcome of a scan. InfectedLines holds the raw FOUND lines.</summary>
    public record ScanResult(
        bool Started,
        int ExitCode,
        bool UsedDaemon,
        List<string> InfectedLines,
        string? Error);

    /// <summary>True while a scan is running, prevents overlapping scans.</summary>
    public static bool ScanInProgress { get; private set; }

    /// <summary>
    /// Runs a scan with the given options and streams live output.
    /// Exit codes: 0 = clean, 1 = infections found, 2+ = error.
    /// Called from: MainWindow Scan_Click and MemoryScan_Click.
    /// </summary>
    public static async Task<ScanResult> RunScanAsync(
        ScanOptions options,
        Action<string> onOutput,
        CancellationToken cancel = default)
    {
        if (ScanInProgress)
            return new ScanResult(false, -1, false, new(), "A scan is already running.");

        // Validate the target before launching anything.
        if (options.Mode == ScanMode.Path)
        {
            if (string.IsNullOrWhiteSpace(options.TargetPath))
                return new ScanResult(false, -1, false, new(), "No target path given.");
            var clean = options.TargetPath.Replace("\"", "").Trim();
            if (!File.Exists(clean) && !Directory.Exists(clean))
                return new ScanResult(false, -1, false, new(), $"Target not found: {clean}");
            options = options with { TargetPath = clean };
        }

        ScanInProgress = true;
        // Hoisted so the cancellation path can report which scanner actually ran
        // (clamdscan vs clamscan) instead of defaulting to false.
        bool useDaemon = false;
        try
        {
            var usage = options.DaemonMode;

            // Whether ANY per-scan exclusions are set (dirs/files/extensions).
            bool hasExcludes = options.ExcludeDirectories is { Count: > 0 }
                               || options.ExcludeExtensions is { Count: > 0 }
                               || options.ExcludeFiles is { Count: > 0 };

            // Exclusions ONLY take effect with "Scan w/o daemon" (Standalone). Any
            // other scan ignores them, so they no longer force the clamscan path.
            bool applyExcludes = usage == DaemonUsage.Standalone;

            if (hasExcludes && options.Mode == ScanMode.Path && !applyExcludes)
                onOutput("Exclusions are set but only apply to 'Scan w/o daemon'; this scan ignores them.");

            // Whether the daemon COULD serve this scan. The caller's DaemonMode then
            // decides: Standalone never uses it, EnsureDaemon starts it if needed,
            // Auto uses it only when it is already running (never starts it).
            bool canUseDaemon = options.Mode == ScanMode.Path
                                && (options.IncludeExtensions is not { Count: > 0 });

            useDaemon = false;
            if (usage != DaemonUsage.Standalone && canUseDaemon)
            {
                if (usage == DaemonUsage.EnsureDaemon && !await DaemonController.IsRunningAsync())
                {
                    onOutput("Prefer-daemon is on; starting clamd for this scan...");
                    await DaemonController.StartAsync(onOutput);
                }
                useDaemon = await DaemonController.IsRunningAsync();
                if (usage == DaemonUsage.EnsureDaemon && !useDaemon)
                    onOutput("Daemon could not be started, falling back to clamscan (slower).");
            }

            string exe = useDaemon ? AppPaths.ClamdScanExe : AppPaths.ClamScanExe;
            string args = useDaemon ? BuildClamdScanArgs(options) : BuildClamScanArgs(options, applyExcludes);

            // Make it visible that disabled databases are left out. Disabling MOVES the file
            // to AppPaths.DisabledDatabaseDir, and clamd/clamscan only load DatabaseDir, so
            // this holds for BOTH engines without any extra arguments.
            var disabled = ConfigManager.ExcludedDatabaseNames();
            if (disabled.Count > 0)
                onOutput($"Databases disabled for scanning are not loaded: {string.Join(", ", disabled)}");

            onOutput($"Running: {Path.GetFileName(exe)} {args}");
            var infected = new List<string>();

            var result = await ProcessRunner.RunAsync(exe, args, line =>
            {
                // clamd(scan) reports infections as "<path>: <signature> FOUND"
                if (line.EndsWith(" FOUND", StringComparison.Ordinal))
                    infected.Add(line);
                onOutput(line);
            }, cancel);

            if (!result.Started)
                return new ScanResult(false, -1, useDaemon, infected, result.StartError);

            onOutput(result.ExitCode switch
            {
                0 => "Scan finished: no threats found.",
                1 => $"Scan finished: {infected.Count} infected file(s) found.",
                _ => $"Scan finished with errors (exit code {result.ExitCode})."
            });

            return new ScanResult(true, result.ExitCode, useDaemon, infected, null);
        }
        catch (OperationCanceledException)
        {
            onOutput("Scan cancelled by user.");
            return new ScanResult(true, -1, useDaemon, new(), "Cancelled");
        }
        finally
        {
            ScanInProgress = false;
        }
    }

    /// <summary>
    /// Builds the clamdscan argument string (daemon scan, parallel capable).
    /// --fdpass lets the daemon read files with the caller's access rights.
    /// Called from: RunScanAsync when the daemon is used.
    /// </summary>
    private static string BuildClamdScanArgs(ScanOptions o)
    {
        var sb = new StringBuilder();
        if (o.MultiScan) sb.Append("--multiscan ");
        sb.Append("--fdpass ");
        sb.Append($"--log=\"{AppPaths.ScanLogFile}\" ");
        AppendAction(sb, o.Action);
        sb.Append($"\"{o.TargetPath}\"");
        return sb.ToString();
    }

    /// <summary>
    /// Builds the clamscan argument string (standalone scanner, fallback and the
    /// only engine that supports --include and --memory). applyExcludes adds the
    /// per-scan exclusions only when true (Standalone / "Scan w/o daemon").
    /// Called from: RunScanAsync when the daemon is not used.
    /// </summary>
    private static string BuildClamScanArgs(ScanOptions o, bool applyExcludes)
    {
        var sb = new StringBuilder();

        if (o.Mode == ScanMode.Memory)
        {
            sb.Append("--memory ");
            if (o.StopInfectedProcesses) sb.Append("--kill --unload ");
            sb.Append($"--log=\"{AppPaths.ScanLogFile}\"");
            return sb.ToString();
        }

        sb.Append("--recursive ");
        sb.Append($"--log=\"{AppPaths.ScanLogFile}\" ");

        if (o.IncludeExtensions is { Count: > 0 })
            foreach (var ext in o.IncludeExtensions)
                sb.Append($"--include=\\.{ext}$ ");

        // Per-scan exclusions for clamscan, applied ONLY for "Scan w/o daemon"
        // (Standalone). Any other scan ignores them. They come from the scan-session
        // set (which starts as a copy of the persistent settings defaults).
        if (applyExcludes)
        {
            if (o.ExcludeDirectories is { Count: > 0 })
                foreach (var dir in o.ExcludeDirectories)
                {
                    var trimmed = dir?.Trim();
                    if (!string.IsNullOrEmpty(trimmed))
                        sb.Append($"--exclude-dir=\"^{Regex.Escape(trimmed)}\" ");
                }
            if (o.ExcludeExtensions is { Count: > 0 })
                foreach (var ext in o.ExcludeExtensions)
                {
                    var clean = ext?.Trim().TrimStart('.');
                    if (!string.IsNullOrEmpty(clean))
                        sb.Append($"--exclude=\"{ExtensionRegex(clean)}\" ");
                }
            if (o.ExcludeFiles is { Count: > 0 })
                foreach (var file in o.ExcludeFiles)
                {
                    var trimmed = file?.Trim();
                    if (!string.IsNullOrEmpty(trimmed))
                        sb.Append($"--exclude=\"^{Regex.Escape(trimmed)}$\" ");
                }
        }

        AppendAction(sb, o.Action);
        sb.Append($"\"{o.TargetPath}\"");
        return sb.ToString();
    }

    /// <summary>
    /// Regex matching any file with the given extension (case-insensitive).
    /// Called from: BuildClamScanArgs and ConfigManager (clamd.conf block).
    /// </summary>
    public static string ExtensionRegex(string ext)
        => $"(?i)\\.{Regex.Escape(ext.TrimStart('.'))}$";

    /// <summary>
    /// Appends the infected file action flags. Note: Quarantine is intentionally
    /// NOT passed to ClamAV here. ClamAV's --move loses the original path and
    /// renames on collision, so the GUI quarantines files itself after the scan
    /// (see MainWindow.QuarantineInfectedFiles) to keep an exact restore path.
    /// Only Remove maps to a ClamAV flag.
    /// Called from: BuildClamdScanArgs and BuildClamScanArgs.
    /// </summary>
    private static void AppendAction(StringBuilder sb, InfectedFileAction action)
    {
        if (action == InfectedFileAction.Remove)
            sb.Append("--remove ");
    }

    /// <summary>
    /// Parses a ClamAV "FOUND" line into the file path and the threat name.
    /// Line format: "&lt;path&gt;: &lt;signature&gt; FOUND". Returns false when the
    /// line does not match. Called from: MainWindow.QuarantineInfectedFiles.
    /// </summary>
    public static bool TryParseFoundLine(string line, out string path, out string threat)
    {
        path = "";
        threat = "";
        if (!line.EndsWith(" FOUND", StringComparison.Ordinal)) return false;

        int lastColon = line.LastIndexOf(": ", StringComparison.Ordinal);
        if (lastColon <= 0) return false;

        path = line[..lastColon].Trim();
        threat = line[(lastColon + 2)..^" FOUND".Length].Trim();
        return path.Length > 0;
    }

    /// <summary>
    /// Parses a user supplied extension list ("exe dll sys") into safe tokens.
    /// Only alphanumeric extensions are accepted to keep the regex passed to
    /// --include valid and to avoid argument injection.
    /// Called from: MainWindow before building ScanOptions.
    /// </summary>
    public static List<string> ParseExtensions(string? input)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(input)) return list;
        foreach (var raw in input.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var ext = raw.TrimStart('.').Trim();
            if (Regex.IsMatch(ext, "^[A-Za-z0-9]{1,10}$"))
                list.Add(ext.ToLowerInvariant());
        }
        return list;
    }
}
