using System.IO;
using System.Linq;
using System.Text;

namespace ClamHub.Core;

/// <summary>
/// Generates freshclam.conf and clamd.conf inside the ClamAV folder when they
/// are missing. Existing files are never overwritten, so manual edits survive.
/// All paths inside the configs are absolute and derived from the current EXE
/// location, which keeps the whole folder portable.
/// Called from: App.xaml.cs on startup (after AppPaths.EnsureDirectories).
/// </summary>
public static class ConfigManager
{
    /// <summary>
    /// Result info shown on the dashboard so the user sees what was generated.
    /// </summary>
    public record ConfigCheckResult(bool FreshClamCreated, bool ClamdCreated, bool BinariesFound);

    /// <summary>
    /// Ensures both config files exist and reports what happened.
    /// Called from: App.xaml.cs startup sequence.
    /// </summary>
    public static ConfigCheckResult EnsureConfigs()
    {
        bool freshCreated = false;
        bool clamdCreated = false;

        if (!File.Exists(AppPaths.FreshClamConf))
        {
            File.WriteAllText(AppPaths.FreshClamConf, BuildFreshClamConf(), Encoding.ASCII);
            freshCreated = true;
        }

        if (!File.Exists(AppPaths.ClamdConf))
        {
            File.WriteAllText(AppPaths.ClamdConf, BuildClamdConf(), Encoding.ASCII);
            clamdCreated = true;
        }

        bool binariesFound = File.Exists(AppPaths.ClamScanExe) && File.Exists(AppPaths.FreshClamExe);

        // Keep clamd.conf in sync with the persistent settings exclusions and
        // remove the legacy Logs/Quarantine entries that older versions added.
        if (File.Exists(AppPaths.ClamdConf))
            WriteClamdExclusions();

        return new ConfigCheckResult(freshCreated, clamdCreated, binariesFound);
    }

    /// <summary>Which config file a rebuild targets.</summary>
    public enum ConfigTarget { Clamd, FreshClam }

    // Keys whose values are absolute paths managed by ClamHub. On a rebuild these
    // always take the fresh, correct values so that moving the app folder cannot
    // leave stale database/log paths behind (the usual cause of daemon exit codes).
    private static readonly HashSet<string> ClamdPathKeys =
        new(StringComparer.OrdinalIgnoreCase) { "DatabaseDirectory", "LogFile", "ExcludePath" };
    private static readonly HashSet<string> FreshPathKeys =
        new(StringComparer.OrdinalIgnoreCase) { "DatabaseDirectory", "UpdateLogFile", "NotifyClamd" };

    /// <summary>
    /// Rewrites one config file from the current defaults so its database and log
    /// paths point at the real folders again (fixes daemon errors after the app
    /// was moved). When transferValues is true the user's other settings are
    /// carried over verbatim while the path entries take the fresh values; when
    /// false the file is reset to first-run defaults. clamd exclusions are always
    /// regenerated from the GUI settings. The daemon reads its config only at
    /// startup, so a restart is needed for changes to apply.
    /// Called from: MainWindow.Settings.cs rebuild buttons.
    /// </summary>
    public static void RebuildConfig(ConfigTarget target, bool transferValues)
    {
        string path = target == ConfigTarget.Clamd ? AppPaths.ClamdConf : AppPaths.FreshClamConf;

        // Capture existing values before overwriting (only when transferring).
        var old = transferValues && File.Exists(path)
            ? ClamConfFile.Load(path).AllValues().ToList()
            : new List<(string Key, string Value)>();

        // Write a clean default file with correct portable paths.
        string fresh = target == ConfigTarget.Clamd ? BuildClamdConf() : BuildFreshClamConf();
        File.WriteAllText(path, fresh, Encoding.ASCII);

        if (transferValues && old.Count > 0)
        {
            var skip = target == ConfigTarget.Clamd ? ClamdPathKeys : FreshPathKeys;
            var conf = ClamConfFile.Load(path);
            foreach (var (key, value) in old)
                if (!skip.Contains(key))
                    conf.SetValue(key, value);
            conf.Save();
        }

        // Re-apply the managed exclusion block to clamd.conf from the settings.
        if (target == ConfigTarget.Clamd)
            WriteClamdExclusions();
    }

    /// <summary>
    /// Rebuilds both config files in one step with the same value-transfer choice
    /// (see RebuildConfig). Called from: the "Rebuild all configs" button.
    /// </summary>
    public static void RebuildAllConfigs(bool transferValues)
    {
        RebuildConfig(ConfigTarget.FreshClam, transferValues);
        RebuildConfig(ConfigTarget.Clamd, transferValues);
    }

    /// <summary>
    /// Escapes a Windows path for use in a ClamAV ExcludePath regex and anchors
    /// it to the start of the path. Called from: BuildClamdConf.
    /// </summary>
    private static string EscapeRegexPath(string path)
        => "^" + System.Text.RegularExpressions.Regex.Escape(path);

    // Markers delimiting the block of user exclusions that the GUI manages in
    // clamd.conf. Everything outside the markers is left untouched.
    private const string ExcludeBlockStart = "# >>> ClamHub user exclusions >>>";
    private const string ExcludeBlockEnd = "# <<< ClamHub user exclusions <<<";

    /// <summary>
    /// Rewrites the managed user-exclusion block in clamd.conf from the current
    /// settings (directories and extensions become ExcludePath regex lines).
    /// Preserves all other content. The daemon reads its config only at startup,
    /// so a restart is needed for changes to take effect.
    /// Called from: the exclusions dialog after saving.
    /// </summary>
    public static void WriteClamdExclusions()
    {
        var lines = File.Exists(AppPaths.ClamdConf)
            ? File.ReadAllLines(AppPaths.ClamdConf).ToList()
            : new List<string>();

        // Remove legacy auto-added entries (Logs/Quarantine ExcludePath lines and
        // their comments) that older versions wrote outside the managed block.
        string logsRx = EscapeRegexPath(AppPaths.LogsDir);
        string quarRx = EscapeRegexPath(AppPaths.QuarantineDir);
        lines.RemoveAll(l =>
        {
            var t = l.Trim();
            return t == $"ExcludePath {logsRx}"
                || t == $"ExcludePath {quarRx}"
                || t == "# Added by ClamHub: skip its own working folders during scans."
                || t.StartsWith("# Skip ClamHub's own working folders");
        });

        // Drop any previous managed block (inclusive of the markers).
        int start = lines.FindIndex(l => l.Trim() == ExcludeBlockStart);
        if (start >= 0)
        {
            int end = lines.FindIndex(start, l => l.Trim() == ExcludeBlockEnd);
            if (end >= start) lines.RemoveRange(start, end - start + 1);
            else lines.RemoveRange(start, lines.Count - start);
            // Trim a trailing blank left behind by the removed block.
            if (start > 0 && start <= lines.Count
                && (start == lines.Count || lines[start].Trim().Length == 0)
                && lines[start - 1].Trim().Length == 0)
                lines.RemoveAt(start - 1);
        }

        var block = BuildExclusionLines();
        if (block.Count > 0)
        {
            if (lines.Count > 0 && lines[^1].Trim().Length != 0) lines.Add("");
            lines.Add(ExcludeBlockStart);
            lines.AddRange(block);
            lines.Add(ExcludeBlockEnd);
        }

        File.WriteAllLines(AppPaths.ClamdConf, lines);
    }

    /// <summary>
    /// Builds the ExcludePath lines for the daemon from the settings lists.
    /// Directories are anchored to the path start; extensions match any file
    /// ending with that extension. Called from: WriteClamdExclusions.
    /// </summary>
    private static List<string> BuildExclusionLines()
    {
        var result = new List<string>();
        foreach (var dir in SettingsManager.Current.ExcludeDirectories)
        {
            var trimmed = dir?.Trim();
            if (!string.IsNullOrEmpty(trimmed))
                result.Add($"ExcludePath {EscapeRegexPath(trimmed)}");
        }
        foreach (var ext in SettingsManager.Current.ExcludeExtensions)
        {
            var clean = ext?.Trim().TrimStart('.');
            if (!string.IsNullOrEmpty(clean))
                result.Add($"ExcludePath {ScanEngine.ExtensionRegex(clean)}");
        }
        return result;
    }

    /// <summary>
    /// Builds the freshclam.conf content with portable absolute paths.
    /// Called from: EnsureConfigs.
    /// </summary>
    private static string BuildFreshClamConf()
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Auto generated by ClamHub. Safe to edit, it will not be overwritten.");
        sb.AppendLine($"DatabaseDirectory \"{AppPaths.DatabaseDir}\"");
        sb.AppendLine($"UpdateLogFile \"{AppPaths.FreshClamLogFile}\"");
        sb.AppendLine("LogTime yes");
        sb.AppendLine("LogVerbose no");
        sb.AppendLine("DatabaseMirror database.clamav.net");
        sb.AppendLine("ConnectTimeout 30");
        sb.AppendLine("ReceiveTimeout 60");
        sb.AppendLine("TestDatabases yes");
        sb.AppendLine("# Notify the running daemon after an update so it reloads signatures.");
        sb.AppendLine($"NotifyClamd \"{AppPaths.ClamdConf}\"");
        return sb.ToString();
    }

    /// <summary>
    /// Builds the clamd.conf content. TCP on localhost only, thread count from
    /// settings (defaults to all logical cores) for parallel daemon scans.
    /// Called from: EnsureConfigs.
    /// </summary>
    private static string BuildClamdConf()
    {
        var s = SettingsManager.Current;
        var sb = new StringBuilder();
        sb.AppendLine("# Auto generated by ClamHub. Safe to edit, it will not be overwritten.");
        sb.AppendLine($"DatabaseDirectory \"{AppPaths.DatabaseDir}\"");
        sb.AppendLine($"LogFile \"{AppPaths.ClamdLogFile}\"");
        sb.AppendLine("LogTime yes");
        sb.AppendLine("LogVerbose no");
        sb.AppendLine("# Listen on localhost only, never expose the daemon to the network.");
        sb.AppendLine($"TCPSocket {s.ClamdPort}");
        sb.AppendLine("TCPAddr 127.0.0.1");
        sb.AppendLine($"MaxThreads {s.EffectiveMaxThreads()}");
        sb.AppendLine("MaxDirectoryRecursion 20");
        sb.AppendLine("FollowDirectorySymlinks no");
        sb.AppendLine("FollowFileSymlinks no");
        sb.AppendLine("SelfCheck 3600");
        sb.AppendLine("DetectPUA yes");
        sb.AppendLine("ScanArchive yes");
        sb.AppendLine("ScanMail yes");
        sb.AppendLine("ScanPE yes");
        sb.AppendLine("ScanOLE2 yes");
        sb.AppendLine("ScanHTML yes");
        return sb.ToString();
    }
}
