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

    // LEGACY markers: older versions wrote ExcludeDatabase lines into clamd.conf between
    // these markers (one block for empty databases, one for user-disabled databases).
    // That was a BUG: ExcludeDatabase is a freshclam.conf-only option; clamd aborts with
    // "Parse error: Unknown option" (exit code 1) when it sees it, so writing either
    // block prevented the daemon from starting at all. The markers are kept ONLY so
    // RemoveManagedDatabaseExclusionBlocks can strip stale blocks from existing configs.
    // Disabling is now done by renaming the file (see DisabledSuffix below).
    private const string EmptyDbBlockStart = "# >>> ClamHub empty-database exclusions >>>";
    private const string EmptyDbBlockEnd = "# <<< ClamHub empty-database exclusions <<<";
    private const string DisabledDbBlockStart = "# >>> ClamHub disabled databases >>>";
    private const string DisabledDbBlockEnd = "# <<< ClamHub disabled databases <<<";

    // Markers for the freshclam.conf block of ExcludeDatabase lines that stops freshclam
    // from downloading/updating databases the user disabled. ExcludeDatabase IS a valid
    // freshclam option (unlike in clamd.conf), so this file is safe to write.
    private const string UpdateExcludeBlockStart = "# >>> ClamHub disabled databases (skip updates) >>>";
    private const string UpdateExcludeBlockEnd = "# <<< ClamHub disabled databases (skip updates) <<<";

    /// <summary>
    /// LEGACY suffix: older versions disabled a database by renaming it to "name.disabled"
    /// INSIDE the database folder. That was the cause of the vanishing databases - freshclam
    /// prunes files with an unknown extension from its DatabaseDirectory, so the file was
    /// deleted on the next update and, being excluded from downloads, never returned.
    /// Disabling now MOVES the file to AppPaths.DisabledDatabaseDir instead. The constant
    /// survives only so MigrateDisabledDatabases can rescue leftovers from older installs.
    /// </summary>
    public const string DisabledSuffix = ".disabled";

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
    /// Repair step: strips the two LEGACY ExcludeDatabase blocks (empty-database and
    /// disabled-database) from clamd.conf if present. ExcludeDatabase is not a valid
    /// clamd.conf option, so any config still carrying such a block makes clamd exit
    /// with a parse error before it even loads; this heals installs written by older
    /// versions. The valid ExcludePath user-exclusion block is untouched. A no-op when
    /// neither block exists (the file is not rewritten then).
    /// Called from: DaemonController.StartAsync (before launching clamd).
    /// </summary>
    public static void RemoveManagedDatabaseExclusionBlocks()
    {
        if (!File.Exists(AppPaths.ClamdConf)) return;
        var lines = File.ReadAllLines(AppPaths.ClamdConf).ToList();

        bool changed = RemoveBlock(lines, EmptyDbBlockStart, EmptyDbBlockEnd);
        changed |= RemoveBlock(lines, DisabledDbBlockStart, DisabledDbBlockEnd);

        if (changed) File.WriteAllLines(AppPaths.ClamdConf, lines);
    }

    /// <summary>Removes one marker-delimited block (inclusive) plus a trailing blank
    /// line; returns whether anything was removed. Called from:
    /// RemoveManagedDatabaseExclusionBlocks.</summary>
    private static bool RemoveBlock(List<string> lines, string startMarker, string endMarker)
    {
        int start = lines.FindIndex(l => l.Trim() == startMarker);
        if (start < 0) return false;

        int end = lines.FindIndex(start, l => l.Trim() == endMarker);
        if (end >= start) lines.RemoveRange(start, end - start + 1);
        else lines.RemoveRange(start, lines.Count - start);
        if (start > 0 && start <= lines.Count
            && (start == lines.Count || lines[start].Trim().Length == 0)
            && lines[start - 1].Trim().Length == 0)
            lines.RemoveAt(start - 1);
        return true;
    }

    /// <summary>
    /// Moves every currently-EMPTY text database out to the parking folder and records it
    /// in settings.ExcludedDatabases, because clamd refuses to start when a database file
    /// holds no signatures ("Malformed database"). The file shows up as disabled in the
    /// Signatures table and can be re-enabled there once it has content (a still-empty
    /// re-enabled file is simply auto-disabled again on the next daemon start). Returns
    /// the affected file names for the status log. Called from: DaemonController.StartAsync.
    /// </summary>
    public static List<string> AutoDisableEmptyDatabases()
    {
        var disabled = new List<string>();
        foreach (var name in FindEmptyDatabases())
        {
            if (SetDatabaseDisabled(name, true, out _))
            {
                disabled.Add(name);
                var list = SettingsManager.Current.ExcludedDatabases;
                if (!list.Contains(name, StringComparer.OrdinalIgnoreCase)) list.Add(name);
            }
        }
        if (disabled.Count > 0) SettingsManager.Save();
        return disabled;
    }

    /// <summary>True when the file name is one of ClamHub's own custom list databases
    /// (blacklist/whitelist). Those must never be auto-disabled or enforced against.
    /// Called from: FindEmptyDatabases, EnforceDatabaseDisables, SetDatabaseDisabled.</summary>
    private static bool IsCustomListFile(string fileName)
        => fileName.Equals(Path.GetFileName(AppPaths.CustomBlacklistDb), StringComparison.OrdinalIgnoreCase)
        || fileName.Equals(Path.GetFileName(AppPaths.CustomWhitelistDb), StringComparison.OrdinalIgnoreCase);

    /// <summary>Full path a database has while ENABLED (inside freshclam's database folder).
    /// Called from: SetDatabaseDisabled, PruneStaleExclusions, EnforceDatabaseDisables.</summary>
    private static string EnabledPath(string fileName) => Path.Combine(AppPaths.DatabaseDir, fileName);

    /// <summary>Full path a database has while DISABLED (parked next to, never inside, the
    /// database folder). Called from: SetDatabaseDisabled, PruneStaleExclusions, MigrateDisabledDatabases.</summary>
    private static string DisabledPath(string fileName) => Path.Combine(AppPaths.DisabledDatabaseDir, fileName);

    /// <summary>True when the path lies in the parking folder for disabled databases.
    /// Called from: the Signatures table (row state) and MigrateDisabledDatabases.</summary>
    public static bool IsInDisabledFolder(string path)
    {
        try
        {
            string dir = Path.GetFullPath(Path.GetDirectoryName(path) ?? "")
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string disabled = Path.GetFullPath(AppPaths.DisabledDatabaseDir)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return dir.Equals(disabled, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    /// <summary>
    /// Disables or enables one database by MOVING its file between the database folder and
    /// the parking folder (AppPaths.DisabledDatabaseDir). The move - not a rename inside the
    /// database folder - is the whole mechanism: freshclam deletes files it does not
    /// recognise from its DatabaseDirectory, so a disabled database parked there was lost on
    /// the next update. Outside that folder it survives untouched, while clamd and clamscan
    /// (which only load DatabaseDir) simply do not see it. Refuses the custom lists. When the
    /// target already exists, the NEWER file wins: enabling keeps a freshly downloaded plain
    /// file and drops the parked copy; disabling replaces a stale parked copy. Does NOT touch
    /// settings; callers keep settings.ExcludedDatabases in sync. Returns false with an error
    /// message when the source is missing or the move fails (e.g. file locked).
    /// Called from: AutoDisableEmptyDatabases, EnforceDatabaseDisables, MigrateDisabledDatabases
    /// and the Signatures context-menu toggle (ToggleDatabaseExclusion_Click).
    /// </summary>
    public static bool SetDatabaseDisabled(string fileName, bool disabled, out string error)
    {
        error = "";
        if (IsCustomListFile(fileName))
        {
            error = "The custom lists cannot be disabled.";
            return false;
        }

        string enabled = EnabledPath(fileName);
        string parked = DisabledPath(fileName);
        string from = disabled ? enabled : parked;
        string to = disabled ? parked : enabled;

        try
        {
            Directory.CreateDirectory(AppPaths.DisabledDatabaseDir);

            if (!File.Exists(from))
            {
                if (File.Exists(to)) return true; // already in the requested state
                error = $"{fileName} was not found in the database folder.";
                return false;
            }

            if (File.Exists(to))
            {
                if (!disabled)
                {
                    // Enabling while a plain file exists again: freshclam re-downloaded it,
                    // so that one is NEWER. Keep it and drop the parked copy.
                    File.Delete(from);
                    return true;
                }
                File.Delete(to); // disabling: replace a stale parked copy
            }

            File.Move(from, to);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// One-time repair for installs written by older versions: moves every legacy
    /// "name.disabled" file out of the database folder into the parking folder under its
    /// real name ("main.cvd.disabled" -> database-disabled\main.cvd). Those files were
    /// being deleted by freshclam (unknown extension in its DatabaseDirectory), which is
    /// exactly how disabled databases went missing. Idempotent and cheap (a directory
    /// listing); a name that already exists in the parking folder is kept and the legacy
    /// leftover removed. Returns the recovered names for the status log.
    /// Called from: DaemonController.StartAsync and UpdateManager.RunUpdateAsync, both
    /// before anything else touches the databases.
    /// </summary>
    public static List<string> MigrateDisabledDatabases()
    {
        var moved = new List<string>();
        if (!Directory.Exists(AppPaths.DatabaseDir)) return moved;

        string[] legacy;
        try { legacy = Directory.GetFiles(AppPaths.DatabaseDir, "*" + DisabledSuffix); }
        catch { return moved; }
        if (legacy.Length == 0) return moved;

        Directory.CreateDirectory(AppPaths.DisabledDatabaseDir);
        foreach (var file in legacy)
        {
            string real = Path.GetFileName(file);
            real = real[..^DisabledSuffix.Length];           // strip ".disabled"
            if (real.Length == 0) continue;

            try
            {
                string target = DisabledPath(real);
                if (File.Exists(target)) File.Delete(file);  // parking folder already has it
                else { File.Move(file, target); moved.Add(real); }
            }
            catch { /* locked: leave it, the next start retries */ }
        }
        return moved;
    }

    /// <summary>
    /// Re-applies the disables from settings.ExcludedDatabases: any listed database whose
    /// file re-appeared in the database folder is moved back out to the parking folder.
    /// This still matters even though disabled databases are excluded from updates: a
    /// custom-URL database can be re-added, and scripted updates switch a container's
    /// extension - hence SIBLING-AWARE, "daily.cvd" in settings also catches a delivered
    /// "daily.cld" (same database, different form). Returns the file names that had to be
    /// re-disabled, for the status log. Called from: DaemonController.StartAsync and after
    /// a signature update (MainWindow.RunSignatureUpdateAsync).
    /// </summary>
    public static List<string> EnforceDatabaseDisables()
    {
        var applied = new List<string>();
        foreach (var name in ExcludedDatabaseNames())
        {
            // Safety net: never enforce against the custom lists, even if their name
            // somehow ended up in the settings (e.g. edited by hand).
            if (IsCustomListFile(name)) continue;

            foreach (var candidate in NameAndContainerSibling(name))
            {
                string plain = Path.Combine(AppPaths.DatabaseDir, candidate);
                if (File.Exists(plain) && SetDatabaseDisabled(candidate, true, out _))
                    applied.Add(candidate);
            }
        }
        return applied;
    }

    /// <summary>The name itself plus, for a container, its .cvd/.cld sibling name
    /// ("daily.cvd" also yields "daily.cld"): both extensions are the SAME database in
    /// different delivery forms. Called from: EnforceDatabaseDisables and
    /// PruneStaleExclusions.</summary>
    private static IEnumerable<string> NameAndContainerSibling(string name)
    {
        yield return name;
        string ext = Path.GetExtension(name);
        if (ext.Equals(".cvd", StringComparison.OrdinalIgnoreCase))
            yield return Path.ChangeExtension(name, ".cld");
        else if (ext.Equals(".cld", StringComparison.OrdinalIgnoreCase))
            yield return Path.ChangeExtension(name, ".cvd");
    }

    /// <summary>
    /// Self-healing: removes settings.ExcludedDatabases entries whose database no longer
    /// exists in ANY form (not in the database folder, not in the parking folder, and for
    /// containers no .cvd/.cld sibling either). Without this, a vanished database stays in
    /// the freshclam ExcludeDatabase block FOREVER and can never be downloaded again (the
    /// deadlock behind "the official databases are gone and never come back"); once pruned,
    /// the next update simply re-downloads it, enabled. Saves the settings and rewrites the
    /// freshclam blocks when something was pruned. Returns the pruned names for the status
    /// log. Called from: DaemonController.StartAsync and UpdateManager.RunUpdateAsync (both
    /// AFTER MigrateDisabledDatabases, so a legacy leftover is rescued before it is judged).
    /// </summary>
    public static List<string> PruneStaleExclusions()
    {
        var pruned = new List<string>();
        var list = SettingsManager.Current.ExcludedDatabases;

        for (int i = list.Count - 1; i >= 0; i--)
        {
            string name = list[i]?.Trim() ?? "";
            if (name.Length == 0) { list.RemoveAt(i); continue; }
            if (IsCustomListFile(name)) { list.RemoveAt(i); continue; }

            bool exists = NameAndContainerSibling(name).Any(candidate =>
                File.Exists(EnabledPath(candidate))                                  // enabled
                || File.Exists(DisabledPath(candidate))                              // parked
                || File.Exists(EnabledPath(candidate) + DisabledSuffix));            // legacy leftover

            if (!exists)
            {
                pruned.Add(name);
                list.RemoveAt(i);
                SettingsManager.Current.DisabledCustomUrls.Remove(name); // drop any parked URL
            }
        }

        if (pruned.Count > 0)
        {
            SettingsManager.Save();
            try { WriteUpdateExclusions(); } catch { /* rewritten before every update anyway */ }
            try { SyncCustomUrlDownloads(); } catch { /* rewritten before every update anyway */ }
        }
        return pruned;
    }

    /// <summary>
    /// Rewrites the managed ExcludeDatabase block in FRESHCLAM.CONF so freshclam does not
    /// download/update the disabled databases (otherwise a disabled official database is
    /// re-downloaded in full on every update, including update-on-start). ExcludeDatabase
    /// is a valid freshclam option; the DBNAME is the base name without extension
    /// ("main.cvd" -> "main", "daily.cld" -> "daily", "bytecode.cvd" -> "bytecode") and
    /// covers the official + mirror-distributed 3rd party databases. Custom-URL databases
    /// (DatabaseCustomURL) are NOT affected by ExcludeDatabase and keep downloading; the
    /// rename + post-update EnforceDatabaseDisables still keep them out of scanning. Custom
    /// lists are never listed. All other content is preserved; with no disables the block
    /// is removed. clamd never reads freshclam.conf, so this cannot break daemon startup.
    /// Called from: UpdateManager.RunUpdateAsync (before every freshclam run) and the
    /// Signatures disable toggle (ToggleDatabaseExclusion_Click).
    /// </summary>
    public static void WriteUpdateExclusions()
    {
        if (!File.Exists(AppPaths.FreshClamConf)) return;
        var lines = File.ReadAllLines(AppPaths.FreshClamConf).ToList();

        RemoveBlock(lines, UpdateExcludeBlockStart, UpdateExcludeBlockEnd);

        var names = SettingsManager.Current.ExcludedDatabases
            .Select(n => n?.Trim() ?? "")
            .Where(n => n.Length > 0 && !IsCustomListFile(n))
            .Select(Path.GetFileNameWithoutExtension)
            .Where(n => !string.IsNullOrEmpty(n))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (names.Count > 0)
        {
            if (lines.Count > 0 && lines[^1].Trim().Length != 0) lines.Add("");
            lines.Add(UpdateExcludeBlockStart);
            foreach (var name in names) lines.Add($"ExcludeDatabase {name}");
            lines.Add(UpdateExcludeBlockEnd);
        }

        File.WriteAllLines(AppPaths.FreshClamConf, lines);
    }

    /// <summary>Text-database extensions whose emptiness is checked by counting signature lines.</summary>
    private static readonly HashSet<string> EmptyCheckExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".hdb", ".hsb", ".mdb", ".msb", ".ndb", ".ldb", ".sdb", ".fp", ".sfp", ".idb",
        ".cdb", ".crb", ".gdb", ".pdb", ".wdb", ".ign", ".ign2", ".imp", ".pwdb", ".ftm", ".yar", ".yara"
    };

    /// <summary>
    /// File names of database files that clamd would fail to load because they hold no
    /// signatures: a 0-byte file, or a text database whose lines are all blank or
    /// comments. Container databases (.cvd/.cld), already-disabled files (their extension
    /// is ".disabled") and unreadable files are skipped.
    /// Called from: AutoDisableEmptyDatabases.
    /// </summary>
    private static List<string> FindEmptyDatabases()
    {
        var names = new List<string>();
        if (!Directory.Exists(AppPaths.DatabaseDir)) return names;

        string[] files;
        try { files = Directory.GetFiles(AppPaths.DatabaseDir); }
        catch { return names; }

        foreach (var file in files)
        {
            if (!EmptyCheckExtensions.Contains(Path.GetExtension(file))) continue;
            // NEVER flag the custom blacklist/whitelist: they are managed by
            // CustomSignatureManager (which deletes the file when the list empties) and
            // renaming them would leave a stale .disabled copy that EnforceDatabaseDisables
            // could later apply to a freshly written list, silently killing custom
            // signatures. IsCustomListFile also guards EnforceDatabaseDisables.
            if (IsCustomListFile(Path.GetFileName(file))) continue;

            try
            {
                var info = new FileInfo(file);
                if (info.Length == 0) { names.Add(info.Name); continue; }

                bool hasSignature = false;
                foreach (var raw in File.ReadLines(file))
                {
                    var t = raw.Trim();
                    if (t.Length > 0 && !t.StartsWith('#')) { hasSignature = true; break; }
                }
                if (!hasSignature) names.Add(info.Name);
            }
            catch { /* unreadable: leave it for clamd to report */ }
        }
        return names;
    }

    /// <summary>
    /// File names (case-insensitive) of the databases the user disabled for scanning.
    /// Called from: ScanEngine (the pre-scan note) and EnforceDatabaseDisables.
    /// </summary>
    public static HashSet<string> ExcludedDatabaseNames()
        => new(SettingsManager.Current.ExcludedDatabases
                  .Select(n => n?.Trim() ?? "").Where(n => n.Length > 0),
               StringComparer.OrdinalIgnoreCase);

    /// <summary>Local file name freshclam derives from a DatabaseCustomURL (the last path
    /// segment of the URL, e.g. ".../rfxn.ndb" -> "rfxn.ndb"). Empty when the URL cannot be
    /// parsed. Called from: SyncCustomUrlDownloads.</summary>
    private static string CustomUrlFileName(string url)
    {
        try { return Path.GetFileName(new Uri(url).AbsolutePath); }
        catch { return ""; }
    }

    /// <summary>
    /// Reconciles freshclam's DatabaseCustomURL lines with the disabled set. freshclam
    /// ExcludeDatabase does NOT stop DatabaseCustomURL downloads, so the ONLY way to stop
    /// updating a disabled custom-URL database is to take its URL out of freshclam.conf.
    /// This moves every disabled custom database's URL into settings.DisabledCustomUrls
    /// (parked) and keeps only the enabled ones as DatabaseCustomURL lines; enabling moves
    /// the URL back. URLs whose file name cannot be derived are always kept active (never
    /// silently dropped). Idempotent - only writes when something actually changed - so it
    /// is safe to call before every freshclam run and on every toggle. Called from:
    /// UpdateManager.RunUpdateAsync (before freshclam) and the Signatures disable toggle.
    /// </summary>
    public static void SyncCustomUrlDownloads()
    {
        if (!File.Exists(AppPaths.FreshClamConf)) return;

        var conf = ClamConfFile.Load(AppPaths.FreshClamConf);
        var active = conf.GetValues("DatabaseCustomURL").ToList();
        var parked = SettingsManager.Current.DisabledCustomUrls;
        var excluded = ExcludedDatabaseNames();

        // Union of every custom URL we know about (in the config or parked), de-duplicated.
        var allUrls = active.Concat(parked.Values)
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var newActive = new List<string>();
        var newParked = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var url in allUrls)
        {
            string file = CustomUrlFileName(url);
            if (file.Length > 0 && excluded.Contains(file))
                newParked[file] = url;      // disabled: keep the URL out of freshclam.conf
            else
                newActive.Add(url);         // enabled (or unidentifiable): download normally
        }

        bool activeChanged = active.Count != newActive.Count
            || !active.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                      .SequenceEqual(newActive.OrderBy(x => x, StringComparer.OrdinalIgnoreCase),
                                     StringComparer.OrdinalIgnoreCase);
        if (activeChanged)
        {
            conf.Remove("DatabaseCustomURL");
            foreach (var url in newActive) conf.AddValue("DatabaseCustomURL", url);
            conf.Save();
        }

        bool parkedChanged = parked.Count != newParked.Count
            || newParked.Any(kv => !parked.TryGetValue(kv.Key, out var v)
                                   || !string.Equals(v, kv.Value, StringComparison.OrdinalIgnoreCase));
        if (parkedChanged)
        {
            SettingsManager.Current.DisabledCustomUrls = newParked;
            SettingsManager.Save();
        }
    }

    /// <summary>
    /// Builds the ExcludePath regex lines for the managed user-exclusion block from the
    /// exclusion settings (directories and file extensions).
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
        foreach (var file in SettingsManager.Current.ExcludeFiles)
        {
            var trimmed = file?.Trim();
            if (!string.IsNullOrEmpty(trimmed))
                result.Add($"ExcludePath {EscapeRegexPath(trimmed)}$");
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
