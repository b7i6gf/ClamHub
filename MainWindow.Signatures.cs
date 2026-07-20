using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using ClamHub.Core;

namespace ClamHub;

/// <summary>
/// Signatures tab logic AND the shared "apply a signature change" flow used by the
/// tab's manage-lists window, the context-menu blacklist/whitelist actions and the
/// quarantine restore+whitelist. The tab shows the official ClamAV database info
/// (sigtool) and the counts of ClamHub's own block/allow lists. The shared flow
/// (ApplySignatureAddAsync / ApplySignatureRemove) enforces that a file is never on
/// both lists (it asks once whether to move a file already on the other list),
/// writes a History entry per change and refreshes the counts; callers trigger the
/// reliable daemon reload (ReloadDaemonAsync). Partial class companion to
/// MainWindow.xaml.cs.
/// </summary>
public partial class MainWindow
{
    /// <summary>Whether the (relatively slow) sigtool DB info has been loaded once.</summary>
    private bool _sigInfoLoaded;

    /// <summary>Cached rows for the non-custom DB files in the folder (official CVDs via
    /// sigtool + any third-party databases); the two custom-list rows are appended
    /// cheaply on every table rebuild.</summary>
    private List<DbRow> _nonCustomRows = new();

    /// <summary>Backing list bound to the table. Kept as ONE stable reference so the
    /// table's default ICollectionView (and thus the active sort column) survives a
    /// rebuild: RebuildSignatureTable mutates this list in place and Refresh()es the
    /// view instead of swapping ItemsSource (a fresh list would reset the sort).</summary>
    private readonly List<DbRow> _signatureRows = new();

    /// <summary>Recognised ClamAV database file extensions shown as table rows.</summary>
    private static readonly HashSet<string> DbFileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cvd", ".cld", ".hdb", ".hsb", ".mdb", ".msb", ".ndb", ".ldb", ".sdb", ".fp", ".sfp",
        ".idb", ".cdb", ".crb", ".gdb", ".pdb", ".wdb", ".ign", ".ign2", ".yar", ".yara",
        ".cbc", ".cud", ".imp", ".pwdb", ".ftm"
    };

    /// <summary>
    /// Runs when the Signatures tab becomes active. Always refreshes the cheap custom
    /// list counts (a context-menu block/whitelist may have changed them) and loads
    /// the sigtool database info once (lazily). Fired-and-forgotten from
    /// Tabs_SelectionChanged, so it must never let an exception escape: an unobserved
    /// task exception would be swallowed (or crash later) instead of being shown.
    /// Called from: Tabs_SelectionChanged.
    /// </summary>
    private async Task OnSignaturesTabOpenedAsync()
    {
        try
        {
            RebuildSignatureTable();
            if (_sigInfoLoaded) return;
            _sigInfoLoaded = true;
            await RefreshDatabaseInfoAsync();
        }
        catch (Exception ex)
        {
            _sigInfoLoaded = false; // allow a retry on the next tab open
            try
            {
                ConsoleFormatting.SetLines(SignaturesDetailBox,
                    new[] { $"Could not load the Signatures tab: {ex.Message}" });
            }
            catch { /* even reporting failed; never rethrow into the void */ }
        }
    }

    /// <summary>
    /// Rebuilds the database table from the cached official rows plus the two custom
    /// lists (blacklist/whitelist), which are cheap to recompute. Called whenever the
    /// custom lists may have changed (tab open, after add/remove) and after the
    /// official rows are (re)loaded. Mutates the stable backing list in place and
    /// refreshes the view so the current sort column is preserved (see _signatureRows);
    /// the selection is cleared because the row objects are rebuilt.
    /// Called from: OnSignaturesTabOpenedAsync, RefreshDatabaseInfoAsync,
    /// RefreshDbInfo_Click and the shared add/remove flow.
    /// </summary>
    private void RebuildSignatureTable()
    {
        _signatureRows.Clear();
        _signatureRows.AddRange(_nonCustomRows);
        _signatureRows.Add(DbRow.Custom(CustomSignatureManager.ListKind.Blacklist));
        _signatureRows.Add(DbRow.Custom(CustomSignatureManager.ListKind.Whitelist));

        // Bind once; afterwards only refresh so the ICollectionView (and its active
        // SortDescriptions) is reused instead of being rebuilt from scratch.
        if (!ReferenceEquals(SignaturesDbList.ItemsSource, _signatureRows))
            SignaturesDbList.ItemsSource = _signatureRows;
        System.Windows.Data.CollectionViewSource.GetDefaultView(_signatureRows)?.Refresh();
    }

    /// <summary>Sorts the database table by the clicked column, reusing the shared
    /// table-sort helper (toggles asc/desc, one active column, shows the arrow).
    /// Called from: the Signatures table GridViewColumnHeader.Click in MainWindow.xaml.</summary>
    private void SignaturesSort_Click(object sender, RoutedEventArgs e)
        => ListViewSorting.SortByColumn(e.OriginalSource as GridViewColumnHeader, SignaturesDbList);

    /// <summary>
    /// Lists every recognised ClamAV database file in the folder as a table row: the
    /// official main/daily/bytecode and any third-party databases (added by file or
    /// fetched from a custom URL). Container databases (.cvd/.cld) are read via sigtool;
    /// text databases show a line count; our two custom lists are appended by
    /// RebuildSignatureTable. All file IO (enumeration, line counting of possibly large
    /// third-party databases, the URL map) runs on a WORKER thread; the UI thread only
    /// binds the finished rows. Selecting a row shows its details. Called from:
    /// OnSignaturesTabOpenedAsync, RefreshDbInfo_Click and after add/URL actions.
    /// </summary>
    private async Task RefreshDatabaseInfoAsync()
    {
        ConsoleFormatting.SetLines(SignaturesDetailBox, new[] { "Reading databases..." });

        int fileCount;
        List<DbRow> rows;
        try
        {
            (fileCount, rows) = await Task.Run(BuildDatabaseRowsAsync);
        }
        catch (Exception ex)
        {
            _nonCustomRows = new();
            RebuildSignatureTable();
            ConsoleFormatting.SetLines(SignaturesDetailBox,
                new[] { $"Could not read the databases: {ex.Message}" });
            return;
        }

        _nonCustomRows = rows;
        RebuildSignatureTable();

        var notes = new List<string>();
        if (!SigTool.IsAvailable)
            notes.Add("sigtool.exe not found: version and verification of .cvd/.cld databases are unavailable.");
        notes.Add(fileCount == 0
            ? "No official or third-party database files found yet (only the custom lists exist). Run a signature update to download the official databases."
            : "Select a database above to see its details.");
        ConsoleFormatting.SetLines(SignaturesDetailBox, notes);
    }

    /// <summary>
    /// Worker-thread part of the table refresh: enumerates the database folder, maps
    /// files to their custom URLs and builds one DbRow per file (sigtool for containers,
    /// direct file reads for the rest). DbRow is plain data, so building it off the UI
    /// thread is safe. Called from: RefreshDatabaseInfoAsync (via Task.Run).
    /// </summary>
    private static async Task<(int FileCount, List<DbRow> Rows)> BuildDatabaseRowsAsync()
    {
        string blName = System.IO.Path.GetFileName(AppPaths.CustomBlacklistDb);
        string wlName = System.IO.Path.GetFileName(AppPaths.CustomWhitelistDb);

        // Both folders: the active databases clamd/clamscan load, plus the disabled ones
        // parked outside freshclam's reach (AppPaths.DisabledDatabaseDir) - those must stay
        // visible or the user could never re-enable them. EffectiveName additionally strips
        // a legacy ".disabled" suffix, so a leftover that migration could not move (locked
        // file) still shows up under its real name. The row's Path always points at the
        // real file on disk, in whichever folder it lives.
        var files = ListDatabaseFiles(AppPaths.DatabaseDir)
            .Concat(ListDatabaseFiles(AppPaths.DisabledDatabaseDir))
            .Where(f => !EffectiveName(f).Equals(blName, StringComparison.OrdinalIgnoreCase)
                     && !EffectiveName(f).Equals(wlName, StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => OfficialRank(EffectiveName(f)))
            .ThenBy(EffectiveName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var urlByFile = LoadDatabaseUrlMap();

        var rows = new List<DbRow>();
        foreach (var f in files)
        {
            string url = urlByFile.TryGetValue(EffectiveName(f), out var u) ? u : "";
            string ext = System.IO.Path.GetExtension(EffectiveName(f));
            bool container = ext.Equals(".cvd", StringComparison.OrdinalIgnoreCase)
                          || ext.Equals(".cld", StringComparison.OrdinalIgnoreCase);
            if (container && SigTool.IsAvailable)
                rows.Add(DbRow.Official(await SigTool.GetInfoAsync(f), f, url));
            else
                // sigtool --info only parses CVD/CLD containers ("Not a CVD file"
                // on a loose .ldb), so loose databases are counted by line the way
                // freshclam does; DbRow.Generic handles that.
                rows.Add(DbRow.Generic(f, url));
        }
        return (files.Count, rows);
    }

    /// <summary>Recognised database files in one folder (empty when it does not exist or is
    /// unreadable). Called from: BuildDatabaseRowsAsync, for the active and the disabled folder.</summary>
    private static List<string> ListDatabaseFiles(string dir)
    {
        try
        {
            if (!System.IO.Directory.Exists(dir)) return new List<string>();
            return System.IO.Directory.GetFiles(dir)
                .Where(f => DbFileExtensions.Contains(System.IO.Path.GetExtension(EffectiveName(f))))
                .ToList();
        }
        catch { return new List<string>(); }
    }

    /// <summary>Database file name without a trailing ".disabled" suffix: the name the
    /// database has when enabled, used as its identity everywhere (table, settings,
    /// URL map). Called from: BuildDatabaseRowsAsync and DbRow.</summary>
    internal static string EffectiveName(string path)
    {
        string name = System.IO.Path.GetFileName(path);
        return name.EndsWith(Core.ConfigManager.DisabledSuffix, StringComparison.OrdinalIgnoreCase)
            ? name[..^Core.ConfigManager.DisabledSuffix.Length]
            : name;
    }

    /// <summary>Sort rank so main/daily/bytecode come first, then everything else. Called from: RefreshDatabaseInfoAsync.</summary>
    private static int OfficialRank(string path)
        => System.IO.Path.GetFileNameWithoutExtension(path).ToLowerInvariant() switch
        {
            "main" => 0,
            "daily" => 1,
            "bytecode" => 2,
            _ => 3
        };

    /// <summary>
    /// Maps a database file name to the custom URL it was downloaded from, read from the
    /// DatabaseCustomURL entries in freshclam.conf (freshclam names the local file after
    /// the URL's last path segment). Empty map on any read error. Called from:
    /// RefreshDatabaseInfoAsync to fill the table's URL column.
    /// </summary>
    private static Dictionary<string, string> LoadDatabaseUrlMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var conf = ClamConfFile.Load(AppPaths.FreshClamConf);
            foreach (var url in conf.GetValues("DatabaseCustomURL"))
            {
                string file = UrlFileName(url);
                if (file.Length > 0) map[file] = url;
            }
        }
        catch { /* no map: URL cells stay empty */ }

        // Disabled custom-URL databases have their DatabaseCustomURL line parked out of
        // freshclam.conf (so freshclam does not download them); merge the parked URLs back
        // in so the table still shows the URL for a disabled row.
        foreach (var kv in SettingsManager.Current.DisabledCustomUrls)
            if (kv.Key.Length > 0 && !map.ContainsKey(kv.Key)) map[kv.Key] = kv.Value;

        return map;
    }

    /// <summary>Last path segment of a URL (the local database file name), or "". Called from: LoadDatabaseUrlMap.</summary>
    private static string UrlFileName(string url)
    {
        try
        {
            var uri = new Uri(url);
            return System.IO.Path.GetFileName(uri.AbsolutePath);
        }
        catch { return ""; }
    }

    /// <summary>
    /// Opens a database's source URL in the default browser when its cell hyperlink is
    /// clicked. Called from: the URL column's Hyperlink in MainWindow.xaml.
    /// </summary>
    private void DatabaseUrl_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkContentElement)?.DataContext is not DbRow row || row.Url.Length == 0)
            return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(row.Url)
            {
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            SetSignaturesStatus($"Could not open the URL: {ex.Message}");
        }
    }

    /// <summary>
    /// Shows the selected row's details in the Signatures console (official sigtool
    /// fields or custom-list info), or a hint when nothing is selected. Called from:
    /// the DB table SelectionChanged.
    /// </summary>
    private void SignaturesDbList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SignaturesDbList.SelectedItem is not DbRow row)
        {
            ConsoleFormatting.SetLines(SignaturesDetailBox, new[] { "Select a database above to see its details." });
            return;
        }
        ConsoleFormatting.SetLines(SignaturesDetailBox, row.BuildDetailLines());
    }

    /// <summary>
    /// Row in the database table: an official/container ClamAV database (via sigtool),
    /// one of ClamHub's own lists (blacklist/whitelist), or any other database file in
    /// the folder (third-party / added). Column values are plain properties; the detail
    /// text is built lazily on selection. Built via the Official/Custom/Generic
    /// factories. Used by: the Signatures DB table.
    /// </summary>
    private sealed class DbRow
    {
        public string FileName { get; }
        public string Version { get; }
        public string Signatures { get; }
        public string Built { get; }
        public string Status { get; }

        /// <summary>Full path of the backing file (used by the remove action).</summary>
        public string Path { get; }

        /// <summary>True for ClamHub's own blacklist/whitelist rows (managed via Manage lists,
        /// not deletable from the table).</summary>
        public bool IsCustom { get; }

        /// <summary>The custom URL the database was downloaded from, or "" when it has none
        /// (official databases and the custom lists). Shown as a clickable cell.</summary>
        public string Url { get; }

        /// <summary>True when this database is disabled for scanning: its file on disk
        /// carries the ".disabled" suffix, or its name is in settings.ExcludedDatabases
        /// (both are kept in sync by the toggle; either alone counts so the table shows
        /// reality even if they diverge). Never true for the custom lists. Drives the
        /// dimmed row + "(disabled)" suffix and is recomputed on every table rebuild.</summary>
        public bool Excluded { get; }

        /// <summary>Name shown in the Database column: the file name, with a "(disabled)"
        /// suffix when Excluded so the state reads clearly even next to the dimmed row.
        /// The column still sorts on FileName (its header Tag), not on this.</summary>
        public string DisplayName => Excluded ? FileName + "  (disabled)" : FileName;

        private readonly Func<IReadOnlyList<string>> _detail;

        /// <summary>True when the file is disabled: it lives in the parking folder
        /// (AppPaths.DisabledDatabaseDir), or it is a legacy "name.disabled" leftover that
        /// migration could not move (locked file). Called from: the DbRow constructor and
        /// the Official/Generic detail builders.</summary>
        private static bool IsDisabledFile(string path)
            => Core.ConfigManager.IsInDisabledFolder(path)
            || path.EndsWith(Core.ConfigManager.DisabledSuffix, StringComparison.OrdinalIgnoreCase);

        private DbRow(string path, string version, string signatures, string built, string status,
            bool isCustom, string url, Func<IReadOnlyList<string>> detail)
        {
            Path = path;
            // The identity of a database is its ENABLED file name: that is what the settings
            // list stores, what the URL map is keyed on and what the user knows it as. A
            // disabled database keeps that exact name, it just lives in the parking folder
            // (EffectiveName additionally strips a legacy ".disabled" suffix).
            FileName = MainWindow.EffectiveName(path);
            Version = version;
            Signatures = signatures;
            Built = built;
            Status = status;
            IsCustom = isCustom;
            Url = url;
            // The custom lists can never be disabled; everything else follows the file's
            // location on disk.
            Excluded = !isCustom && IsDisabledFile(path);
            _detail = detail;
        }

        /// <summary>Detail lines shown in the console. Called from: SignaturesDbList_SelectionChanged.</summary>
        public IReadOnlyList<string> BuildDetailLines() => _detail();

        /// <summary>Row for a container database read via sigtool (.cvd/.cld). Called from: RefreshDatabaseInfoAsync.</summary>
        public static DbRow Official(SigTool.DbInfo d, string path, string url)
        {
            string version = d.Ok ? (d.Version ?? "?") : "-";
            string sigs = d.Ok ? (d.Signatures ?? "?") : "-";
            string built = d.Ok ? (d.BuildTime ?? "?") : FileTime(path);
            // A parked (disabled) container keeps its real .cvd/.cld name, so sigtool
            // verifies it exactly like an active one - no special case needed. Only a legacy
            // "name.disabled" leftover cannot be verified (extension check), and SigTool
            // already reports that as Ok with Verified=false, which shows as "not verified".
            string status = !d.Ok ? "error" : (d.Verified ? "verified" : "not verified");
            return new DbRow(path, version, sigs, built, status, false, url, () => OfficialDetail(d, path, url));
        }

        /// <summary>Row for one of ClamHub's own lists. Called from: RebuildSignatureTable.</summary>
        public static DbRow Custom(CustomSignatureManager.ListKind kind)
        {
            string path = kind == CustomSignatureManager.ListKind.Blacklist
                ? AppPaths.CustomBlacklistDb : AppPaths.CustomWhitelistDb;
            int count = CustomSignatureManager.Count(kind);
            return new DbRow(path, "custom", count.ToString(), FileTime(path), "n/a", true, "",
                () => CustomDetail(kind, path, count));
        }

        /// <summary>Row for any other database file in the folder. Loose databases
        /// are counted by line the way freshclam does (sigtool cannot parse them).
        /// Called from: BuildDatabaseRowsAsync.</summary>
        public static DbRow Generic(string path, string url)
        {
            string sigs = CountSignatures(path);
            return new DbRow(path, "-", sigs, FileTime(path), "n/a", false, url,
                () => GenericDetail(path, sigs, url));
        }

        /// <summary>File mtime formatted, or "-" when the file is absent/unreadable.</summary>
        private static string FileTime(string path)
        {
            try
            {
                return System.IO.File.Exists(path)
                    ? System.IO.File.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:mm")
                    : "-";
            }
            catch { return "-"; }
        }

        /// <summary>Text-database extensions whose signatures can be counted by line.</summary>
        private static readonly HashSet<string> TextDbExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".hdb", ".hsb", ".mdb", ".msb", ".ndb", ".ldb", ".sdb", ".fp", ".sfp", ".idb",
            ".cdb", ".crb", ".gdb", ".pdb", ".wdb", ".ign", ".ign2", ".yar", ".yara", ".imp", ".pwdb", ".ftm"
        };

        /// <summary>Counts non-empty, non-comment lines of a text database, or "-" otherwise.</summary>
        private static string CountSignatures(string path)
        {
            if (!TextDbExtensions.Contains(System.IO.Path.GetExtension(path))) return "-";
            try
            {
                int n = 0;
                foreach (var line in System.IO.File.ReadLines(path))
                {
                    var t = line.Trim();
                    if (t.Length > 0 && !t.StartsWith('#')) n++;
                }
                return n.ToString();
            }
            catch { return "-"; }
        }

        /// <summary>Detail lines for a container database (sigtool fields or the read error).</summary>
        private static IReadOnlyList<string> OfficialDetail(SigTool.DbInfo d, string path, string url)
        {
            bool disabled = IsDisabledFile(path);
            var lines = new List<string> { EffectiveName(path) };
            if (disabled) lines.Add("Status: disabled (parked outside the database folder: not scanned, not updated)");
            if (!d.Ok)
            {
                lines.Add($"Error: {d.Error}");
            }
            else
            {
                lines.Add($"Version: {d.Version ?? "?"}");
                lines.Add($"Signatures: {d.Signatures ?? "?"}");
                if (!string.IsNullOrWhiteSpace(d.BuildTime)) lines.Add($"Built: {d.BuildTime}");
                if (!string.IsNullOrWhiteSpace(d.FunctionalityLevel)) lines.Add($"Functionality level: {d.FunctionalityLevel}");
                if (!string.IsNullOrWhiteSpace(d.Builder)) lines.Add($"Builder: {d.Builder}");
                lines.Add($"Signature verification: {(d.Verified ? "OK" : "not verified")}");
            }
            if (url.Length > 0) lines.Add($"URL: {url}");
            lines.Add($"Path: {path}");
            return lines;
        }

        /// <summary>Detail lines for a custom list (blacklist/whitelist).</summary>
        private static IReadOnlyList<string> CustomDetail(CustomSignatureManager.ListKind kind, string path, int count)
        {
            string type = kind == CustomSignatureManager.ListKind.Blacklist
                ? "Blacklist (matching files are DETECTED)"
                : "Whitelist (matching files are IGNORED as false positives)";
            string modified = System.IO.File.Exists(path)
                ? System.IO.File.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:mm:ss")
                : "not created yet (the list is empty)";
            return new List<string>
            {
                System.IO.Path.GetFileName(path),
                $"Type: {type}",
                $"Entries: {count}",
                $"Last modified: {modified}",
                $"Path: {path}"
            };
        }

        /// <summary>Detail lines for a third-party / added database file.</summary>
        private static IReadOnlyList<string> GenericDetail(string path, string sigs, string url)
        {
            bool disabled = IsDisabledFile(path);
            var lines = new List<string>
            {
                EffectiveName(path),
                disabled ? "Status: disabled (parked outside the database folder: not scanned, not updated)"
                         : "Type: additional database (loaded by clamd)"
            };
            if (sigs != "-")
            {
                lines.Add($"Signatures: {sigs} (signature lines in the file)");
                // freshclam's update log ("sigs: N") counts raw lines at download
                // time and includes blank lines, so its number can differ from the
                // signatures present in the file on disk right now.
                lines.Add("Note: freshclam's \"sigs\" figure is counted at download time and may differ.");
            }
            string modified = System.IO.File.Exists(path)
                ? System.IO.File.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:mm:ss")
                : "-";
            lines.Add($"Last modified: {modified}");
            if (url.Length > 0) lines.Add($"URL: {url}");
            lines.Add($"Path: {path}");
            return lines;
        }
    }

    /// <summary>
    /// Deletes the selected database file from the folder after confirmation, logs a
    /// History entry, refreshes the table and reloads the daemon. ClamHub's own
    /// blacklist/whitelist rows are not deletable here (they are managed via Manage
    /// lists). Called from: the table context menu and the Delete key.
    /// </summary>
    private async Task RemoveSelectedDatabaseAsync()
    {
        if (SignaturesDbList.SelectedItem is not DbRow row)
        {
            SetSignaturesStatus("Select a database to remove.");
            return;
        }
        if (row.IsCustom)
        {
            SetSignaturesStatus("The custom lists are managed with 'Manage lists...'.");
            return;
        }
        if (!System.IO.File.Exists(row.Path))
        {
            SetSignaturesStatus($"{row.FileName} no longer exists.");
            await RefreshDatabaseInfoAsync();
            return;
        }

        if (!Confirm("Remove database",
                $"Delete {row.FileName} from the database folder?\n\n"
                + "Official databases are downloaded again on the next signature update.",
                "Delete", "Cancel"))
            return;

        try
        {
            System.IO.File.Delete(row.Path);
        }
        catch (Exception ex)
        {
            SetSignaturesStatus($"Could not delete {row.FileName}: {ex.Message}");
            return;
        }

        AddHistory("Databases", "", "", "database removed",
            $"Removed database file from the folder:{Environment.NewLine}{row.FileName}");

        // Drop a stale disable entry so a later re-download starts enabled as expected.
        var excluded = SettingsManager.Current.ExcludedDatabases;
        bool changed = excluded.RemoveAll(n => string.Equals(n, row.FileName, StringComparison.OrdinalIgnoreCase)) > 0;
        changed |= SettingsManager.Current.DisabledCustomUrls.Remove(row.FileName);
        if (changed) SettingsManager.Save();

        _sigInfoLoaded = false;
        await RefreshDatabaseInfoAsync();
        SetSignaturesStatus($"Removed {row.FileName}.");
        await ReloadDaemonAsync();
    }

    /// <summary>Remove database context-menu item. Called from: XAML Click binding.</summary>
    private async void RemoveDatabase_Click(object sender, RoutedEventArgs e)
        => await RemoveSelectedDatabaseAsync();

    /// <summary>Deletes the selected database on the Delete key. Called from: XAML KeyDown binding.</summary>
    private async void SignaturesDbList_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key != System.Windows.Input.Key.Delete) return;
        e.Handled = true;
        await RemoveSelectedDatabaseAsync();
    }

    /// <summary>
    /// Suppresses the table context menu entirely for the custom blacklist/whitelist rows
    /// (managed via "Manage lists...", neither disable nor remove applies) and when no row
    /// is selected, so a right-click there shows nothing at all.
    /// Called from: the SignaturesDbList ContextMenuOpening binding in MainWindow.xaml.
    /// </summary>
    private void SignaturesDbList_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        if (SignaturesDbList.SelectedItem is not DbRow row || row.IsCustom)
            e.Handled = true; // no menu
    }

    /// <summary>
    /// Updates the "Disable/Enable database" context-menu item just before the menu
    /// shows (custom rows and empty selection never get here; the menu is suppressed for
    /// them in SignaturesDbList_ContextMenuOpening), labelled to match the toggle
    /// direction of the selected row.
    /// Called from: the Signatures ContextMenu.Opened in MainWindow.xaml.
    /// </summary>
    private void SignaturesContextMenu_Opened(object sender, RoutedEventArgs e)
    {
        var row = SignaturesDbList.SelectedItem as DbRow;
        ToggleExcludeMenuItem.IsEnabled = row != null && !row.IsCustom;
        ToggleExcludeMenuItem.Header = (row != null && row.Excluded)
            ? "Enable database" : "Disable database";
    }

    /// <summary>
    /// Toggles whether the selected database is loaded for scanning: updates
    /// settings.ExcludedDatabases, rewrites the clamd.conf disabled-database block so the
    /// daemon skips it, and reloads the daemon; standalone clamscan picks up the same list
    /// on its next run. The custom lists are rejected. Called from: the "Disable/Enable for
    /// scanning" context-menu item in MainWindow.xaml.
    /// </summary>
    private async void ToggleDatabaseExclusion_Click(object sender, RoutedEventArgs e)
    {
        if (SignaturesDbList.SelectedItem is not DbRow row)
        {
            SetSignaturesStatus("Select a database first.");
            return;
        }
        if (row.IsCustom)
        {
            SetSignaturesStatus("The custom lists cannot be disabled for scanning.");
            return;
        }

        bool nowDisabled = !row.Excluded;

        // MOVE the file FIRST (database folder <-> database-disabled folder); only a
        // successful move changes the settings, so the list and the disk never diverge.
        // The move is the actual scan mechanism: clamd and clamscan only load DatabaseDir,
        // so a parked database is invisible to both, with no clamd.conf change (clamd has
        // no ExcludeDatabase and dies on it). It also keeps the file out of freshclam's
        // folder, which is what stopped freshclam from deleting disabled databases.
        if (!ConfigManager.SetDatabaseDisabled(row.FileName, nowDisabled, out string error))
        {
            SetSignaturesStatus($"Could not {(nowDisabled ? "disable" : "enable")} {row.FileName}: {error}");
            return;
        }

        var list = SettingsManager.Current.ExcludedDatabases;
        int idx = list.FindIndex(n => string.Equals(n, row.FileName, StringComparison.OrdinalIgnoreCase));
        if (nowDisabled && idx < 0) list.Add(row.FileName);
        else if (!nowDisabled && idx >= 0) list.RemoveAt(idx);
        SettingsManager.Save();

        // Keep freshclam from re-downloading a disabled database (and resume it on enable):
        // ExcludeDatabase for official databases, and parking the DatabaseCustomURL line
        // for custom-URL databases (ExcludeDatabase does not cover those).
        try
        {
            ConfigManager.WriteUpdateExclusions();
            ConfigManager.SyncCustomUrlDownloads();
        }
        catch (Exception ex) { SetSignaturesStatus($"Could not update freshclam.conf: {ex.Message}"); }

        AddHistory("Databases", "", "", nowDisabled ? "database disabled" : "database enabled",
            (nowDisabled ? "Disabled (moved to the disabled-databases folder; not scanned, not updated):"
                         : "Enabled (moved back into the database folder):")
            + Environment.NewLine + row.FileName);

        await RefreshDatabaseInfoAsync(); // rebuild rows so the dimmed "(disabled)" hint updates
        SetSignaturesStatus(nowDisabled
            ? $"{row.FileName} disabled for scanning. Reloading the daemon..."
            : $"{row.FileName} enabled for scanning. Reloading the daemon...");
        await ReloadDaemonAsync();
    }

    /// <summary>
    /// Shows a one-line action result in the Signatures console (the tab has no status
    /// text; the console below is its output). Empty text is ignored so a caller can
    /// leave the current database details in place. Called from: the tab button handlers,
    /// the remove action and the context-menu signature actions.
    /// </summary>
    private void SetSignaturesStatus(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        ConsoleFormatting.SetLines(SignaturesDetailBox, new[] { text });
    }

    /// <summary>
    /// Refresh info button: re-reads the custom counts and the sigtool database info.
    /// Called from: XAML Click binding.
    /// </summary>
    private async void RefreshDbInfo_Click(object sender, RoutedEventArgs e)
    {
        RebuildSignatureTable();
        await RefreshDatabaseInfoAsync();
    }

    /// <summary>
    /// Manage lists button: opens the multi-file blacklist/whitelist window
    /// NON-MODAL (v1.0.3.2) so the rest of the app stays usable; when it closes,
    /// refreshes the counts and, if anything changed, prints the reload hint (no
    /// automatic daemon reload anymore, per user request). A second click focuses
    /// the already open window. Called from: XAML Click binding.
    /// </summary>
    private void ManageSignatureLists_Click(object sender, RoutedEventArgs e)
    {
        if (_signaturesWindow != null)
        {
            _signaturesWindow.Activate();
            return;
        }
        _signaturesWindow = new SignaturesWindow(this);
        _signaturesWindow.Closed += (_, _) =>
        {
            bool changed = _signaturesWindow?.Changed == true;
            _signaturesWindow = null;
            RebuildSignatureTable();
            if (changed)
                SetSignaturesStatus(DaemonReloadNote);
        };
        ToolWindows.Show(_signaturesWindow, this);
    }

    /// <summary>The open manage-lists window, or null (singleton guard). Used by: ManageSignatureLists_Click.</summary>
    private SignaturesWindow? _signaturesWindow;

    /// <summary>
    /// Opens the signature-search window (search or list the signatures inside the
    /// databases). Read-only, so nothing needs refreshing afterwards. Called from: XAML
    /// Click binding (Search signatures).
    /// </summary>
    private void SearchSignatures_Click(object sender, RoutedEventArgs e)
        => ToolWindows.Show(new SignatureSearchWindow(), this);

    /// <summary>
    /// Opens the ClamAV database folder in Explorer (creating it if missing).
    /// Called from: XAML Click binding (Open DB folder).
    /// </summary>
    private void OpenDbFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.IO.Directory.CreateDirectory(AppPaths.DatabaseDir);
            System.Diagnostics.Process.Start("explorer.exe", AppPaths.DatabaseDir);
        }
        catch (Exception ex)
        {
            SetSignaturesStatus($"Could not open the database folder: {ex.Message}");
        }
    }

    /// <summary>
    /// Lets the user pick ClamAV database file(s) and copies them into the database
    /// folder (with an overwrite prompt per file), then reloads the daemon and
    /// refreshes the table. A malformed database is surfaced by the reload failing
    /// rather than blocked up front. Called from: XAML Click binding (Add database).
    /// </summary>
    private async void AddDatabaseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select ClamAV database file(s)",
            Multiselect = true,
            Filter = "ClamAV databases|*.cvd;*.cld;*.hdb;*.hsb;*.mdb;*.msb;*.ndb;*.ldb;*.fp;*.sfp;"
                   + "*.cdb;*.crb;*.gdb;*.idb;*.ign;*.ign2;*.pdb;*.wdb;*.sdb;*.yar;*.yara|All files|*.*"
        };
        if (dialog.ShowDialog(this) != true) return;

        System.IO.Directory.CreateDirectory(AppPaths.DatabaseDir);

        var copiedNames = new List<string>();
        var errors = new List<string>();
        foreach (var src in dialog.FileNames)
        {
            try
            {
                string name = System.IO.Path.GetFileName(src);
                string dest = System.IO.Path.Combine(AppPaths.DatabaseDir, name);
                if (System.IO.File.Exists(dest) &&
                    !Confirm("Overwrite",
                        $"{name} already exists in the database folder. Overwrite it?",
                        "Overwrite", "Cancel"))
                    continue;

                System.IO.File.Copy(src, dest, overwrite: true);
                copiedNames.Add(name);
            }
            catch (Exception ex)
            {
                errors.Add($"{System.IO.Path.GetFileName(src)}: {ex.Message}");
            }
        }

        // A copied file may be an official DB, so reload the official rows too.
        _sigInfoLoaded = false;
        await RefreshDatabaseInfoAsync();

        string msg = copiedNames.Count > 0
            ? $"Copied {copiedNames.Count} database file(s) into the folder."
            : "No files were copied.";
        if (errors.Count > 0) msg += $" {errors.Count} failed: {string.Join("; ", errors)}";
        SetSignaturesStatus(msg);

        if (copiedNames.Count > 0)
        {
            AddHistory("Databases", "", "", "database added",
                "Added database file(s) to the folder:" + Environment.NewLine
                + string.Join(Environment.NewLine, copiedNames));
            await ReloadDaemonAsync();
        }
    }

    /// <summary>
    /// Opens the custom-database-URL manager (freshclam DatabaseCustomURL entries).
    /// After it closes, refreshes the table (fetched third-party databases are not
    /// table rows but the official rows are re-read for safety). Called from: XAML
    /// Click binding (Add from URL).
    /// </summary>
    private void AddDatabaseUrl_Click(object sender, RoutedEventArgs e)
    {
        if (_databaseUrlWindow != null)
        {
            _databaseUrlWindow.Activate();
            return;
        }
        // NON-MODAL (v1.0.3.2): the refresh moved into the Closed handler so the rest
        // of the app stays usable while the window is open.
        var window = new CustomDatabaseUrlWindow();
        _databaseUrlWindow = window;
        window.Closed += async (_, _) =>
        {
            _databaseUrlWindow = null;
            // The window may have logged database History entries (URL add/remove, update).
            BindHistory();
            if (window.Changed)
            {
                _sigInfoLoaded = false;
                await RefreshDatabaseInfoAsync();
                SetSignaturesStatus("Custom database URLs updated.");
            }
        };
        ToolWindows.Show(window, this);
    }

    /// <summary>The open custom-URL manager, or null (singleton guard). Used by: AddDatabaseUrl_Click.</summary>
    private CustomDatabaseUrlWindow? _databaseUrlWindow;

    // ---- Shared signature-change flow (window, context menu, quarantine) ----

    /// <summary>
    /// Adds files to a list, enforcing that a file is never on both lists. Hashes once
    /// (AnalyzeAsync), and if any file is currently on the OTHER list asks ONCE whether
    /// to move them (removing them from the other list) or leave them; a file already
    /// on the target list is a silent no-op. Writes one History entry when anything was
    /// written and refreshes the counts. Does NOT reload the daemon (callers decide
    /// when, so the window can batch). Returns the commit result for the caller to
    /// report. Called from: SignaturesWindow, StartContextMenuSignature and the
    /// quarantine restore+whitelist.
    /// </summary>
    internal async Task<CustomSignatureManager.CommitResult> ApplySignatureAddAsync(
        CustomSignatureManager.ListKind kind, IReadOnlyList<string> paths, Window dialogOwner)
    {
        var empty = new CustomSignatureManager.CommitResult(
            Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(),
            Array.Empty<string>(), Array.Empty<(string, string)>());
        if (paths.Count == 0) return empty;

        var plan = await CustomSignatureManager.AnalyzeAsync(kind, paths);

        // Ask once whether to move files that are currently on the other list.
        int conflicts = plan.Files.Count(f => f.Status == CustomSignatureManager.AddStatus.ConflictOtherList);
        bool moveConflicts = false;
        if (conflicts > 0)
        {
            string other = kind == CustomSignatureManager.ListKind.Blacklist ? "whitelist" : "blacklist";
            string target = kind == CustomSignatureManager.ListKind.Blacklist ? "blacklist" : "whitelist";
            string msg = conflicts == 1
                ? $"1 file is already on the {other}. Move it to the {target}? "
                    + $"It will be removed from the {other}."
                : $"{conflicts} files are already on the {other}. Move them to the {target}? "
                    + $"They will be removed from the {other}.";
            moveConflicts = new MessageDialog("Move between lists", msg, "Move", "Keep On " + other)
                { Owner = dialogOwner }.ShowDialog() == true;
        }

        var result = CustomSignatureManager.Commit(plan, moveConflicts);
        RebuildSignatureTable();

        if (result.Added.Count > 0 || result.Moved.Count > 0)
            WriteSignatureAddHistory(kind, plan, moveConflicts);

        return result;
    }

    /// <summary>
    /// Removes entries from a list, writes a History entry and refreshes the counts.
    /// Returns whether anything was removed (the caller reloads the daemon). Called
    /// from: SignaturesWindow remove buttons.
    /// </summary>
    internal bool ApplySignatureRemove(CustomSignatureManager.ListKind kind,
        IReadOnlyList<CustomSignatureManager.SignatureEntry> entries)
    {
        if (entries.Count == 0) return false;
        int n = CustomSignatureManager.Remove(kind, entries);
        if (n == 0) return false;

        RebuildSignatureTable();

        string listName = kind == CustomSignatureManager.ListKind.Blacklist ? "blacklist" : "whitelist";
        var sb = new StringBuilder();
        sb.AppendLine($"Removed from {listName} ({n}):");
        foreach (var e in entries) sb.AppendLine($"  {e.Name}");
        WriteSignatureHistory(kind, sb.ToString());
        return true;
    }

    /// <summary>
    /// Builds the History summary for an add/move and writes the entry. Lists the
    /// actual file paths that were added and, when a move happened, those moved in from
    /// the other list, plus any failures. Called from: ApplySignatureAddAsync.
    /// </summary>
    private void WriteSignatureAddHistory(CustomSignatureManager.ListKind kind,
        CustomSignatureManager.AddPlan plan, bool moved)
    {
        string listName = kind == CustomSignatureManager.ListKind.Blacklist ? "blacklist" : "whitelist";
        string otherName = kind == CustomSignatureManager.ListKind.Blacklist ? "whitelist" : "blacklist";
        var sb = new StringBuilder();

        var added = plan.Files.Where(f => f.Status == CustomSignatureManager.AddStatus.New).ToList();
        if (added.Count > 0)
        {
            sb.AppendLine($"Added to {listName} ({added.Count}):");
            foreach (var f in added) sb.AppendLine($"  {f.Path}");
        }

        if (moved)
        {
            var movedFiles = plan.Files
                .Where(f => f.Status == CustomSignatureManager.AddStatus.ConflictOtherList).ToList();
            if (movedFiles.Count > 0)
            {
                sb.AppendLine($"Moved from {otherName} to {listName} ({movedFiles.Count}):");
                foreach (var f in movedFiles) sb.AppendLine($"  {f.Path}");
            }
        }

        var failed = plan.Files.Where(f => f.Status == CustomSignatureManager.AddStatus.Failed).ToList();
        if (failed.Count > 0)
        {
            sb.AppendLine($"Failed ({failed.Count}):");
            foreach (var f in failed) sb.AppendLine($"  {f.Path} - {f.Error}");
        }

        WriteSignatureHistory(kind, sb.ToString());
    }

    /// <summary>
    /// Writes a single History entry for a signature change: Kind "Signatures", Process
    /// "sigtool.exe", empty Target, ResultLabel "blacklist modified"/"whitelist
    /// modified" and the given per-file summary. Called from: WriteSignatureAddHistory
    /// and ApplySignatureRemove.
    /// </summary>
    private void WriteSignatureHistory(CustomSignatureManager.ListKind kind, string summary)
    {
        string label = kind == CustomSignatureManager.ListKind.Blacklist
            ? "blacklist modified" : "whitelist modified";
        AddHistory("Signatures", "", "sigtool.exe", label, summary);
    }

    /// <summary>
    /// Reliably reloads the running daemon after a database change (via
    /// DaemonController.RestartAsync, because clamd's async RELOAD can leave stale
    /// detections). Feedback goes to the Settings status line, NOT the output console.
    /// A no-op with a status note when the daemon is not running. Called from: the
    /// daemon-settings Reload button, the context-menu signature actions, the quarantine
    /// restore+whitelist and after the manage-lists window closes.
    /// </summary>
    internal async Task ReloadDaemonAsync()
        => await RunGuarded(async () =>
        {
            if (!await DaemonController.IsRunningAsync())
            {
                SetSettingsStatus("Daemon not running; changes apply to standalone scans now and to the daemon on its next start.", "OkBrush");
                return;
            }

            SetSettingsStatus("Reloading the daemon (restart) to apply signature changes...", "WarnBrush");
            bool ok = await DaemonController.RestartAsync();
            SetSettingsStatus(
                ok ? "Daemon reloaded; custom signatures are active."
                   : "Daemon reload failed; check the daemon status.",
                ok ? "OkBrush" : "DangerBrush");
        });

    /// <summary>
    /// Context menu "Blacklist file" / "Whitelist file": switches to the Signatures
    /// tab, adds the single file through the shared flow (which enforces mutual
    /// exclusion and writes History) and reloads the daemon when something changed.
    /// A file already on the target list is silent per spec. Called from:
    /// DispatchContextAction ("blacklist"/"whitelist").
    /// </summary>
    private async Task StartContextMenuSignature(string path, CustomSignatureManager.ListKind kind)
    {
        MainTabs.SelectedIndex = 3; // Signatures tab
        string kindName = kind == CustomSignatureManager.ListKind.Blacklist ? "Blacklist" : "Whitelist";

        if (!System.IO.File.Exists(path))
        {
            Inform($"{kindName} file", $"This action only works on a single file.\n\nNot a file:\n{path}");
            return;
        }

        var result = await ApplySignatureAddAsync(kind, new[] { path }, this);
        string fileName = System.IO.Path.GetFileName(path);
        string listName = kindName.ToLowerInvariant();

        if (result.Added.Count > 0 || result.Moved.Count > 0)
        {
            string what = result.Moved.Count > 0 ? "moved to" : "added to";
            Inform($"{kindName} file", $"{fileName} {what} the {listName}.\n\n{DaemonReloadNote}");
        }
        else if (result.SkippedConflict.Count > 0)
        {
            Inform($"{kindName} file",
                $"{fileName} was kept on the other list; nothing was added to the {listName}.");
        }
        else if (result.SkippedSameList.Count > 0)
        {
            // Already on the target list: silent per spec (no dialog).
        }
        else
        {
            string reason = result.Failed.Count > 0 ? result.Failed[0].Error : "unknown error";
            Inform($"{kindName} file", $"Could not add {fileName}: {reason}.");
        }
    }
}
