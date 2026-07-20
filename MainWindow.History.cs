using System.Windows;
using System.Windows.Controls;
using ClamHub.Core;
using ClamHub.Models;

namespace ClamHub;

/// <summary>
/// History tab logic: shows past scans in a table and the infected files of the
/// selected entry. Partial class companion to MainWindow.xaml.cs, initialized
/// from InitializeAsync.
/// </summary>
public partial class MainWindow
{
    /// <summary>
    /// Loads history.json and binds it to the list.
    /// Called from: MainWindow.InitializeAsync.
    /// </summary>
    private void InitializeHistory()
    {
        HistoryManager.Load();
        BindHistory();
        SetHistoryDetail("Select an entry to see its details.");
        // Recompute the fill on resize and when the tab becomes visible (its
        // width and viewport are 0 until first shown). Deferred to Loaded
        // priority so the ScrollViewer viewport is already measured.
        HistoryList.SizeChanged += (_, _) => ScheduleFill(HistoryList, HistoryGridView);
        HistoryList.IsVisibleChanged += (_, _) => ScheduleFill(HistoryList, HistoryGridView);
    }

    /// <summary>
    /// Queues a FillLastColumn pass at Loaded priority so layout and the
    /// ScrollViewer viewport are settled first. Called from: table SizeChanged,
    /// IsVisibleChanged and bind methods.
    /// </summary>
    private void ScheduleFill(System.Windows.Controls.ListView list,
        System.Windows.Controls.GridView grid)
        => Dispatcher.BeginInvoke(new Action(() => FillLastColumn(list, grid)),
            System.Windows.Threading.DispatcherPriority.Loaded);

    /// <summary>
    /// Resizes the final GridView column so the columns exactly fill the visible
    /// content width, removing the empty area WPF otherwise shows to the right of
    /// the last column. Uses the inner ScrollViewer's ViewportWidth (the exact
    /// width minus the actual scrollbar, which is narrower than the system
    /// metric), and the declared widths of the other columns. Shared by the
    /// History and Quarantine tables.
    /// Called from: SizeChanged/IsVisibleChanged handlers and after binding.
    /// </summary>
    private static void FillLastColumn(System.Windows.Controls.ListView list,
        System.Windows.Controls.GridView grid)
    {
        if (grid.Columns.Count == 0) return;

        double available = FindViewportWidth(list);
        if (available <= 0) available = list.ActualWidth - 12; // fallback: list minus thin scrollbar
        if (available <= 0) return;

        double used = 0;
        for (int i = 0; i < grid.Columns.Count - 1; i++)
        {
            var col = grid.Columns[i];
            used += double.IsNaN(col.Width) ? col.ActualWidth : col.Width;
        }

        double remaining = available - used;
        if (remaining > 60)
            grid.Columns[^1].Width = remaining;
    }

    /// <summary>
    /// Returns the horizontal viewport width of the ScrollViewer inside a control,
    /// i.e. the content area excluding the actual scrollbar. 0 if not measured yet.
    /// Called from: FillLastColumn.
    /// </summary>
    private static double FindViewportWidth(System.Windows.DependencyObject root)
    {
        int count = System.Windows.Media.VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(root, i);
            if (child is System.Windows.Controls.ScrollViewer sv && sv.ViewportWidth > 0)
                return sv.ViewportWidth;
            double nested = FindViewportWidth(child);
            if (nested > 0) return nested;
        }
        return 0;
    }

    /// <summary>
    /// Rebinds the list to the current in-memory history.
    /// Called from: InitializeHistory, RecordScan, Refresh and Clear handlers.
    /// </summary>
    private void BindHistory()
    {
        HistoryList.ItemsSource = HistoryManager.Entries;
        // The list raises no change notifications, so force the (sorted) default
        // view to re-read it; this makes the table reflect every add/delete
        // immediately, including the first one.
        System.Windows.Data.CollectionViewSource.GetDefaultView(HistoryManager.Entries)?.Refresh();
        ScheduleFill(HistoryList, HistoryGridView);
    }

    /// <summary>
    /// Adds one history entry (any kind) and refreshes the list. Called from:
    /// RecordScan and the VirusTotal/Quarantine/Hash recorders.
    /// </summary>
    private void AddHistory(string kind, string target, string process, string resultLabel, string summary)
    {
        HistoryManager.Add(new ScanHistoryEntry
        {
            Timestamp = DateTime.Now,
            Kind = kind,
            Target = target,
            Process = process,
            ResultLabel = resultLabel,
            Summary = summary.TrimEnd()
        });
        BindHistory();
    }

    /// <summary>Past-tense word for what happened to infected files. Called from: RecordScan, RunQueueScan.</summary>
    private static string ActionWord(InfectedFileAction action) => action switch
    {
        InfectedFileAction.Remove => "removed",
        InfectedFileAction.Quarantine => "quarantined",
        _ => "reported"
    };

    /// <summary>
    /// Lists the files a path scan actually covered when an extension filter is in
    /// effect: the target itself if it is a file, otherwise every file under the
    /// folder (recursive) whose extension is in the filter. Best-effort, skips
    /// inaccessible folders. Called from: RecordScan (only-extensions summary).
    /// </summary>
    private static List<string> MatchedFiles(string target, IReadOnlyList<string> exts)
    {
        var result = new List<string>();
        try
        {
            if (System.IO.File.Exists(target)) { result.Add(target); return result; }
            if (!System.IO.Directory.Exists(target)) return result;

            var set = exts.Select(e => "." + e.TrimStart('.').ToLowerInvariant()).ToHashSet();
            var opts = new System.IO.EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true
            };
            foreach (var f in System.IO.Directory.EnumerateFiles(target, "*", opts))
                if (set.Contains(System.IO.Path.GetExtension(f).ToLowerInvariant()))
                    result.Add(f);
        }
        catch
        {
            // Best-effort listing only; a partial or empty list is acceptable.
        }
        return result;
    }

    /// <summary>Human label for an infected-file action. Called from: BuildScanSettingsHeader.</summary>
    private static string ActionLabel(InfectedFileAction action) => action switch
    {
        InfectedFileAction.ReportOnly => "Report only",
        InfectedFileAction.Quarantine => "Quarantine",
        InfectedFileAction.Remove => "Remove",
        _ => action.ToString()
    };

    /// <summary>
    /// Builds the settings block placed at the top of a scan summary: the active
    /// profile (if one is selected), the action, the extension filter and the
    /// exclusions in effect. Called from: RecordScan.
    /// </summary>
    private string BuildScanSettingsHeader(ScanEngine.ScanOptions options)
    {
        var sb = new System.Text.StringBuilder();
        if (ActiveProfileName is { } profile)
            sb.AppendLine($"Profile: {profile}");
        sb.AppendLine($"Action: {ActionLabel(options.Action)}");
        sb.AppendLine($"Only extensions: {(options.IncludeExtensions is { Count: > 0 } inc ? string.Join(" ", inc) : "(all files)")}");

        var ex = new List<string>();
        if (options.ExcludeDirectories is { Count: > 0 } ed) ex.Add("dirs: " + string.Join(", ", ed));
        if (options.ExcludeExtensions is { Count: > 0 } ee) ex.Add("extensions: " + string.Join(" ", ee));
        if (options.ExcludeFiles is { Count: > 0 } ef)
            ex.Add("files: " + string.Join(", ", ef.Select(f => System.IO.Path.GetFileName(f))));
        sb.AppendLine($"Exclusions: {(ex.Count > 0 ? string.Join("; ", ex) : "(none)")}");
        return sb.ToString();
    }

    /// <summary>
    /// Persists one finished single scan (with its full summary) and refreshes the
    /// list. Queue runs are recorded separately as one combined entry.
    /// Called from: ScanOneAsync (when record is true).
    /// </summary>
    private async Task RecordScan(ScanEngine.ScanOptions options, ScanEngine.ScanResult result,
                            TimeSpan duration, DateTime startedAt)
    {
        bool memory = options.Mode == ScanEngine.ScanMode.Memory;
        string target = memory ? "Process memory" : options.TargetPath ?? "";
        string process = result.UsedDaemon
            ? System.IO.Path.GetFileName(AppPaths.ClamdScanExe)
            : System.IO.Path.GetFileName(AppPaths.ClamScanExe);

        // Kind reflects what was scanned: a profile run, a folder, or a single file.
        string kind = memory ? "Memory scan"
            : ActiveProfileName is { } pn ? $"{pn} scan"
            : System.IO.Directory.Exists(target) ? "Folder scan"
            : "File scan";

        // Result always states the infection outcome (never a bare "Error"): a scan
        // that finished with per-file errors still tells whether infections were
        // found; the unscannable files are listed in the summary below.
        string resultLabel = result.InfectedLines.Count > 0
            ? $"{result.InfectedLines.Count} infected ({ActionWord(options.Action)})"
            : "Clean";
        if (result.ExitCode >= 2)
            resultLabel += result.ErrorLines.Count > 0
                ? $", {result.ErrorLines.Count} not scanned"
                : ", with errors";

        var sb = new System.Text.StringBuilder();
        sb.Append(BuildScanSettingsHeader(options));
        sb.AppendLine();
        sb.AppendLine($"Target: {target}");
        sb.AppendLine($"Scanner: {(result.UsedDaemon ? "clamdscan (daemon)" : "clamscan")}");
        sb.AppendLine($"Started: {startedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Finished: {startedAt + duration:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Duration: {duration:hh\\:mm\\:ss\\.f}");
        sb.AppendLine($"Result: {result.ExitCode switch
        {
            0 => "CLEAN",
            1 => "INFECTIONS FOUND",
            _ => $"COMPLETED WITH ERRORS (exit code {result.ExitCode}, see log)"
        }}");
        if (result.InfectedLines.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"Infected files ({result.InfectedLines.Count}):");
            foreach (var line in result.InfectedLines) sb.AppendLine(line);
        }

        // Files ClamAV could not scan (locked, access denied, ...). This is what
        // "COMPLETED WITH ERRORS" refers to; the raw ERROR lines carry the reason.
        if (result.ErrorLines.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"Files not scanned ({result.ErrorLines.Count}):");
            const int errCap = 500;
            foreach (var line in result.ErrorLines.Take(errCap)) sb.AppendLine(line);
            if (result.ErrorLines.Count > errCap)
                sb.AppendLine($"...and {result.ErrorLines.Count - errCap} more");
        }

        // For an only-extensions scan, list the files that were actually covered.
        if (!memory && options.IncludeExtensions is { Count: > 0 } incExt)
        {
            // Enumerating a large folder again can take a moment, so keep it off the
            // UI thread to avoid freezing the window while the history entry is built.
            var scanned = await Task.Run(() => MatchedFiles(target, incExt));
            sb.AppendLine();
            sb.AppendLine($"Scanned objects ({scanned.Count}):");
            const int cap = 1000;
            foreach (var f in scanned.Take(cap)) sb.AppendLine(f);
            if (scanned.Count > cap) sb.AppendLine($"...and {scanned.Count - cap} more");
        }

        AddHistory(kind, target, process, resultLabel, sb.ToString());
    }

    /// <summary>Short per-target status used in the queue summary and console. Called from: RunQueueScan, RecordQueueScan.</summary>
    private static string QueueStatus(ScanEngine.ScanResult r) =>
        !r.Started ? (r.Error ?? "not started")
        : r.Error == "Cancelled" ? "CANCELLED"
        : r.ExitCode switch
        {
            0 => "CLEAN",
            1 => $"{r.InfectedLines.Count} infected",
            _ => r.InfectedLines.Count > 0
                ? $"{r.InfectedLines.Count} infected, {r.ErrorLines.Count} not scanned"
                : $"clean, {r.ErrorLines.Count} not scanned"
        };

    /// <summary>
    /// Records the whole queue run as a single history entry: the shared settings,
    /// start/end, every target with its result, and the aggregate. Called from:
    /// MainWindow.RunQueueScan after the batch finishes.
    /// </summary>
    private async Task RecordQueueScan(
        List<(string Target, ScanEngine.ScanResult Result)> results,
        InfectedFileAction action, IReadOnlyList<string> extensions,
        DateTime startedAt, TimeSpan duration, bool cancelled)
    {
        int totalInfected = results.Where(r => r.Result.ExitCode == 1).Sum(r => r.Result.InfectedLines.Count);
        bool anyError = results.Any(r => !r.Result.Started || r.Result.ExitCode >= 2);

        string resultLabel =
            totalInfected > 0 ? $"{totalInfected} infected ({ActionWord(action)})"
            : cancelled ? "Cancelled"
            : anyError ? "Clean, with errors"
            : "Clean";

        // Representative options just for the settings header (target path unused there).
        var headerOptions = new ScanEngine.ScanOptions(
            ScanEngine.ScanMode.Path, null, action,
            SettingsManager.Current.MultiScan, extensions, false,
            _sessionExcludeDirs, _sessionExcludeExts, _sessionExcludeFiles);

        bool usedDaemon = results.Any(r => r.Result.UsedDaemon);
        string process = usedDaemon
            ? System.IO.Path.GetFileName(AppPaths.ClamdScanExe)
            : System.IO.Path.GetFileName(AppPaths.ClamScanExe);

        var sb = new System.Text.StringBuilder();
        sb.Append(BuildScanSettingsHeader(headerOptions));
        sb.AppendLine();
        sb.AppendLine($"Started: {startedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Finished: {startedAt + duration:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Duration: {duration:hh\\:mm\\:ss\\.f}");
        if (cancelled) sb.AppendLine("Note: the run was cancelled before all targets were scanned.");
        sb.AppendLine();
        sb.AppendLine($"Targets ({results.Count}):");
        foreach (var (t, r) in results)
            sb.AppendLine($"  {QueueStatus(r),-24}  {t}");

        if (totalInfected > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"Infected files ({totalInfected}):");
            foreach (var (_, res) in results)
                foreach (var line in res.InfectedLines)
                    sb.AppendLine(line);
        }

        // Files ClamAV could not scan across all targets (locked, access denied, ...).
        int totalErrors = results.Sum(r => r.Result.ErrorLines.Count);
        if (totalErrors > 0)
        {
            const int errCap = 500;
            int written = 0;
            sb.AppendLine();
            sb.AppendLine($"Files not scanned ({totalErrors}):");
            foreach (var (_, res) in results)
                foreach (var line in res.ErrorLines)
                {
                    if (written++ >= errCap) break;
                    sb.AppendLine(line);
                }
            if (totalErrors > errCap) sb.AppendLine($"...and {totalErrors - errCap} more");
        }

        // For an only-extensions queue scan, list the covered files per target.
        if (extensions is { Count: > 0 })
        {
            const int perTargetCap = 500;
            sb.AppendLine();
            sb.AppendLine("Scanned objects (only-extensions scan):");
            foreach (var (t, _) in results)
            {
                var matched = await Task.Run(() => MatchedFiles(t, extensions));
                sb.AppendLine($"  {t} ({matched.Count}):");
                foreach (var f in matched.Take(perTargetCap)) sb.AppendLine($"    {f}");
                if (matched.Count > perTargetCap) sb.AppendLine($"    ...and {matched.Count - perTargetCap} more");
            }
        }

        AddHistory("Queue scan", $"{results.Count} target(s)", process, resultLabel, sb.ToString());
    }

    /// <summary>Renders one plain text block into the detail pane. Called from: the history handlers.</summary>
    private void SetHistoryDetail(string text)
        => ConsoleFormatting.SetLines(HistoryDetailBox, new[] { text });

    /// <summary>
    /// Shows the stored summary of the selected history entry (URLs clickable).
    /// Called from: XAML SelectionChanged binding of HistoryList.
    /// </summary>
    private void HistoryList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (HistoryList.SelectedItem is not ScanHistoryEntry entry)
            return;

        if (string.IsNullOrEmpty(entry.Summary))
        {
            SetHistoryDetail("(no details stored for this entry)");
            return;
        }
        ConsoleFormatting.SetLines(HistoryDetailBox,
            entry.Summary.Replace("\r\n", "\n").Split('\n'));
    }

    /// <summary>
    /// History "Export" button: writes the selected entry to a UTF-8 .txt file
    /// named "{Kind}_{Time}.txt". When "Always export to this path" is on the
    /// file is written to the configured folder without prompting; otherwise a
    /// save dialog opens in that folder and the user may choose any location.
    /// The result path is reported in the detail console. Called from: XAML.
    /// </summary>
    private void ExportHistoryEntry_Click(object sender, RoutedEventArgs e)
    {
        if (HistoryList.SelectedItem is not ScanHistoryEntry entry)
        {
            SetHistoryDetail("Select a history entry to export.");
            return;
        }

        string fileName = BuildExportFileName(entry);
        string folder = ResolveHistoryExportFolder();
        string content = BuildExportContent(entry);

        string targetPath;
        if (SettingsManager.Current.HistoryAlwaysExportToPath)
        {
            // No prompt: straight to the configured folder.
            targetPath = System.IO.Path.Combine(folder, fileName);
        }
        else
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export history entry",
                FileName = fileName,
                DefaultExt = ".txt",
                Filter = "Text file (*.txt)|*.txt",
                AddExtension = true,
                OverwritePrompt = true
            };
            if (System.IO.Directory.Exists(folder)) dialog.InitialDirectory = folder;
            if (dialog.ShowDialog() != true) return; // user cancelled
            targetPath = dialog.FileName;
        }

        try
        {
            var dir = System.IO.Path.GetDirectoryName(targetPath);
            if (!string.IsNullOrEmpty(dir)) System.IO.Directory.CreateDirectory(dir);
            System.IO.File.WriteAllText(targetPath, content, new System.Text.UTF8Encoding(false));
            SetHistoryDetail($"Entry successfully saved to {targetPath}");
        }
        catch (Exception ex)
        {
            SetHistoryDetail($"Export failed: {ex.Message}");
        }
    }

    /// <summary>Builds the export file name. For entries whose target is a file
    /// the file name is prepended: "{Filename}_{Kind}_{Time}.txt"; otherwise
    /// "{Kind}_{Time}.txt". Time uses the entry timestamp (yyyy-MM-dd_HH-mm-ss);
    /// characters illegal in file names and spaces become '_'.
    /// Called from: ExportHistoryEntry_Click.</summary>
    private static string BuildExportFileName(ScanHistoryEntry entry)
    {
        string kind = string.IsNullOrWhiteSpace(entry.Kind) ? "Entry" : entry.Kind;
        string time = entry.Timestamp.ToString("yyyy-MM-dd_HH-mm-ss");

        // Prepend the file name when the target is a file (exists as one, or has a
        // file extension so folder targets like C:\Downloads stay unprefixed).
        string prefix = "";
        string target = entry.Target ?? "";
        if (target.Length > 0)
        {
            try
            {
                bool looksLikeFile = System.IO.File.Exists(target)
                    || System.IO.Path.GetExtension(target).Length > 0;
                string name = System.IO.Path.GetFileName(target.TrimEnd('\\', '/'));
                if (looksLikeFile && name.Length > 0) prefix = name + "_";
            }
            catch { /* invalid path chars in target: skip the prefix */ }
        }

        string raw = $"{prefix}{kind}_{time}.txt";
        foreach (char c in System.IO.Path.GetInvalidFileNameChars())
            raw = raw.Replace(c, '_');
        raw = raw.Replace(' ', '_');
        return raw;
    }

    /// <summary>The full text written to the export file: a small header plus the
    /// stored summary. Called from: ExportHistoryEntry_Click.</summary>
    private static string BuildExportContent(ScanHistoryEntry entry)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Time    : {entry.Timestamp:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Kind    : {entry.Kind}");
        sb.AppendLine($"Target  : {entry.Target}");
        if (!string.IsNullOrWhiteSpace(entry.Process)) sb.AppendLine($"Process : {entry.Process}");
        if (!string.IsNullOrWhiteSpace(entry.ResultLabel)) sb.AppendLine($"Result  : {entry.ResultLabel}");
        sb.AppendLine(new string('=', 60));
        sb.AppendLine();
        sb.Append(string.IsNullOrEmpty(entry.Summary)
            ? "(no details stored for this entry)"
            : entry.Summary.Replace("\r\n", "\n").Replace("\n", Environment.NewLine));
        return sb.ToString();
    }

    /// <summary>Returns the configured export folder, falling back to the Logs
    /// folder when unset or missing. Called from: ExportHistoryEntry_Click.</summary>
    private static string ResolveHistoryExportFolder()
    {
        string configured = SettingsManager.Current.HistoryExportPath;
        if (!string.IsNullOrWhiteSpace(configured) && System.IO.Directory.Exists(configured))
            return configured;
        try { AppPaths.EnsureDirectories(); } catch { }
        return AppPaths.ExportsDir;
    }

    /// <summary>Shows the resolved export folder in Settings. Called from:
    /// InitializeSettingsTab and ChangeHistoryExportFolder_Click.</summary>
    private void UpdateHistoryExportPathDisplay()
    {
        if (HistoryExportPathText != null)
            HistoryExportPathText.Text = ResolveHistoryExportFolder();
    }

    /// <summary>Settings "Change export folder" button: folder picker, saves the
    /// choice to settings.json. Called from: Settings XAML Click binding.</summary>
    private void ChangeHistoryExportFolder_Click(object sender, RoutedEventArgs e)
    {
        var picker = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Select the default folder for History exports"
        };
        string current = ResolveHistoryExportFolder();
        if (System.IO.Directory.Exists(current)) picker.InitialDirectory = current;
        if (picker.ShowDialog() != true) return;

        SettingsManager.Current.HistoryExportPath = picker.FolderName;
        SettingsManager.Save();
        UpdateHistoryExportPathDisplay();
    }

    /// <summary>"Open Exports": opens the export folder in Explorer, creating
    /// it if needed. Called from: History XAML Click binding.</summary>
    private void OpenExportsFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string folder = ResolveHistoryExportFolder();
            System.IO.Directory.CreateDirectory(folder);
            System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo { FileName = folder, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            SetHistoryDetail($"Could not open the export folder: {ex.Message}");
        }
    }

    /// <summary>Reloads the history from disk. Called from: XAML Click binding.</summary>
    private void RefreshHistory_Click(object sender, RoutedEventArgs e)
    {
        HistoryManager.Load();
        BindHistory();
        SetHistoryDetail("Select an entry to see its details.");
    }

    /// <summary>
    /// Opens history.json in the default editor. Called from: XAML Click binding.
    /// </summary>
    private void OpenHistoryFile_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!System.IO.File.Exists(AppPaths.HistoryFile))
            {
                SetHistoryDetail("No history file yet, run a scan first.");
                return;
            }
            System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo { FileName = AppPaths.HistoryFile, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            SetHistoryDetail($"Could not open history file: {ex.Message}");
        }
    }

    /// <summary>Clears the history after confirmation. Called from: XAML Click binding.</summary>
    private void ClearHistory_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm("Clear history", "Delete the entire scan history?", "Delete", "Cancel"))
            return;

        HistoryManager.Clear();
        BindHistory();
        SetHistoryDetail("History cleared.");
    }

    /// <summary>
    /// Deletes the selected history entries (multi-selection with Ctrl/Shift,
    /// v1.0.3.5). Called from: XAML Click binding (Delete entry button).
    /// </summary>
    private void DeleteHistoryEntry_Click(object sender, RoutedEventArgs e)
    {
        var entries = HistoryList.SelectedItems.Cast<ScanHistoryEntry>().ToList();
        if (entries.Count == 0)
        {
            SetHistoryDetail("Select one or more history entries to delete.");
            return;
        }

        int removed = HistoryManager.DeleteMany(entries);
        BindHistory();
        SetHistoryDetail(removed == 1 ? "Entry deleted." : $"{removed} entries deleted.");
    }

    /// <summary>
    /// Recomputes the last-column fill when the scrollbar appears or disappears
    /// (which changes the viewport width). Called from: ScrollViewer.ScrollChanged
    /// on both tables.
    /// </summary>
    private void Table_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (e.ViewportWidthChange == 0) return;
        if (sender is ListView list && list.View is GridView grid)
            ScheduleFill(list, grid);
    }

    /// <summary>Sorts the history table by the clicked column. Called from: XAML header Click.</summary>
    private void HistorySort_Click(object sender, RoutedEventArgs e)
        => ListViewSorting.SortByColumn(e.OriginalSource as GridViewColumnHeader, HistoryList);

    /// <summary>Sorts the quarantine table by the clicked column. Called from: XAML header Click.</summary>
    private void QuarantineSort_Click(object sender, RoutedEventArgs e)
        => ListViewSorting.SortByColumn(e.OriginalSource as GridViewColumnHeader, QuarantineList);

}
