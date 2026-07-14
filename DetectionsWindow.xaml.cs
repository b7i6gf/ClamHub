using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using ClamHub.Core;
using ClamHub.Models;

namespace ClamHub;

/// <summary>
/// Works through the infected files reported by report-only scans: the list from
/// DetectionManager with one row per finding (file, directory, time, signature,
/// database, VirusTotal verdict, status) plus an action panel and its own console
/// for the action output. Since v1.0.3.3 every list action supports a
/// MULTI-SELECTION (Ctrl/Shift); Compare signature and Open folder act on the
/// first selected entry. Whitelisting is delegated to
/// MainWindow.ApplySignatureAddAsync so the shared cross-list rules apply (no
/// automatic daemon reload, only the hint). Long-running actions are cancelled
/// when the window closes.
/// Opened from: the "Detections" title bar button (MainWindow.Detections_Click).
/// </summary>
public partial class DetectionsWindow : Window
{
    /// <summary>Owner window; whitelist/quarantine actions delegate into it.</summary>
    private readonly MainWindow _owner;

    /// <summary>Guards the action buttons against re-entry while one action runs.</summary>
    private bool _busy;

    /// <summary>Cancels running actions (rescan, VirusTotal, Find database) on close.</summary>
    private readonly CancellationTokenSource _cts = new();

    public DetectionsWindow(MainWindow owner)
    {
        InitializeComponent();
        _owner = owner;
        DetectionList.ItemsSource = DetectionManager.Entries;
        if (DetectionManager.Entries.Count == 0)
            StatusText.Text = "No detections recorded. Scans with the Report action add their findings here.";
    }

    /// <summary>Cancels any running action when the window closes. Called by: WPF.</summary>
    protected override void OnClosed(EventArgs e)
    {
        _cts.Cancel();
        _cts.Dispose();
        base.OnClosed(e);
    }

    /// <summary>
    /// Appends one line to the window console via the shared formatter, so any URL
    /// (the VirusTotal report link) is rendered as a clickable hyperlink.
    /// THREAD-SAFE: scan/sigtool output arrives on worker threads (ProcessRunner
    /// raises OutputDataReceived on the thread pool); marshals to the UI thread
    /// first, otherwise the RichTextBox throws and crashes the app (v1.0.3.4 fix).
    /// Called from: all action handlers and their output callbacks.
    /// </summary>
    private void Log(string line)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.InvokeAsync(() => Log(line));
            return;
        }
        ConsoleFormatting.AppendLine(ConsoleBox, line);
    }

    /// <summary>
    /// Returns a snapshot of the selected entries (possibly several since
    /// v1.0.3.3), with a status hint when nothing is selected. Called from: all
    /// action handlers.
    /// </summary>
    private List<DetectionEntry> SelectedEntries()
    {
        var list = DetectionList.SelectedItems.Cast<DetectionEntry>().ToList();
        if (list.Count == 0) StatusText.Text = "Select one or more entries first.";
        return list;
    }

    /// <summary>
    /// Disables/enables the action panel while an async action runs, so two
    /// actions cannot interleave. Called from: the async handlers.
    /// </summary>
    private void SetBusy(bool busy)
    {
        _busy = busy;
        foreach (var b in new[] { RescanButton, QuarantineButton, RemoveButton, WhitelistButton,
                     IgnoreButton, VirusTotalButton, CompareButton, FindDbButton, DeleteEntryButton,
                     DeleteManagedButton, DeleteAllButton, OpenFolderButton })
            b.IsEnabled = !busy;
    }

    /// <summary>Grammar helper for count summaries. Called from: the multi handlers.</summary>
    private static string Plural(int n, string singular, string plural)
        => n == 1 ? $"{n} {singular}" : $"{n} {plural}";

    /// <summary>
    /// Rescans the selected file(s) one by one (report-only, own ScanEngine run with
    /// the output in this console) and updates each entry: no longer reported ->
    /// status Clean; still reported -> timestamp refreshed, signature updated (a
    /// changed signature clears the traced database), status back to Pending.
    /// Refuses politely while a main-window scan runs (shared ScanEngine guard).
    /// Called from: XAML Click binding.
    /// </summary>
    private async void Rescan_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var entries = SelectedEntries();
        if (entries.Count == 0) return;

        SetBusy(true);
        try
        {
            int clean = 0, infected = 0, skipped = 0;
            try
            {
            foreach (var entry in entries)
            {
                if (_cts.IsCancellationRequested) break;
                if (!File.Exists(entry.FilePath))
                {
                    Log($"File not found, skipped: {entry.FilePath}");
                    skipped++;
                    continue;
                }

                Log($"Rescanning {entry.FilePath} ...");
                var options = new ScanEngine.ScanOptions(
                    ScanEngine.ScanMode.Path, entry.FilePath, InfectedFileAction.ReportOnly,
                    MultiScan: false, IncludeExtensions: null, StopInfectedProcesses: false);
                var result = await ScanEngine.RunScanAsync(options, Log, _cts.Token);

                if (!result.Started || result.Error == "Cancelled")
                {
                    Log(result.Error ?? "The scan could not be started.");
                    // Another scan blocks the engine for every remaining file too.
                    if (result.Error == "A scan is already running.") break;
                    if (result.Error == "Cancelled") break;
                    skipped++;
                    continue;
                }

                if (result.ExitCode == 0)
                {
                    entry.Status = DetectionStatus.Clean;
                    clean++;
                    Log($"No longer reported (clean): {entry.FileName}");
                }
                else if (result.ExitCode == 1)
                {
                    var line = result.InfectedLines.FirstOrDefault();
                    if (line != null && ScanEngine.TryParseFoundLine(line, out _, out var threat)
                        && !string.Equals(threat, entry.Signature, StringComparison.Ordinal))
                    {
                        entry.Signature = threat;
                        entry.Database = ""; // the traced database belonged to the old name
                    }
                    entry.DetectedAt = DateTime.Now;
                    entry.Status = DetectionStatus.Pending;
                    infected++;
                    Log($"Still reported: {entry.FileName} ({entry.Signature})");
                }
                else
                {
                    skipped++;
                    Log($"Rescan finished with errors (exit {result.ExitCode}): {entry.FileName}");
                }
            }

            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log($"Rescan aborted: {ex.Message}");
            }

            DetectionManager.Save();
            StatusText.Text = $"Rescan done: {Plural(clean, "entry", "entries")} clean, " +
                              $"{infected} still reported, {skipped} skipped.";
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>
    /// Moves the selected file(s) into the quarantine (neutralized copies,
    /// restorable) and marks the entries Quarantined. Called from: XAML Click binding.
    /// </summary>
    private void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var entries = SelectedEntries();
        if (entries.Count == 0) return;

        int done = 0, failed = 0;
        foreach (var entry in entries)
        {
            if (!File.Exists(entry.FilePath))
            {
                Log($"File not found, skipped: {entry.FilePath}");
                failed++;
                continue;
            }
            if (QuarantineManager.Quarantine(entry.FilePath, entry.Signature, out var error))
            {
                entry.Status = DetectionStatus.Quarantined;
                done++;
                Log($"Quarantined: {entry.FilePath}");
            }
            else
            {
                failed++;
                Log($"Quarantine failed for {entry.FilePath}: {error}");
            }
        }

        DetectionManager.Save();
        if (done > 0) _owner.RefreshQuarantineView();
        StatusText.Text = failed == 0
            ? $"{Plural(done, "file", "files")} moved to quarantine."
            : $"{done} quarantined, {failed} failed or skipped (see console).";
    }

    /// <summary>
    /// Deletes the selected file(s) from disk after one combined confirmation and
    /// marks the entries Removed. Called from: XAML Click binding.
    /// </summary>
    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var entries = SelectedEntries();
        if (entries.Count == 0) return;

        var existing = entries.Where(x => File.Exists(x.FilePath)).ToList();
        foreach (var entry in entries.Except(existing))
            Log($"File not found, skipped: {entry.FilePath}");
        if (existing.Count == 0)
        {
            StatusText.Text = "None of the selected files exist on disk.";
            return;
        }

        string preview = string.Join("\n", existing.Take(5).Select(x => x.FilePath));
        if (existing.Count > 5) preview += $"\n...and {existing.Count - 5} more";
        bool ok = new MessageDialog("Remove files",
            $"Permanently delete {Plural(existing.Count, "file", "files")} from disk?\n\n{preview}\n\n" +
            "This cannot be undone. Use Quarantine instead if you want to keep restorable copies.",
            "Delete", "Cancel") { Owner = this }.ShowDialog() == true;
        if (!ok) return;

        int done = 0, failed = 0;
        foreach (var entry in existing)
        {
            try
            {
                File.Delete(entry.FilePath);
                entry.Status = DetectionStatus.Removed;
                done++;
                Log($"Removed: {entry.FilePath}");
            }
            catch (Exception ex)
            {
                failed++;
                Log($"Remove failed for {entry.FilePath}: {ex.Message}");
            }
        }

        DetectionManager.Save();
        StatusText.Text = failed == 0
            ? $"{Plural(done, "file", "files")} deleted."
            : $"{done} deleted, {failed} failed (see console).";
    }

    /// <summary>
    /// Adds the selected file(s) to the whitelist in ONE pass through the shared
    /// flow (mutual exclusion with the blacklist, one History entry) and marks the
    /// affected entries Whitelisted. The shared flow reports per FILE NAME, so the
    /// entries are matched back by name. No automatic daemon reload, only the hint.
    /// Only for confirmed false positives. Called from: XAML Click binding.
    /// </summary>
    private async void Whitelist_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var entries = SelectedEntries();
        if (entries.Count == 0) return;

        var existing = entries.Where(x => File.Exists(x.FilePath)).ToList();
        foreach (var entry in entries.Except(existing))
            Log($"File not found, skipped: {entry.FilePath}");
        if (existing.Count == 0)
        {
            StatusText.Text = "None of the selected files exist on disk.";
            return;
        }

        bool ok = new MessageDialog("Whitelist files",
            $"Add {Plural(existing.Count, "file", "files")} to the whitelist so future scans ignore them?\n\n" +
            "Only do this if you are sure the detections are false positives.",
            "Whitelist", "Cancel") { Owner = this }.ShowDialog() == true;
        if (!ok) return;

        SetBusy(true);
        try
        {
            var result = await _owner.ApplySignatureAddAsync(
                CustomSignatureManager.ListKind.Whitelist,
                existing.Select(x => x.FilePath).ToArray(), this);

            // The commit reports file names; map them back onto the entries.
            var whitelisted = new HashSet<string>(
                result.Added.Concat(result.Moved).Concat(result.SkippedSameList),
                StringComparer.OrdinalIgnoreCase);
            int done = 0;
            foreach (var entry in existing.Where(x => whitelisted.Contains(x.FileName)))
            {
                entry.Status = DetectionStatus.Whitelisted;
                done++;
                Log($"Whitelisted: {entry.FilePath}");
            }
            foreach (var name in result.SkippedConflict)
                Log($"Kept on the blacklist, not whitelisted: {name}");
            foreach (var (path, reason) in result.Failed)
                Log($"Whitelist failed for {path}: {reason}");

            DetectionManager.Save();
            if (done > 0)
            {
                Log(MainWindow.DaemonReloadNote);
                StatusText.Text = $"{Plural(done, "file", "files")} whitelisted. " + MainWindow.DaemonReloadNote;
            }
            else
            {
                StatusText.Text = "Nothing was whitelisted, see console.";
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"Whitelisting aborted: {ex.Message}");
            StatusText.Text = "Whitelisting aborted, see console.";
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>Marks the selected entries Ignored (files untouched). Called from: XAML Click binding.</summary>
    private void Ignore_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var entries = SelectedEntries();
        if (entries.Count == 0) return;

        foreach (var entry in entries)
        {
            entry.Status = DetectionStatus.Ignored;
            Log($"Ignored: {entry.FilePath}");
        }
        DetectionManager.Save();
        StatusText.Text = $"{Plural(entries.Count, "entry", "entries")} marked as ignored.";
    }

    /// <summary>
    /// Looks up the SHA256 of the selected file(s) on VirusTotal one after another
    /// (hash only, nothing is uploaded; the client itself enforces the free-tier
    /// rate limit of 4 lookups/minute, so many entries take a while) and writes the
    /// short verdicts into the rows; details go to the console.
    /// Called from: XAML Click binding.
    /// </summary>
    private async void VirusTotal_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var entries = SelectedEntries();
        if (entries.Count == 0) return;

        SettingsManager.Load();
        var apiKey = SettingsManager.Current.VirusTotalApiKey;
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            Log("No VirusTotal API key configured. Add your personal key in Settings.");
            StatusText.Text = "No VirusTotal API key configured.";
            return;
        }
        if (entries.Count > 4)
            Log($"{entries.Count} lookups queued; the free VirusTotal tier allows 4 per minute, so this takes a while.");

        SetBusy(true);
        try
        {
            int done = 0, failed = 0;
            foreach (var entry in entries)
            {
                if (_cts.IsCancellationRequested) break;
                if (!File.Exists(entry.FilePath))
                {
                    Log($"File not found, skipped: {entry.FilePath}");
                    failed++;
                    continue;
                }

                Log($"VirusTotal lookup for {entry.FileName} ...");
                var sha256 = await HashTool.ComputeAsync(entry.FilePath, "SHA256");
                if (sha256 == null)
                {
                    Log("SHA256 computation failed (file locked or unreadable).");
                    failed++;
                    continue;
                }

                string link = $"https://www.virustotal.com/gui/file/{sha256.ToLowerInvariant()}";
                VirusTotalClient.VtResult result;
                try
                {
                    result = await VirusTotalClient.LookupAsync(sha256, apiKey, Log, _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (!result.Success)
                {
                    Log(result.Error ?? "Lookup failed.");
                    entry.VirusTotal = "lookup failed";
                    entry.VirusTotalUrl = "";
                    failed++;
                }
                else if (result.NotFound)
                {
                    Log($"{entry.FileName}: hash unknown to VirusTotal (unknown does not mean safe).");
                    entry.VirusTotal = "unknown to VT";
                    entry.VirusTotalUrl = link;
                    done++;
                }
                else
                {
                    int total = result.Malicious + result.Suspicious + result.Harmless + result.Undetected;
                    entry.VirusTotal = $"{result.Malicious}/{total} malicious";
                    entry.VirusTotalUrl = link;
                    Log($"{entry.FileName}: {result.Malicious}/{total} engines flag this file as malicious" +
                        (result.Suspicious > 0 ? $", {result.Suspicious} as suspicious." : "."));
                    Log($"Details: {link}");
                    done++;
                }
            }

            DetectionManager.Save();
            StatusText.Text = failed == 0
                ? $"{Plural(done, "verdict", "verdicts")} written into the rows; click a result to open the report."
                : $"{done} lookups done, {failed} failed or skipped (see console).";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"VirusTotal lookup aborted: {ex.Message}");
            StatusText.Text = "VirusTotal lookup aborted, see console.";
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>Strips libclamav's ".UNOFFICIAL" report suffix, which never appears
    /// inside the database files. Called from: Compare_Click, FindDatabase_Click.</summary>
    private static string StripUnofficial(string signature)
    {
        var threat = signature.Trim();
        const string unofficial = ".UNOFFICIAL";
        return threat.EndsWith(unofficial, StringComparison.OrdinalIgnoreCase)
            ? threat[..^unofficial.Length]
            : threat;
    }

    /// <summary>
    /// Opens the signature search window (non-modal) pre-seeded with the FIRST
    /// selected entry's signature. Called from: XAML Click binding.
    /// </summary>
    private void Compare_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var entries = SelectedEntries();
        if (entries.Count == 0) return;

        string threat = StripUnofficial(entries[0].Signature);
        if (threat.Length == 0)
        {
            StatusText.Text = "The first selected entry has no signature name to search for.";
            return;
        }
        if (entries.Count > 1)
            Log($"Compare signature uses the first selected entry: {entries[0].Signature}");
        // Ownerless (v1.0.3.6) so either window can be brought to front by clicking.
        ToolWindows.Show(new SignatureSearchWindow(threat), this);
    }

    /// <summary>
    /// Traces which database file(s) carry the signature(s) of the selected
    /// entries and writes the names into the Database column ("not found" when no
    /// database matched). One pass over all databases resolves every selected
    /// signature at once; container databases (.cvd/.cld) are listed through
    /// sigtool and take a while. The FOUND line itself never names the database,
    /// which is why this is an on-demand action. Called from: XAML Click binding.
    /// </summary>
    private async void FindDatabase_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var entries = SelectedEntries();
        if (entries.Count == 0) return;

        // Signature name -> entries carrying it (several files can share one).
        var byName = new Dictionary<string, List<DetectionEntry>>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            string name = StripUnofficial(entry.Signature);
            if (name.Length == 0) continue;
            if (!byName.TryGetValue(name, out var list)) byName[name] = list = new();
            list.Add(entry);
        }
        if (byName.Count == 0)
        {
            StatusText.Text = "The selected entries have no signature names to trace.";
            return;
        }

        List<string> databases;
        try
        {
            databases = Directory.Exists(AppPaths.DatabaseDir)
                ? Directory.GetFiles(AppPaths.DatabaseDir)
                    .Where(SignatureSearch.IsSearchableDatabase)
                    .OrderBy(System.IO.Path.GetFileName, StringComparer.OrdinalIgnoreCase)
                    .ToList()
                : new List<string>();
        }
        catch (Exception ex)
        {
            Log($"Could not list the database folder: {ex.Message}");
            return;
        }
        if (databases.Count == 0)
        {
            StatusText.Text = "No searchable databases found in the database folder.";
            return;
        }

        var pattern = new Regex(
            "^(?:" + string.Join("|", byName.Keys.Select(Regex.Escape)) + ")$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));

        SetBusy(true);
        try
        {
            Log($"Tracing {Plural(byName.Count, "signature", "signatures")} across {databases.Count} database(s)...");

            // The search runs on a worker thread (container listing is slow), so the
            // hits are collected under a lock and applied on the UI thread afterwards.
            var hitLock = new object();
            var hits = new List<SignatureSearch.SigHit>();
            bool cancelled = false;
            try
            {
                await Task.Run(() => SignatureSearch.SearchAsync(
                    databases, pattern, matchRawLine: false,
                    hit => { lock (hitLock) hits.Add(hit); },
                    db => Log($"Searching {db} ..."),
                    _cts.Token), _cts.Token);
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
            }

            var dbsPerEntry = new Dictionary<DetectionEntry, SortedSet<string>>();
            lock (hitLock)
            {
                foreach (var hit in hits)
                {
                    if (!byName.TryGetValue(hit.Name, out var list)) continue;
                    foreach (var entry in list)
                    {
                        if (!dbsPerEntry.TryGetValue(entry, out var set))
                            dbsPerEntry[entry] = set = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
                        set.Add(hit.Database);
                    }
                }
            }

            int resolved = 0;
            foreach (var list in byName.Values)
                foreach (var entry in list)
                {
                    if (dbsPerEntry.TryGetValue(entry, out var set))
                    {
                        entry.Database = string.Join(", ", set);
                        resolved++;
                        Log($"{entry.Signature} -> {entry.Database}");
                    }
                    else if (!cancelled)
                    {
                        entry.Database = "not found";
                        Log($"{entry.Signature} -> not found in any searchable database");
                    }
                }

            DetectionManager.Save();
            StatusText.Text = cancelled
                ? "Database trace cancelled."
                : $"Database traced for {Plural(resolved, "entry", "entries")}.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"Database trace aborted: {ex.Message}");
            StatusText.Text = "Database trace aborted, see console.";
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>Removes the selected entries from the list (files untouched). Called from: XAML Click binding.</summary>
    private void DeleteEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var entries = SelectedEntries();
        if (entries.Count == 0) return;
        int removed = DetectionManager.DeleteMany(entries);
        Log($"{Plural(removed, "entry", "entries")} deleted from the list.");
        StatusText.Text = $"{Plural(removed, "entry", "entries")} removed from the list.";
    }

    /// <summary>
    /// Removes every entry that is no longer pending (clean, quarantined, removed,
    /// whitelisted or ignored). Called from: XAML Click binding.
    /// </summary>
    private void DeleteManaged_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        int removed = DetectionManager.DeleteManaged();
        Log($"{Plural(removed, "managed entry", "managed entries")} removed from the list.");
        StatusText.Text = removed > 0
            ? $"{Plural(removed, "managed entry", "managed entries")} removed."
            : "No managed entries to remove (everything is still pending).";
    }

    /// <summary>
    /// Removes every entry from the list after a confirmation (files untouched).
    /// Called from: XAML Click binding.
    /// </summary>
    private void DeleteAll_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        int count = DetectionManager.Entries.Count;
        if (count == 0)
        {
            StatusText.Text = "The list is already empty.";
            return;
        }
        bool ok = new MessageDialog("Delete all entries",
            $"Remove all {count} entr{(count == 1 ? "y" : "ies")} from the detections list?\n\n" +
            "The files themselves stay untouched; pending findings will only reappear when a scan reports them again.",
            "Delete all", "Cancel") { Owner = this }.ShowDialog() == true;
        if (!ok) return;
        DetectionManager.Clear();
        Log($"All {count} entries removed from the list.");
        StatusText.Text = "List cleared.";
    }

    /// <summary>Opens the folder of the FIRST selected entry in Explorer. Called from: XAML Click binding.</summary>
    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var entries = SelectedEntries();
        if (entries.Count == 0) return;
        var entry = entries[0];
        try
        {
            if (File.Exists(entry.FilePath))
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{entry.FilePath}\"");
            else
                System.Diagnostics.Process.Start("explorer.exe", entry.Directory);
        }
        catch (Exception ex)
        {
            Log($"Could not open the folder: {ex.Message}");
        }
    }

    /// <summary>Sorts the detections table by the clicked column (shared 3-state
    /// cycle). Called from: XAML GridViewColumnHeader.Click binding.</summary>
    private void DetectionsSort_Click(object sender, RoutedEventArgs e)
        => ListViewSorting.SortByColumn(
            e.OriginalSource as System.Windows.Controls.GridViewColumnHeader, DetectionList);

    /// <summary>
    /// Opens the row's VirusTotal report in the browser when the VirusTotal cell is
    /// clicked. Rows without a lookup (or with a failed one) have no URL and do
    /// nothing. Called from: the VirusTotal column's Hyperlink Click (XAML).
    /// </summary>
    private void VtLink_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Documents.Hyperlink link
            || link.DataContext is not DetectionEntry entry
            || string.IsNullOrWhiteSpace(entry.VirusTotalUrl))
            return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = entry.VirusTotalUrl,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            Log($"Could not open the VirusTotal report: {ex.Message}");
        }
    }

    /// <summary>Closes the window. Called from: title bar X and footer Close.</summary>
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
