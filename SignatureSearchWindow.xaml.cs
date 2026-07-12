using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using ClamHub.Core;

namespace ClamHub;

/// <summary>
/// Searches the signatures of the installed ClamAV databases, or groups them to find
/// duplicates. The user picks databases, enters a regular expression (empty lists
/// everything) and gets one row per matching signature with the database it came from;
/// in duplicate mode the rows are groups of signatures that share a name or the same
/// detection payload. Selecting a row decodes that signature via sigtool. Results are
/// collected on a worker thread and bound in one go, because a full listing can be
/// millions of rows (there is no result cap by design).
/// Opened from: MainWindow.SearchSignatures_Click, and (pre-seeded) the Quarantine tab's
/// "Compare with databanks" button via MainWindow.CompareWithDatabanks_Click.
/// </summary>
public partial class SignatureSearchWindow : Window
{
    /// <summary>What the Search button does: plain search or one of the duplicate scans.</summary>
    private enum Mode { Search, DuplicatesByName, DuplicatesByContent }

    /// <summary>Cancels the running search (Stop button, window close).</summary>
    private CancellationTokenSource? _searchCancel;

    /// <summary>Cancels a decode that is still running when another row is selected.</summary>
    private CancellationTokenSource? _decodeCancel;

    /// <summary>Ticks while a search runs to show live progress without flooding the UI.</summary>
    private readonly DispatcherTimer _progressTimer = new() { Interval = TimeSpan.FromMilliseconds(200) };

    /// <summary>Guards the worker's result collections against the progress timer.</summary>
    private readonly object _resultLock = new();

    /// <summary>Signatures seen so far, for the live progress line.</summary>
    private int _progressCount;

    /// <summary>Database currently being read, for the live progress line.</summary>
    private volatile string _currentDb = "";

    public SignatureSearchWindow()
    {
        InitializeComponent();
        _progressTimer.Tick += (_, _) => UpdateProgress();
        LoadDatabases();
    }

    /// <summary>
    /// Opens the window pre-seeded with a signature/threat name and runs a plain search
    /// for it across all databases once the window is shown, so the user can see which
    /// databases carry that detection and under which names. The name is used as-is as the
    /// (case-insensitive) search pattern: Search_Click already guards against an invalid
    /// regular expression, so an exotic character just yields a status message instead of
    /// throwing, and characters like '.' act as a wildcard, which only broadens the match.
    /// Called from: the Quarantine "Compare with databanks" button (MainWindow.Quarantine.cs).
    /// </summary>
    public SignatureSearchWindow(string initialPattern) : this()
    {
        Loaded += (_, _) =>
        {
            ModeBox.SelectedIndex = 0;      // plain Search (not the duplicate scans)
            MatchRawBox.IsChecked = false;  // match the name anywhere in the line
            PatternBox.Text = initialPattern ?? "";
            Search_Click(this, new RoutedEventArgs());
        };
    }

    /// <summary>The mode selected in the combo box. Called from: the run and mode handlers.</summary>
    private Mode CurrentMode => ModeBox.SelectedIndex switch
    {
        1 => Mode.DuplicatesByName,
        2 => Mode.DuplicatesByContent,
        _ => Mode.Search
    };

    /// <summary>
    /// One selectable database. IsSelected is bound two-way to the checkbox; the plain
    /// property is enough because nothing else changes it. Used by: the database picker.
    /// </summary>
    private sealed class DbPick
    {
        public string Path { get; init; } = "";
        public string Label { get; init; } = "";
        public bool IsSelected { get; set; }
    }

    /// <summary>
    /// Accumulates the signatures that share a duplicate key while the scan runs: how
    /// often the key occurred, which databases it came from, which distinct names it had
    /// and one raw line for decoding. Used by: RunDuplicatesAsync.
    /// </summary>
    private sealed class DupAccum
    {
        public int Count;
        public string? SampleRaw;
        public readonly string FirstName;
        public readonly HashSet<string> Databases = new(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> Names = new(StringComparer.Ordinal);

        public DupAccum(string firstName) => FirstName = firstName;

        /// <summary>Records one occurrence. Called from: the scan callback (worker thread).</summary>
        public void Add(SignatureSearch.SigHit hit)
        {
            Count++;
            Databases.Add(hit.Database);
            Names.Add(hit.Name);
            SampleRaw ??= hit.RawLine;
        }
    }

    /// <summary>A duplicate group row. Bound to: the duplicates table.</summary>
    private sealed record DupRow(string Signature, int Count, string Databases, string Name, string? RawLine);

    /// <summary>
    /// Fills the database picker with every signature database in the folder (all selected
    /// by default). Container databases are marked so the user knows they are the slow ones.
    /// Called from: the constructor.
    /// </summary>
    private void LoadDatabases()
    {
        var picks = new List<DbPick>();
        try
        {
            if (Directory.Exists(AppPaths.DatabaseDir))
            {
                foreach (var path in Directory.GetFiles(AppPaths.DatabaseDir)
                             .Where(IsSearchableDatabase)
                             .OrderBy(System.IO.Path.GetFileName, StringComparer.OrdinalIgnoreCase))
                {
                    string name = System.IO.Path.GetFileName(path);
                    picks.Add(new DbPick
                    {
                        Path = path,
                        Label = SignatureSearch.IsTextDatabase(path) ? name : name + "  (container)",
                        IsSelected = true
                    });
                }
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Could not read the database folder: {ex.Message}";
        }

        DbList.ItemsSource = picks;
        if (picks.Count == 0)
            StatusText.Text = "No databases found. Run a signature update first.";
    }

    /// <summary>True for files this window can search (text databases plus .cvd/.cld containers).</summary>
    private static bool IsSearchableDatabase(string path)
    {
        if (SignatureSearch.IsTextDatabase(path)) return true;
        string ext = System.IO.Path.GetExtension(path);
        return ext.Equals(".cvd", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".cld", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Checks every database. Called from: All button.</summary>
    private void SelectAll_Click(object sender, RoutedEventArgs e) => SetAllSelected(true);

    /// <summary>Unchecks every database. Called from: None button.</summary>
    private void SelectNone_Click(object sender, RoutedEventArgs e) => SetAllSelected(false);

    /// <summary>Sets every checkbox and refreshes the list. Called from: SelectAll_Click and SelectNone_Click.</summary>
    private void SetAllSelected(bool selected)
    {
        if (DbList.ItemsSource is not IEnumerable<DbPick> picks) return;
        foreach (var p in picks) p.IsSelected = selected;
        DbList.Items.Refresh();
    }

    /// <summary>
    /// Swaps the visible result table and the button caption when the mode changes.
    /// Fires once during InitializeComponent (before the controls exist), hence the guard.
    /// Called from: XAML SelectionChanged binding.
    /// </summary>
    private void ModeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResultList == null) return; // still initialising

        bool search = CurrentMode == Mode.Search;
        ResultList.Visibility = search ? Visibility.Visible : Visibility.Collapsed;
        DuplicateList.Visibility = search ? Visibility.Collapsed : Visibility.Visible;
        MatchRawBox.IsEnabled = search;
        SearchButton.Content = search ? "Search" : "Find";
        DecodeBox.Clear();
        StatusText.Text = search
            ? "Select databases and search."
            : "Groups signatures that occur more than once. Leave the pattern empty to scan everything.";
    }

    /// <summary>Starts the run on Enter. Called from: XAML KeyDown binding.</summary>
    private void PatternBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Search_Click(sender, e);
    }

    /// <summary>Cancels a running search. Called from: Stop button.</summary>
    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        _searchCancel?.Cancel();
        StatusText.Text = "Stopping...";
    }

    /// <summary>
    /// Validates the input and dispatches to the plain search or the duplicate scan.
    /// Called from: Search button and Enter in the pattern box.
    /// </summary>
    private async void Search_Click(object sender, RoutedEventArgs e)
    {
        if (_searchCancel != null) return; // already running

        var selected = (DbList.ItemsSource as IEnumerable<DbPick>)?
            .Where(p => p.IsSelected).Select(p => p.Path).ToList() ?? new List<string>();
        if (selected.Count == 0)
        {
            StatusText.Text = "Select at least one database.";
            return;
        }

        Regex? pattern;
        try
        {
            string text = PatternBox.Text.Trim();
            pattern = text.Length == 0
                ? null
                : new Regex(text, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                    TimeSpan.FromSeconds(2));
        }
        catch (ArgumentException ex)
        {
            StatusText.Text = $"Invalid regular expression: {ex.Message}";
            return;
        }

        var mode = CurrentMode;
        if (mode == Mode.Search)
        {
            await RunSearchAsync(selected, pattern);
            return;
        }

        // Content duplicates need the raw signature line, which container databases do not
        // provide (sigtool only lists their names), so they are dropped from that scan.
        var containers = selected.Where(p => !SignatureSearch.IsTextDatabase(p)).ToList();
        string note = "";
        if (mode == Mode.DuplicatesByContent && containers.Count > 0)
        {
            selected = selected.Except(containers).ToList();
            if (selected.Count == 0)
            {
                StatusText.Text = "Duplicates by content need text databases; container "
                    + "databases (.cvd/.cld) only expose signature names.";
                return;
            }
            note = $" {containers.Count} container database(s) skipped.";
        }
        else if (containers.Count > 0 && !ConfirmHeavyScan(containers))
        {
            return;
        }

        await RunDuplicatesAsync(selected, pattern, mode, note);
    }

    /// <summary>
    /// Warns before scanning container databases for duplicates: every signature name has
    /// to be listed and held in memory (daily alone has millions). Returns whether to go
    /// ahead. Called from: Search_Click.
    /// </summary>
    private bool ConfirmHeavyScan(IReadOnlyList<string> containers)
    {
        string names = string.Join(", ", containers.Select(System.IO.Path.GetFileName));
        return new MessageDialog("Scan container databases",
            $"{names} will be listed in full. This can take minutes and use a lot of memory.\n\n"
            + "Continue?",
            "Continue", "Cancel") { Owner = this }.ShowDialog() == true;
    }

    /// <summary>
    /// Streams matching signatures into a list on a worker thread while a timer shows the
    /// count, then binds the finished list to the results table. Called from: Search_Click.
    /// </summary>
    private async Task RunSearchAsync(List<string> databases, Regex? pattern)
    {
        bool matchRaw = MatchRawBox.IsChecked == true;
        var hits = new List<SignatureSearch.SigHit>();

        var outcome = await RunScanAsync(cancel => SignatureSearch.SearchAsync(
            databases, pattern, matchRaw,
            hit => { lock (_resultLock) { hits.Add(hit); _progressCount++; } },
            db => _currentDb = db, cancel));

        // Bind once: per-hit notifications would be unusable at these row counts.
        ResultList.ItemsSource = hits;
        ReportOutcome(outcome, $"{hits.Count:N0} signature(s)", "");
    }

    /// <summary>
    /// Scans the databases and groups the signatures by name or by detection payload,
    /// keeping only the groups that occur at least twice. Called from: Search_Click.
    /// </summary>
    private async Task RunDuplicatesAsync(List<string> databases, Regex? pattern, Mode mode, string note)
    {
        bool byName = mode == Mode.DuplicatesByName;
        var groups = new Dictionary<string, DupAccum>(StringComparer.Ordinal);

        var outcome = await RunScanAsync(cancel => SignatureSearch.SearchAsync(
            databases, pattern, false,
            hit =>
            {
                // By name the key is the malware name; by content it is the payload of the
                // raw line (same detection under possibly different names).
                string? key = byName
                    ? hit.Name
                    : hit.RawLine != null ? SignatureSearch.ExtractContent(hit.RawLine) : null;
                if (key == null) return;

                lock (_resultLock)
                {
                    if (!groups.TryGetValue(key, out var acc))
                        groups[key] = acc = new DupAccum(hit.Name);
                    acc.Add(hit);
                    _progressCount++;
                }
            },
            db => _currentDb = db, cancel));

        var rows = groups.Values
            .Where(a => a.Count >= 2)
            .OrderByDescending(a => a.Count)
            .ThenBy(a => a.FirstName, StringComparer.OrdinalIgnoreCase)
            .Select(a => new DupRow(
                a.Names.Count > 1 ? $"{a.FirstName}  (+{a.Names.Count - 1} more name(s))" : a.FirstName,
                a.Count,
                string.Join(", ", a.Databases.OrderBy(d => d, StringComparer.OrdinalIgnoreCase)),
                a.FirstName,
                a.SampleRaw))
            .ToList();

        DuplicateList.ItemsSource = rows;
        ReportOutcome(outcome, $"{rows.Count:N0} duplicate group(s) in {_progressCount:N0} signature(s)", note);
    }

    /// <summary>Result of a scan run: how it ended and how long it took.</summary>
    private sealed record ScanOutcome(bool Cancelled, string? Error, double Seconds);

    /// <summary>
    /// Runs a scan delegate on a worker thread with the busy state, the progress timer and
    /// cancellation wired up, and reports how it ended. Called from: RunSearchAsync and
    /// RunDuplicatesAsync.
    /// </summary>
    private async Task<ScanOutcome> RunScanAsync(Func<CancellationToken, Task> scan)
    {
        ResultList.ItemsSource = null;
        DuplicateList.ItemsSource = null;
        DecodeBox.Clear();

        lock (_resultLock) _progressCount = 0;
        _currentDb = "";
        var cts = new CancellationTokenSource();
        _searchCancel = cts;
        SetSearching(true);

        bool cancelled = false;
        string? error = null;
        var started = DateTime.UtcNow;

        try
        {
            await Task.Run(() => scan(cts.Token), cts.Token);
        }
        catch (OperationCanceledException) { cancelled = true; }
        catch (RegexMatchTimeoutException) { error = "The regular expression took too long; simplify it."; }
        catch (Exception ex) { error = ex.Message; }
        finally
        {
            _searchCancel = null;
            cts.Dispose();
            SetSearching(false);
        }

        return new ScanOutcome(cancelled, error, (DateTime.UtcNow - started).TotalSeconds);
    }

    /// <summary>Writes the final status line. Called from: RunSearchAsync and RunDuplicatesAsync.</summary>
    private void ReportOutcome(ScanOutcome outcome, string what, string note)
    {
        StatusText.Text = outcome.Error != null
            ? $"Failed: {outcome.Error}"
            : outcome.Cancelled
                ? $"Stopped after {what} in {outcome.Seconds:F1}s.{note}"
                : $"Found {what} in {outcome.Seconds:F1}s.{note}";
    }

    /// <summary>
    /// Toggles the busy state: work bar, Search/Stop buttons and the progress timer.
    /// Called from: RunScanAsync.
    /// </summary>
    private void SetSearching(bool on)
    {
        WorkBar.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        SearchButton.IsEnabled = !on;
        StopButton.IsEnabled = on;
        if (on) _progressTimer.Start(); else _progressTimer.Stop();
    }

    /// <summary>Shows live progress while the worker runs. Called from: the progress timer.</summary>
    private void UpdateProgress()
    {
        int count;
        lock (_resultLock) count = _progressCount;
        string db = _currentDb;
        StatusText.Text = db.Length > 0
            ? $"Reading {db} - {count:N0} signature(s) so far..."
            : $"Working - {count:N0} signature(s) so far...";
    }

    /// <summary>Decodes the selected search result. Called from: the results SelectionChanged.</summary>
    private async void ResultList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResultList.SelectedItem is not SignatureSearch.SigHit hit)
        {
            DecodeBox.Clear();
            return;
        }
        await DecodeAsync(hit.RawLine, hit.Name);
    }

    /// <summary>Decodes a representative signature of the selected group. Called from: the duplicates SelectionChanged.</summary>
    private async void DuplicateList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (DuplicateList.SelectedItem is not DupRow row)
        {
            DecodeBox.Clear();
            return;
        }
        await DecodeAsync(row.RawLine, row.Name);
    }

    /// <summary>
    /// Shows a signature's raw line and its sigtool decoding. Text-database hits carry the
    /// raw line; container hits need it fetched first, which is why this is async and
    /// cancels a previous decode. Called from: both SelectionChanged handlers.
    /// </summary>
    private async Task DecodeAsync(string? rawLine, string signatureName)
    {
        _decodeCancel?.Cancel();
        var cts = new CancellationTokenSource();
        _decodeCancel = cts;
        DecodeBox.Text = "Decoding...";

        try
        {
            string? raw = rawLine ?? await SignatureSearch.FindRawLineAsync(signatureName, cts.Token);
            if (cts.IsCancellationRequested) return;

            if (raw == null)
            {
                DecodeBox.Text = "The raw signature line for this container database entry could not be "
                    + "retrieved, so it cannot be decoded.";
                return;
            }

            var lines = await SigTool.DecodeSignatureAsync(raw, cts.Token);
            if (cts.IsCancellationRequested) return;

            DecodeBox.Text = raw + Environment.NewLine + Environment.NewLine
                + string.Join(Environment.NewLine, lines);
        }
        catch (OperationCanceledException) { /* superseded by a newer selection */ }
        catch (Exception ex)
        {
            DecodeBox.Text = $"Could not decode the signature: {ex.Message}";
        }
        finally
        {
            if (ReferenceEquals(_decodeCancel, cts)) _decodeCancel = null;
            cts.Dispose();
        }
    }

    /// <summary>Closes the window. Called from: Close buttons.</summary>
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    /// <summary>Cancels background work so nothing keeps running after the window is gone.</summary>
    protected override void OnClosed(EventArgs e)
    {
        _progressTimer.Stop();
        _searchCancel?.Cancel();
        _decodeCancel?.Cancel();
        base.OnClosed(e);
    }
}
