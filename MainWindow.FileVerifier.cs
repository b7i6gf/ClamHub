using System.Windows;
using Microsoft.Win32;
using ClamHub.Core;
using ClamHub.Models;

namespace ClamHub;

/// <summary>
/// File-Verifier tab logic (v1.0.3.7, formerly the Hash-Verifier): file picker,
/// the Inspect pipeline (FILE metadata always; hashes, file system, PE,
/// signature, ClamAV and VirusTotal per check box), cancellation and the
/// context menu entry points. The hash logic that lived in MainWindow.xaml.cs
/// (ComputeHashAsync and friends) moved here and now runs through
/// Core.IntegrityScanner; the console output format of the hash lines is
/// unchanged. ClamAV finds of a run are ADDITIONALLY recorded in the
/// Detections list here (UI thread). Partial class companion to
/// MainWindow.xaml.cs, initialized from InitializeAsync.
/// </summary>
public partial class MainWindow
{
    /// <summary>Cancellation source for the running verification, or null when idle.</summary>
    private CancellationTokenSource? _verifierCts;

    /// <summary>
    /// Restores the check-box states AND the hash algorithm from settings.json so
    /// the stage selection survives restarts. Sets _verifierUiReady last, so the
    /// restore itself does not trigger a save through the change handlers.
    /// Called from: MainWindow.InitializeAsync.
    /// </summary>
    private void InitializeFileVerifierTab()
    {
        IncludeHashesCheck.IsChecked = SettingsManager.Current.FileVerifierIncludeHashes;
        IncludeFileSystemCheck.IsChecked = SettingsManager.Current.FileVerifierIncludeFileSystem;
        IncludePeCheck.IsChecked = SettingsManager.Current.FileVerifierIncludePe;
        IncludeDocumentCheck.IsChecked = SettingsManager.Current.FileVerifierIncludeDocument;
        IncludeSignatureCheck.IsChecked = SettingsManager.Current.FileVerifierIncludeSignature;
        IncludeClamAvCheck.IsChecked = SettingsManager.Current.FileVerifierIncludeClamAv;
        IncludeVirusTotalCheck.IsChecked = SettingsManager.Current.FileVerifierIncludeVirusTotal;
        IncludeStringsCheck.IsChecked = SettingsManager.Current.FileVerifierIncludeStrings;
        SelectHashAlgo(SettingsManager.Current.FileVerifierHashAlgo);
        _verifierUiReady = true;
    }

    // True once InitializeFileVerifierTab has applied the saved state; before that
    // the change handlers must not write settings back.
    private bool _verifierUiReady;

    // Greater than zero while the code (not the user) changes a control, e.g. the
    // context menu "Compute Hash" forcing "All". Such changes must not overwrite
    // the user's saved preference.
    private int _suppressVerifierPersist;

    /// <summary>
    /// Saves the current stage selection and hash algorithm immediately. Called
    /// from: the check box Checked/Unchecked and combo SelectionChanged handlers,
    /// so a preference is stored the moment it is set rather than only when
    /// Inspect runs (the context menu uses the same values).
    /// </summary>
    private void PersistVerifierOptions()
    {
        var s = SettingsManager.Current;
        s.FileVerifierIncludeHashes = IncludeHashesCheck.IsChecked == true;
        s.FileVerifierIncludeFileSystem = IncludeFileSystemCheck.IsChecked == true;
        s.FileVerifierIncludePe = IncludePeCheck.IsChecked == true;
        s.FileVerifierIncludeDocument = IncludeDocumentCheck.IsChecked == true;
        s.FileVerifierIncludeSignature = IncludeSignatureCheck.IsChecked == true;
        s.FileVerifierIncludeClamAv = IncludeClamAvCheck.IsChecked == true;
        s.FileVerifierIncludeVirusTotal = IncludeVirusTotalCheck.IsChecked == true;
        s.FileVerifierIncludeStrings = IncludeStringsCheck.IsChecked == true;
        if (HashAlgoCombo.SelectedItem is System.Windows.Controls.ComboBoxItem ci)
            s.FileVerifierHashAlgo = ci.Content?.ToString() ?? "All";
        SettingsManager.Save();
    }

    /// <summary>
    /// Any File-Verifier stage check box or the algorithm combo changed: persist
    /// at once, unless the change came from code or from the initial restore.
    /// Called from: XAML Checked/Unchecked and SelectionChanged bindings.
    /// </summary>
    private void VerifierOption_Changed(object sender, RoutedEventArgs e)
    {
        if (!_verifierUiReady || _suppressVerifierPersist > 0) return;
        PersistVerifierOptions();
    }

    /// <summary>
    /// Hash algorithm changed: persist it like the check boxes. Separate handler
    /// because SelectionChanged carries SelectionChangedEventArgs.
    /// Called from: XAML SelectionChanged binding of HashAlgoCombo.
    /// </summary>
    private void HashAlgo_SelectionChanged(object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (!_verifierUiReady || _suppressVerifierPersist > 0) return;
        PersistVerifierOptions();
    }

    /// <summary>
    /// Builds the option set for the context menu "Create Integrity Report":
    /// every local CHECK (hashes, file system, PE, document, digital signature,
    /// strings) is forced ON regardless of the tab selection; only the two SCANS
    /// (ClamAV, VirusTotal) follow the saved settings, so a scan the user turned
    /// off stays off. The saved selection itself is NOT touched (nothing is
    /// persisted and the tab check boxes keep showing the saved state), so the
    /// restart behaviour of the tab is unchanged. Before 2026-07-19 the context
    /// report ran exactly the saved selection instead.
    /// Called from: StartContextMenuIntegrity.
    /// </summary>
    private static IntegrityScanner.IntegrityOptions BuildContextIntegrityOptions()
    {
        var s = SettingsManager.Current;
        return new IntegrityScanner.IntegrityOptions(
            IncludeHashes: true,
            IncludeFileSystem: true,
            IncludePe: true,
            string.IsNullOrWhiteSpace(s.FileVerifierHashAlgo) ? "All" : s.FileVerifierHashAlgo,
            "",                                   // no expected hash from the context menu
            IncludeSignature: true,
            IncludeClamAv: s.FileVerifierIncludeClamAv,
            IncludeVirusTotal: s.FileVerifierIncludeVirusTotal,
            IncludeStrings: true,
            IncludeDocument: true);
    }

    /// <summary>File picker for the File-Verifier. Called from: XAML Click binding.</summary>
    private void BrowseHashFile_Click(object sender, RoutedEventArgs e)
    {
        // Multi-select: picking several files routes them through the same rule
        // as a drop (HandleVerifierBoxDrop), so they land in the queue instead
        // of only the last one ending up in the box.
        var dialog = new OpenFileDialog { Title = "Select file(s) to verify", Multiselect = true };
        if (dialog.ShowDialog() != true) return;
        HandleVerifierBoxDrop(dialog.FileNames);
    }

    /// <summary>
    /// Inspect button: reads file, algorithm, expected value and the stage
    /// check boxes, persists the stage selection and runs the verification.
    /// Called from: XAML Click binding of the Inspect button.
    /// </summary>
    private async void Inspect_Click(object sender, RoutedEventArgs e)
    {
        // With a non-empty queue, Inspect runs the WHOLE queue; a valid file in
        // the box is transferred into it first so both are processed (previously
        // the box file was run alone and the queue was ignored). With an empty queue, the box file runs alone as before.
        if (_verifierQueue.Count > 0)
        {
            TransferVerifierBoxToQueue();
            await RunVerifierQueue(_verifierQueue.ToList());
            return;
        }
        var path = HashFileBox.Text.Replace("\"", "").Trim();
        await RunFileVerifierAsync(path, BuildOptionsFromUi(persist: true));
    }

    /// <summary>
    /// Reads the check-box selection and hash algorithm into an IntegrityOptions,
    /// optionally persisting the selection (as Inspect does). Reused so the queue
    /// runs every file with exactly the settings shown in the tab.
    /// Called from: Inspect_Click and RunVerifierQueue.
    /// </summary>
    private IntegrityScanner.IntegrityOptions BuildOptionsFromUi(bool persist)
    {
        string algo = ((System.Windows.Controls.ComboBoxItem)HashAlgoCombo.SelectedItem)
            .Content.ToString()!;
        bool hashes = IncludeHashesCheck.IsChecked == true;
        bool fileSystem = IncludeFileSystemCheck.IsChecked == true;
        bool pe = IncludePeCheck.IsChecked == true;
        bool document = IncludeDocumentCheck.IsChecked == true;
        bool signature = IncludeSignatureCheck.IsChecked == true;
        bool clamAv = IncludeClamAvCheck.IsChecked == true;
        bool virusTotal = IncludeVirusTotalCheck.IsChecked == true;
        bool strings = IncludeStringsCheck.IsChecked == true;

        if (persist)
        {
            SettingsManager.Current.FileVerifierIncludeHashes = hashes;
            SettingsManager.Current.FileVerifierIncludeFileSystem = fileSystem;
            SettingsManager.Current.FileVerifierIncludePe = pe;
            SettingsManager.Current.FileVerifierIncludeDocument = document;
            SettingsManager.Current.FileVerifierIncludeSignature = signature;
            SettingsManager.Current.FileVerifierIncludeClamAv = clamAv;
            SettingsManager.Current.FileVerifierIncludeVirusTotal = virusTotal;
            SettingsManager.Current.FileVerifierIncludeStrings = strings;
            SettingsManager.Save();
        }

        return new IntegrityScanner.IntegrityOptions(
            hashes, fileSystem, pe, algo, ExpectedHashBox.Text,
            IncludeSignature: signature, IncludeClamAv: clamAv,
            IncludeVirusTotal: virusTotal, IncludeStrings: strings,
            IncludeDocument: document);
    }

    /// <summary>
    /// Red X on the File-Verifier field, two-stage: if the field holds text the
    /// first click clears the field; when the field is already empty the click
    /// clears the whole verifier queue instead. So one click empties the target,
    /// a second empties the queue. Called from: File-Verifier XAML Click binding.
    /// </summary>
    private void ClearVerifierField_Click(object sender, RoutedEventArgs e)
    {
        if (HashFileBox.Text.Trim().Length > 0)
        {
            HashFileBox.Clear(); // first click: clear the target field
            return;
        }
        if (_verifierQueue.Count > 0) // field already empty: clear the queue
        {
            _verifierQueue.Clear();
            UpdateVerifierQueueIndicator();
            AppendSection("VERIFIER QUEUE");
            AppendLine("Verifier queue cleared.");
        }
    }

    /// <summary>Backing store for the File-Verifier queue (files only). Mirrors
    /// the scan tab's _queue but without folders or saved named queues.</summary>
    private readonly List<string> _verifierQueue = new();

    /// <summary>
    /// Silently moves a valid FILE path from the File-Verifier box into the
    /// verifier queue and clears the box (mirror of the Scan tab's
    /// AddTargetToQueue). Invalid or empty box content is left untouched as
    /// feedback. Ensures the box file always joins queue runs instead of being
    /// silently skipped. Called from: HandleVerifierBoxDrop, VerifierQueue_Click
    /// and Inspect_Click.
    /// </summary>
    private void TransferVerifierBoxToQueue()
    {
        var path = HashFileBox.Text.Replace("\"", "").Trim();
        if (path.Length == 0 || !System.IO.File.Exists(path)) return;

        if (!_verifierQueue.Any(x => x.Equals(path, StringComparison.OrdinalIgnoreCase)))
            _verifierQueue.Add(path);
        HashFileBox.Clear();
        UpdateVerifierQueueIndicator();
    }

    /// <summary>
    /// Adds file paths to the verifier queue (existing FILES only, no duplicates),
    /// without running anything. Folders and drives are filtered out with console
    /// feedback. Called from: PathBox_PreviewDrop (multi-file drop on the
    /// File-Verifier box) and SendScanTargetsToVerifier_Click (arrow button on
    /// the Scan tab).
    /// </summary>
    private void AddFilesToVerifierQueue(IEnumerable<string> paths)
    {
        MainTabs.SelectedIndex = 1; // File-Verifier tab
        AppendSection("VERIFIER QUEUE");
        int added = 0;
        foreach (var raw in paths)
        {
            var p = raw.Trim().Trim('"');
            if (System.IO.Directory.Exists(p)) { AppendLine($"Skipped folder/drive (files only): {p}"); continue; }
            if (!System.IO.File.Exists(p)) { AppendLine($"Skipped (not found): {p}"); continue; }
            if (_verifierQueue.Any(x => x.Equals(p, StringComparison.OrdinalIgnoreCase))) continue;
            _verifierQueue.Add(p);
            AppendLine($"Added to queue: {p}");
            added++;
        }
        AppendLine(added == 0
            ? "Nothing added (folders, missing files or already queued)."
            : $"Verifier queue now has {_verifierQueue.Count} file(s).");
        UpdateVerifierQueueIndicator();
    }

    /// <summary>
    /// "Queue..." button: opens the verifier queue window, keeps any edits made
    /// there, and runs all queued files when the user pressed "Verify all".
    /// Called from: File-Verifier XAML Click binding.
    /// </summary>
    private async void VerifierQueue_Click(object sender, RoutedEventArgs e)
    {
        // Mirror of ScanQueue_Click: a valid file in the box joins the queue
        // before the window opens, so it is visible/editable there and always
        // part of a "Verify all" run.
        TransferVerifierBoxToQueue();
        var window = new VerifierQueueWindow(_verifierQueue) { Owner = this };
        window.ShowDialog();

        _verifierQueue.Clear();
        _verifierQueue.AddRange(window.Files); // keep edits made in the window
        UpdateVerifierQueueIndicator();

        if (window.VerifyRequested && _verifierQueue.Count > 0)
        {
            MainTabs.SelectedIndex = 1;
            await RunVerifierQueue(_verifierQueue.ToList());
        }
    }

    /// <summary>
    /// Runs the File-Verifier over each queued file in turn, using the current
    /// tab check selection, streaming each report to the console and recording a
    /// History entry per file. Cancelling (the Cancel button) stops the whole
    /// queue. Called from: VerifierQueue_Click.
    /// </summary>
    private async Task RunVerifierQueue(List<string> files)
    {
        var options = BuildOptionsFromUi(persist: true);
        AppendSection("VERIFIER QUEUE");
        AppendLine($"Running the verifier over {files.Count} queued file(s)...");
        int done = 0;
        foreach (var file in files)
        {
            if (_verifierQueueCancelled) break;
            if (!System.IO.File.Exists(file)) { AppendLine($"Skipped (not found): {file}"); continue; }
            HashFileBox.Text = file;
            await RunFileVerifierAsync(file, options);
            done++;
        }
        bool cancelled = _verifierQueueCancelled;
        _verifierQueueCancelled = false;

        // Match the scan queue: after a completed (non-cancelled) run, empty the
        // queue. Additionally clear the file box so the tab is reset for the next
        // use (the box held the last processed file during the run).
        if (!cancelled)
        {
            _verifierQueue.Clear();
            HashFileBox.Clear();
            UpdateVerifierQueueIndicator();
        }

        AppendSection("VERIFIER QUEUE");
        AppendLine(cancelled
            ? $"Queue cancelled: {done} of {files.Count} file(s) processed."
            : $"Queue finished: {done} of {files.Count} file(s) processed.");
    }

    /// <summary>Set when Cancel is pressed so RunVerifierQueue stops after the
    /// current file instead of continuing with the rest.</summary>
    private bool _verifierQueueCancelled;

    /// <summary>
    /// Updates the "Queue..." button on the File-Verifier tab to show the number
    /// of queued files (e.g. "Queue (3)") and accents it while non-empty, exactly
    /// like the scan tab's queue button. Called from: AddFilesToVerifierQueue,
    /// VerifierQueue_Click and RunVerifierQueue.
    /// </summary>
    private void UpdateVerifierQueueIndicator()
    {
        int n = _verifierQueue.Count;
        VerifierQueueButton.Content = n > 0 ? $"Queue ({n})" : "Queue...";
        _accentBrush ??= (System.Windows.Media.Brush)FindResource("AccentBrush");
        _mutedQueueTextBrush ??= (System.Windows.Media.Brush)FindResource("TextBrush");
        VerifierQueueButton.Foreground = n > 0 ? _accentBrush : _mutedQueueTextBrush;
    }

    /// <summary>
    /// Runs one File-Verifier pass over a single file: streams every finished
    /// section into the console (AppendLine marshals worker-thread callbacks
    /// itself) and records ONE history entry. Hash-only runs keep the
    /// established history kinds ("Hash compute"/"Hash comparison"); anything
    /// beyond hashes is recorded as "Integrity check" with the findings label.
    /// Shared so the context menu entries produce identical output.
    /// Called from: Inspect_Click, StartContextMenuHash and StartContextMenuIntegrity.
    /// </summary>
    private async Task RunFileVerifierAsync(string path, IntegrityScanner.IntegrityOptions options)
    {
        if (!System.IO.File.Exists(path))
        {
            AppendLine($"File-Verifier: file not found: {path}");
            return;
        }
        if (!options.IncludeHashes && !options.IncludeFileSystem && !options.IncludePe
            && !options.IncludeSignature && !options.IncludeClamAv && !options.IncludeVirusTotal
            && !options.IncludeStrings && !options.IncludeDocument)
        {
            AppendLine("File-Verifier: no check selected. Enable at least one check box.");
            return;
        }

        InspectButton.IsEnabled = false;
        // A single indicator band (VerifierIndicator) shows what is happening for
        // the whole run: determinate while hashing/PE read the file (a percentage
        // on large files), pulsing for the other stages. UpdateVerifierStageIndicator
        // sets its mode and label per stage; the Progress<T> below feeds the bar.
        _verifierCts = new CancellationTokenSource();
        var progress = new Progress<double>(f =>
        {
            VerifierProgressBar.IsIndeterminate = false;
            VerifierProgressBar.Value = f;
        });
        VerifierProgressBar.Value = 0;
        VerifierIndicator.Visibility = Visibility.Collapsed;
        CancelHashButton.IsEnabled = true;
        try
        {
            var report = await IntegrityScanner.RunAsync(path, options, progress,
                onSection: (title, lines) =>
                {
                    // May arrive on a worker thread; AppendSection/AppendLine
                    // buffer + marshal via the Dispatcher themselves.
                    AppendSection(title);
                    foreach (var line in lines) AppendLine(line);
                },
                onStatus: AppendLine,
                onStage: UpdateVerifierStageIndicator,
                _verifierCts.Token);

            // ClamAV finds of a report-only run still belong in the Detections
            // list. DetectionManager mutates a bound ObservableCollection, so
            // this stays here on the UI thread (continuation context).
            if (report.ClamAv is { RawFoundLines.Count: > 0 })
                DetectionManager.AddFindings(report.ClamAv.RawFoundLines);

            RecordVerifierHistory(path, options, report);
        }
        catch (OperationCanceledException)
        {
            AppendLine("Verification cancelled.");
        }
        finally
        {
            VerifierIndicator.Visibility = Visibility.Collapsed;
            CancelHashButton.IsEnabled = false;
            InspectButton.IsEnabled = true;
            _verifierCts?.Dispose();
            _verifierCts = null;
        }
    }

    /// <summary>
    /// Updates the single indicator band as each stage starts (called on the UI
    /// thread from IntegrityScanner via onStage). Hashing and PE read the whole
    /// file, so the bar runs determinate (the Progress callback fills it); the
    /// file-system, signature, ClamAV and VirusTotal stages have no natural
    /// percentage, so the bar pulses. The label always says what is happening.
    /// Called from: RunFileVerifierAsync.
    /// </summary>
    private void UpdateVerifierStageIndicator(string stage)
    {
        bool determinate = stage is "hashes" or "pe";
        if (determinate)
        {
            VerifierProgressBar.IsIndeterminate = false;
            VerifierProgressBar.Value = 0;
        }
        else
        {
            VerifierProgressBar.IsIndeterminate = true;
        }
        VerifierIndicatorText.Text = stage switch
        {
            "hashes" => "Computing hashes and entropy...",
            "filesystem" => "Reading file system metadata...",
            "pe" => "Analyzing the PE structure...",
            "document" => "Analyzing document structure...",
            "signature" => "Verifying the Authenticode signature...",
            "clamav" => "ClamAV scan running...",
            "virustotal" => "Querying VirusTotal (hash only)...",
            "strings" => "Extracting indicator strings...",
            _ => "Working..."
        };
        VerifierIndicator.Visibility = Visibility.Visible;
    }

    /// <summary>
    /// Records the run in the History tab. Kind and result label depend on what
    /// ran: pure hash runs keep the legacy kinds and labels, full runs become
    /// an "Integrity check" whose summary is the complete report.
    /// Called from: RunFileVerifierAsync.
    /// </summary>
    /// <summary>
    /// Records a File-Verifier run that was executed OUTSIDE this tab (currently
    /// the Detections window's "Verify file" button) in the shared History with
    /// the same kinds and labels as tab runs. Must be called on the UI thread
    /// (History backs a bound collection); WPF has one UI thread, so the
    /// Detections handler's continuation qualifies.
    /// Called from: DetectionsWindow.Verify_Click.
    /// </summary>
    public void AddIntegrityHistoryEntry(string path,
        IntegrityScanner.IntegrityOptions options, IntegrityReport report)
        => RecordVerifierHistory(path, options, report);

    private void RecordVerifierHistory(string path, IntegrityScanner.IntegrityOptions options,
        IntegrityReport report)
    {
        string summary = IntegrityReportWriter.RenderAll(report);

        // Pure hash run (hashes only): keep the established history kinds/labels.
        bool noExtras = !options.IncludeSignature && !options.IncludeClamAv
                        && !options.IncludeVirusTotal;
        if (options.IncludeHashes && !options.IncludeFileSystem && !options.IncludePe && noExtras)
        {
            var h = report.Hashes;
            if (h != null && h.Status == StageStatus.Failed)
            {
                AddHistory("Hash compute", path, "", "compute failed", summary);
                return;
            }
            if (h != null && !string.IsNullOrWhiteSpace(h.Expected))
            {
                AddHistory("Hash comparison", path, "",
                    h.Matched == true ? "successful comparison" : "unsuccessful comparison", summary);
                return;
            }
            AddHistory("Hash compute", path, "", "hash computed", summary);
            return;
        }

        // Pure PE run (only PE selected in the tab): its own kind, no findings label.
        if (options.IncludePe && !options.IncludeHashes && !options.IncludeFileSystem && noExtras)
        {
            string peLabel = report.Pe?.Status switch
            {
                StageStatus.Skipped => "not a PE file",
                StageStatus.Failed => "PE parse failed",
                _ => report.Pe?.FileType ?? "PE info"
            };
            AddHistory("PE info", path, "", peLabel, summary);
            return;
        }

        // Anything else is a full integrity check. The Process column shows the
        // external tools the verifier actually used: the ClamAV executable when
        // the ClamAV stage ran (clamdscan.exe with the daemon, otherwise
        // clamscan.exe) and "VirusTotal" when the hash lookup ran.
        var procs = new List<string>();
        if (report.ClamAv is { Status: StageStatus.Ok } av)
            procs.Add(av.UsedDaemon ? "clamdscan.exe" : "clamscan.exe");
        if (report.VirusTotal is { Status: StageStatus.Ok })
            procs.Add("VirusTotal");
        string process = string.Join(", ", procs);

        AddHistory("Integrity check", path, process, IntegrityReportWriter.FindingsLabel(report), summary);
    }

    /// <summary>
    /// Cancels the in-progress verification. Safe when nothing is running.
    /// Called from: the File-Verifier tab Cancel button.
    /// </summary>
    private void CancelHash_Click(object sender, RoutedEventArgs e)
    {
        _verifierQueueCancelled = true; // stop the queue after the current file
        _verifierCts?.Cancel();
    }

    /// <summary>
    /// Selects the given algorithm in the hash combo by its item content, so the
    /// UI reflects a run started from the context menu.
    /// Called from: StartContextMenuHash and StartContextMenuIntegrity.
    /// </summary>
    private void SelectHashAlgo(string algo)
    {
        // Programmatic change: must not overwrite the user's saved algorithm
        // (the context "Compute Hash" action forces "All" for its own run).
        _suppressVerifierPersist++;
        try
        {
            foreach (var item in HashAlgoCombo.Items)
                if (item is System.Windows.Controls.ComboBoxItem ci
                    && string.Equals(ci.Content?.ToString(), algo, StringComparison.OrdinalIgnoreCase))
                {
                    HashAlgoCombo.SelectedItem = item;
                    return;
                }
        }
        finally
        {
            _suppressVerifierPersist--;
        }
    }

    /// <summary>
    /// Context menu "Compute Hash": switches to the File-Verifier tab and
    /// computes all hashes of the file (hash stage only, legacy behavior; the
    /// saved check-box selection is not touched).
    /// Called from: DispatchContextAction.
    /// </summary>
    private async Task StartContextMenuHash(string path)
    {
        MainTabs.SelectedIndex = 1; // File-Verifier tab
        if (!System.IO.File.Exists(path))
        {
            AppendSection("HASH");
            AppendLine($"Hash: not a file (folders cannot be hashed): {path}");
            return;
        }
        HashFileBox.Text = path;
        ExpectedHashBox.Clear();
        SelectHashAlgo("All");
        await RunFileVerifierAsync(path, new IntegrityScanner.IntegrityOptions(
            IncludeHashes: true, IncludeFileSystem: false, IncludePe: false, "All", ""));
    }

    /// <summary>
    /// Context menu "Create Integrity Report": switches to the File-Verifier tab
    /// and runs the file through ALL local checks; only the ClamAV and VirusTotal
    /// scans follow the saved tab selection (BuildContextIntegrityOptions). The
    /// tab check boxes intentionally keep showing the SAVED selection, not the
    /// forced set of this run (the report itself lists what ran); mirroring the
    /// forced set would risk persisting it on the next check box click.
    /// Called from: DispatchContextAction (the "integrity" action).
    /// </summary>
    private async Task StartContextMenuIntegrity(string path)
    {
        MainTabs.SelectedIndex = 1; // File-Verifier tab
        if (!System.IO.File.Exists(path))
        {
            AppendSection("FILE VERIFIER");
            AppendLine($"File-Verifier: not a file (folders cannot be verified): {path}");
            return;
        }
        HashFileBox.Text = path;
        ExpectedHashBox.Clear();

        var options = BuildContextIntegrityOptions();
        SelectHashAlgo(options.HashAlgorithm);
        await RunFileVerifierAsync(path, options);
    }
}
