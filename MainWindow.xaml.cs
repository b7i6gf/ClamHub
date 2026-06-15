using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using ClamAVGui.Core;
using ClamAVGui.Models;
using Microsoft.Win32;

namespace ClamAVGui;

/// <summary>
/// Main window. Stage 3: scan panel (file/folder/drive, action selection,
/// extension filter, memory scan, cancel) on top of the stage 2 daemon and
/// update controls. Infected file reporting follows in stage 4.
/// Created by: WPF runtime via StartupUri in App.xaml.
/// </summary>
public partial class MainWindow : Window
{
    private bool _busy;

    // Scan-session exclusions: a temporary working copy that starts from the
    // persistent settings defaults and resets on startup and profile change.
    // Applied to clamscan runs only (the daemon uses clamd.conf defaults).
    private List<string> _sessionExcludeDirs = new();
    private List<string> _sessionExcludeExts = new();

    /// <summary>
    /// Resets the scan-session exclusions to the persistent settings defaults.
    /// Called from: InitializeAsync (startup) and on profile change.
    /// </summary>
    private void ResetSessionExclusions()
    {
        _sessionExcludeDirs = new List<string>(SettingsManager.Current.ExcludeDirectories);
        _sessionExcludeExts = new List<string>(SettingsManager.Current.ExcludeExtensions);
    }
    private CancellationTokenSource? _scanCts;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await InitializeAsync();
    }

    /// <summary>
    /// Startup sequence after the window is visible: show config check results,
    /// query the ClamAV version, optionally run an update and auto start clamd.
    /// Called from: Loaded event in the constructor.
    /// </summary>
    private async Task InitializeAsync()
    {
        ShowConfigStatus();
        ActionCombo.SelectedIndex = (int)SettingsManager.Current.DefaultAction;
        MultiScanCheck.IsChecked = SettingsManager.Current.MultiScan;
        InitializeSettingsTab();
        InitializeProfiles();
        InitializeHistory();
        InitializeQuarantine();
        RefreshVirusTotalButtons();
        InitializeConsoleView();
        ResetSessionExclusions();

        if (IsElevated())
        {
            AdminRestartButton.IsEnabled = false;
            AdminRestartButton.Content = "Admin mode";
            Title = "ClamHub 1.0.0 (Administrator)";
        }

        var version = await UpdateManager.GetVersionAsync();
        VersionText.Text = version != null ? FormatVersion(version) : "ClamAV binaries not found";

        if (version == null)
        {
            AppendLine("ClamAV binaries are missing. Copy the portable ClamAV files into the ClamAV folder and restart.");
            await RefreshDaemonStatusAsync();
            return;
        }

        if (SettingsManager.Current.UpdateOnStart)
        {
            await RunGuarded(() => UpdateManager.RunUpdateAsync(AppendLine));
            // Re-query after the update so the database version in the header is current.
            var updated = await UpdateManager.GetVersionAsync();
            if (updated != null) VersionText.Text = FormatVersion(updated);
        }

        if (SettingsManager.Current.AutoStartDaemon && SettingsManager.Current.UseDaemon)
            await RunGuarded(() => DaemonController.StartAsync(AppendLine));

        await RefreshDaemonStatusAsync();

        // Listen for scan requests forwarded by further ClamHub launches.
        SingleInstance.StartServer(msg => Dispatcher.Invoke(() => OnForwardedRequest(msg)));

        // Launched from the Windows context menu with a path: prefill and scan.
        if (!string.IsNullOrWhiteSpace(App.StartupScanPath))
            await StartContextMenuScan(App.StartupScanPath);
    }

    /// <summary>
    /// Handles a request forwarded from a second ClamHub launch: brings this
    /// window to the front and, if a real path was sent, starts a scan.
    /// Called from: the SingleInstance pipe server (on the UI thread).
    /// </summary>
    private async void OnForwardedRequest(string message)
    {
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
        Topmost = true; Topmost = false; // nudge to foreground without staying on top

        if (message != SingleInstance.ActivateMessage && !string.IsNullOrWhiteSpace(message)
            && !_busy)
            await StartContextMenuScan(message);
    }

    /// <summary>
    /// Prefills the scan target from a context menu launch and starts a scan
    /// with the configured default action. Called from: InitializeAsync.
    /// </summary>
    private async Task StartContextMenuScan(string path)
    {
        MainTabs.SelectedIndex = 0;
        TargetBox.Text = path.Trim();
        var options = new ScanEngine.ScanOptions(
            ScanEngine.ScanMode.Path,
            TargetBox.Text,
            (InfectedFileAction)ActionCombo.SelectedIndex,
            MultiScanCheck.IsChecked == true,
            ScanEngine.ParseExtensions(ExtensionsBox.Text),
            false,
            _sessionExcludeDirs,
            _sessionExcludeExts);
        await RunScanGuarded(options);
    }

    /// <summary>
    /// Shows the ConfigManager results from app startup in the status line.
    /// Called from: InitializeAsync.
    /// </summary>
    private void ShowConfigStatus()
    {
        var c = App.StartupCheck;
        var parts = new List<string>
        {
            c is { FreshClamCreated: true } ? "freshclam.conf created" : "freshclam.conf found",
            c is { ClamdCreated: true } ? "clamd.conf created" : "clamd.conf found",
            "settings.json loaded"
        };
        ConfigStatusText.Text = string.Join("  |  ", parts);
    }

    /// <summary>
    /// Updates the daemon status indicator (dot color and text).
    /// Called from: InitializeAsync and after every guarded action.
    /// </summary>
    private async Task RefreshDaemonStatusAsync()
    {
        bool running = await DaemonController.IsRunningAsync();
        DaemonDot.Fill = (Brush)FindResource(running ? "OkBrush" : "WarnBrush");
        DaemonStatusText.Text = running
            ? $"Daemon: running on 127.0.0.1:{SettingsManager.Current.ClamdPort}"
            : "Daemon: not running";
        StartDaemonButton.IsEnabled = !running && !_busy;
        StopDaemonButton.IsEnabled = running && !_busy;

        // Multi-scan only applies to the daemon, so disable and gray it when down.
        MultiScanCheck.IsEnabled = running;
        MultiScanCheck.Foreground = (Brush)FindResource(running ? "TextBrush" : "MutedTextBrush");
        MultiScanCheck.ToolTip = running
            ? "Let the daemon scan with multiple threads"
            : "Available only while the daemon is running";
    }

    /// <summary>
    /// Reformats the clamscan --version string into a compact engine + database
    /// line. clamscan reports "ClamAV &lt;ver&gt;/&lt;dbver&gt;/&lt;ctime date&gt;"; the date is
    /// ClamAV's own ctime format and is kept verbatim. Called from: InitializeAsync, Update.
    /// </summary>
    private static string FormatVersion(string raw)
    {
        var parts = raw.Split('/');
        if (parts.Length >= 3)
            return $"{parts[0].Trim()}      |      Database: Ver. {parts[1].Trim()} from {parts[2].Trim()}";
        return raw.Trim();
    }

    /// <summary>
    /// Runs a long operation while disabling the action buttons, then refreshes
    /// the daemon status. Prevents overlapping clamd/freshclam/scan operations.
    /// Called from: all button click handlers and InitializeAsync.
    /// </summary>
    private async Task RunGuarded(Func<Task> action)
    {
        if (_busy) return;
        _busy = true;
        StartDaemonButton.IsEnabled = StopDaemonButton.IsEnabled = false;
        UpdateButton.IsEnabled = ScanButton.IsEnabled = MemoryScanButton.IsEnabled = false;
        try
        {
            await action();
        }
        finally
        {
            _busy = false;
            UpdateButton.IsEnabled = ScanButton.IsEnabled = MemoryScanButton.IsEnabled = true;
            await RefreshDaemonStatusAsync();
        }
    }

    /// <summary>Start daemon button. Called from: XAML Click binding.</summary>
    private async void StartDaemon_Click(object sender, RoutedEventArgs e)
        => await RunGuarded(() => { AppendSection("DAEMON START"); return DaemonController.StartAsync(AppendLine); });

    /// <summary>Stop daemon button. Called from: XAML Click binding.</summary>
    private async void StopDaemon_Click(object sender, RoutedEventArgs e)
        => await RunGuarded(() => { AppendSection("DAEMON STOP"); return DaemonController.StopAsync(AppendLine); });

    /// <summary>Update signatures button. Called from: XAML Click binding.</summary>
    private async void Update_Click(object sender, RoutedEventArgs e)
        => await RunGuarded(async () =>
        {
            AppendSection("SIGNATURE UPDATE");
            await UpdateManager.RunUpdateAsync(AppendLine);
            var version = await UpdateManager.GetVersionAsync();
            if (version != null) VersionText.Text = FormatVersion(version);
        });

    /// <summary>File picker for the scan target. Called from: XAML Click binding.</summary>
    private void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Select file to scan" };
        if (dialog.ShowDialog() == true)
            TargetBox.Text = dialog.FileName;
    }

    /// <summary>Folder picker for the scan target. Called from: XAML Click binding.</summary>
    private void BrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select folder or drive to scan" };
        if (dialog.ShowDialog() == true)
            TargetBox.Text = dialog.FolderName;
    }

    /// <summary>
    /// Builds ScanOptions from the UI inputs and starts a path scan.
    /// Called from: XAML Click binding of the Start scan button.
    /// </summary>
    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        var options = new ScanEngine.ScanOptions(
            ScanEngine.ScanMode.Path,
            TargetBox.Text,
            (InfectedFileAction)ActionCombo.SelectedIndex,
            MultiScanCheck.IsChecked == true,
            ScanEngine.ParseExtensions(ExtensionsBox.Text),
            false,
            _sessionExcludeDirs,
            _sessionExcludeExts);

        await RunScanGuarded(options);
    }

    /// <summary>
    /// Starts a memory scan (clamscan --memory), optionally killing infected
    /// processes. Called from: XAML Click binding of the Memory scan button.
    /// </summary>
    private async void MemoryScan_Click(object sender, RoutedEventArgs e)
    {
        var options = new ScanEngine.ScanOptions(
            ScanEngine.ScanMode.Memory,
            null,
            InfectedFileAction.ReportOnly,
            false,
            null,
            KillProcessesCheck.IsChecked == true);

        await RunScanGuarded(options);
    }

    /// <summary>
    /// Shared scan runner: wires cancellation, busy state, the running-scan
    /// indicator and prints a custom summary block with statistics that
    /// clamdscan omits (engine version, target, duration, result).
    /// Called from: Scan_Click and MemoryScan_Click.
    /// </summary>
    private async Task RunScanGuarded(ScanEngine.ScanOptions options)
    {
        await RunGuarded(async () =>
        {
            string title = options.Mode == ScanEngine.ScanMode.Memory
                ? "MEMORY SCAN"
                : $"SCAN  {options.TargetPath}";
            AppendSection(title);

            InfectedCountText.Text = "";
            _scanCts = new CancellationTokenSource();
            CancelScanButton.IsEnabled = true;
            ScanIndicator.Visibility = Visibility.Visible;
            ScanIndicatorText.Text = options.Mode == ScanEngine.ScanMode.Memory
                ? "Memory scan running..."
                : $"Scanning {options.TargetPath} ...";
            var watch = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var result = await ScanEngine.RunScanAsync(options, line =>
                {
                    AppendLine(line);
                    MaybePlayDetectionSound(line);
                }, _scanCts.Token);
                watch.Stop();

                if (!result.Started && result.Error != null)
                {
                    AppendLine(result.Error);
                    return;
                }

                // Persist findings so infected files can be located later.
                if (result.InfectedLines.Count > 0)
                {
                    string desc = options.Mode == ScanEngine.ScanMode.Memory
                        ? "Memory scan"
                        : $"Scan of {options.TargetPath}";
                    LogManager.AppendInfected(result.InfectedLines, desc);
                }

                // Append only what ClamAV's own SCAN SUMMARY does not already show.
                // No leading blank line: the whole output of one scan stays together.
                AppendLine($"Duration: {watch.Elapsed:hh\\:mm\\:ss\\.f}");
                AppendLine($"Scanner:  {(result.UsedDaemon ? "clamdscan (daemon, parallel)" : "clamscan")}");

                // clamdscan does not report a scanned-file count; optionally add
                // it by counting the target on a background thread (no scan slowdown).
                if (result.UsedDaemon && options.Mode == ScanEngine.ScanMode.Path
                    && SettingsManager.Current.CountFilesOnDaemonScan
                    && !string.IsNullOrWhiteSpace(options.TargetPath))
                {
                    int fileCount = await Task.Run(() => SafeCountFiles(options.TargetPath));
                    AppendLine($"Files in target: {fileCount}");
                }

                AppendLine($"Result:   {result.ExitCode switch
                {
                    0 => "CLEAN",
                    1 => "INFECTIONS FOUND",
                    _ => $"COMPLETED WITH ERRORS (exit code {result.ExitCode}, see log)"
                }}");

                int found = result.InfectedLines.Count;
                if (found == 0)
                {
                    InfectedCountText.Text = "Clean";
                    InfectedCountText.Foreground = (Brush)FindResource("OkBrush");
                }
                else
                {
                    // Wording matches the chosen action. Quarantine is updated
                    // below to the actually moved count (only successful moves).
                    InfectedCountText.Text = options.Action switch
                    {
                        InfectedFileAction.Remove => $"{found} infected file(s) removed",
                        InfectedFileAction.Quarantine => $"{found} infected file(s) found",
                        _ => $"{found} infected file(s) found"
                    };
                    InfectedCountText.Foreground = (Brush)FindResource("DangerBrush");
                }

                // Persist the scan into the history tab.
                RecordScan(options, result, watch.Elapsed);

                // If the user chose Quarantine, move the infected files now.
                // ClamAV scanned report-only (see ScanEngine.AppendAction); the
                // GUI moves files itself to preserve their original paths.
                if (options.Action == InfectedFileAction.Quarantine && found > 0)
                {
                    int moved = QuarantineInfectedFiles(result.InfectedLines);
                    if (moved > 0)
                        InfectedCountText.Text = moved == found
                            ? $"{moved} infected file(s) quarantined"
                            : $"{moved} of {found} infected file(s) quarantined";
                    else
                        InfectedCountText.Text = $"{found} infected file(s) found (quarantine failed)";
                }
            }
            finally
            {
                ScanIndicator.Visibility = Visibility.Collapsed;
                CancelScanButton.IsEnabled = false;
                _scanCts.Dispose();
                _scanCts = null;
            }
        });
    }

    /// <summary>
    /// Counts files under a path, skipping folders that cannot be accessed.
    /// Returns 1 for a single file. Runs on a background thread so it does not
    /// block the UI. Called from: the scan summary for daemon scans.
    /// </summary>
    private static int SafeCountFiles(string? path)
    {
        if (string.IsNullOrEmpty(path)) return 0;
        if (System.IO.File.Exists(path)) return 1;
        if (!System.IO.Directory.Exists(path)) return 0;

        int count = 0;
        var stack = new Stack<string>();
        stack.Push(path);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            try
            {
                foreach (var _ in System.IO.Directory.EnumerateFiles(dir)) count++;
                foreach (var sub in System.IO.Directory.EnumerateDirectories(dir)) stack.Push(sub);
            }
            catch { /* skip inaccessible directories */ }
        }
        return count;
    }

    /// <summary>
    /// Enables the VirusTotal buttons only when an API key is configured, and
    /// swaps the tooltip to explain when it is missing. Called from:
    /// InitializeAsync and after saving GUI settings.
    /// </summary>
    private void RefreshVirusTotalButtons()
    {
        bool hasKey = !string.IsNullOrWhiteSpace(SettingsManager.Current.VirusTotalApiKey);
        string activeTip = "Look up the file's SHA256 on VirusTotal. Only the hash is sent, never the file.";
        string missingTip = "A VirusTotal API key is required. Add one in Settings.";

        VirusTotalButton.IsEnabled = hasKey;
        VirusTotalButton.ToolTip = hasKey ? activeTip : missingTip;
        QuarantineVtButton.IsEnabled = hasKey;
        QuarantineVtButton.ToolTip = hasKey ? activeTip : missingTip;
    }

    /// <summary>
    /// Scan tab "Exclusions..." button: edits the TEMPORARY scan-session
    /// exclusions (reset to settings defaults on restart/profile change). These
    /// apply to clamscan runs only and are not persisted.
    /// Called from: XAML Click binding (Exclusions button).
    /// </summary>
    private void Exclusions_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ExclusionsWindow(_sessionExcludeDirs, _sessionExcludeExts,
            "Temporary exclusions for this session. They reset to the Settings defaults "
            + "on restart or profile change, and apply to clamscan scans (the daemon uses "
            + "the defaults from Settings).") { Owner = this };
        if (dialog.ShowDialog() != true) return;

        _sessionExcludeDirs = dialog.ResultDirectories;
        _sessionExcludeExts = dialog.ResultExtensions;
        AppendSection("SCAN EXCLUSIONS");
        AppendLine($"Session exclusions set: {_sessionExcludeDirs.Count} director" +
                   $"{(_sessionExcludeDirs.Count == 1 ? "y" : "ies")}, {_sessionExcludeExts.Count} extension(s).");
        AppendLine("These apply to clamscan scans and reset on restart or profile change.");
    }

    /// <summary>
    /// Settings page (clamd.conf ExcludePath row): edits the PERSISTENT default
    /// exclusions. Saves them to settings.json, rewrites the clamd.conf block,
    /// resets the session copy and offers a daemon restart.
    /// Called from: the ExcludePath "Manage list..." button.
    /// </summary>
    private async void OpenExclusionsFromSettings()
    {
        var dialog = new ExclusionsWindow(
            SettingsManager.Current.ExcludeDirectories,
            SettingsManager.Current.ExcludeExtensions,
            "Default exclusions. Always active, including after restart. Used by the "
            + "daemon (via clamd.conf) and as the starting point for scan-session exclusions.")
            { Owner = this };
        if (dialog.ShowDialog() != true) return;

        SettingsManager.Current.ExcludeDirectories = dialog.ResultDirectories;
        SettingsManager.Current.ExcludeExtensions = dialog.ResultExtensions;
        SettingsManager.Save();
        ResetSessionExclusions();

        try { ConfigManager.WriteClamdExclusions(); }
        catch (Exception ex) { SetSettingsStatus($"clamd.conf update failed: {ex.Message}", "DangerBrush"); return; }

        SetSettingsStatus("Default exclusions saved.", "OkBrush");
        AppendSection("DEFAULT EXCLUSIONS");
        AppendLine($"Saved {dialog.ResultDirectories.Count} default director" +
                   $"{(dialog.ResultDirectories.Count == 1 ? "y" : "ies")} and {dialog.ResultExtensions.Count} extension(s).");

        if (await DaemonController.IsRunningAsync(1000))
        {
            var answer = MessageBox.Show(
                "Default exclusions saved. The daemon must restart to apply them to daemon scans.\n\nRestart the daemon now?",
                "Restart daemon", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (answer == MessageBoxResult.Yes)
                await RunGuarded(async () =>
                {
                    await DaemonController.StopAsync(AppendLine);
                    await DaemonController.StartAsync(AppendLine);
                });
            else
                AppendLine("Note: daemon scans use the new defaults after the next daemon restart.");
        }
    }

    /// <summary>Cancels the running scan. Called from: XAML Click binding.</summary>
    private void CancelScan_Click(object sender, RoutedEventArgs e)
        => _scanCts?.Cancel();

    /// <summary>
    /// Allows file drops on path text boxes (TextBox blocks drops by default).
    /// Called from: XAML PreviewDragOver binding of TargetBox and HashFileBox.
    /// </summary>
    private void PathBox_PreviewDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    /// <summary>
    /// Writes the first dropped file/folder path into the targeted text box.
    /// Called from: XAML PreviewDrop binding of TargetBox and HashFileBox.
    /// </summary>
    private void PathBox_PreviewDrop(object sender, DragEventArgs e)
    {
        if (sender is System.Windows.Controls.TextBox box
            && e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths)
        {
            box.Text = paths[0];
            e.Handled = true;
        }
    }

    /// <summary>File picker for the hash tool. Called from: XAML Click binding.</summary>
    private void BrowseHashFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Select file to hash" };
        if (dialog.ShowDialog() == true)
            HashFileBox.Text = dialog.FileName;
    }

    /// <summary>
    /// Computes the selected hash (or all) for the chosen file and optionally
    /// compares it with the expected value. Results go to the console.
    /// Called from: XAML Click binding of the Compute button.
    /// </summary>
    private async void ComputeHash_Click(object sender, RoutedEventArgs e)
    {
        var path = HashFileBox.Text.Replace("\"", "").Trim();
        if (!System.IO.File.Exists(path))
        {
            AppendLine($"Hash: file not found: {path}");
            return;
        }

        ComputeHashButton.IsEnabled = false;
        try
        {
            string algo = ((System.Windows.Controls.ComboBoxItem)HashAlgoCombo.SelectedItem)
                .Content.ToString()!;
            var expected = ExpectedHashBox.Text;
            AppendSection($"HASH  {path}");

            if (algo == "All")
            {
                var all = await HashTool.ComputeAllAsync(path);
                foreach (var (name, hash) in all)
                    AppendLine($"{name,-7}: {hash ?? "FAILED (file locked or unreadable)"}");

                // Compare the expected hash against every algorithm and name the match.
                if (!string.IsNullOrWhiteSpace(expected))
                {
                    var match = all.FirstOrDefault(kv =>
                        kv.Value != null && HashTool.Matches(kv.Value, expected));
                    AppendLine(match.Key != null
                        ? $"MATCH: expected hash equals the {match.Key} hash."
                        : "MISMATCH: expected hash matches none of the computed hashes.");
                }
            }
            else
            {
                var hash = await HashTool.ComputeAsync(path, algo);
                if (hash == null)
                {
                    AppendLine($"{algo}: FAILED (file locked or unreadable)");
                    return;
                }
                AppendLine($"{algo}: {hash}");

                if (!string.IsNullOrWhiteSpace(expected))
                {
                    AppendLine(HashTool.Matches(hash, expected)
                        ? "MATCH: computed hash equals the expected value."
                        : $"MISMATCH: expected {expected.Trim()}");
                }
            }
        }
        finally
        {
            ComputeHashButton.IsEnabled = true;
        }
    }

    /// <summary>Clears the console box (and the separate window). Called from: XAML Click binding.</summary>
    private void ClearConsole_Click(object sender, RoutedEventArgs e)
    {
        ConsoleBox.Clear();
        _consoleWindow?.Clear();
    }

    /// <summary>
    /// Computes the file's SHA256 locally and looks it up on VirusTotal.
    /// Reloads settings.json first so a freshly added API key works without an
    /// app restart. Only the hash leaves the machine, never the file.
    /// Called from: XAML Click binding of the VirusTotal button.
    /// </summary>
    private async void VirusTotal_Click(object sender, RoutedEventArgs e)
    {
        var path = HashFileBox.Text.Replace("\"", "").Trim();
        VirusTotalButton.IsEnabled = false;
        try
        {
            await RunVirusTotalLookup(path, path);
        }
        finally
        {
            RefreshVirusTotalButtons();
        }
    }

    /// <summary>
    /// Shared VirusTotal routine: computes the SHA256 of fileToHash locally and
    /// looks it up, printing the verdict to the console. displayName is shown in
    /// the section header (the original name for quarantined files). Only the
    /// hash leaves the machine. Reloads settings.json so a freshly added key
    /// works without a restart.
    /// Called from: VirusTotal_Click (hash tab) and QuarantineVirusTotal_Click.
    /// </summary>
    private async Task RunVirusTotalLookup(string fileToHash, string displayName)
    {
        if (!System.IO.File.Exists(fileToHash))
        {
            AppendSection("VIRUSTOTAL");
            AppendLine($"File not found: {fileToHash}");
            return;
        }

        SettingsManager.Load();
        var apiKey = SettingsManager.Current.VirusTotalApiKey;
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            AppendSection("VIRUSTOTAL");
            AppendLine("No API key configured. Add your personal key in Settings, or to settings.json:");
            AppendLine("  \"VirusTotalApiKey\": \"<your key>\"");
            AppendLine("A free key is available at virustotal.com after registration. No restart needed.");
            return;
        }

        AppendSection($"VIRUSTOTAL  {displayName}");
        AppendLine("Computing SHA256 locally...");
        var sha256 = await HashTool.ComputeAsync(fileToHash, "SHA256");
        if (sha256 == null)
        {
            AppendLine("SHA256 computation failed (file locked or unreadable).");
            return;
        }
        AppendLine($"SHA256: {sha256}");
        AppendLine("Querying VirusTotal (hash only, the file is not uploaded)...");

        var result = await VirusTotalClient.LookupAsync(sha256, apiKey, AppendLine);

        if (!result.Success)
        {
            AppendLine(result.Error ?? "Lookup failed.");
            return;
        }
        if (result.NotFound)
        {
            AppendLine("Hash unknown to VirusTotal. The file has never been submitted there.");
            AppendLine("Note: unknown does not mean safe, only that no one uploaded it yet.");
            return;
        }

        int total = result.Malicious + result.Suspicious + result.Harmless + result.Undetected;
        AppendLine($"Verdict: {result.Malicious}/{total} engines flag this file as malicious" +
                    (result.Suspicious > 0 ? $", {result.Suspicious} as suspicious." : "."));
        AppendLine(result.Malicious == 0
            ? "No engine reports this file as malicious."
            : "CAUTION: at least one engine reports this file as malicious.");
        AppendLine($"Details: https://www.virustotal.com/gui/file/{sha256.ToLowerInvariant()}");
    }

    /// <summary>
    /// Prints the infected file report into the console.
    /// Called from: XAML Click binding (Show infected report).
    /// </summary>
    private void ShowReport_Click(object sender, RoutedEventArgs e)
    {
        var report = LogManager.ReadReport();
        AppendSection("INFECTED FILE REPORT");
        AppendLine(report ?? "No report yet, no infections recorded.");
    }

    /// <summary>
    /// Pulls FOUND lines from all log files into the report.
    /// Called from: XAML Click binding (Extract from logs).
    /// </summary>
    private void ExtractLogs_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            int added = LogManager.ExtractFromLogs();
            AppendLine(added > 0
                ? $"{added} new FOUND entr{(added == 1 ? "y" : "ies")} added to the report."
                : "No new FOUND entries in the log files.");
        }
        catch (Exception ex)
        {
            AppendLine($"Extract from logs failed: {ex.Message}");
        }
    }

    /// <summary>
    /// True when the process runs with administrator rights.
    /// Called from: InitializeAsync (button state) and RestartAsAdmin_Click.
    /// </summary>
    private static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Restarts the GUI elevated via UAC prompt and closes this instance.
    /// Replaces the ADMINSTART section of the old batch script, but without a
    /// hardcoded shortcut path: it relaunches the running EXE itself.
    /// Called from: XAML Click binding (Restart as admin).
    /// </summary>
    private void RestartAsAdmin_Click(object sender, RoutedEventArgs e)
    {
        if (IsElevated())
        {
            AppendLine("Already running with administrator rights.");
            return;
        }

        var exe = Environment.ProcessPath;
        if (exe == null)
        {
            AppendLine("Could not determine the executable path for the restart.");
            return;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = true,
                Verb = "runas"
            });
            Application.Current.Shutdown();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User declined the UAC prompt, keep the current instance running.
            AppendLine("Elevation cancelled, still running without administrator rights.");
        }
    }

    /// <summary>
    /// Switches the right-aligned header caption when the active tab changes.
    /// Called from: XAML SelectionChanged binding of MainTabs.
    /// </summary>
    private void Tabs_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (TabCaption == null || !ReferenceEquals(e.Source, MainTabs)) return;
        int index = MainTabs.SelectedIndex;
        TabCaption.Text = index switch
        {
            1 => "I N T E G R I T Y",
            2 => "I S O L A T I O N",
            3 => "A C T I V I T Y",
            4 => "C O N F I G U R A T I O N",
            _ => "A N T I V I R U S"
        };

        // The daemon control panel is only meaningful for scanning.
        DaemonPanel.Visibility = index == 0 ? Visibility.Visible : Visibility.Collapsed;

        // Refresh the data tables when their tab is opened so the newest entries
        // always show (also refreshed in the background right after a scan).
        if (index == 2) BindQuarantine();
        else if (index == 3) BindHistory();

        // Settings (4) and History (3) hide the main output console: Settings uses
        // the full area, History shows its own output console (in the bottom row).
        _onSettingsTab = index == 4;
        _onHistoryTab = index == 3;
        _consoleHiddenForTab = index == 4 || index == 3;
        ApplyConsoleLayout();

        // On the Settings tab, show a small "(running...)" note by the clamd header.
        if (_onSettingsTab)
            _ = UpdateClamdRunningLabelAsync();
    }

    // --- Output console placement (bottom / right / separate window) ---

    private ConsolePosition _consoleMode = ConsolePosition.Bottom;
    private bool _onSettingsTab;
    private bool _onHistoryTab;
    private bool _consoleHiddenForTab;
    private ConsoleWindow? _consoleWindow;
    private bool _applyingConsoleView;

    // Console column width when docked right (the user can make this wider).
    private const double RightConsoleWidth = 420;
    private const double RightConsoleMargin = 16;
    private double RightDockExtra => RightConsoleWidth + RightConsoleMargin;

    // Window width while NOT docked right, so we can restore it exactly. Updated
    // on user resize via the SizeChanged hook. Set during construction.
    private double _normalWidth;
    // Main column width captured when entering right dock; the column is frozen
    // to this so the main area never stretches.
    private double _mainColWidth;
    // Guards width changes we make ourselves from the SizeChanged capture.
    private bool _resizingForDock;

    /// <summary>
    /// Fired when a title bar view toggle is selected. Persists the choice and
    /// applies the new layout. Called from: the three RadioButtons.
    /// </summary>
    private void ConsoleView_Checked(object sender, RoutedEventArgs e)
    {
        if (_applyingConsoleView) return;
        var newMode =
            ReferenceEquals(sender, ViewRight) ? ConsolePosition.Right :
            ReferenceEquals(sender, ViewWindow) ? ConsolePosition.Window :
            ConsolePosition.Bottom;
        if (newMode == _consoleMode) return;

        SetConsoleMode(newMode);
        SettingsManager.Current.ConsolePosition = newMode;
        SettingsManager.Save();
    }

    /// <summary>
    /// Remembers the window width whenever the user resizes while not docked
    /// right, so leaving the right dock restores the right size.
    /// Called from: the SizeChanged hook set up in InitializeConsoleView.
    /// </summary>
    private void Window_SizeChanged(object? sender, SizeChangedEventArgs e)
    {
        if (_resizingForDock) return;
        if (_consoleMode != ConsolePosition.Right && WindowState == WindowState.Normal)
            _normalWidth = Width;
    }

    /// <summary>
    /// Switches the console mode: grows/shrinks the window for the right dock and
    /// opens/closes the separate window, then re-applies the layout. The main
    /// area keeps its exact width because its column is frozen in right mode.
    /// Called from: ConsoleView_Checked and InitializeConsoleView.
    /// </summary>
    private void SetConsoleMode(ConsolePosition mode)
    {
        bool enteringRight = mode == ConsolePosition.Right && _consoleMode != ConsolePosition.Right;
        bool leavingRight = mode != ConsolePosition.Right && _consoleMode == ConsolePosition.Right;

        _resizingForDock = true;

        if (enteringRight)
        {
            // Freeze the main column to the content width it has in non-right mode
            // (window minus the 20px RootGrid margins and 1px window borders), so
            // it stays identical regardless of which tab is active right now.
            _mainColWidth = Math.Max(200, _normalWidth - 42);
            MinWidth += RightDockExtra;
            if (WindowState == WindowState.Normal)
                Width = _normalWidth + RightDockExtra;
        }
        else if (leavingRight)
        {
            // Lower the minimum BEFORE shrinking, otherwise Width gets clamped to
            // the old (larger) minimum and the window stays wide.
            MinWidth -= RightDockExtra;
            if (WindowState == WindowState.Normal)
                Width = _normalWidth;
        }

        _consoleMode = mode;

        if (mode == ConsolePosition.Window)
            OpenConsoleWindow();
        else
            CloseConsoleWindow();

        ApplyConsoleLayout();
        _resizingForDock = false;
    }

    /// <summary>
    /// Places the ConsoleBorder according to the current mode and tab. On the
    /// Settings tab the console is always hidden so the tab area can expand. In
    /// right mode the main column is frozen to its captured width so it never
    /// stretches; the console column takes the remaining (added) space.
    /// Called from: SetConsoleMode and Tabs_SelectionChanged.
    /// </summary>
    private void ApplyConsoleLayout()
    {
        // History tab: show its own output panel in the bottom row (a separate
        // PanelBrush card, separated from the table card exactly like the main
        // console), and keep the main console hidden.
        HistoryConsoleBorder.Visibility = _onHistoryTab ? Visibility.Visible : Visibility.Collapsed;
        if (_onHistoryTab)
        {
            System.Windows.Controls.Grid.SetRowSpan(ConsoleBorder, 1);
            ConsoleBorder.Visibility = Visibility.Collapsed;
            MainColumn.Width = new GridLength(1, GridUnitType.Star);
            ConsoleColumn.Width = new GridLength(0);
            ConsoleRow.Height = new GridLength(170);
            return;
        }

        bool showInMain = !_consoleHiddenForTab && _consoleMode != ConsolePosition.Window;

        if (showInMain && _consoleMode == ConsolePosition.Bottom)
        {
            System.Windows.Controls.Grid.SetRow(ConsoleBorder, 2);
            System.Windows.Controls.Grid.SetRowSpan(ConsoleBorder, 1);
            System.Windows.Controls.Grid.SetColumn(ConsoleBorder, 0);
            System.Windows.Controls.Grid.SetColumnSpan(ConsoleBorder, 2);
            ConsoleBorder.Margin = new Thickness(0, 16, 0, 0);
            ConsoleBorder.Visibility = Visibility.Visible;
            ConsoleRow.Height = new GridLength(1, GridUnitType.Star);
            MainColumn.Width = new GridLength(1, GridUnitType.Star);
            ConsoleColumn.Width = new GridLength(0);
        }
        else if (showInMain && _consoleMode == ConsolePosition.Right)
        {
            System.Windows.Controls.Grid.SetRow(ConsoleBorder, 0);
            System.Windows.Controls.Grid.SetRowSpan(ConsoleBorder, 3);
            System.Windows.Controls.Grid.SetColumn(ConsoleBorder, 1);
            System.Windows.Controls.Grid.SetColumnSpan(ConsoleBorder, 1);
            ConsoleBorder.Margin = new Thickness(16, 0, 0, 0);
            ConsoleBorder.Visibility = Visibility.Visible;
            ConsoleRow.Height = new GridLength(0);
            // Freeze main to its captured width; console flexes to fill the rest.
            MainColumn.Width = new GridLength(_mainColWidth);
            ConsoleColumn.Width = new GridLength(1, GridUnitType.Star);
        }
        else
        {
            // Window mode or Settings tab: no console in the main grid.
            System.Windows.Controls.Grid.SetRowSpan(ConsoleBorder, 1);
            MainColumn.Width = new GridLength(1, GridUnitType.Star);
            ConsoleBorder.Visibility = Visibility.Collapsed;
            ConsoleRow.Height = new GridLength(0);
            ConsoleColumn.Width = new GridLength(0);
        }
    }

    /// <summary>Opens (or focuses) the separate console window and seeds its text.</summary>
    private void OpenConsoleWindow()
    {
        if (_consoleWindow != null) { _consoleWindow.Activate(); return; }
        _consoleWindow = new ConsoleWindow { Owner = this };
        _consoleWindow.SetText(ConsoleBox.Text);
        _consoleWindow.ClearRequested += () =>
        {
            ConsoleBox.Clear();
            _consoleWindow?.Clear();
        };
        _consoleWindow.OpenLogsRequested += () => OpenLogsFolder_Click(this, new RoutedEventArgs());
        // If the user closes the window, fall back to the bottom dock.
        _consoleWindow.Closed += (_, _) =>
        {
            _consoleWindow = null;
            if (_consoleMode == ConsolePosition.Window)
            {
                _applyingConsoleView = true;
                ViewBottom.IsChecked = true;
                _applyingConsoleView = false;
                SetConsoleMode(ConsolePosition.Bottom);
                SettingsManager.Current.ConsolePosition = ConsolePosition.Bottom;
                SettingsManager.Save();
            }
        };
        _consoleWindow.Show();
    }

    /// <summary>Closes the separate console window if open. Called from: SetConsoleMode.</summary>
    private void CloseConsoleWindow()
    {
        if (_consoleWindow == null) return;
        var w = _consoleWindow;
        _consoleWindow = null; // prevent the Closed handler from switching modes
        w.Close();
    }

    /// <summary>
    /// Applies the persisted console position at startup and checks the matching
    /// title bar toggle. Called from: InitializeAsync.
    /// </summary>
    private void InitializeConsoleView()
    {
        var saved = SettingsManager.Current.ConsolePosition;
        _applyingConsoleView = true;
        (saved switch
        {
            ConsolePosition.Right => ViewRight,
            ConsolePosition.Window => ViewWindow,
            _ => ViewBottom
        }).IsChecked = true;
        _applyingConsoleView = false;

        // Seed the remembered normal width and track later user resizes.
        _normalWidth = Width;
        SizeChanged += Window_SizeChanged;

        // _consoleMode starts at Bottom; SetConsoleMode performs any transition.
        SetConsoleMode(saved);
    }

    /// <summary>
    /// Sets the "(running...)" note next to the clamd.conf header in Settings
    /// based on the live daemon status. Called from: Tabs_SelectionChanged.
    /// </summary>
    private async Task UpdateClamdRunningLabelAsync()
    {
        bool running = await DaemonController.IsRunningAsync(1000);
        ClamdRunningRun.Text = running ? "   (running...)" : "";
    }

    private DateTime _lastDetectionSound = DateTime.MinValue;
    private byte[]? _detectionWav;

    /// <summary>
    /// Plays a soft notification tone when a FOUND line arrives, throttled to
    /// once per second. Uses a quiet, faded sine wave generated in memory
    /// (amplitude controls the volume) so it is gentle and independent of the
    /// Windows sound scheme. Called from: the scan output callback.
    /// </summary>
    private void MaybePlayDetectionSound(string line)
    {
        if (!SettingsManager.Current.SoundOnDetection) return;
        if (!line.EndsWith(" FOUND", StringComparison.Ordinal)) return;
        if ((DateTime.Now - _lastDetectionSound).TotalSeconds < 1) return;
        _lastDetectionSound = DateTime.Now;

        try
        {
            _detectionWav ??= BuildSoftTone();
            var player = new System.Media.SoundPlayer(new System.IO.MemoryStream(_detectionWav));
            player.Play(); // non-blocking, plays on a background thread
        }
        catch { /* sound is optional, never break a scan over it */ }
    }

    /// <summary>
    /// Builds a short, quiet sine-wave WAV (16-bit mono) with fade in/out to
    /// avoid clicks. Cached after the first call. Called from: MaybePlayDetectionSound.
    /// </summary>
    private static byte[] BuildSoftTone()
    {
        const int sampleRate = 44100;
        const double seconds = 0.16;
        const double freq = 587.33;   // D5, soft and unobtrusive
        const double amplitude = 0.14; // low volume
        int samples = (int)(sampleRate * seconds);
        int fade = (int)(sampleRate * 0.012);
        int dataSize = samples * 2;

        using var ms = new System.IO.MemoryStream();
        using var bw = new System.IO.BinaryWriter(ms);
        bw.Write(System.Text.Encoding.ASCII.GetBytes("RIFF"));
        bw.Write(36 + dataSize);
        bw.Write(System.Text.Encoding.ASCII.GetBytes("WAVE"));
        bw.Write(System.Text.Encoding.ASCII.GetBytes("fmt "));
        bw.Write(16);
        bw.Write((short)1);          // PCM
        bw.Write((short)1);          // mono
        bw.Write(sampleRate);
        bw.Write(sampleRate * 2);    // byte rate
        bw.Write((short)2);          // block align
        bw.Write((short)16);         // bits per sample
        bw.Write(System.Text.Encoding.ASCII.GetBytes("data"));
        bw.Write(dataSize);
        for (int i = 0; i < samples; i++)
        {
            double env = 1.0;
            if (i < fade) env = (double)i / fade;
            else if (i > samples - fade) env = (double)(samples - i) / fade;
            double v = Math.Sin(2 * Math.PI * freq * i / sampleRate) * amplitude * env;
            bw.Write((short)(v * short.MaxValue));
        }
        bw.Flush();
        return ms.ToArray();
    }

    /// <summary>Minimizes the window. Called from: title bar minimize button.</summary>
    private void Minimize_Click(object sender, RoutedEventArgs e)
        => WindowState = WindowState.Minimized;

    /// <summary>Toggles maximize/restore. Called from: title bar button.</summary>
    private void MaxRestore_Click(object sender, RoutedEventArgs e)
        => WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;

    /// <summary>Closes the window. Called from: title bar close button.</summary>
    private void Close_Click(object sender, RoutedEventArgs e)
        => Close();

    /// <summary>
    /// Keeps the maximize/restore glyph in sync and compensates for the way a
    /// borderless WindowChrome window overshoots the screen when maximized.
    /// Called from: Window StateChanged event.
    /// </summary>
    private void Window_StateChanged(object sender, EventArgs e)
    {
        bool max = WindowState == WindowState.Maximized;
        // Padding stops the content from being clipped under the screen edges
        // when maximized (WindowChrome extends slightly past the work area).
        WindowRoot.Padding = max ? new Thickness(7) : new Thickness(0);
        MaximizeGlyph.Visibility = max ? Visibility.Collapsed : Visibility.Visible;
        RestoreGlyph.Visibility = max ? Visibility.Visible : Visibility.Collapsed;
        MaxRestoreButton.ToolTip = max ? "Restore" : "Maximize";
    }

    /// <summary>Opens the About dialog. Called from: title bar About button.</summary>
    private void About_Click(object sender, RoutedEventArgs e)
        => new AboutWindow { Owner = this }.ShowDialog();

    /// <summary>
    /// Appends a line to the console box, thread safe for process output events.
    /// Called from: all Core modules via callback parameters.
    /// </summary>
    private void AppendLine(string line)
    {
        Dispatcher.Invoke(() =>
        {
            ConsoleBox.AppendText(line + Environment.NewLine);
            ConsoleBox.ScrollToEnd();
            _consoleWindow?.AppendLine(line);
        });
    }

    /// <summary>
    /// Writes a visual separator with title and time before a new operation,
    /// so consecutive scans/updates/hashes are clearly distinguishable.
    /// Called from: all operation entry points (scan, update, daemon, hash, report).
    /// </summary>
    private void AppendSection(string title)
    {
        if (ConsoleBox.Text.Length > 0) AppendLine("");
        AppendLine($"================ {title} | {DateTime.Now:HH:mm:ss} ================");
    }

    /// <summary>
    /// Opens the Logs directory in Windows Explorer.
    /// Called from: XAML Click binding (Open logs folder).
    /// </summary>
    private void OpenLogsFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Diagnostics.Process.Start("explorer.exe", AppPaths.LogsDir);
        }
        catch (Exception ex)
        {
            AppendLine($"Could not open Logs folder: {ex.Message}");
        }
    }

    /// <summary>
    /// Window close hook: cancels a running scan and force terminates clamd and
    /// any other bundled ClamAV process, so nothing keeps running in the
    /// background after the app is closed. Synchronous so it always completes
    /// before the process exits (the previous async stop could be cut off).
    /// Called from: XAML Closing binding.
    /// </summary>
    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        _scanCts?.Cancel();
        CloseConsoleWindow();
        DaemonController.KillAllOwned();
    }
}
