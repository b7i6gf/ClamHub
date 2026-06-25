using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using ClamHub.Core;
using ClamHub.Models;
using Microsoft.Win32;

namespace ClamHub;

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
    private List<string> _sessionExcludeFiles = new();

    /// <summary>
    /// Resets the scan-session exclusions to the persistent settings defaults.
    /// Called from: InitializeAsync (startup) and on profile change.
    /// </summary>
    private void ResetSessionExclusions()
    {
        _sessionExcludeDirs = new List<string>(SettingsManager.Current.ExcludeDirectories);
        _sessionExcludeExts = new List<string>(SettingsManager.Current.ExcludeExtensions);
        _sessionExcludeFiles = new List<string>(SettingsManager.Current.ExcludeFiles);
    }
    private CancellationTokenSource? _scanCts;

    /// <summary>Latest ClamAV/database version info, shown in the title and the About box.</summary>
    private UpdateManager.VersionInfo? _versionInfo;

    public MainWindow()
    {
        InitializeComponent();
        // Surface non fatal background errors (e.g. a failed save) in the console.
        AppNotifications.ErrorOccurred += OnBackgroundError;
        // Stop table columns from being dragged down to zero width and vanishing.
        ClampColumnWidths(HistoryGridView, MinColumnWidth);
        ClampColumnWidths(QuarantineGridView, MinColumnWidth);
        RestoreWindowSize();
        Loaded += async (_, _) => await InitializeAsync();
    }

    /// <summary>Smallest width (px) a table column may be dragged to.</summary>
    private const double MinColumnWidth = 60;

    /// <summary>
    /// Stops GridView columns from being resized narrower than MinColumnWidth, so a
    /// column cannot be dragged until it disappears. A width watcher on each column
    /// snaps any smaller value back to the minimum. Called from: the constructor.
    /// </summary>
    private static void ClampColumnWidths(GridView grid, double min)
    {
        var descriptor = DependencyPropertyDescriptor.FromProperty(
            GridViewColumn.WidthProperty, typeof(GridViewColumn));
        foreach (var column in grid.Columns)
        {
            descriptor.AddValueChanged(column, (_, _) =>
            {
                if (column.Width < min)
                    column.Width = min;
            });
        }
    }

    /// <summary>
    /// Restores the window to the exact size and on-screen position it had when
    /// last closed, so the user continues in the same state. If the saved position
    /// is no longer visible (e.g. a monitor was disconnected) the window is opened
    /// centered instead, and the size is capped to the whole desktop as a safety
    /// net. Called from: the constructor.
    /// </summary>
    private void RestoreWindowSize()
    {
        var s = SettingsManager.Current;
        bool haveSaved = s.WindowWidth >= MinWidth && s.WindowHeight >= MinHeight;

        if (haveSaved)
        {
            // Keep the exact saved size; only guard against it being larger than
            // every monitor combined (an impossible-to-show window).
            Width = Math.Min(s.WindowWidth, SystemParameters.VirtualScreenWidth);
            Height = Math.Min(s.WindowHeight, SystemParameters.VirtualScreenHeight);

            if (IsOnScreen(s.WindowLeft, s.WindowTop, Width, Height))
            {
                WindowStartupLocation = System.Windows.WindowStartupLocation.Manual;
                Left = s.WindowLeft;
                Top = s.WindowTop;
            }
            // else: leave the XAML CenterScreen so it opens centered.
        }

        if (s.WindowMaximized)
            WindowState = WindowState.Maximized;
    }

    /// <summary>
    /// Returns true if at least a visible strip of the given window rectangle
    /// falls on some monitor, so a position saved on a now-disconnected screen
    /// does not place the window off-screen. Called from: RestoreWindowSize.
    /// </summary>
    private static bool IsOnScreen(double left, double top, double width, double height)
    {
        double vl = SystemParameters.VirtualScreenLeft;
        double vt = SystemParameters.VirtualScreenTop;
        double vr = vl + SystemParameters.VirtualScreenWidth;
        double vb = vt + SystemParameters.VirtualScreenHeight;
        const double strip = 80; // require at least this many px visible
        bool xVisible = left + strip < vr && left + width - strip > vl;
        bool yVisible = top + strip < vb && top + height - strip > vt;
        return xVisible && yVisible;
    }

    /// <summary>
    /// Shows a reported background error in the output console (marshalled to the
    /// UI thread). Called from: AppNotifications.ErrorOccurred.
    /// </summary>
    private void OnBackgroundError(string message)
        => Dispatcher.Invoke(() => AppendLine(message));

    /// <summary>
    /// Startup sequence after the window is visible: show config check results,
    /// query the ClamAV version, optionally run an update and auto start clamd.
    /// Called from: Loaded event in the constructor.
    /// </summary>
    private async Task InitializeAsync()
    {
        ShowConfigStatus();
        ActionCombo.SelectedIndex = (int)SettingsManager.Current.DefaultAction;
        InitializeSettingsTab();
        InitializeProfiles();
        InitializeHistory();
        InitializeQuarantine();
        // Keep the Scan-tab VirusTotal button in sync with the chosen target.
        TargetBox.TextChanged += (_, _) => RefreshVirusTotalButtons();
        RefreshVirusTotalButtons();
        InitializeConsoleView();
        ResetSessionExclusions();
        UpdateQueueIndicator();

        if (IsElevated())
        {
            AdminRestartButton.IsEnabled = false;
            AdminRestartButton.Content = "Admin mode";
            Title = "ClamHub 1.0.0 (Administrator)";
        }

        var info = await UpdateManager.GetVersionInfoAsync();
        _versionInfo = info;

        if (info == null)
        {
            await OfferClamAvSetupAsync();
            // If the user just set up ClamAV, _versionInfo is now populated and the
            // normal startup continues (signature download + daemon start). If it is
            // still missing (manual setup or a failed/declined download), stop here.
            if (_versionInfo == null)
            {
                await RefreshDaemonStatusAsync();
                return;
            }
        }

        if (SettingsManager.Current.UpdateOnStart)
        {
            bool daemonWasRunning = await DaemonController.IsRunningAsync();
            await RunGuarded(() => RunSignatureUpdateAsync());
            // Reload an already running daemon (with retries) so it uses the new DB.
            if (daemonWasRunning)
                await RunGuarded(() => DaemonController.ReloadAsync(AppendLine));
            // Re-query after the update so the About box shows current versions.
            var updated = await UpdateManager.GetVersionInfoAsync();
            if (updated != null) _versionInfo = updated;
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
            SettingsManager.Current.MultiScan,
            ScanEngine.ParseExtensions(ExtensionsBox.Text),
            false,
            _sessionExcludeDirs,
            _sessionExcludeExts,
            _sessionExcludeFiles);
        await RunScanGuarded(options);
    }

    /// <summary>
    /// Writes the ConfigManager results from app startup into the console as
    /// status messages. Called from: InitializeAsync.
    /// </summary>
    private void ShowConfigStatus()
    {
        var c = App.StartupCheck;
        AppendSection("STARTUP");
        AppendLine(c is { FreshClamCreated: true } ? "freshclam.conf created" : "freshclam.conf found");
        AppendLine(c is { ClamdCreated: true } ? "clamd.conf created" : "clamd.conf found");
        AppendLine("settings.json loaded");
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
        SetOutputViewSwitchingEnabled(false); // lock output layout mid-scan
        StartDaemonButton.IsEnabled = StopDaemonButton.IsEnabled = false;
        UpdateButton.IsEnabled = ScanButton.IsEnabled = MemoryScanButton.IsEnabled = false;
        ScanVirusTotalButton.IsEnabled = false;
        try
        {
            await action();
        }
        finally
        {
            _busy = false;
            SetOutputViewSwitchingEnabled(true);
            UpdateButton.IsEnabled = ScanButton.IsEnabled = MemoryScanButton.IsEnabled = true;
            RefreshVirusTotalButtons();
            await RefreshDaemonStatusAsync();
        }
    }

    /// <summary>
    /// Enables or disables the output view toggles (bottom/right/window) so the
    /// output layout cannot be switched mid-scan while the console is streaming.
    /// Tabs stay usable. Called from: RunGuarded.
    /// </summary>
    private void SetOutputViewSwitchingEnabled(bool enabled)
    {
        ViewBottom.IsEnabled = ViewRight.IsEnabled = ViewWindow.IsEnabled = enabled;
    }

    /// <summary>Start daemon button. Called from: XAML Click binding.</summary>
    private async void StartDaemon_Click(object sender, RoutedEventArgs e)
        => await RunGuarded(() => { AppendSection("DAEMON START"); return DaemonController.StartAsync(AppendLine); });

    /// <summary>Stop daemon button. Called from: XAML Click binding.</summary>
    private async void StopDaemon_Click(object sender, RoutedEventArgs e)
        => await RunGuarded(() => { AppendSection("DAEMON STOP"); return DaemonController.StopAsync(AppendLine); });

    /// <summary>
    /// Runs a freshclam signature update. ONLY when no databases exist yet (the
    /// initial download, which is slow) it shows a dark wait window and disables
    /// the main window until the download finishes; routine updates show nothing.
    /// The wait window closes automatically when done. Called from: Update_Click
    /// and the startup update-on-start path.
    /// </summary>
    private async Task<bool> RunSignatureUpdateAsync()
    {
        bool initialCreation = !UpdateManager.DatabasesPresent();
        DbDownloadWindow? wait = null;
        if (initialCreation)
        {
            wait = new DbDownloadWindow { Owner = this };
            wait.Show();
            IsEnabled = false; // gate the whole main window until the first download ends
        }
        try
        {
            return await UpdateManager.RunUpdateAsync(AppendLine);
        }
        finally
        {
            if (wait != null)
            {
                IsEnabled = true;
                wait.CloseForced();
            }
        }
    }

    /// <summary>Update signatures button. Called from: XAML Click binding.</summary>
    private async void Update_Click(object sender, RoutedEventArgs e)
        => await RunGuarded(async () =>
        {
            AppendSection("SIGNATURE UPDATE");
            bool daemonWasRunning = await DaemonController.IsRunningAsync();
            bool ok = await RunSignatureUpdateAsync();
            // A running daemon can briefly refuse connections while it swaps
            // databases; reload it with retries so it picks up the new signatures.
            if (daemonWasRunning)
                await DaemonController.ReloadAsync(AppendLine);
            var info = await UpdateManager.GetVersionInfoAsync();
            if (info != null) _versionInfo = info;
            SetSettingsStatus(
                ok ? "Signature update finished. See the console for details."
                   : "Signature update failed. See the console.",
                ok ? "OkBrush" : "DangerBrush");
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
    /// Opens the scan queue window; if the user chooses Scan all, scans every
    /// queued file and folder in turn in the main console.
    /// Called from: XAML Click binding (Queue button).
    /// </summary>
    /// <summary>The integrated scan queue (session-persistent). Built via the Target [+] button / Enter
    /// and the queue window; scanned by the global Start scan when not empty.</summary>
    private readonly List<string> _queue = new();

    /// <summary>
    /// Opens the queue window seeded with the current queue, syncs any edits back
    /// when it closes, and runs the queue if the window asked to. Called from:
    /// XAML Click binding of the Queue button.
    /// </summary>
    private async void ScanQueue_Click(object sender, RoutedEventArgs e)
    {
        var window = new ScanQueueWindow(_queue) { Owner = this };
        window.ShowDialog();

        _queue.Clear();
        _queue.AddRange(window.Targets); // keep edits made in the window
        UpdateQueueIndicator();

        if (window.ScanRequested && _queue.Count > 0)
        {
            bool hadProfile = ActiveProfileName != null;
            await RunQueueScan(_queue.ToList());
            if (hadProfile) SelectNoProfile();
        }
    }

    /// <summary>
    /// Adds the path currently in the Target box to the queue (skipping a missing
    /// or duplicate path), then clears the box so the next can be entered. On a
    /// missing path the box is left as-is as feedback. Called from: the Target [+]
    /// button and pressing Enter in the Target box.
    /// </summary>
    private void AddTargetToQueue()
    {
        var path = TargetBox.Text.Replace("\"", "").Trim().TrimEnd('\\');
        if (path.Length == 0) return;
        if (!System.IO.File.Exists(path) && !System.IO.Directory.Exists(path))
            return; // not found: keep the text visible, add nothing

        if (!_queue.Any(x => x.Equals(path, StringComparison.OrdinalIgnoreCase)))
            _queue.Add(path);
        TargetBox.Clear();
        UpdateQueueIndicator();
    }

    /// <summary>Target [+] button. Called from: XAML Click binding.</summary>
    private void AddToQueue_Click(object sender, RoutedEventArgs e) => AddTargetToQueue();

    /// <summary>Enter in the Target box adds it to the queue. Called from: XAML KeyDown binding.</summary>
    private void TargetBox_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter)
        {
            AddTargetToQueue();
            e.Handled = true;
        }
    }

    /// <summary>
    /// Updates the Queue button to show the queued count and an accent colour when
    /// the queue is not empty (the visual indicator). Called from: queue changes
    /// and InitializeAsync.
    /// </summary>
    private void UpdateQueueIndicator()
    {
        int n = _queue.Count;
        QueueButton.Content = n > 0 ? $"Queue ({n})" : "Queue...";
        QueueButton.Foreground = (System.Windows.Media.Brush)FindResource(n > 0 ? "AccentBrush" : "TextBrush");
    }

    /// <summary>
    /// Global Start scan: runs the whole queue when it has entries, otherwise a
    /// single scan of the Target box. Called from: XAML Click binding.
    /// </summary>
    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        bool hadProfile = ActiveProfileName != null;

        if (_queue.Count > 0)
        {
            await RunQueueScan(_queue.ToList());
        }
        else
        {
            var options = new ScanEngine.ScanOptions(
                ScanEngine.ScanMode.Path,
                TargetBox.Text,
                (InfectedFileAction)ActionCombo.SelectedIndex,
                SettingsManager.Current.MultiScan,
                ScanEngine.ParseExtensions(ExtensionsBox.Text),
                false,
                _sessionExcludeDirs,
                _sessionExcludeExts,
                _sessionExcludeFiles);

            await RunScanGuarded(options);
        }

        // After a profile scan, drop back to "(-)" which clears the scan tab.
        if (hadProfile) SelectNoProfile();
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
        => await RunGuarded(async () => { await ScanOneAsync(options); });

    /// <summary>
    /// Runs every queued target in turn in the main console (each with its normal
    /// per-scan summary), using the current Scan-tab settings (action, extensions
    /// and session exclusions), then prints a combined QUEUE SUMMARY. A cancelled
    /// scan stops the rest of the queue. Wrapped in one RunGuarded so the whole
    /// batch is a single busy operation. Called from: ScanQueue_Click.
    /// </summary>
    private async Task RunQueueScan(IReadOnlyList<string> targets)
        => await RunGuarded(async () =>
        {
            var action = (InfectedFileAction)ActionCombo.SelectedIndex;
            var extensions = ScanEngine.ParseExtensions(ExtensionsBox.Text);
            var startedAt = DateTime.Now;

            var results = new List<(string Target, ScanEngine.ScanResult Result)>();
            bool cancelled = false;

            foreach (var raw in targets)
            {
                var target = raw.Replace("\"", "").Trim();
                if (target.Length == 0) continue;

                var options = new ScanEngine.ScanOptions(
                    ScanEngine.ScanMode.Path,
                    target,
                    action,
                    SettingsManager.Current.MultiScan,
                    extensions,
                    false,
                    _sessionExcludeDirs,
                    _sessionExcludeExts,
                    _sessionExcludeFiles);

                // record:false - the queue is logged as one combined entry below.
                var result = await ScanOneAsync(options, record: false);
                results.Add((target, result));

                // A user cancellation aborts the remaining targets.
                if (result.Error == "Cancelled") { cancelled = true; break; }
            }

            AppendSection("QUEUE SUMMARY");
            if (results.Count == 0)
                AppendLine("No valid targets in the queue.");
            else
                foreach (var (t, r) in results)
                    AppendLine($"{QueueStatus(r),-24}  {t}");

            // One combined history entry for the whole queue run.
            if (results.Count > 0)
                RecordQueueScan(results, action, extensions, startedAt, DateTime.Now - startedAt, cancelled);

            // Clear the queue after a completed (non-cancelled) run.
            if (!cancelled)
            {
                _queue.Clear();
                UpdateQueueIndicator();
            }
        });

    /// <summary>
    /// Runs a single scan and prints its full output plus the custom summary block
    /// with statistics clamdscan omits (engine, target, duration, result). Returns
    /// the raw ScanResult so a batch run can aggregate it. Does NOT wrap itself in
    /// RunGuarded; the caller does. Called from: RunScanGuarded (single scan) and
    /// RunQueueScan (each queued target).
    /// </summary>
    private async Task<ScanEngine.ScanResult> ScanOneAsync(ScanEngine.ScanOptions options, bool record = true)
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
        var startedAt = DateTime.Now;
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
                return result;
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

            // Persist the scan into the history tab (suppressed for queued targets,
            // which the queue runner records as one combined entry instead).
            if (record) RecordScan(options, result, watch.Elapsed, startedAt);

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

            return result;
        }
        finally
        {
            ScanIndicator.Visibility = Visibility.Collapsed;
            CancelScanButton.IsEnabled = false;
            _scanCts.Dispose();
            _scanCts = null;
        }
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

        // Scan tab: VirusTotal looks up exactly one file, so enable it only when
        // the scan target is a single existing file (a folder cannot be hashed)
        // and no scan is currently running.
        bool targetIsFile = System.IO.File.Exists(TargetBox.Text.Replace("\"", "").Trim());
        ScanVirusTotalButton.IsEnabled = hasKey && targetIsFile && !_busy;
        ScanVirusTotalButton.ToolTip =
            !hasKey ? missingTip
            : targetIsFile ? activeTip
            : "Select a single file as the scan target (folders cannot be looked up on VirusTotal).";
    }

    /// <summary>
    /// Scan tab "Exclusions..." button: edits the TEMPORARY scan-session
    /// exclusions (reset to settings defaults on restart/profile change). These
    /// apply to clamscan runs only and are not persisted.
    /// Called from: XAML Click binding (Exclusions button).
    /// </summary>
    private void Exclusions_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ExclusionsWindow(_sessionExcludeDirs, _sessionExcludeFiles, _sessionExcludeExts,
            "Temporary exclusions for this session. They reset to the Settings defaults "
            + "on restart or profile change, and apply to clamscan scans (the daemon uses "
            + "the defaults from Settings). Drag files or folders in to add them.") { Owner = this };
        if (dialog.ShowDialog() != true) return;

        _sessionExcludeDirs = dialog.ResultDirectories;
        _sessionExcludeFiles = dialog.ResultFiles;
        _sessionExcludeExts = dialog.ResultExtensions;
        AppendSection("SCAN EXCLUSIONS");
        AppendLine($"Session exclusions set: {_sessionExcludeDirs.Count} folder(s), " +
                   $"{_sessionExcludeFiles.Count} file(s), {_sessionExcludeExts.Count} extension(s).");
        AppendLine("Exclusions beyond the Settings defaults make that scan use clamscan; defaults stay on the daemon.");
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
            SettingsManager.Current.ExcludeFiles,
            SettingsManager.Current.ExcludeExtensions,
            "Default exclusions. Always active, including after restart. Used by the "
            + "daemon (via clamd.conf) and as the starting point for scan-session exclusions. "
            + "Drag files or folders in to add them.")
            { Owner = this };
        if (dialog.ShowDialog() != true) return;

        SettingsManager.Current.ExcludeDirectories = dialog.ResultDirectories;
        SettingsManager.Current.ExcludeFiles = dialog.ResultFiles;
        SettingsManager.Current.ExcludeExtensions = dialog.ResultExtensions;
        SettingsManager.Save();
        ResetSessionExclusions();

        try { ConfigManager.WriteClamdExclusions(); }
        catch (Exception ex) { SetSettingsStatus($"clamd.conf update failed: {ex.Message}", "DangerBrush"); return; }

        SetSettingsStatus("Default exclusions saved.", "OkBrush");
        AppendSection("DEFAULT EXCLUSIONS");
        AppendLine($"Saved {dialog.ResultDirectories.Count} folder(s), {dialog.ResultFiles.Count} file(s) " +
                   $"and {dialog.ResultExtensions.Count} extension(s) as defaults.");

        if (await DaemonController.IsRunningAsync(1000))
        {
            if (Confirm("Restart daemon",
                    "Default exclusions saved. The daemon must restart to apply them to daemon scans.\n\nRestart the daemon now?",
                    "Restart", "Not now"))
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
            bool hasExpected = !string.IsNullOrWhiteSpace(expected);
            AppendSection($"HASH  {path}");

            var summary = new System.Text.StringBuilder();
            summary.AppendLine($"File: {path}");
            bool matched = false;

            if (algo == "All")
            {
                var all = await HashTool.ComputeAllAsync(path);
                foreach (var (name, hash) in all)
                {
                    string line = $"{name,-7}: {hash ?? "FAILED (file locked or unreadable)"}";
                    AppendLine(line);
                    summary.AppendLine(line);
                }

                // Compare the expected hash against every algorithm and name the match.
                if (hasExpected)
                {
                    summary.AppendLine($"Expected: {expected.Trim()}");
                    var match = all.FirstOrDefault(kv =>
                        kv.Value != null && HashTool.Matches(kv.Value, expected));
                    matched = match.Key != null;
                    string verdict = matched
                        ? $"MATCH: expected hash equals the {match.Key} hash."
                        : "MISMATCH: expected hash matches none of the computed hashes.";
                    AppendLine(verdict);
                    summary.AppendLine(verdict);
                }
            }
            else
            {
                var hash = await HashTool.ComputeAsync(path, algo);
                if (hash == null)
                {
                    AppendLine($"{algo}: FAILED (file locked or unreadable)");
                    AddHistory("Hash compute", path, "", "compute failed",
                        $"File: {path}{Environment.NewLine}{algo}: FAILED (file locked or unreadable)");
                    return;
                }
                string hline = $"{algo}: {hash}";
                AppendLine(hline);
                summary.AppendLine(hline);

                if (hasExpected)
                {
                    summary.AppendLine($"Expected: {expected.Trim()}");
                    matched = HashTool.Matches(hash, expected);
                    string verdict = matched
                        ? "MATCH: computed hash equals the expected value."
                        : $"MISMATCH: expected {expected.Trim()}";
                    AppendLine(verdict);
                    summary.AppendLine(verdict);
                }
            }

            // A pasted expected hash makes this a comparison; otherwise a plain compute.
            if (hasExpected)
                AddHistory("Hash comparison", path, "",
                    matched ? "successful comparison" : "unsuccessful comparison", summary.ToString());
            else
                AddHistory("Hash compute", path, "", "hash computed", summary.ToString());
        }
        finally
        {
            ComputeHashButton.IsEnabled = true;
        }
    }

    /// <summary>Clears the console box (and the separate window). Called from: XAML Click binding.</summary>
    private void ClearConsole_Click(object sender, RoutedEventArgs e) => ClearConsoleAll();

    /// <summary>
    /// Clears both console views and the backing line list. Called from:
    /// ClearConsole_Click and the separate window's Clear button.
    /// </summary>
    private void ClearConsoleAll()
    {
        _consoleLines.Clear();
        _consoleChars = 0;
        ConsoleFormatting.Clear(ConsoleBox);
        _consoleWindow?.Clear();
    }

    /// <summary>
    /// Scan tab VirusTotal button: looks up the scan target file's SHA256 on
    /// VirusTotal. Enabled only for a single existing file (see
    /// RefreshVirusTotalButtons). Only the hash leaves the machine, never the file.
    /// Called from: XAML Click binding of the Scan-tab VirusTotal button.
    /// </summary>
    private async void ScanVirusTotal_Click(object sender, RoutedEventArgs e)
    {
        var path = TargetBox.Text.Replace("\"", "").Trim();
        ScanVirusTotalButton.IsEnabled = false;
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
            AddHistory("VirusTotal scan", displayName, "VirusTotal", "Unknown to VT",
                $"SHA256: {sha256}{Environment.NewLine}" +
                "Hash unknown to VirusTotal (the file has never been submitted there).");
            return;
        }

        int total = result.Malicious + result.Suspicious + result.Harmless + result.Undetected;
        string verdictLine = $"Verdict: {result.Malicious}/{total} engines flag this file as malicious" +
                             (result.Suspicious > 0 ? $", {result.Suspicious} as suspicious." : ".");
        string cautionLine = result.Malicious == 0
            ? "No engine reports this file as malicious."
            : "CAUTION: at least one engine reports this file as malicious.";
        string link = $"https://www.virustotal.com/gui/file/{sha256.ToLowerInvariant()}";
        AppendLine(verdictLine);
        AppendLine(cautionLine);
        AppendLine($"Details: {link}");

        AddHistory("VirusTotal scan", displayName, "VirusTotal",
            result.Malicious == 0 ? $"Clean (0/{total})" : $"{result.Malicious}/{total} malicious",
            string.Join(Environment.NewLine, new[]
            {
                $"SHA256: {sha256}",
                verdictLine,
                cautionLine,
                $"Details: {link}"
            }));
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
    /// Restarts the GUI by relaunching the running EXE and closing this instance.
    /// Bundled ClamAV processes are stopped by the OnExit/Window_Closing cleanup.
    /// Called from: XAML Click binding (Restart button in Settings Maintenance).
    /// </summary>
    private void Restart_Click(object sender, RoutedEventArgs e)
    {
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
                UseShellExecute = true
            });
            SingleInstance.ReleasePrimary(); // only after the relaunch started
            Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            AppendLine($"Restart failed: {ex.Message}");
        }
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
            SingleInstance.ReleasePrimary(); // only after the elevated relaunch started
            Application.Current.Shutdown();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User declined the UAC prompt, keep the current instance (and its mutex).
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

    /// <summary>
    /// Fixed height (px) of the tab card (the main section) in the default
    /// bottom-console view. The card stays this size while the output console
    /// (a star row) absorbs any extra window height, so dragging the window
    /// taller grows the console rather than the main section. Sized to fit the
    /// scan controls including the progress indicator that appears mid-scan.
    /// </summary>
    private const double MainCardHeight = 270;
    private bool _onSettingsTab;
    private bool _onHistoryTab;
    private bool _consoleHiddenForTab;
    private ConsoleWindow? _consoleWindow;

    /// <summary>Raw console lines, kept so the separate window can be seeded and so
    /// AppendSection can tell whether the console already has content.</summary>
    private readonly List<string> _consoleLines = new();
    private bool _applyingConsoleView;

    // Console geometry when docked on the right. The main area keeps a FIXED width
    // (so dragging the window edge only resizes the console, never the main area)
    // and the console column is a star that grows/shrinks with the window.
    private const double RightConsoleMargin = 16;    // gap between the main card and the console
    private const double RightConsoleDefault = 420;  // console width right after switching to right
    private const double RightConsoleMin = 280;      // smallest the console may shrink to
    private const double RootChromeWidth = 42;       // RootGrid margins (2x20) + window border (2x1)
    private double RightDockGrowth => RightConsoleMargin + RightConsoleDefault;   // width added on enter
    private double RightDockMinGrowth => RightConsoleMargin + RightConsoleMin;    // min extra width
    // Window MinWidth from XAML, captured once so it can be toggled for the dock.
    private double _baseMinWidth;
    // Fixed main-column width while docked right (the base content width).
    private double _mainFixedWidth;

    // Window width while NOT docked right, so we can restore it exactly. Updated
    // on user resize via the SizeChanged hook. Set during construction.
    private double _normalWidth;
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
            // Keep the main area at its base width and add the console to the right;
            // the window can shrink until only the console's minimum remains.
            MinWidth = _baseMinWidth + RightDockMinGrowth;
            if (WindowState == WindowState.Normal)
                Width = _normalWidth + RightDockGrowth;
        }
        else if (leavingRight)
        {
            // Restore the base minimum BEFORE shrinking, otherwise Width gets clamped
            // to the larger right-dock minimum and the window stays wide.
            MinWidth = _baseMinWidth;
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
    /// Places the output console for the current mode and tab. The normal console
    /// and the History output panel share the same docking (bottom or right) via
    /// PositionDockedConsole, so both follow the view setting. On the Settings tab
    /// the console is hidden; in Window mode the normal console moves to a separate
    /// window, but the History panel does not use Window mode and falls back to a
    /// bottom dock. Called from: SetConsoleMode and Tabs_SelectionChanged.
    /// </summary>
    private void ApplyConsoleLayout()
    {
        bool history = _onHistoryTab;
        HistoryConsoleBorder.Visibility = history ? Visibility.Visible : Visibility.Collapsed;

        if (history)
        {
            // The History output follows the same docking as the normal console,
            // except the separate-window mode is not used here: it falls back to a
            // bottom dock. The normal console stays hidden on this tab.
            ConsoleBorder.Visibility = Visibility.Collapsed;
            System.Windows.Controls.Grid.SetRowSpan(ConsoleBorder, 1);
            PositionDockedConsole(HistoryConsoleBorder,
                _consoleMode == ConsolePosition.Right ? ConsolePosition.Right : ConsolePosition.Bottom);
            return;
        }

        bool showInMain = !_consoleHiddenForTab && _consoleMode != ConsolePosition.Window;

        if (showInMain && _consoleMode == ConsolePosition.Bottom)
            PositionDockedConsole(ConsoleBorder, ConsolePosition.Bottom);
        else if (showInMain && _consoleMode == ConsolePosition.Right)
            PositionDockedConsole(ConsoleBorder, ConsolePosition.Right);
        else
        {
            // Window mode or Settings tab: no console in the main grid.
            System.Windows.Controls.Grid.SetRowSpan(ConsoleBorder, 1);
            MainRow.Height = new GridLength(1, GridUnitType.Star);
            TabCardRow.Height = new GridLength(1, GridUnitType.Star);
            MainColumn.Width = new GridLength(1, GridUnitType.Star);
            ConsoleBorder.Visibility = Visibility.Collapsed;
            ConsoleRow.Height = new GridLength(0);
            ConsoleColumn.Width = new GridLength(0);
        }
    }

    /// <summary>
    /// Docks the given console border at the bottom (main card fixed height,
    /// console row grows with the window) or on the right (main column flexes,
    /// console column is a fixed width panel). Shared by the normal output console
    /// and the History output panel so both honor the same view setting.
    /// Called from: ApplyConsoleLayout.
    /// </summary>
    private void PositionDockedConsole(System.Windows.Controls.Border border, ConsolePosition mode)
    {
        if (mode == ConsolePosition.Bottom)
        {
            System.Windows.Controls.Grid.SetRow(border, 2);
            System.Windows.Controls.Grid.SetRowSpan(border, 1);
            System.Windows.Controls.Grid.SetColumn(border, 0);
            System.Windows.Controls.Grid.SetColumnSpan(border, 2);
            border.Margin = new Thickness(0, 16, 0, 0);
            border.Visibility = Visibility.Visible;
            // Main section keeps a fixed height; the console (star row) takes all
            // the extra height so dragging the window taller grows the console.
            MainRow.Height = GridLength.Auto;
            TabCardRow.Height = new GridLength(MainCardHeight);
            ConsoleRow.Height = new GridLength(1, GridUnitType.Star);
            MainColumn.Width = new GridLength(1, GridUnitType.Star);
            ConsoleColumn.Width = new GridLength(0);
        }
        else // Right
        {
            System.Windows.Controls.Grid.SetRow(border, 0);
            System.Windows.Controls.Grid.SetRowSpan(border, 3);
            System.Windows.Controls.Grid.SetColumn(border, 1);
            System.Windows.Controls.Grid.SetColumnSpan(border, 1);
            border.Margin = new Thickness(16, 0, 0, 0);
            border.Visibility = Visibility.Visible;
            // Main keeps a FIXED width; the console (star column) takes the rest,
            // so dragging the window edge resizes only the console. The MinWidth set
            // on entering right stops the shrink once the console reaches its minimum.
            MainRow.Height = new GridLength(1, GridUnitType.Star);
            TabCardRow.Height = new GridLength(1, GridUnitType.Star);
            ConsoleRow.Height = new GridLength(0);
            MainColumn.Width = new GridLength(_mainFixedWidth);
            ConsoleColumn.Width = new GridLength(1, GridUnitType.Star);
        }
    }

    /// <summary>Opens (or focuses) the separate console window and seeds its text.</summary>
    private void OpenConsoleWindow()
    {
        if (_consoleWindow != null) { _consoleWindow.Activate(); return; }
        _consoleWindow = new ConsoleWindow { Owner = this };
        _consoleWindow.SetLines(_consoleLines);
        _consoleWindow.ClearRequested += () => ClearConsoleAll();
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

        // Seed the remembered normal width and track later user resizes. Capture
        // the XAML MinWidth and derive the fixed main width (base content width)
        // before SetConsoleMode can change MinWidth for the right dock.
        _normalWidth = Width;
        _baseMinWidth = MinWidth;
        _mainFixedWidth = Math.Max(200, _baseMinWidth - RootChromeWidth);
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
    {
        var dialog = new AboutWindow(_versionInfo) { Owner = this };
        // Run any follow-up after the dialog closes so its output shows in the console.
        if (dialog.ShowDialog() == true)
        {
            if (dialog.UpdateRequested)
                Update_Click(this, new RoutedEventArgs());
            else if (dialog.CheckUpdatesRequested)
                OpenUpdateCheck();
        }
    }

    /// <summary>App/engine update check button. Called from: Maintenance XAML Click binding and About_Click.</summary>
    private async void OpenUpdateCheck() => await ShowUpdateCheckAsync();

    /// <summary>
    /// Opens the GitHub update dialog (latest ClamHub + ClamAV releases with their
    /// date). If ClamAV was downloaded and unpacked from it, refreshes the version
    /// info and daemon status. Called from: OpenUpdateCheck and OfferClamAvSetupAsync.
    /// </summary>
    private async Task ShowUpdateCheckAsync()
    {
        var asm = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        string appVersion = asm != null ? $"{asm.Major}.{asm.Minor}.{asm.Build}" : "1.0.0";

        var dialog = new UpdateCheckWindow(appVersion, _versionInfo?.Engine) { Owner = this };
        dialog.ShowDialog();

        if (dialog.ClamAvWasInstalled)
        {
            AppendSection("CLAMAV SETUP");
            AppendLine("ClamAV was downloaded and unpacked into the ClamAV folder.");
            UpdateClamAvPathDisplay();
            var info = await UpdateManager.GetVersionInfoAsync();
            if (info != null) _versionInfo = info;
            await ValidateConfigAndReportAsync();
            await RefreshDaemonStatusAsync();
        }
    }

    /// <summary>
    /// Shown at startup when the ClamAV binaries are missing: asks whether to set
    /// up ClamAV automatically or manually. "Download automatically" opens the
    /// update dialog (which shows the version and release date before downloading);
    /// "Set up manually" prints the copy instructions and opens the ClamAV folder.
    /// Neither option cancels anything. Called from: InitializeAsync when version
    /// info is unavailable.
    /// </summary>
    private async Task OfferClamAvSetupAsync()
    {
        AppendSection("CLAMAV SETUP");
        AppendLine("ClamAV was not found.");

        bool auto = new MessageDialog(
            "ClamAV not found",
            "ClamHub could not find ClamAV. Download and set it up automatically, " +
            "or select an existing ClamAV folder on this PC yourself.",
            "Download automatically",
            "Select existing folder") { Owner = this }.ShowDialog() == true;

        if (auto)
            await ShowUpdateCheckAsync();
        else
            await LocateClamAvFolderAsync();
    }

    /// <summary>
    /// Opens a folder picker for the user to select an EXISTING ClamAV folder. If
    /// it holds the ClamAV executables, the app uses that folder, saves the path,
    /// regenerates the configs for the new location and refreshes version + daemon
    /// status. The user never copies files anywhere; an existing install is used in
    /// place. Returns true on success. Called from: OfferClamAvSetupAsync (manual)
    /// and ChangeClamAvFolder_Click (Settings).
    /// </summary>
    private async Task<bool> LocateClamAvFolderAsync()
    {
        var picker = new OpenFolderDialog
        {
            Title = "Select the folder that contains ClamAV (clamd.exe, freshclam.exe, ...)"
        };
        if (System.IO.Directory.Exists(AppPaths.ClamAvDir))
            picker.InitialDirectory = AppPaths.ClamAvDir;
        if (picker.ShowDialog() != true) return false;

        string chosen = picker.FolderName;
        if (!AppPaths.ContainsClamAvBinaries(chosen))
        {
            Inform("ClamAV not found here",
                "The selected folder does not contain the ClamAV executables " +
                "(clamd.exe, clamscan.exe, clamdscan.exe, freshclam.exe). " +
                "Select the folder where ClamAV is installed.");
            return false;
        }

        DaemonController.KillAllOwned(); // stop any daemon running from the old folder
        AppPaths.SetClamAvDir(chosen);
        SettingsManager.Current.ClamAvPath = chosen;
        SettingsManager.Save();

        AppendSection("CLAMAV FOLDER");
        AppendLine("Using ClamAV at: " + chosen);
        try
        {
            AppPaths.EnsureDirectories();
            ConfigManager.RebuildAllConfigs(transferValues: true);
            AppendLine("Configuration updated for this location.");
        }
        catch (Exception ex)
        {
            AppendLine("Could not write the ClamAV configuration here: " + ex.Message);
            AppendLine("If this folder is write-protected, choose a writable location.");
        }

        UpdateClamAvPathDisplay();
        await ValidateConfigAndReportAsync();
        var info = await UpdateManager.GetVersionInfoAsync();
        if (info != null) _versionInfo = info;
        await RefreshDaemonStatusAsync();
        return true;
    }

    /// <summary>Shows the resolved ClamAV folder in Settings. Called from: InitializeSettingsTab and LocateClamAvFolderAsync.</summary>
    private void UpdateClamAvPathDisplay()
    {
        if (ClamAvPathText != null)
            ClamAvPathText.Text = AppPaths.ClamAvDir;
    }

    /// <summary>Settings "Change ClamAV folder" button. Called from: Settings XAML Click binding.</summary>
    private async void ChangeClamAvFolder_Click(object sender, RoutedEventArgs e)
        => await LocateClamAvFolderAsync();

    /// <summary>App/engine update check button. Called from: Maintenance XAML Click binding.</summary>
    private void CheckUpdates_Click(object sender, RoutedEventArgs e) => OpenUpdateCheck();

    /// <summary>
    /// Maintenance "Run diagnostics" button: runs clamconf and dumps its engine,
    /// build, database and config report into the console for troubleshooting.
    /// Called from: Maintenance XAML Click binding.
    /// </summary>
    private async void RunDiagnostics_Click(object sender, RoutedEventArgs e)
        => await RunGuarded(async () =>
        {
            AppendSection("DIAGNOSTICS (clamconf)");
            if (!ClamConf.Available)
            {
                AppendLine("clamconf.exe was not found in the ClamAV folder.");
                SetSettingsStatus("clamconf.exe not found; diagnostics unavailable.", "WarnBrush");
                return;
            }
            var result = await ClamConf.RunAsync(ClamConf.ConfigDirArg, AppendLine);
            if (result.Started)
                AppendLine($"clamconf finished (exit code {result.ExitCode}).");
            SetSettingsStatus("Diagnostics finished. The full output is in the console.", "OkBrush");
        });

    /// <summary>
    /// Runs clamconf against the app's config folder and prints a short summary
    /// (problems, compiled features, per-database signature counts) to the console.
    /// Does nothing useful when clamconf is absent. Called from: after a config
    /// rebuild, a ClamAV folder change and an auto-install.
    /// </summary>
    private async Task ValidateConfigAndReportAsync()
    {
        if (!ClamConf.Available)
        {
            AppendLine("clamconf.exe not present; skipping configuration validation.");
            return;
        }
        AppendLine("Validating configuration (clamconf)...");
        var report = await ClamConf.ValidateAsync();
        if (!report.Ran)
        {
            AppendLine("clamconf could not run; skipping validation.");
            return;
        }

        if (report.Issues.Count == 0)
            AppendLine(report.ExitCode == 0
                ? "Configuration valid."
                : $"No problems parsed, but clamconf exited with code {report.ExitCode}.");
        else
        {
            AppendLine("Configuration problems found:");
            foreach (var issue in report.Issues) AppendLine("  " + issue);
        }

        foreach (var feature in report.Features) AppendLine(feature);

        if (report.Signatures.Count > 0)
        {
            AppendLine("Databases:");
            foreach (var sig in report.Signatures) AppendLine("  " + sig);
        }
    }

    /// <summary>
    /// Shows a custom modal confirm dialog (dark, About-box style) and returns
    /// true when the confirm button is chosen. Replaces the Windows message box.
    /// Called from: delete/restore/restart confirmations across the tabs.
    /// </summary>
    private bool Confirm(string title, string message, string confirmLabel, string cancelLabel)
        => new MessageDialog(title, message, confirmLabel, cancelLabel) { Owner = this }
            .ShowDialog() == true;

    /// <summary>
    /// Shows a custom modal info dialog (dark, About-box style) with a single OK
    /// button. Replaces the Windows message box. Called from: the settings
    /// save-failure path.
    /// </summary>
    private void Inform(string title, string message)
        => new MessageDialog(title, message, "OK", null) { Owner = this }.ShowDialog();

    /// <summary>
    /// Appends a line to the console box, thread safe for process output events.
    /// Called from: all Core modules via callback parameters.
    /// </summary>
    private void AppendLine(string line)
    {
        Dispatcher.Invoke(() =>
        {
            _consoleLines.Add(line);
            _consoleChars += line.Length + 1;
            ConsoleFormatting.AppendLine(ConsoleBox, line);
            _consoleWindow?.AppendLine(line);
            TrimConsole();
        });
    }

    // Upper bound on console text. A full clamconf diagnostics dump is only a few tens
    // of KB, so this keeps many of them while preventing the unbounded growth that
    // slows the RichTextBox down. When exceeded, the oldest lines are dropped.
    private const int MaxConsoleChars = 200_000;
    private int _consoleChars;

    /// <summary>
    /// Drops the oldest lines from both console views once the text passes
    /// MaxConsoleChars, trimming down to ~85% so it does not run on every append.
    /// Called from: AppendLine.
    /// </summary>
    private void TrimConsole()
    {
        if (_consoleChars <= MaxConsoleChars) return;
        int target = MaxConsoleChars * 85 / 100;
        int removed = 0;
        while (_consoleChars > target && _consoleLines.Count > 1)
        {
            _consoleChars -= _consoleLines[0].Length + 1;
            _consoleLines.RemoveAt(0);
            removed++;
        }
        if (removed > 0)
        {
            ConsoleFormatting.RemoveLeadingLines(ConsoleBox, removed);
            _consoleWindow?.RemoveLeadingLines(removed);
        }
    }

    /// <summary>
    /// Writes a visual separator with title and time before a new operation,
    /// so consecutive scans/updates/hashes are clearly distinguishable.
    /// Called from: all operation entry points (scan, update, daemon, hash, report).
    /// </summary>
    private void AppendSection(string title)
    {
        if (_consoleLines.Count > 0) AppendLine("");
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
        SaveWindowSize();
        DaemonController.KillAllOwned();
    }

    /// <summary>
    /// Saves the current window size and position so it can be restored next
    /// launch. Uses the normal (non maximized) restore bounds and the tracked
    /// normal width so the window does not grow or drift each session. Called
    /// from: Window_Closing.
    /// </summary>
    private void SaveWindowSize()
    {
        var s = SettingsManager.Current;
        s.WindowMaximized = WindowState == WindowState.Maximized;

        if (WindowState == WindowState.Maximized)
        {
            // RestoreBounds is the size/position the window had before maximizing.
            s.WindowWidth = RestoreBounds.Width;
            s.WindowHeight = RestoreBounds.Height;
            s.WindowLeft = RestoreBounds.Left;
            s.WindowTop = RestoreBounds.Top;
        }
        else
        {
            // In right-dock mode the window is widened by RightDockGrowth; store the
            // tracked normal width instead so it restores at the right size.
            s.WindowWidth = _consoleMode == ConsolePosition.Right && _normalWidth > 0
                ? _normalWidth : Width;
            s.WindowHeight = Height;
            s.WindowLeft = Left;
            s.WindowTop = Top;
        }

        SettingsManager.Save();
    }
}
