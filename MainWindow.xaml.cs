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
    // Shared descriptor + the value-changed watchers registered by ClampColumnWidths.
    // DependencyPropertyDescriptor.AddValueChanged roots its handlers globally, so the
    // watchers are detached in Window_Closing to avoid the classic leak pattern.
    private static readonly DependencyPropertyDescriptor ColumnWidthDescriptor =
        DependencyPropertyDescriptor.FromProperty(GridViewColumn.WidthProperty, typeof(GridViewColumn));
    private readonly List<(GridViewColumn column, EventHandler handler)> _columnWidthWatchers = new();

    private void ClampColumnWidths(GridView grid, double min)
    {
        foreach (var c in grid.Columns)
        {
            var column = c; // capture this iteration's column
            EventHandler handler = (_, _) =>
            {
                if (column.Width < min)
                    column.Width = min;
            };
            ColumnWidthDescriptor.AddValueChanged(column, handler);
            _columnWidthWatchers.Add((column, handler));
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
        StartDaemonHeartbeat();

        // Start listening for forwarded context menu requests as early as possible
        // (right after the UI is usable), BEFORE the slow signature update below, so
        // a right-click launched during startup can always reach us. Requests that
        // arrive before initialization finishes are queued and drained at the end.
        SingleInstance.StartServer(msg => Dispatcher.Invoke(() => OnForwardedRequest(msg)));

        if (IsElevated())
        {
            AdminRestartButton.IsEnabled = false;
            AdminRestartButton.Content = "Admin mode";
            Title = "ClamHub 1.0.2 (Administrator)";
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

        await RefreshDaemonStatusAsync();

        // Initialization done: run this launch's own action (if any), then any
        // requests that were forwarded by other launches while we were starting up.
        _initComplete = true;

        if (!string.IsNullOrWhiteSpace(App.StartupActionPath))
            await DispatchContextAction(App.StartupActionId ?? "scan", App.StartupActionPath, App.StartupInfectedAction);

        await DrainPendingRequests();

        // "Start daemon on startup" is intentionally LOWER priority: it runs after
        // the launch action above (so a context Compute Hash / VirusTotal / Add to
        // Queue / Exclude is never delayed by it) and in the background, independent
        // of "Prefer daemon for scans".
        _ = StartDaemonOnStartupAsync();
    }

    /// <summary>
    /// Background daemon auto-start on launch (setting "Start daemon on startup").
    /// Runs without the busy guard so it never blocks foreground actions; the
    /// StartAsync lock prevents a double start with a prefer-daemon scan.
    /// Called from: the end of InitializeAsync (fire-and-forget).
    /// </summary>
    private async Task StartDaemonOnStartupAsync()
    {
        try
        {
            if (!SettingsManager.Current.AutoStartDaemon) return;
            if (!await DaemonController.IsRunningAsync())
                await DaemonController.StartAsync(AppendLine);
            await RefreshDaemonStatusAsync();
        }
        catch
        {
            // A failed background start must not crash the app.
        }
    }

    /// <summary>
    /// Handles a request forwarded from a second ClamHub launch: brings this window
    /// to the front and runs the request. Requests that arrive before startup has
    /// finished are queued and drained once InitializeAsync completes, so nothing is
    /// lost. Called from: the SingleInstance pipe server (on the UI thread).
    /// </summary>
    private async void OnForwardedRequest(string message)
    {
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
        Topmost = true; Topmost = false; // nudge to foreground without staying on top

        if (!SingleInstance.TryParseRequest(message, out var actionId, out var path, out var infected))
            return;

        if (!_initComplete)
        {
            _pendingRequests.Add((actionId, path, infected));
            return;
        }
        await DispatchContextAction(actionId, path, infected);
    }

    /// <summary>
    /// Runs any context requests that were forwarded while the app was still
    /// initializing (see OnForwardedRequest). Called from: the end of InitializeAsync.
    /// </summary>
    private async Task DrainPendingRequests()
    {
        if (_pendingRequests.Count == 0) return;
        var pending = _pendingRequests.ToList();
        _pendingRequests.Clear();
        foreach (var (id, path, infected) in pending)
            await DispatchContextAction(id, path, infected);
    }

    /// <summary>
    /// Routes a context menu action (by id) to its handler. For "scan", an optional
    /// infected-file action (report/quarantine/remove) overrides the app default for
    /// that scan. New context menu options are added here and in
    /// Core.ContextMenuManager.Actions; nothing else needs to change. Called from:
    /// InitializeAsync (a startup launch), OnForwardedRequest and DrainPendingRequests.
    /// </summary>
    // Serializes context menu actions so several files selected together in Explorer
    // (each launches its own ClamHub process that forwards a request over the pipe)
    // are handled strictly one after another. Without it the async hash/VT handlers
    // interleave at their await points and their console blocks get mixed (all
    // section titles first, then all results). Held only inside DispatchContextAction.
    private readonly System.Threading.SemaphoreSlim _contextActionGate = new(1, 1);

    private async Task DispatchContextAction(string actionId, string path, string? infected = null)
    {
        path = path.Trim().Trim('"');

        // One action at a time: a file's title, calculation and trailing spacing are
        // written as one uninterrupted block before the next file starts. The wait
        // resumes on the UI thread, so all handlers below stay UI-thread safe; the
        // "scan" case returns immediately (only arms the debounce timer) and the
        // startup/DrainPendingRequests callers are already sequential, so no deadlock.
        await _contextActionGate.WaitAsync();
        try
        {
            switch (actionId.ToLowerInvariant())
            {
                case "scan": QueueContextScan(path, ParseInfectedAction(infected)); break;
                case "queue": StartContextMenuAddToQueue(path); break;
                case "hash": await StartContextMenuHash(path); break;
                case "vt": await StartContextMenuVirusTotal(path); break;
                case "exclude": await AddPermanentExclusion(path); break;
                default:
                    AppendSection("CONTEXT MENU");
                    AppendLine($"Unknown context action: {actionId}");
                    break;
            }
        }
        finally
        {
            _contextActionGate.Release();
        }
    }

    /// <summary>
    /// Maps an "--infected" value to the enum, or null when absent/unrecognized (so
    /// the caller uses the app default action). Called from: DispatchContextAction.
    /// </summary>
    private static InfectedFileAction? ParseInfectedAction(string? value)
        => value?.Trim().ToLowerInvariant() switch
        {
            "report" => InfectedFileAction.ReportOnly,
            "quarantine" => InfectedFileAction.Quarantine,
            "remove" => InfectedFileAction.Remove,
            _ => null
        };

    // Context "scan" requests are debounced so a multi-file Explorer selection
    // (which launches ClamHub once per file) is gathered into ONE scan run.
    private readonly List<string> _contextScanPaths = new();
    private InfectedFileAction? _contextScanAction;
    private System.Windows.Threading.DispatcherTimer? _contextScanTimer;

    /// <summary>
    /// Collects a context "Scan with ClamHub" path and (re)arms a short debounce
    /// timer; when a multi-selection fires several launches in quick succession they
    /// all land here and are scanned together on the tick. Called from:
    /// DispatchContextAction (the "scan" case).
    /// </summary>
    private void QueueContextScan(string path, InfectedFileAction? action)
    {
        _contextScanPaths.Add(path);
        if (action.HasValue) _contextScanAction = action;

        _contextScanTimer ??= CreateContextScanTimer();
        _contextScanTimer.Stop();
        _contextScanTimer.Start();
    }

    /// <summary>
    /// Builds the one-shot debounce timer that runs the gathered context-scan paths.
    /// Called from: QueueContextScan (lazily, once).
    /// </summary>
    private System.Windows.Threading.DispatcherTimer CreateContextScanTimer()
    {
        var timer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(600)
        };
        timer.Tick += async (_, _) =>
        {
            timer.Stop();
            var paths = _contextScanPaths.ToList();
            _contextScanPaths.Clear();
            var action = _contextScanAction;
            _contextScanAction = null;
            await RunContextScan(paths, action);
        };
        return timer;
    }

    /// <summary>
    /// Runs the gathered context-scan paths: a single new path onto an empty queue
    /// is scanned directly (classic behavior); otherwise all new paths are appended
    /// to the queue and the whole queue is scanned. An optional infected-file action
    /// overrides the app default (reflected in the action combo so single and queue
    /// scans use it). Called from: the context-scan debounce timer.
    /// </summary>
    private async Task RunContextScan(List<string> paths, InfectedFileAction? action)
    {
        MainTabs.SelectedIndex = 0;
        if (action.HasValue) ActionCombo.SelectedIndex = (int)action.Value;

        // "Prefer daemon for scans" applies ONLY to context menu scans: on -> ensure
        // the daemon (start it if needed); off -> standalone clamscan.
        var daemonMode = SettingsManager.Current.UseDaemon
            ? ScanEngine.DaemonUsage.EnsureDaemon
            : ScanEngine.DaemonUsage.Standalone;

        var valid = paths
            .Where(p => System.IO.File.Exists(p) || System.IO.Directory.Exists(p))
            .Where(p => !_queue.Any(q => q.Equals(p, StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (valid.Count == 0 && _queue.Count == 0)
        {
            AppendSection("SCAN");
            AppendLine("Nothing to scan (paths missing or already queued).");
            return;
        }

        // One new path with an empty queue keeps the classic single-file scan.
        if (_queue.Count == 0 && valid.Count == 1)
        {
            await StartSingleScan(valid[0], daemonMode);
            return;
        }

        foreach (var p in valid) _queue.Add(p);
        UpdateQueueIndicator();

        bool hadProfile = ActiveProfileName != null;
        await RunQueueScan(_queue.ToList(), daemonMode);
        if (hadProfile) SelectNoProfile();
    }

    /// <summary>
    /// Scans a single path directly with the configured default action (no queue).
    /// daemonMode controls whether the daemon is used/started. Called from: RunContextScan.
    /// </summary>
    private async Task StartSingleScan(string path, ScanEngine.DaemonUsage daemonMode)
    {
        MainTabs.SelectedIndex = 0;
        TargetBox.Text = path;
        var options = new ScanEngine.ScanOptions(
            ScanEngine.ScanMode.Path,
            TargetBox.Text,
            (InfectedFileAction)ActionCombo.SelectedIndex,
            SettingsManager.Current.MultiScan,
            ScanEngine.ParseExtensions(ExtensionsBox.Text),
            false,
            _sessionExcludeDirs,
            _sessionExcludeExts,
            _sessionExcludeFiles,
            daemonMode);
        await RunScanGuarded(options);
    }

    /// <summary>
    /// Context menu "Add to Queue": switches to the Scan tab and adds the path to
    /// the scan queue without starting a scan. Called from: DispatchContextAction.
    /// </summary>
    private void StartContextMenuAddToQueue(string path)
    {
        MainTabs.SelectedIndex = 0;
        AppendSection("QUEUE");
        if (!System.IO.File.Exists(path) && !System.IO.Directory.Exists(path))
        {
            AppendLine($"Cannot add to queue, path not found: {path}");
            return;
        }
        if (!_queue.Any(x => x.Equals(path, StringComparison.OrdinalIgnoreCase)))
            _queue.Add(path);
        UpdateQueueIndicator();
        AppendLine($"Added to scan queue ({_queue.Count} total): {path}");
    }

    /// <summary>
    /// Adds several file/folder paths to the scan queue (existing + not already
    /// queued), without starting a scan. Used when multiple items are dropped on the
    /// Scan target. Called from: PathBox_PreviewDrop.
    /// </summary>
    private void AddPathsToQueue(IEnumerable<string> paths)
    {
        MainTabs.SelectedIndex = 0;
        AppendSection("QUEUE");
        int added = 0;
        foreach (var raw in paths)
        {
            var p = raw.Trim().Trim('"');
            if (!System.IO.File.Exists(p) && !System.IO.Directory.Exists(p)) continue;
            if (_queue.Any(x => x.Equals(p, StringComparison.OrdinalIgnoreCase))) continue;
            _queue.Add(p);
            AppendLine($"Added to queue: {p}");
            added++;
        }
        AppendLine(added == 0
            ? "Nothing added (paths missing or already queued)."
            : $"Queue now has {_queue.Count} item(s).");
        UpdateQueueIndicator();
    }

    /// <summary>
    /// Context menu "Compute Hash": switches to the Hash Verifier tab and computes
    /// all hashes of the file (only single files can be hashed).
    /// Called from: DispatchContextAction.
    /// </summary>
    private async Task StartContextMenuHash(string path)
    {
        MainTabs.SelectedIndex = 1; // Hash Verifier tab
        if (!System.IO.File.Exists(path))
        {
            AppendSection("HASH");
            AppendLine($"Hash: not a file (folders cannot be hashed): {path}");
            return;
        }
        HashFileBox.Text = path;
        ExpectedHashBox.Clear();
        SelectHashAlgo("All");
        await ComputeHashAsync(path, "All", "");
    }

    /// <summary>
    /// Context menu "VT Report": switches to the Hash Verifier tab and looks the
    /// file up on VirusTotal (hash only). Requires an API key and a single file;
    /// RunVirusTotalLookup re-checks the key itself.
    /// Called from: DispatchContextAction.
    /// </summary>
    private async Task StartContextMenuVirusTotal(string path)
    {
        MainTabs.SelectedIndex = 1; // Hash Verifier tab
        if (!System.IO.File.Exists(path))
        {
            AppendSection("VIRUSTOTAL");
            AppendLine($"VirusTotal: not a file (folders cannot be looked up): {path}");
            return;
        }
        HashFileBox.Text = path;
        await RunVirusTotalLookup(path, path);
    }

    /// <summary>
    /// Selects the given algorithm in the hash combo by its item content, so the
    /// UI reflects a hash started from the context menu.
    /// Called from: StartContextMenuHash.
    /// </summary>
    private void SelectHashAlgo(string algo)
    {
        foreach (var item in HashAlgoCombo.Items)
            if (item is System.Windows.Controls.ComboBoxItem ci
                && string.Equals(ci.Content?.ToString(), algo, StringComparison.OrdinalIgnoreCase))
            {
                HashAlgoCombo.SelectedItem = item;
                return;
            }
    }

    /// <summary>
    /// Adds one file or folder to the PERSISTENT default exclusions: updates
    /// settings.json (ExcludeFiles for a file, ExcludeDirectories for a folder,
    /// de-duplicated), rewrites the clamd.conf managed block, refreshes the session
    /// copy, and offers a daemon restart when one is running. Mirrors the Settings
    /// ExcludePath flow but for a single path. Called from: DispatchContextAction
    /// (the "Exclude Path" context menu entry).
    /// </summary>
    private async Task AddPermanentExclusion(string path)
    {
        AppendSection("DEFAULT EXCLUSIONS");

        bool isDir = System.IO.Directory.Exists(path);
        bool isFile = System.IO.File.Exists(path);
        if (!isDir && !isFile)
        {
            AppendLine($"Cannot exclude, path not found: {path}");
            return;
        }

        var list = isDir
            ? SettingsManager.Current.ExcludeDirectories
            : SettingsManager.Current.ExcludeFiles;

        if (list.Any(p => p.Equals(path, StringComparison.OrdinalIgnoreCase)))
        {
            AppendLine($"Already in the default exclusions: {path}");
            return;
        }

        // Confirm before writing. This action can be triggered by any local process
        // forwarding an "exclude" request over the pipe (or launching us with an
        // exclude argument), which could silently hide a folder from scans. Making it
        // an explicit prompt closes that and turns a genuine right-click into a
        // deliberate choice. The context-action gate serializes multi-file launches,
        // so prompts appear one at a time rather than stacking.
        var confirm = new MessageDialog(
            "Add permanent exclusion?",
            $"Add this {(isDir ? "folder" : "file")} to the permanent scan exclusions?\n\n{path}\n\n" +
            "Excluded paths are skipped in future scans. Only confirm if you started this yourself.",
            "Add exclusion", "Cancel") { Owner = this };
        if (confirm.ShowDialog() != true)
        {
            AppendLine($"Exclusion cancelled: {path}");
            return;
        }

        list.Add(path);
        SettingsManager.Save();
        ResetSessionExclusions();

        try { ConfigManager.WriteClamdExclusions(); }
        catch (Exception ex) { AppendLine($"clamd.conf update failed: {ex.Message}"); return; }

        AppendLine($"Added {(isDir ? "folder" : "file")} to permanent exclusions: {path}");

        // No modal prompt here: this runs from a (possibly multi-file) context menu
        // launch and could stack dialogs or be shown while another modal window is
        // open, which blocks input. Just note how to apply it.
        if (await DaemonController.IsRunningAsync(1000))
            AppendLine("Note: this applies to standalone 'Scan w/o daemon' scans. For daemon scans, restart the daemon (Stop then Start on the Scan tab).");
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

        // One line only when settings.json could not be read (SettingsManager fell
        // back to defaults). The broken file is left untouched; saving from the
        // Settings tab overwrites it with the current values.
        if (SettingsManager.LoadError != null)
            AppendLine("Settings.json corrupted - defaults reloaded");
        else
            AppendLine("settings.json loaded");
    }

    /// <summary>
    /// Updates the daemon status indicator (dot color and text).
    /// Called from: InitializeAsync, the heartbeat timer and after every guarded action.
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

    private System.Windows.Threading.DispatcherTimer? _daemonHeartbeatTimer;

    /// <summary>
    /// Starts a periodic status refresh so the indicator reflects clamd stopping on
    /// its own (crash, external kill, PC sleep), not only after a user action which
    /// was the previous behavior. Skips a tick while a guarded operation runs (that
    /// path refreshes on its own and IsRunningAsync there would just add noise).
    /// Called from: InitializeAsync.
    /// </summary>
    private void StartDaemonHeartbeat()
    {
        if (_daemonHeartbeatTimer != null) return;
        _daemonHeartbeatTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(5)
        };
        _daemonHeartbeatTimer.Tick += async (_, _) =>
        {
            if (_busy) return;
            await RefreshDaemonStatusAsync();
        };
        _daemonHeartbeatTimer.Start();
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
        SetOutputViewSwitchingEnabled(false); // lock only the pop-out toggle mid-scan (bottom/right stay switchable)
        StartDaemonButton.IsEnabled = StopDaemonButton.IsEnabled = false;
        UpdateButton.IsEnabled = ScanButton.IsEnabled = MemoryScanButton.IsEnabled = false;
        ScanVirusTotalButton.IsEnabled = false;
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            // An operation failed unexpectedly: report it in the console and recover,
            // rather than letting it bubble up as an unhandled (crashing) exception.
            AppendLine($"Operation failed: {ex.Message}");
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
    /// <summary>
    /// Locks/unlocks ONLY the pop-out (Window) output toggle during a scan. Docking
    /// between bottom and right just repositions the same ConsoleBox in the grid, which
    /// is safe mid-scan, so those two toggles stay enabled; only opening/closing the
    /// separate window (which seeds/reparents content) is held until the scan finishes.
    /// Called from: RunGuarded (disable on start, re-enable in finally).
    /// </summary>
    private void SetOutputViewSwitchingEnabled(bool enabled)
    {
        ViewWindow.IsEnabled = enabled;
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

    /// <summary>
    /// Clears the text box referenced by the clicked button's Tag (the X buttons on
    /// the Target, Hash File and Expected boxes). Called from: XAML Click bindings.
    /// </summary>
    private void ClearTextBox_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button { Tag: System.Windows.Controls.TextBox box })
            box.Clear();
    }

    /// <summary>
    /// Opens the small "Choose files / Choose folder" popup under the Scan "File..."
    /// button (a single native dialog cannot pick both files and folders).
    /// Called from: XAML Click binding.
    /// </summary>
    private void ScanBrowse_Click(object sender, RoutedEventArgs e)
        => ScanBrowsePopup.IsOpen = true;

    /// <summary>
    /// Scan "Choose files...": picks one or more files; a single file fills the
    /// Target box, several are added to the queue. Called from: the browse popup.
    /// </summary>
    private void ScanChooseFiles_Click(object sender, RoutedEventArgs e)
    {
        ScanBrowsePopup.IsOpen = false;
        var dialog = new OpenFileDialog { Title = "Select file(s) to scan", Multiselect = true };
        if (dialog.ShowDialog() != true) return;

        if (dialog.FileNames.Length == 1)
            TargetBox.Text = dialog.FileNames[0];
        else if (dialog.FileNames.Length > 1)
            AddPathsToQueue(dialog.FileNames);
    }

    /// <summary>
    /// Scan "Choose folder...": picks a folder or drive into the Target box.
    /// Called from: the browse popup.
    /// </summary>
    private void ScanChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        ScanBrowsePopup.IsOpen = false;
        var dialog = new OpenFolderDialog { Title = "Select folder(s) or drive to scan", Multiselect = true };
        if (dialog.ShowDialog() != true) return;

        if (dialog.FolderNames.Length == 1)
            TargetBox.Text = dialog.FolderNames[0];
        else if (dialog.FolderNames.Length > 1)
            AddPathsToQueue(dialog.FolderNames);
    }

    /// <summary>
    /// Opens the scan queue window; if the user chooses Scan all, scans every
    /// queued file and folder in turn in the main console.
    /// Called from: XAML Click binding (Queue button).
    /// </summary>
    /// <summary>The integrated scan queue (session-persistent). Built via the Target [+] button / Enter
    /// and the queue window; scanned by the global Start scan when not empty.</summary>
    private readonly List<string> _queue = new();

    /// <summary>True once InitializeAsync has finished; gates deferred context requests.</summary>
    private bool _initComplete;

    /// <summary>Context requests forwarded before startup finished; drained afterwards.</summary>
    private readonly List<(string id, string path, string? infected)> _pendingRequests = new();

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
            await RunQueueScan(_queue.ToList(), ScanEngine.DaemonUsage.Auto);
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
    // Cached once so UpdateQueueIndicator does not hit FindResource on every change.
    private System.Windows.Media.Brush? _accentBrush;
    private System.Windows.Media.Brush? _mutedQueueTextBrush;

    private void UpdateQueueIndicator()
    {
        int n = _queue.Count;
        QueueButton.Content = n > 0 ? $"Queue ({n})" : "Queue...";
        _accentBrush ??= (System.Windows.Media.Brush)FindResource("AccentBrush");
        _mutedQueueTextBrush ??= (System.Windows.Media.Brush)FindResource("TextBrush");
        QueueButton.Foreground = n > 0 ? _accentBrush : _mutedQueueTextBrush;
    }

    /// <summary>
    /// Global "Start scan": in-app scan using the daemon only if it already runs
    /// (Auto, never starts it). Called from: XAML Click binding.
    /// </summary>
    private async void Scan_Click(object sender, RoutedEventArgs e)
        => await RunUiScan(ScanEngine.DaemonUsage.Auto);

    /// <summary>
    /// "Scan w/o daemon": same scan but always with standalone clamscan, so per-scan
    /// exclusions take effect. Called from: XAML Click binding.
    /// </summary>
    private async void ScanNoDaemon_Click(object sender, RoutedEventArgs e)
        => await RunUiScan(ScanEngine.DaemonUsage.Standalone);

    /// <summary>
    /// Runs the in-app Scan-tab scan: the whole queue when it has entries, otherwise
    /// a single scan of the Target box. daemonMode is Auto ("Start scan") or
    /// Standalone ("Scan w/o daemon"); in-app scans never start the daemon.
    /// Called from: Scan_Click and ScanNoDaemon_Click.
    /// </summary>
    private async Task RunUiScan(ScanEngine.DaemonUsage daemonMode)
    {
        bool hadProfile = ActiveProfileName != null;

        if (_queue.Count > 0)
        {
            await RunQueueScan(_queue.ToList(), daemonMode);
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
                _sessionExcludeFiles,
                daemonMode);

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
    /// per-scan summary), then prints a combined QUEUE SUMMARY. daemonMode is passed
    /// to each target's scan (Auto for in-app runs, EnsureDaemon/Standalone for a
    /// context menu scan). A cancelled scan stops the rest of the queue. Wrapped in
    /// one RunGuarded. Called from: ScanQueue_Click, RunUiScan and RunContextScan.
    /// </summary>
    private async Task RunQueueScan(IReadOnlyList<string> targets, ScanEngine.DaemonUsage daemonMode)
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
                    _sessionExcludeFiles,
                    daemonMode);

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
                await RecordQueueScan(results, action, extensions, startedAt, DateTime.Now - startedAt, cancelled);

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

        // Heads-up for a whole-drive scan while file counting is on: counting the
        // drive afterwards can add noticeable time and can be disabled in Settings.
        // Emitted upfront so it appears even when the scan is cancelled (P3: inform,
        // never block the feature).
        if (options.Mode == ScanEngine.ScanMode.Path
            && SettingsManager.Current.CountFilesOnDaemonScan
            && !string.IsNullOrWhiteSpace(options.TargetPath)
            && IsDriveRoot(options.TargetPath!))
            AppendLine("Note: whole-drive scan. Counting files afterwards can take a while; " +
                       "you can turn \"Count files on daemon scans\" off in Settings.");

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

            // clamdscan does not report a scanned-file count; optionally add it by
            // counting the target on a background thread. Skipped on a cancelled scan
            // (result.Error set) so a whole drive the user just aborted is not counted.
            if (result.UsedDaemon && result.Error == null
                && options.Mode == ScanEngine.ScanMode.Path
                && SettingsManager.Current.CountFilesOnDaemonScan
                && !string.IsNullOrWhiteSpace(options.TargetPath))
            {
                int fileCount = await Task.Run(() => SafeCountFiles(options.TargetPath));
                AppendLine($"Files in target: {fileCount}");
            }

            AppendLine($"Result:   {(result.Error == "Cancelled" ? "CANCELLED" : result.ExitCode switch
            {
                0 => "CLEAN",
                1 => "INFECTIONS FOUND",
                _ => $"COMPLETED WITH ERRORS (exit code {result.ExitCode}, see log)"
            })}");

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
            if (record) await RecordScan(options, result, watch.Elapsed, startedAt);

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
    /// True when the path is a drive root like "C:\" (a whole-drive scan target),
    /// where counting files is expensive. Called from: ScanOneAsync's file count.
    /// </summary>
    private static bool IsDriveRoot(string path)
    {
        try
        {
            var full = System.IO.Path.GetFullPath(path);
            var root = System.IO.Path.GetPathRoot(full);
            return !string.IsNullOrEmpty(root) &&
                   string.Equals(
                       full.TrimEnd(System.IO.Path.DirectorySeparatorChar),
                       root.TrimEnd(System.IO.Path.DirectorySeparatorChar),
                       StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
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
            "Temporary exclusions for this session (reset to the Settings defaults on restart "
            + "or profile change). Exclusions apply to standalone clamscan scans only - use "
            + "'Scan w/o daemon'; daemon scans ignore them. Drag files or folders in to add them.",
            "Scan exclusions - temporary") { Owner = this };
        if (dialog.ShowDialog() != true) return;

        _sessionExcludeDirs = dialog.ResultDirectories;
        _sessionExcludeFiles = dialog.ResultFiles;
        _sessionExcludeExts = dialog.ResultExtensions;
        AppendSection("SCAN EXCLUSIONS");
        AppendLine($"Session exclusions set: {_sessionExcludeDirs.Count} folder(s), " +
                   $"{_sessionExcludeFiles.Count} file(s), {_sessionExcludeExts.Count} extension(s).");
        AppendLine("Exclusions only take effect with 'Scan w/o daemon' (clamscan); daemon scans ignore them.");
    }

    /// <summary>
    /// Settings page (clamd.conf ExcludePath row): edits the PERSISTENT default
    /// exclusions. Saves them to settings.json, rewrites the clamd.conf block,
    /// resets the session copy and offers a daemon restart.
    /// Called from: the ExcludePath "Manage list..." button.
    /// </summary>
    private void OpenExclusionsFromSettings()
    {
        var dialog = new ExclusionsWindow(
            SettingsManager.Current.ExcludeDirectories,
            SettingsManager.Current.ExcludeFiles,
            SettingsManager.Current.ExcludeExtensions,
            "Default exclusions and the starting point for scan-session exclusions. They apply "
            + "to standalone clamscan scans ('Scan w/o daemon'); daemon scans ignore per-scan "
            + "exclusions. Drag files or folders in to add them.",
            "Scan exclusions - default")
            { Owner = this };
        if (dialog.ShowDialog() != true) return;

        SettingsManager.Current.ExcludeDirectories = dialog.ResultDirectories;
        SettingsManager.Current.ExcludeFiles = dialog.ResultFiles;
        SettingsManager.Current.ExcludeExtensions = dialog.ResultExtensions;
        SettingsManager.Save();
        ResetSessionExclusions();

        try { ConfigManager.WriteClamdExclusions(); }
        catch (Exception ex) { SetSettingsStatus($"clamd.conf update failed: {ex.Message}", "DangerBrush"); return; }

        // No daemon-restart prompt/console note here: exclusions do not affect daemon
        // scans (they only apply to standalone "Scan w/o daemon").
        SetSettingsStatus("Default exclusions saved.", "OkBrush");
    }

    /// <summary>Cancels the running scan. Called from: XAML Click binding.</summary>
    private void CancelScan_Click(object sender, RoutedEventArgs e)
        => _scanCts?.Cancel();

    /// <summary>
    /// Allows file drops on path text boxes (TextBox blocks drops by default). The
    /// Hash box accepts files only, so a folder-only drop is rejected here to show
    /// the "no drop" cursor. Called from: XAML PreviewDragOver of TargetBox and HashFileBox.
    /// </summary>
    private void PathBox_PreviewDragOver(object sender, DragEventArgs e)
    {
        bool allow = e.Data.GetDataPresent(DataFormats.FileDrop);

        if (allow && ReferenceEquals(sender, HashFileBox)
            && e.Data.GetData(DataFormats.FileDrop) is string[] paths)
            allow = paths.Any(p => System.IO.File.Exists(p));

        e.Effects = allow ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    /// <summary>
    /// Handles a file/folder drop: the Hash box takes the first dropped FILE (folders
    /// ignored); the Scan target fills its box for a single item or queues them all
    /// for several. Called from: XAML PreviewDrop of TargetBox and HashFileBox.
    /// </summary>
    private void PathBox_PreviewDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] { Length: > 0 } paths)
            return;
        e.Handled = true;

        // Hash tab: files only. Pick the first dropped file, ignore folders.
        if (ReferenceEquals(sender, HashFileBox))
        {
            var file = paths.FirstOrDefault(p => System.IO.File.Exists(p));
            if (file != null) HashFileBox.Text = file;
            return;
        }

        // Scan target: one item fills the box, several go to the queue.
        if (paths.Length == 1)
            TargetBox.Text = paths[0];
        else
            AddPathsToQueue(paths);
    }

    /// <summary>File picker for the hash tool. Called from: XAML Click binding.</summary>
    private void BrowseHashFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Select file to hash" };
        if (dialog.ShowDialog() == true)
            HashFileBox.Text = dialog.FileName;
    }

    /// <summary>
    /// Reads the file, algorithm and expected value from the Hash tab and computes
    /// the hash. Called from: XAML Click binding of the Compute button.
    /// </summary>
    private async void ComputeHash_Click(object sender, RoutedEventArgs e)
    {
        var path = HashFileBox.Text.Replace("\"", "").Trim();
        string algo = ((System.Windows.Controls.ComboBoxItem)HashAlgoCombo.SelectedItem)
            .Content.ToString()!;
        await ComputeHashAsync(path, algo, ExpectedHashBox.Text);
    }

    /// <summary>
    /// Computes one hash (or all) for a file and, when an expected value is given,
    /// compares them; results go to the console and a history entry is recorded.
    /// Shared so the "Compute Hash" context menu entry produces identical output.
    /// Called from: ComputeHash_Click and StartContextMenuHash.
    /// </summary>
    private async Task ComputeHashAsync(string path, string algo, string expected)
    {
        if (!System.IO.File.Exists(path))
        {
            AppendLine($"Hash: file not found: {path}");
            return;
        }

        ComputeHashButton.IsEnabled = false;
        // Progress bar + Cancel button are shown only for the duration of the hash,
        // so large files give feedback and can be aborted. Progress marshals to the
        // UI thread via Progress<T>.
        _hashCts = new CancellationTokenSource();
        var progress = new Progress<double>(f =>
        {
            HashProgress.IsIndeterminate = false;
            HashProgress.Value = f;
        });
        HashProgress.Value = 0;
        HashProgress.Visibility = Visibility.Visible;
        CancelHashButton.IsEnabled = true;
        try
        {
            var token = _hashCts.Token;
            bool hasExpected = !string.IsNullOrWhiteSpace(expected);
            AppendSection($"HASH  {path}");

            var summary = new System.Text.StringBuilder();
            summary.AppendLine($"File: {path}");
            bool matched = false;

            // Distinguish a genuine read failure from a SHA-3 variant that this
            // Windows build cannot run (SHA-3 needs a recent Windows).
            static string FailMsg(string a) => HashTool.IsSupported(a)
                ? "FAILED (file locked or unreadable)"
                : "not supported on this Windows build";

            if (algo == "All")
            {
                var all = await HashTool.ComputeAllAsync(path, progress, token);
                foreach (var (name, hash) in all)
                {
                    string line = $"{name,-8}: {hash ?? FailMsg(name)}";
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
                var hash = await HashTool.ComputeAsync(path, algo, progress, token);
                if (hash == null)
                {
                    AppendLine($"{algo}: {FailMsg(algo)}");
                    AddHistory("Hash compute", path, "", "compute failed",
                        $"File: {path}{Environment.NewLine}{algo}: {FailMsg(algo)}");
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
        catch (OperationCanceledException)
        {
            AppendLine("Hash cancelled.");
        }
        finally
        {
            HashProgress.Visibility = Visibility.Collapsed;
            CancelHashButton.IsEnabled = false;
            ComputeHashButton.IsEnabled = true;
            _hashCts?.Dispose();
            _hashCts = null;
        }
    }

    /// <summary>Cancellation source for the running hash, or null when idle.</summary>
    private CancellationTokenSource? _hashCts;

    /// <summary>
    /// Cancels the in-progress hash computation. Safe when nothing is running.
    /// Called from: the Hash tab Cancel button.
    /// </summary>
    private void CancelHash_Click(object sender, RoutedEventArgs e) => _hashCts?.Cancel();

    /// <summary>Clears the console box (and the separate window). Called from: XAML Click binding.</summary>
    private void ClearConsole_Click(object sender, RoutedEventArgs e) => ClearConsoleAll();

    /// <summary>
    /// Clears both console views and the backing line list. Called from:
    /// ClearConsole_Click and the separate window's Clear button.
    /// </summary>
    private void ClearConsoleAll()
    {
        lock (_consoleLock) _pendingLines.Clear();
        _consoleLines.Clear();
        _consoleChars = 0;
        _mainRenderChars = 0;
        _mainLineLengths.Clear();
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
    /// <summary>
    /// Looks up a file's SHA256 on VirusTotal (hash only, the file is never
    /// uploaded) and records the verdict. When precomputedSha256 is given it is used
    /// as-is instead of hashing fileToHash - the quarantine path passes the ORIGINAL
    /// hash (de-obfuscated in memory) because the stored .quar bytes are XOR-masked.
    /// Called from: Hash tab, Scan tab and QuarantineVirusTotal_Click.
    /// </summary>
    private async Task RunVirusTotalLookup(string fileToHash, string displayName, string? precomputedSha256 = null)
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
        string? sha256 = precomputedSha256;
        if (sha256 == null)
        {
            AppendLine("Computing SHA256 locally...");
            sha256 = await HashTool.ComputeAsync(fileToHash, "SHA256");
            if (sha256 == null)
            {
                AppendLine("SHA256 computation failed (file locked or unreadable).");
                return;
            }
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
        // The data tables refresh themselves on every add/delete (each mutation calls
        // BindHistory/BindQuarantine), so opening their tab only needs to re-fit the
        // last column to the now-visible viewport; a full rebind/Refresh here is wasted
        // work on every switch.
        if (index == 2) ScheduleFill(QuarantineList, QuarantineGridView);
        else if (index == 3) ScheduleFill(HistoryList, HistoryGridView);

        // Settings (4) and History (3) hide the main output console: Settings uses
        // the full area, History shows its own output console (in the bottom row).
        // Only redo the console layout when that placement actually changes (e.g. to or
        // from Settings/History), not on every switch between console-visible tabs.
        bool newHidden = index == 4 || index == 3;
        bool newHistory = index == 3;
        bool layoutChanged = newHidden != _consoleHiddenForTab || newHistory != _onHistoryTab;
        _onHistoryTab = newHistory;
        _consoleHiddenForTab = newHidden;
        if (layoutChanged) ApplyConsoleLayout();

        // Clear any Settings status message on a tab change so a stale note (e.g.
        // "Diagnostics finished...") does not linger after switching away and back.
        SetSettingsStatus("", null);
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
    private bool _onHistoryTab;
    private bool _consoleHiddenForTab;
    private ConsoleWindow? _consoleWindow;

    /// <summary>Raw console lines, kept so the separate window can be seeded and so
    /// AppendSection can tell whether the console already has content.</summary>
    private readonly List<string> _consoleLines = new();

    // Producer/consumer buffer that decouples log producers (scan output arrives on
    // background threads) from the UI: AppendLine only enqueues here, and a single
    // scheduled FlushConsole drains the whole buffer at once. This replaces the old
    // per-line synchronous Dispatcher.Invoke + per-line ScrollToEnd, which relaid out
    // the RichTextBox on every line and was the main cause of scan-time UI lag.
    private readonly object _consoleLock = new();
    private readonly List<string> _pendingLines = new();
    private bool _flushScheduled;
    // Hard cap on buffered-but-not-yet-rendered lines. Under an output flood (e.g. a
    // full freshclam/clamscan dump faster than the UI can draw) the oldest pending
    // lines are dropped; they would be trimmed off screen almost immediately anyway.
    private const int MaxPendingLines = 5000;
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
        string appVersion = asm != null ? $"{asm.Major}.{asm.Minor}.{asm.Build}" : "1.0.2";

        var dialog = new UpdateCheckWindow(appVersion, _versionInfo?.Engine, AppendLine) { Owner = this };
        dialog.ShowDialog();

        if (dialog.ClamAvWasInstalled)
        {
            AppendSection("CLAMAV SETUP");
            AppendLine("ClamAV was downloaded and unpacked into the ClamAV folder.");
            UpdateClamAvPathDisplay();
            var info = await UpdateManager.GetVersionInfoAsync();
            if (info != null) _versionInfo = info;
            await ValidateConfigAndReportAsync();

            // The install stopped the daemon to unlock clamd.exe. Bring it back if it
            // was running before (or auto-start is on) and a signature database exists
            // to load - clamd cannot start without one (e.g. right after a first-time
            // install, before the initial signature update).
            bool shouldRun = dialog.DaemonWasRunningBeforeInstall || SettingsManager.Current.AutoStartDaemon;
            if (shouldRun && UpdateManager.DatabasesPresent() && !await DaemonController.IsRunningAsync())
            {
                AppendLine("Restarting the daemon after the ClamAV update...");
                await DaemonController.StartAsync(AppendLine);
            }
            await RefreshDaemonStatusAsync();
        }
    }

    /// <summary>
    /// Shown at startup when the ClamAV binaries are missing: asks whether to set
    /// up ClamAV automatically or manually. "Download automatically" opens the
    /// update dialog (which shows the version and release date before downloading);
    /// "Select existing folder" lets the user point at an existing ClamAV folder;
    /// "Cancel" aborts setup and the app continues without ClamAV (set it up later
    /// via Check for updates). Called from: InitializeAsync when version info is
    /// unavailable.
    /// </summary>
    private async Task OfferClamAvSetupAsync()
    {
        AppendSection("CLAMAV SETUP");
        AppendLine("ClamAV was not found.");

        var dialog = new MessageDialog(
            "ClamAV not found",
            "ClamHub could not find ClamAV. Download and set it up automatically, " +
            "or select an existing ClamAV folder on this PC yourself.",
            "Download automatically",
            "Select existing folder",
            "Cancel") { Owner = this };
        dialog.ShowDialog();

        // Use the explicit ClickedButton so "Cancel" (extra) never falls into the
        // "Select existing folder" branch and opens the folder picker.
        if (dialog.ClickedButton == "confirm")
            await ShowUpdateCheckAsync();
        else if (dialog.ClickedButton == "cancel")
            await LocateClamAvFolderAsync();
        else
            AppendLine("Setup cancelled. You can set up ClamAV later via Check for updates.");
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
    /// build, database and config report into the console, and records the full
    /// report as a History entry so it can be reviewed later.
    /// Called from: Maintenance XAML Click binding.
    /// </summary>
    private async void RunDiagnostics_Click(object sender, RoutedEventArgs e)
        => await RunGuarded(async () =>
        {
            AppendSection("DIAGNOSTICS (clamconf)");

            // Capture every line for the History entry while still streaming to the
            // console. The clamconf callback can fire from more than one thread, so
            // guard the builder (AppendLine is already thread-safe).
            var report = new System.Text.StringBuilder();
            var reportLock = new object();
            void Capture(string line)
            {
                AppendLine(line);
                lock (reportLock) report.AppendLine(line);
            }

            if (!ClamConf.Available)
            {
                Capture("clamconf.exe was not found in the ClamAV folder.");
                AddHistory("Diagnostics", "clamconf", "clamconf", "unavailable", report.ToString());
                SetSettingsStatus("clamconf.exe not found; diagnostics unavailable.", "WarnBrush");
                return;
            }

            var result = await ClamConf.RunAsync(ClamConf.ConfigDirArg, Capture);
            if (result.Started)
                Capture($"clamconf finished (exit code {result.ExitCode}).");

            AddHistory("Diagnostics", "clamconf", "clamconf",
                result.Started ? "Diagnosis finished" : "failed to start",
                report.ToString());
            SetSettingsStatus("Diagnostics finished. Full report available in History.", "OkBrush");
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
    /// <summary>
    /// Queues one line for the console. Thread-safe: callable from any thread (scan
    /// output runs on background threads). The line is buffered and a single flush is
    /// scheduled on the UI thread; it does not render synchronously. Called from:
    /// every place that writes to the output console.
    /// </summary>
    private void AppendLine(string line)
    {
        bool schedule = false;
        lock (_consoleLock)
        {
            _pendingLines.Add(line);
            if (_pendingLines.Count > MaxPendingLines)
                _pendingLines.RemoveRange(0, _pendingLines.Count - MaxPendingLines);
            if (!_flushScheduled) { _flushScheduled = true; schedule = true; }
        }
        if (schedule)
            Dispatcher.BeginInvoke(new Action(FlushConsole),
                System.Windows.Threading.DispatcherPriority.Background);
    }

    /// <summary>
    /// Drains the pending-line buffer and renders the whole batch with a single
    /// ScrollToEnd and a single trim. Runs on the UI thread. Called from: AppendLine
    /// (via a scheduled dispatcher callback).
    /// </summary>
    private void FlushConsole()
    {
        string[] batch;
        lock (_consoleLock)
        {
            _flushScheduled = false;
            if (_pendingLines.Count == 0) return;
            batch = _pendingLines.ToArray();
            _pendingLines.Clear();
        }
        foreach (var line in batch)
        {
            _consoleLines.Add(line);
            int len = line.Length + 1;
            _consoleChars += len;        // full history (kept in _consoleLines + pop-out)
            _mainRenderChars += len;     // only what the main box actually renders
            _mainLineLengths.Enqueue(len);
            ConsoleFormatting.AppendLineNoScroll(ConsoleBox, line);
            _consoleWindow?.AppendLineNoScroll(line);
        }
        ConsoleBox.ScrollToEnd();
        _consoleWindow?.ScrollToEnd();
        TrimConsole();
    }

    /// <summary>True if the console shows or has buffered any content. Called from: AppendSection.</summary>
    private bool ConsoleHasContent()
    {
        if (_consoleLines.Count > 0) return true;
        lock (_consoleLock) return _pendingLines.Count > 0;
    }

    // The FULL scroll-back is kept in _consoleLines (plain strings, cheap) so nothing
    // the user produced is lost. Only the last MaxRenderChars are RENDERED into the
    // main ConsoleBox, which is what keeps switching tabs cheap when the log is huge.
    // The pop-out console window mirrors the full history (a "full log" viewer opened
    // on demand). MaxHistoryChars only bounds memory in a pathological session; it is
    // far above the render cap, so normal use keeps the complete scroll-back.
    private const int MaxRenderChars = 15_000;
    private const int MaxHistoryChars = 750_000;
    private int _consoleChars;                            // chars in _consoleLines (full history + pop-out)
    private int _mainRenderChars;                         // chars currently rendered in the main ConsoleBox
    private readonly Queue<int> _mainLineLengths = new(); // per-line lengths of what the main box renders

    /// <summary>
    /// Keeps the console bounded on two levels: the MAIN ConsoleBox renders only the
    /// last MaxRenderChars (so switching tabs stays cheap even with a huge log), while
    /// the full history in _consoleLines and the pop-out window are only capped at the
    /// much larger MaxHistoryChars (a memory safety net). Trims to ~85% so it does not
    /// run on every append. Called from: FlushConsole.
    /// </summary>
    private void TrimConsole()
    {
        // 1. Keep the main rendered box small (this is the tab-switch cost).
        if (_mainRenderChars > MaxRenderChars)
        {
            int target = MaxRenderChars * 85 / 100;
            int removed = 0;
            while (_mainRenderChars > target && _mainLineLengths.Count > 1)
            {
                _mainRenderChars -= _mainLineLengths.Dequeue();
                removed++;
            }
            if (removed > 0)
                ConsoleFormatting.RemoveLeadingLines(ConsoleBox, removed);
        }

        // 2. Bound the full history (and the pop-out, which mirrors it). Rarely hit.
        if (_consoleChars > MaxHistoryChars)
        {
            int target = MaxHistoryChars * 85 / 100;
            int removed = 0;
            while (_consoleChars > target && _consoleLines.Count > 1)
            {
                _consoleChars -= _consoleLines[0].Length + 1;
                _consoleLines.RemoveAt(0);
                removed++;
            }
            if (removed > 0)
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
        if (ConsoleHasContent()) AppendLine("");
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
        // Detach the column-width watchers so their handlers are not left rooted.
        foreach (var (column, handler) in _columnWidthWatchers)
            ColumnWidthDescriptor.RemoveValueChanged(column, handler);
        _columnWidthWatchers.Clear();
        CloseConsoleWindow();
        SaveWindowSize();
        // Leave clamd running when the app is restarting to finish an update, so the
        // fresh instance finds it up; otherwise stop all bundled ClamAV processes.
        if (!SelfUpdater.RestartingForUpdate)
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
