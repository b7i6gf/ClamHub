using System.Diagnostics;
using System.Threading;
using System.Windows;
using ClamHub.Core;

namespace ClamHub;

/// <summary>
/// Dark dialog that shows the latest ClamHub and ClamAV GitHub releases with
/// their release date, lets the user open the ClamHub release page, and can
/// download and unpack ClamAV into the ClamAV folder. Each card carries an amber
/// dot (ClamHubDot/ClamAvDot, same style as the Detections and About dots) that
/// is shown only for the component that really has an update. The ClamHub repo is
/// private for now, so its lookup returns "not available" rather than failing.
/// Created by: MainWindow.OpenUpdateCheck.
/// </summary>
public partial class UpdateCheckWindow : Window
{
    // Repository coordinates. ClamHub is private for now, so the API returns 404.
    private const string ClamHubOwner = "b7i6gf";
    private const string ClamHubRepo = "ClamHub";
    private const string ClamAvOwner = "Cisco-Talos";
    private const string ClamAvRepo = "clamav";

    private readonly string _clamHubVersion;
    private readonly string _clamAvEngine;
    private string? _clamHubUrl;
    private GitHubReleaseClient.ReleaseAsset? _clamHubAsset;
    private bool _clamHubIsZip;
    private bool _clamHubUpgrade;
    private GitHubReleaseClient.ReleaseAsset? _clamAvAsset;
    private bool _clamAvUpdate;
    private CancellationTokenSource? _downloadCts;
    private bool _busy;

    /// <summary>True after ClamAV was downloaded and unpacked, so the owner can refresh.</summary>
    public bool ClamAvWasInstalled { get; private set; }

    /// <summary>Combined result of the last completed check: true when a ClamHub
    /// upgrade or a ClamAV update is available, false when neither is, null while
    /// no check finished or GitHub was unreachable. MainWindow syncs the
    /// About-button dot from this after the dialog closes.</summary>
    public bool? UpdatesAvailable { get; private set; }

    /// <summary>True when clamd was running just before a ClamAV install stopped it to
    /// unlock the files, so the owner knows to restart it after the update.</summary>
    public bool DaemonWasRunningBeforeInstall { get; private set; }

    /// <summary>
    /// Builds the dialog with the currently installed versions to display.
    /// Called from: MainWindow.OpenUpdateCheck.
    /// </summary>
    /// <summary>Optional sink to mirror upgrade progress (incl. the SHA256 integrity
    /// check) into the main window's console, so it leaves a visible record instead
    /// of only the transient status label. Set via the constructor.</summary>
    private readonly Action<string>? _consoleLog;

    public UpdateCheckWindow(string clamHubVersion, string? clamAvEngine, Action<string>? consoleLog = null)
    {
        InitializeComponent();
        _clamHubVersion = clamHubVersion;
        _clamAvEngine = string.IsNullOrWhiteSpace(clamAvEngine) ? "not installed" : clamAvEngine!;
        _consoleLog = consoleLog;
        Loaded += async (_, _) => await CheckAsync();
    }

    /// <summary>
    /// Queries both repositories and fills the cards (version + release date).
    /// Called from: Loaded and the Refresh button.
    /// </summary>
    private async Task CheckAsync()
    {
        if (_busy) return;
        SetBusy(true, "Checking GitHub for the latest releases...");
        ClamHubInstalled.Text = $"Installed: {_clamHubVersion}";
        ClamAvInstalled.Text = $"Installed: {_clamAvEngine}";
        if (_clamAvEngine != "not installed" && !UpdateManager.DatabasesPresent())
            ClamAvInstalled.Text += " - no signature database yet";
        ClamHubLatest.Text = "Latest: checking...";
        ClamAvLatest.Text = "Latest: checking...";
        // Clear both card dots up front so a previous result (or a Refresh after
        // an install) never leaves a stale dot visible while the check runs.
        ClamHubDot.Visibility = Visibility.Collapsed;
        ClamAvDot.Visibility = Visibility.Collapsed;

        var clamHubTask = GitHubReleaseClient.GetLatestReleaseAsync(ClamHubOwner, ClamHubRepo);
        var clamAvTask = GitHubReleaseClient.GetLatestReleaseAsync(ClamAvOwner, ClamAvRepo);
        await Task.WhenAll(clamHubTask, clamAvTask);

        ApplyClamHub(clamHubTask.Result.Release, clamHubTask.Result.Reached);
        ApplyClamAv(clamAvTask.Result.Release, clamAvTask.Result.Reached);
        // null when GitHub was unreachable, so the owner leaves the dot as-is.
        UpdatesAvailable = clamHubTask.Result.Reached || clamAvTask.Result.Reached
            ? _clamHubUpgrade || _clamAvUpdate
            : null;
        SetBusy(false, "");
    }

    /// <summary>
    /// Fills the ClamHub card. When the latest release is newer than the running
    /// version and ships a Windows asset, the button becomes "Upgrade"; otherwise it
    /// stays "Release page". Called from: CheckAsync.
    /// </summary>
    private void ApplyClamHub(GitHubReleaseClient.ReleaseInfo? release, bool reached)
    {
        _clamHubUrl = null;
        _clamHubAsset = null;
        _clamHubUpgrade = false;
        ClamHubButton.Content = "Release Page";
        ClamHubButton.IsEnabled = false;
        if (!reached)
        {
            ClamHubLatest.Text = "Latest: could not reach GitHub.";
            return;
        }
        if (release == null)
        {
            ClamHubLatest.Text = "Latest: not available (repository is private or has no release).";
            return;
        }

        _clamHubUrl = string.IsNullOrWhiteSpace(release.HtmlUrl) ? null : release.HtmlUrl;
        var installedVer = ParseVersion(_clamHubVersion);
        var latestVer = ParseVersion(release.Tag) ?? ParseVersion(release.Name);
        var asset = GitHubReleaseClient.FindClamHubWindowsAsset(release.Assets);

        if (asset != null && installedVer != null && latestVer != null && latestVer > installedVer)
        {
            _clamHubAsset = asset.Value.Asset;
            _clamHubIsZip = asset.Value.IsZip;
            _clamHubUpgrade = true;
            ClamHubDot.Visibility = Visibility.Visible;
            ClamHubLatest.Text = $"Latest: {Describe(release)} - update available: {installedVer} -> {latestVer}.";
            ClamHubButton.Content = "Upgrade";
            ClamHubButton.IsEnabled = true;
            return;
        }

        string text = $"Latest: {Describe(release)}";
        if (installedVer != null && latestVer != null && installedVer >= latestVer)
            text += " You are up to date.";
        ClamHubLatest.Text = text;
        ClamHubButton.IsEnabled = _clamHubUrl != null;
    }

    /// <summary>
    /// Fills the ClamAV card: locates the portable x64 zip, compares the installed
    /// engine version against the latest release, and picks a fitting button label
    /// (Download & set up / Install locally / Update / Reinstall) and hint text for
    /// each situation. Called from: CheckAsync.
    /// </summary>
    private void ApplyClamAv(GitHubReleaseClient.ReleaseInfo? release, bool reached)
    {
        _clamAvAsset = null;
        _clamAvUpdate = false;
        ClamAvButton.IsEnabled = false;
        if (!reached)
        {
            ClamAvLatest.Text = "Latest: could not reach GitHub.";
            return;
        }
        if (release == null)
        {
            ClamAvLatest.Text = "Latest: no release found on GitHub.";
            return;
        }

        string latestLabel = Describe(release);
        _clamAvAsset = GitHubReleaseClient.FindWindowsX64Zip(release.Assets);
        if (_clamAvAsset == null)
        {
            ClamAvLatest.Text = $"Latest: {latestLabel} - no Windows x64 package in this release.";
            return;
        }

        bool installed = _clamAvEngine != "not installed";
        bool custom = AppPaths.ClamAvDirIsCustom;
        var installedVer = ParseVersion(_clamAvEngine);
        var latestVer = ParseVersion(release.Tag) ?? ParseVersion(release.Name);

        string text = $"Latest: {latestLabel}";
        string button;

        if (!installed)
        {
            button = "Download & set up";
        }
        else if (custom)
        {
            // ClamAV is used from an external folder: offer to bring it in-house.
            button = "Install locally";
            text += "\nCurrently using ClamAV from another folder. This installs it into ClamHub's own folder and uses that copy.";
            if (installedVer != null && latestVer != null && installedVer == latestVer)
                text += " Same version, only relocating.";
        }
        else if (installedVer == null || latestVer == null)
        {
            button = "Reinstall";
            text += "\nInstalled in ClamHub's folder. Versions could not be compared.";
        }
        else if (installedVer < latestVer)
        {
            button = "Update";
            _clamAvUpdate = true;
            ClamAvDot.Visibility = Visibility.Visible;
            text += $"\nUpdate available: {installedVer} -> {latestVer}.";
        }
        else if (installedVer == latestVer)
        {
            button = "Reinstall";
            text += $"\nYou already have the latest version ({installedVer}). No update needed.";
        }
        else
        {
            button = "Reinstall";
            text += $"\nYour version ({installedVer}) is newer than the latest release ({latestVer}).";
        }

        ClamAvLatest.Text = text;
        ClamAvButton.Content = button;
        ClamAvButton.IsEnabled = true;
    }

    /// <summary>
    /// Extracts a comparable version from a string such as "ClamAV 1.5.2" or
    /// "clamav-1.5.2" (the first dotted number found), or null when there is none.
    /// Called from: ApplyClamHub, ApplyClamAv and ProbeAsync.
    /// </summary>
    private static Version? ParseVersion(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var m = System.Text.RegularExpressions.Regex.Match(text, @"\d+(?:\.\d+)+");
        return m.Success && Version.TryParse(m.Value, out var v) ? v : null;
    }

    /// <summary>Result of the silent startup probe. Reached is false only when
    /// BOTH GitHub lookups failed; the notes are "installed -> latest" strings
    /// for the console line.</summary>
    public readonly record struct UpdateProbe(
        bool Reached,
        bool ClamHubUpdate, string? ClamHubNote,
        bool ClamAvUpdate, string? ClamAvNote);

    /// <summary>
    /// Silent version probe for the startup update check: queries both
    /// repositories and applies the SAME update semantics as the dialog cards.
    /// ClamHub counts as an update when a newer release ships a Windows asset;
    /// ClamAV counts only in the dialog's "Update" situation (engine installed in
    /// ClamHub's own folder, a Windows x64 zip exists and the installed version is
    /// older). "Not installed", custom-folder and reinstall situations do NOT
    /// count. Touches no UI and throws for no network reason.
    /// Called from: MainWindow.CheckForUpdatesOnStartupAsync.
    /// </summary>
    public static async Task<UpdateProbe> ProbeAsync(string clamHubVersion, string? clamAvEngine)
    {
        var clamHubTask = GitHubReleaseClient.GetLatestReleaseAsync(ClamHubOwner, ClamHubRepo);
        var clamAvTask = GitHubReleaseClient.GetLatestReleaseAsync(ClamAvOwner, ClamAvRepo);
        await Task.WhenAll(clamHubTask, clamAvTask);
        var hub = clamHubTask.Result;
        var av = clamAvTask.Result;
        bool reached = hub.Reached || av.Reached;

        bool hubUpdate = false;
        string? hubNote = null;
        if (hub.Reached && hub.Release != null)
        {
            var installedVer = ParseVersion(clamHubVersion);
            var latestVer = ParseVersion(hub.Release.Tag) ?? ParseVersion(hub.Release.Name);
            var asset = GitHubReleaseClient.FindClamHubWindowsAsset(hub.Release.Assets);
            if (asset != null && installedVer != null && latestVer != null && latestVer > installedVer)
            {
                hubUpdate = true;
                hubNote = $"{installedVer} -> {latestVer}";
            }
        }

        bool avUpdate = false;
        string? avNote = null;
        if (av.Reached && av.Release != null
            && !string.IsNullOrWhiteSpace(clamAvEngine) && !AppPaths.ClamAvDirIsCustom
            && GitHubReleaseClient.FindWindowsX64Zip(av.Release.Assets) != null)
        {
            var installedVer = ParseVersion(clamAvEngine);
            var latestVer = ParseVersion(av.Release.Tag) ?? ParseVersion(av.Release.Name);
            if (installedVer != null && latestVer != null && installedVer < latestVer)
            {
                avUpdate = true;
                avNote = $"{installedVer} -> {latestVer}";
            }
        }

        return new UpdateProbe(reached, hubUpdate, hubNote, avUpdate, avNote);
    }

    /// <summary>Formats "tag (released yyyy-MM-dd)". Called from: ApplyClamHub/ApplyClamAv.</summary>
    private static string Describe(GitHubReleaseClient.ReleaseInfo r)
    {
        string label = string.IsNullOrWhiteSpace(r.Tag) ? r.Name : r.Tag;
        if (string.IsNullOrWhiteSpace(label)) label = "unknown";
        return r.PublishedAt.HasValue
            ? $"{label} (released {r.PublishedAt.Value.ToLocalTime():yyyy-MM-dd})"
            : label;
    }

    /// <summary>
    /// Either upgrades ClamHub (when a newer release with a Windows asset was found)
    /// or opens the release page in the browser. Called from: the ClamHub button.
    /// </summary>
    private async void ClamHubRelease_Click(object sender, RoutedEventArgs e)
    {
        if (_clamHubUpgrade && _clamHubAsset != null)
        {
            await UpgradeClamHubAsync();
            return;
        }
        if (_clamHubUrl == null) return;
        try
        {
            Process.Start(new ProcessStartInfo { FileName = _clamHubUrl, UseShellExecute = true });
        }
        catch
        {
            // Ignore: nothing useful to do if no browser is available.
        }
    }

    /// <summary>
    /// Downloads the new ClamHub build (progress + cancel), swaps it in for the
    /// running exe via SelfUpdater, then relaunches and exits. On any failure the
    /// current version is kept and a readable message is shown. Called from:
    /// ClamHubRelease_Click.
    /// </summary>
    private async Task UpgradeClamHubAsync()
    {
        if (_busy || _clamHubAsset == null) return;

        bool go = new MessageDialog(
            "Upgrade ClamHub?",
            "ClamHub will download the new version, replace the current one, and restart.\n\nContinue?",
            "Continue", "Cancel") { Owner = this }.ShowDialog() == true;
        if (!go) return;

        var asset = _clamHubAsset;
        _downloadCts = new CancellationTokenSource();
        SetBusy(true, $"Preparing {asset.Name}...");
        CancelButton.Visibility = Visibility.Visible;

        // Anchor the upgrade in the main console so the SHA256 integrity result below
        // is visible there (the status label only shows the latest line transiently).
        _consoleLog?.Invoke("");
        _consoleLog?.Invoke($"ClamHub self-upgrade: {asset.Name}");

        string? staged;
        try
        {
            var token = _downloadCts.Token;
            staged = await SelfUpdater.PrepareUpdateAsync(
                asset.DownloadUrl, _clamHubIsZip, asset.Size, asset.Digest,
                msg => Dispatcher.Invoke(() =>
                {
                    StatusText.Text = msg;
                    _consoleLog?.Invoke(msg); // download + "Verifying SHA256..."/"SHA256 verified." etc.
                }),
                (done, total) => Dispatcher.Invoke(() => ShowProgress(done, total)),
                token);
        }
        finally
        {
            CancelButton.Visibility = Visibility.Collapsed;
            BusyBar.IsIndeterminate = true;
            _busy = false;
            BusyBar.Visibility = Visibility.Collapsed;
            RefreshButton.IsEnabled = true;
            ClamAvButton.IsEnabled = _clamAvAsset != null;
        }

        _downloadCts.Dispose();
        _downloadCts = null;

        if (staged == null)
        {
            // PrepareUpdateAsync already set a readable message (cancel/error).
            ClamHubButton.IsEnabled = true;
            return;
        }

        StatusText.Text = "Installing the new version...";
        _consoleLog?.Invoke("Installing the new version...");
        var (ok, error) = SelfUpdater.TrySwap(staged);
        if (!ok)
        {
            try { System.IO.File.Delete(staged); } catch { /* leftover staged file */ }
            string swapMsg = error ?? "Could not replace the current version.";
            StatusText.Text = swapMsg;
            _consoleLog?.Invoke(swapMsg);
            ClamHubButton.IsEnabled = true;
            return;
        }

        // Swap done: start the new exe (which cleans up the old one) and exit.
        StatusText.Text = "Restarting...";
        _consoleLog?.Invoke("Update installed. Restarting...");
        // Keep the daemon alive across the restart: the exit cleanup checks this and
        // skips killing clamd, so the fresh instance finds it already running.
        SelfUpdater.RestartingForUpdate = true;
        try
        {
            SingleInstance.ReleasePrimary();
            Process.Start(new ProcessStartInfo
            {
                FileName = SelfUpdater.CurrentExe,
                UseShellExecute = true,
                Arguments = "--finish-update"
            });
        }
        catch (Exception ex)
        {
            SelfUpdater.RestartingForUpdate = false; // restart failed; normal cleanup applies
            StatusText.Text = $"Could not start the new version: {ex.Message}";
            return;
        }
        Application.Current.Shutdown();
    }

    /// <summary>
    /// Downloads and unpacks the ClamAV portable zip into the ClamAV folder. Warns
    /// first if a different ClamAV install is currently in use (to avoid two
    /// installations), shows download progress, can be cancelled, and closes the
    /// dialog automatically once ClamAV is installed. Called from: the Download button.
    /// </summary>
    private async void ClamAvInstall_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _clamAvAsset == null) return;

        // If ClamAV is used from another folder, this installs a local copy into
        // ClamHub's own folder instead; confirm and switch the active folder first.
        bool wasCustom = AppPaths.ClamAvDirIsCustom;
        if (wasCustom)
        {
            bool go = new MessageDialog(
                "Install ClamAV locally?",
                $"ClamHub is currently using ClamAV at:\n{AppPaths.ClamAvDir}\n\n" +
                $"This installs ClamAV into ClamHub's own folder:\n{AppPaths.DefaultClamAvDir}\n\n" +
                "and uses that copy instead. Your other ClamAV folder stays untouched. Continue?",
                "Continue", "Cancel") { Owner = this }.ShowDialog() == true;
            if (!go) return;

            AppPaths.SetClamAvDir(null); // back to the default folder before installing
            SettingsManager.Current.ClamAvPath = null;
            SettingsManager.Save();
            try { AppPaths.EnsureDirectories(); }
            catch { /* the download will surface a write error if the folder is locked */ }
        }

        var asset = _clamAvAsset;
        _downloadCts = new CancellationTokenSource();
        SetBusy(true, $"Preparing {asset.Name}...");
        CancelButton.Visibility = Visibility.Visible;
        // Remember if the daemon was up before we stop it to unlock clamd.exe, so the
        // owner can bring it back after the update.
        DaemonWasRunningBeforeInstall = await DaemonController.IsRunningAsync();
        DaemonController.KillAllOwned("ClamAV update: releasing the lock on clamd.exe");

        // Anchor the install in the main console so the SHA256 integrity result is
        // visible there (the status label only shows the latest line transiently).
        _consoleLog?.Invoke("");
        _consoleLog?.Invoke($"ClamAV install: {asset.Name}");

        bool ok;
        try
        {
            var token = _downloadCts.Token;
            ok = await Task.Run(() => ClamAvInstaller.DownloadAndExtractAsync(
                asset.DownloadUrl, asset.Size, asset.Digest,
                msg => Dispatcher.Invoke(() =>
                {
                    StatusText.Text = msg;
                    _consoleLog?.Invoke(msg); // download + "Verifying SHA256..."/result + extract
                }),
                (done, total) => Dispatcher.Invoke(() => ShowProgress(done, total)),
                token));
        }
        finally
        {
            CancelButton.Visibility = Visibility.Collapsed;
            BusyBar.IsIndeterminate = true; // reset for next time
            _busy = false;
            BusyBar.Visibility = Visibility.Collapsed;
            RefreshButton.IsEnabled = true;
            ClamHubButton.IsEnabled = _clamHubUrl != null;
        }

        bool cancelled = _downloadCts.IsCancellationRequested;
        _downloadCts.Dispose();
        _downloadCts = null;

        if (ok)
        {
            // Point the configs at the now-local ClamAV folder when we switched.
            if (wasCustom)
            {
                try { ConfigManager.RebuildAllConfigs(true); }
                catch { /* the owner re-validates configs after this dialog closes */ }
            }
            ClamAvWasInstalled = true;
            // The pending update was just installed: clear the card dot and the
            // state the owner reads for its own dots (the dialog closes without
            // re-checking, so nothing else would reset them).
            _clamAvUpdate = false;
            UpdatesAvailable = _clamHubUpgrade;
            ClamAvDot.Visibility = Visibility.Collapsed;
            ClamAvButton.IsEnabled = false;
            StatusText.Text = "ClamAV installed.";
            await Task.Delay(700); // brief confirmation, then close automatically
            Close();
            return;
        }

        StatusText.Text = cancelled
            ? "Download cancelled."
            : (string.IsNullOrEmpty(StatusText.Text) ? "Setup did not complete." : StatusText.Text);
        ClamAvButton.IsEnabled = true;
    }

    /// <summary>
    /// Shows downloaded MB / total MB / percent on the progress bar and status.
    /// Called from: the installer progress callback (on the UI thread).
    /// </summary>
    private void ShowProgress(long downloaded, long? total)
    {
        if (downloaded < 0) // sentinel: switch to the animated bar (e.g. during extraction)
        {
            BusyBar.IsIndeterminate = true;
            return;
        }
        double doneMb = downloaded / 1048576.0;
        if (total is > 0)
        {
            double totalMb = total.Value / 1048576.0;
            int percent = (int)(downloaded * 100 / total.Value);
            BusyBar.IsIndeterminate = false;
            BusyBar.Maximum = 100;
            BusyBar.Value = percent;
            StatusText.Text = $"Downloading: {doneMb:F1} MB / {totalMb:F1} MB ({percent}%)";
        }
        else
        {
            BusyBar.IsIndeterminate = true;
            StatusText.Text = $"Downloading: {doneMb:F1} MB";
        }
    }

    /// <summary>Cancels the running ClamAV download. Called from: the Cancel button.</summary>
    private void CancelDownload_Click(object sender, RoutedEventArgs e)
    {
        _downloadCts?.Cancel();
        StatusText.Text = "Cancelling...";
    }

    /// <summary>Re-runs the GitHub check. Called from: the Refresh button.</summary>
    private async void Refresh_Click(object sender, RoutedEventArgs e) => await CheckAsync();

    /// <summary>
    /// Shows/hides the progress bar, sets the status text, and disables the action
    /// buttons while work runs. Called from: CheckAsync and the install handler.
    /// </summary>
    private void SetBusy(bool busy, string status)
    {
        _busy = busy;
        BusyBar.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        RefreshButton.IsEnabled = !busy;
        if (busy)
        {
            ClamHubButton.IsEnabled = false;
            ClamAvButton.IsEnabled = false;
        }
        if (busy || status.Length > 0) StatusText.Text = status;
    }

    /// <summary>Closes the dialog. Called from: the title bar and footer Close buttons.</summary>
    /// <summary>Minimizes the window. Called from: the title-bar minimize button.</summary>
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
