using System.Diagnostics;
using System.Threading;
using System.Windows;
using ClamHub.Core;

namespace ClamHub;

/// <summary>
/// Dark dialog that shows the latest ClamHub and ClamAV GitHub releases with
/// their release date, lets the user open the ClamHub release page, and can
/// download and unpack ClamAV into the ClamAV folder. The ClamHub repo is
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
    private GitHubReleaseClient.ReleaseAsset? _clamAvAsset;
    private CancellationTokenSource? _downloadCts;
    private bool _busy;

    /// <summary>True after ClamAV was downloaded and unpacked, so the owner can refresh.</summary>
    public bool ClamAvWasInstalled { get; private set; }

    /// <summary>
    /// Builds the dialog with the currently installed versions to display.
    /// Called from: MainWindow.OpenUpdateCheck.
    /// </summary>
    public UpdateCheckWindow(string clamHubVersion, string? clamAvEngine)
    {
        InitializeComponent();
        _clamHubVersion = clamHubVersion;
        _clamAvEngine = string.IsNullOrWhiteSpace(clamAvEngine) ? "not installed" : clamAvEngine!;
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
        ClamHubLatest.Text = "Latest: checking...";
        ClamAvLatest.Text = "Latest: checking...";

        var clamHubTask = GitHubReleaseClient.GetLatestReleaseAsync(ClamHubOwner, ClamHubRepo);
        var clamAvTask = GitHubReleaseClient.GetLatestReleaseAsync(ClamAvOwner, ClamAvRepo);
        await Task.WhenAll(clamHubTask, clamAvTask);

        ApplyClamHub(clamHubTask.Result);
        ApplyClamAv(clamAvTask.Result);
        SetBusy(false, "");
    }

    /// <summary>Fills the ClamHub card. Called from: CheckAsync.</summary>
    private void ApplyClamHub(GitHubReleaseClient.ReleaseInfo? release)
    {
        if (release == null)
        {
            ClamHubLatest.Text = "Latest: not available (repository is private or has no release).";
            _clamHubUrl = null;
            ClamHubButton.IsEnabled = false;
            return;
        }
        ClamHubLatest.Text = $"Latest: {Describe(release)}";
        _clamHubUrl = string.IsNullOrWhiteSpace(release.HtmlUrl) ? null : release.HtmlUrl;
        ClamHubButton.IsEnabled = _clamHubUrl != null;
    }

    /// <summary>Fills the ClamAV card and locates the portable x64 zip. Called from: CheckAsync.</summary>
    private void ApplyClamAv(GitHubReleaseClient.ReleaseInfo? release)
    {
        if (release == null)
        {
            ClamAvLatest.Text = "Latest: not available (could not reach GitHub).";
            _clamAvAsset = null;
            ClamAvButton.IsEnabled = false;
            return;
        }
        _clamAvAsset = GitHubReleaseClient.FindWindowsX64Zip(release.Assets);
        if (_clamAvAsset == null)
        {
            ClamAvLatest.Text = $"Latest: {Describe(release)} - no Windows x64 package in this release.";
            ClamAvButton.IsEnabled = false;
            return;
        }
        ClamAvLatest.Text = $"Latest: {Describe(release)}";
        ClamAvButton.IsEnabled = true;
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

    /// <summary>Opens the ClamHub release page in the browser. Called from: Release page button.</summary>
    private void ClamHubRelease_Click(object sender, RoutedEventArgs e)
    {
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
    /// Downloads and unpacks the ClamAV portable zip into the ClamAV folder. Warns
    /// first if a different ClamAV install is currently in use (to avoid two
    /// installations), shows download progress, can be cancelled, and closes the
    /// dialog automatically once ClamAV is installed. Called from: the Download button.
    /// </summary>
    private async void ClamAvInstall_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _clamAvAsset == null) return;

        // If a custom ClamAV folder is in use, the download targets ClamHub's own
        // folder instead; warn so the user does not run two installations.
        if (AppPaths.ClamAvDirIsCustom)
        {
            bool go = new MessageDialog(
                "Switch to ClamHub's own ClamAV?",
                $"ClamHub is currently using ClamAV at:\n{AppPaths.ClamAvDir}\n\n" +
                $"Downloading will set up ClamAV in ClamHub's own folder:\n{AppPaths.DefaultClamAvDir}\n\n" +
                "ClamHub will then use that folder. Your other ClamAV folder stays untouched. Continue?",
                "Continue", "Cancel") { Owner = this }.ShowDialog() == true;
            if (!go) return;

            AppPaths.SetClamAvDir(null); // back to the default folder before installing
            SettingsManager.Current.ClamAvPath = null;
            SettingsManager.Save();
            try
            {
                AppPaths.EnsureDirectories();
                ConfigManager.EnsureConfigs();
            }
            catch { /* configs are re-validated after install */ }
        }

        var asset = _clamAvAsset;
        _downloadCts = new CancellationTokenSource();
        SetBusy(true, $"Preparing {asset.Name}...");
        CancelButton.Visibility = Visibility.Visible;
        DaemonController.KillAllOwned(); // release any lock on clamd.exe before overwriting

        bool ok;
        try
        {
            var token = _downloadCts.Token;
            ok = await Task.Run(() => ClamAvInstaller.DownloadAndExtractAsync(
                asset.DownloadUrl, asset.Size,
                msg => Dispatcher.Invoke(() => StatusText.Text = msg),
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
            ClamAvWasInstalled = true;
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
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
