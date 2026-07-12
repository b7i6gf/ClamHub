using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using ClamHub.Core;
using ClamHub.Models;

namespace ClamHub;

/// <summary>
/// Manages freshclam's DatabaseCustomURL entries: extra ClamAV databases that
/// freshclam downloads on each update in addition to the official ones. The user
/// adds/removes URLs, Saves them to freshclam.conf (via ClamConfFile), and can run
/// "Update now" to fetch them (freshclam) and reliably reload the daemon. Exposes
/// Changed so the caller (Signatures tab) refreshes the DB table after close.
/// Opened from: MainWindow.AddDatabaseUrl_Click.
/// </summary>
public partial class CustomDatabaseUrlWindow : Window
{
    /// <summary>True when the URL list was saved differently or an update ran; the
    /// Signatures tab refreshes its table on close.</summary>
    public bool Changed { get; private set; }

    /// <summary>Unsaved edits to the list (guards close + used by Update now).</summary>
    private bool _dirty;

    /// <summary>Guards against overlapping update runs.</summary>
    private bool _working;

    /// <summary>The URL list as last saved to disk, used to log added/removed URLs to History.</summary>
    private List<string> _savedUrls = new();

    public CustomDatabaseUrlWindow()
    {
        InitializeComponent();
        LoadUrls();
    }

    /// <summary>Loads the current DatabaseCustomURL entries from freshclam.conf. Called from: constructor.</summary>
    private void LoadUrls()
    {
        try
        {
            var conf = ClamConfFile.Load(AppPaths.FreshClamConf);
            UrlList.Items.Clear();
            foreach (var url in conf.GetValues("DatabaseCustomURL"))
                UrlList.Items.Add(url);
            _savedUrls = UrlList.Items.Cast<string>().ToList();
            _dirty = false;
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Could not read freshclam.conf: {ex.Message}";
        }
    }

    /// <summary>Basic URL check: http/https/file scheme and no whitespace. Called from: AddCurrentUrl.</summary>
    private static bool IsValidUrl(string url)
    {
        if (url.Length == 0 || url.Any(char.IsWhiteSpace)) return false;
        return url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || url.StartsWith("file://", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Validates and adds the URL from the input box. Called from: Add button and Enter key.</summary>
    private void AddCurrentUrl()
    {
        string url = UrlInput.Text.Trim();
        if (!IsValidUrl(url))
        {
            StatusText.Text = "Enter a valid http, https or file URL (no spaces).";
            return;
        }
        if (UrlList.Items.Cast<string>().Any(u => u.Equals(url, StringComparison.OrdinalIgnoreCase)))
        {
            StatusText.Text = "That URL is already in the list.";
            return;
        }
        UrlList.Items.Add(url);
        UrlInput.Clear();
        _dirty = true;
        string where = Describe(url);
        StatusText.Text = LooksLikeDbUrl(url)
            ? $"Added {where} (not saved yet)."
            : $"Added {where}, but this URL does not end in a known ClamAV database extension "
              + "(e.g. .ndb, .hdb, .cvd). If it points to a checksum (.sha256) or a web page it will be "
              + "skipped by ClamAV.";
    }

    /// <summary>
    /// Describes a URL as "database-name (domain)", e.g.
    /// "urlhaus_clamav.ndb (urlhaus.abuse.ch)". Falls back to the raw URL when it cannot
    /// be parsed. Called from: AddCurrentUrl and the History lines in SaveUrls.
    /// </summary>
    private static string Describe(string url)
    {
        try
        {
            var uri = new Uri(url);
            string name = System.IO.Path.GetFileName(uri.AbsolutePath);
            if (name.Length == 0) name = url;
            return $"{name} ({uri.Host})";
        }
        catch
        {
            return url;
        }
    }

    /// <summary>Database file extensions a valid DatabaseCustomURL is expected to end in.</summary>
    private static readonly System.Collections.Generic.HashSet<string> DbUrlExtensions =
        new(StringComparer.OrdinalIgnoreCase)
    {
        ".cvd", ".cld", ".hdb", ".hsb", ".mdb", ".msb", ".ndb", ".ldb", ".sdb", ".fp", ".sfp",
        ".idb", ".cdb", ".crb", ".gdb", ".pdb", ".wdb", ".ign", ".ign2", ".yar", ".yara", ".cbc", ".cud"
    };

    /// <summary>
    /// Whether the URL's file name (ignoring any query/fragment) ends in a recognised
    /// ClamAV database extension. Used to warn about checksum/HTML URLs. Called from:
    /// AddCurrentUrl.
    /// </summary>
    private static bool LooksLikeDbUrl(string url)
    {
        int cut = url.IndexOfAny(new[] { '?', '#' });
        string clean = cut >= 0 ? url[..cut] : url;
        return DbUrlExtensions.Contains(System.IO.Path.GetExtension(clean));
    }

    /// <summary>Add button. Called from: XAML Click binding.</summary>
    private void Add_Click(object sender, RoutedEventArgs e) => AddCurrentUrl();

    /// <summary>Adds on Enter in the input box. Called from: XAML KeyDown binding.</summary>
    private void UrlInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) AddCurrentUrl();
    }

    /// <summary>Removes the selected URL(s) from the list. Called from: Remove selected button.</summary>
    private void RemoveSelected_Click(object sender, RoutedEventArgs e)
    {
        if (UrlList.SelectedItems.Count == 0)
        {
            StatusText.Text = "Select one or more URLs to remove.";
            return;
        }
        foreach (var it in UrlList.SelectedItems.Cast<object>().ToList())
            UrlList.Items.Remove(it);
        _dirty = true;
        StatusText.Text = "Removed (not saved yet).";
    }

    /// <summary>Save button. Called from: XAML Click binding.</summary>
    private void Save_Click(object sender, RoutedEventArgs e) => SaveUrls(report: true);

    /// <summary>
    /// Writes the current list to freshclam.conf: removes all existing
    /// DatabaseCustomURL lines then appends the current ones. Returns whether it
    /// succeeded. Called from: Save button and Update now.
    /// </summary>
    private bool SaveUrls(bool report)
    {
        try
        {
            var conf = ClamConfFile.Load(AppPaths.FreshClamConf);
            conf.Remove("DatabaseCustomURL");
            foreach (var url in UrlList.Items.Cast<string>())
                conf.AddValue("DatabaseCustomURL", url);
            conf.Save();

            // Log the diff versus the last saved state to History (added / removed URLs).
            var after = UrlList.Items.Cast<string>().ToList();
            var added = after.Where(u => !_savedUrls.Contains(u, StringComparer.OrdinalIgnoreCase)).ToList();
            var removed = _savedUrls.Where(u => !after.Contains(u, StringComparer.OrdinalIgnoreCase)).ToList();
            if (added.Count > 0) LogHistory("database URL added", DescribeLines(added));
            if (removed.Count > 0) LogHistory("database URL removed", DescribeLines(removed));
            _savedUrls = after;

            _dirty = false;
            Changed = true;
            if (report) StatusText.Text = $"Saved {UrlList.Items.Count} URL(s) to freshclam.conf.";
            return true;
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Could not save freshclam.conf: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Turns URLs into History lines: "name (domain)" followed by the full URL, so an
    /// entry shows which database came from where. Called from: SaveUrls.
    /// </summary>
    private static IEnumerable<string> DescribeLines(IEnumerable<string> urls)
    {
        foreach (var url in urls)
        {
            yield return Describe(url);
            yield return "  " + url;
        }
    }

    /// <summary>
    /// Writes a "Databases" History entry (used for added/removed URLs and update runs).
    /// Called from: SaveUrls and UpdateNow_Click. The Signatures tab refreshes the
    /// History list after the window closes.
    /// </summary>
    private static void LogHistory(string result, IEnumerable<string> lines, string process = "")
    {
        HistoryManager.Add(new ScanHistoryEntry
        {
            Timestamp = DateTime.Now,
            Kind = "Databases",
            Target = "",
            Process = process,
            ResultLabel = result,
            Summary = string.Join(Environment.NewLine, lines)
        });
    }

    /// <summary>
    /// Update now: saves the list if needed, runs freshclam to fetch the databases
    /// (streaming output to the log) and then reliably reloads the daemon.
    /// Called from: XAML Click binding.
    /// </summary>
    private async void UpdateNow_Click(object sender, RoutedEventArgs e)
    {
        if (_working) return;
        if (UpdateManager.UpdateInProgress)
        {
            StatusText.Text = "A signature update is already running.";
            return;
        }
        if (_dirty && !SaveUrls(report: false)) return;

        SetWorking(true, "Updating databases (freshclam)...");
        UpdateLog.Clear();

        bool ok;
        try
        {
            ok = await UpdateManager.RunUpdateAsync(AppendLog);
        }
        catch (Exception ex)
        {
            AppendLog($"Update failed: {ex.Message}");
            SetWorking(false, "Update failed.");
            return;
        }

        Changed = true;

        if (ok)
        {
            AppendLog("");
            AppendLog("Reloading the daemon...");
            bool reloaded = await DaemonController.RestartAsync(AppendLog);
            SetWorking(false, reloaded
                ? "Update complete; databases loaded."
                : "Updated, but the daemon reload needs attention.");
        }
        else
        {
            SetWorking(false, "Update finished with errors; see the log.");
        }
    }

    /// <summary>
    /// Appends a line to the update log (marshals to the UI thread since freshclam
    /// output arrives on worker threads). Called from: UpdateNow_Click.
    /// </summary>
    private void AppendLog(string line)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.Invoke(() => AppendLog(line));
            return;
        }
        UpdateLog.AppendText(line + Environment.NewLine);
        UpdateLog.ScrollToEnd();
    }

    /// <summary>
    /// Toggles the busy state: shows/hides the working bar, disables Update now and
    /// optionally sets the status line. Called from: UpdateNow_Click.
    /// </summary>
    private void SetWorking(bool on, string? status)
    {
        _working = on;
        WorkBar.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        UpdateNowButton.IsEnabled = !on;
        if (status != null) StatusText.Text = status;
    }

    /// <summary>
    /// Closes the window, warning first when the list has unsaved edits. Called from:
    /// Close button and the title-bar close button.
    /// </summary>
    private void Close_Click(object sender, RoutedEventArgs e)
    {
        if (_dirty)
        {
            bool discard = new MessageDialog("Unsaved changes",
                "The URL list has unsaved changes. Close without saving?",
                "Close", "Cancel") { Owner = this }.ShowDialog() == true;
            if (!discard) return;
        }
        Close();
    }
}
