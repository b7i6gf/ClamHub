using System.Windows;
using ClamHub.Core;
using ClamHub.Models;

namespace ClamHub;

/// <summary>
/// Quarantine tab logic: lists isolated files and restores or deletes them.
/// Also provides the post-scan quarantine routine used by the scan flow.
/// Partial class companion to MainWindow.xaml.cs, initialized from InitializeAsync.
/// </summary>
public partial class MainWindow
{
    /// <summary>
    /// Loads quarantine.json and binds the list, wiring the fill-width column.
    /// Called from: MainWindow.InitializeAsync.
    /// </summary>
    private void InitializeQuarantine()
    {
        QuarantineManager.Load();
        BindQuarantine();
        QuarantineList.SizeChanged += (_, _) => ScheduleFill(QuarantineList, QuarantineGridView);
        QuarantineList.IsVisibleChanged += (_, _) => ScheduleFill(QuarantineList, QuarantineGridView);
    }

    /// <summary>Rebinds the quarantine list. Called from: init and every action.</summary>
    private void BindQuarantine()
    {
        QuarantineList.ItemsSource = QuarantineManager.Entries;
        // Force the (sorted) default view to re-read the change-less list so every
        // restore/delete refreshes the table immediately, including the first one.
        System.Windows.Data.CollectionViewSource.GetDefaultView(QuarantineManager.Entries)?.Refresh();
        QuarantineStatus.Text = $"{QuarantineManager.Entries.Count} file(s) in quarantine.";
        ScheduleFill(QuarantineList, QuarantineGridView);
    }

    /// <summary>
    /// Rebinds the quarantine list for callers outside this class (the Detections
    /// window quarantines files too). Called from: DetectionsWindow.Quarantine_Click.
    /// </summary>
    internal void RefreshQuarantineView() => BindQuarantine();

    /// <summary>
    /// Moves the scan's infected files into quarantine (GUI-managed move that
    /// keeps the original path for an exact restore). Returns how many were
    /// moved successfully. Called from: RunScanGuarded after a Quarantine scan.
    /// </summary>
    private int QuarantineInfectedFiles(IReadOnlyList<string> infectedLines)
    {
        int moved = 0, failed = 0;
        foreach (var line in infectedLines)
        {
            if (!ScanEngine.TryParseFoundLine(line, out var path, out var threat))
                continue;
            if (QuarantineManager.Quarantine(path, threat, out var error))
                moved++;
            else
            {
                failed++;
                AppendLine($"Quarantine failed for {path}: {error}");
            }
        }

        if (moved > 0 || failed > 0)
            AppendLine($"Quarantine: {moved} file(s) moved" +
                       (failed > 0 ? $", {failed} failed (see above)." : "."));
        BindQuarantine();
        return moved;
    }

    /// <summary>Reloads the quarantine index. Called from: XAML Click binding.</summary>
    private void RefreshQuarantine_Click(object sender, RoutedEventArgs e)
    {
        QuarantineManager.Load();
        BindQuarantine();
    }

    /// <summary>
    /// Returns a snapshot of the selected quarantine entries (multi-selection with
    /// Ctrl/Shift, v1.0.3.5), with a status hint when nothing is selected.
    /// Called from: the quarantine action handlers.
    /// </summary>
    private List<QuarantineEntry> SelectedQuarantineEntries(string emptyHint)
    {
        var list = QuarantineList.SelectedItems.Cast<QuarantineEntry>().ToList();
        if (list.Count == 0) QuarantineStatus.Text = emptyHint;
        return list;
    }

    /// <summary>Preview text for batch confirmations (up to 5 names). Called from: the quarantine handlers.</summary>
    private static string QuarantinePreview(IReadOnlyList<QuarantineEntry> entries)
    {
        string preview = string.Join("\n", entries.Take(5).Select(x => x.OriginalName));
        if (entries.Count > 5) preview += $"\n...and {entries.Count - 5} more";
        return preview;
    }

    /// <summary>
    /// Restores ONE quarantined file, asking per file before overwriting an
    /// existing target, and writes the console line + History record on success.
    /// Returns true when the file is back at its original path. Called from:
    /// RestoreQuarantine_Click and RestoreWhitelistQuarantine_Click (batch loops).
    /// </summary>
    private bool RestoreOneQuarantine(QuarantineEntry entry)
    {
        bool overwritten = false;
        if (!QuarantineManager.Restore(entry, overwrite: false, out var error))
        {
            // Offer overwrite when the only problem is an existing target file.
            if (error == null || !error.Contains("already exists"))
            {
                AppendLine($"{entry.OriginalName}: restore failed: {error ?? "unknown error"}");
                return false;
            }
            if (!Confirm("Overwrite",
                    $"A file already exists at:\n{entry.OriginalPath}\n\nOverwrite it?",
                    "Overwrite", "Cancel"))
            {
                AppendLine($"{entry.OriginalName}: restore skipped (a file exists at the target).");
                return false;
            }
            if (!QuarantineManager.Restore(entry, overwrite: true, out var overwriteError))
            {
                AppendLine($"{entry.OriginalName}: restore failed: {overwriteError ?? "unknown error"}");
                return false;
            }
            overwritten = true;
        }

        AppendLine($"{entry.OriginalName} restored{(overwritten ? " (overwritten)" : "")} to {entry.OriginalPath}");
        AddHistory("Quarantine action", entry.OriginalPath, "", "Restored",
            $"Restored from quarantine.{Environment.NewLine}" +
            $"File: {entry.OriginalName}{Environment.NewLine}" +
            $"To: {entry.OriginalPath}" +
            (overwritten ? $"{Environment.NewLine}(an existing file was overwritten)" : ""));
        return true;
    }

    /// <summary>
    /// Restores the selected file(s) to their original paths (one combined
    /// confirmation; overwrite conflicts are asked per file). Called from: XAML
    /// Click binding.
    /// </summary>
    private void RestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var entries = SelectedQuarantineEntries("Select one or more files to restore.");
        if (entries.Count == 0) return;

        if (!Confirm("Restore from quarantine",
                $"Restore {entries.Count} file(s) to their original locations?\n\n{QuarantinePreview(entries)}\n\n" +
                "These files were flagged as infected. Restore anyway?",
                "Restore", "Cancel"))
            return;

        AppendSection("QUARANTINE");
        int done = 0;
        foreach (var entry in entries)
            if (RestoreOneQuarantine(entry)) done++;

        BindQuarantine();
        QuarantineStatus.Text = done == entries.Count
            ? $"{done} file(s) restored."
            : $"{done} of {entries.Count} restored (see console).";
    }

    /// <summary>
    /// Permanently deletes the selected quarantined file(s) after one combined
    /// confirmation. Called from: XAML Click binding.
    /// </summary>
    private void DeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var entries = SelectedQuarantineEntries("Select one or more files to delete.");
        if (entries.Count == 0) return;

        if (!Confirm("Delete from quarantine",
                $"Permanently delete {entries.Count} file(s) from quarantine?\n\n{QuarantinePreview(entries)}\n\n" +
                "This cannot be undone.",
                "Delete", "Cancel"))
            return;

        AppendSection("QUARANTINE");
        int done = 0, failed = 0;
        foreach (var entry in entries)
        {
            if (QuarantineManager.Delete(entry, out var error))
            {
                done++;
                AppendLine($"{entry.OriginalName} permanently deleted.");
                AddHistory("Quarantine action", entry.OriginalPath, "", "Removed",
                    $"Permanently removed from quarantine.{Environment.NewLine}" +
                    $"File: {entry.OriginalName}{Environment.NewLine}" +
                    $"Original path: {entry.OriginalPath}");
            }
            else
            {
                failed++;
                AppendLine($"{entry.OriginalName}: delete failed: {error ?? "unknown error"}");
            }
        }

        BindQuarantine();
        QuarantineStatus.Text = failed == 0
            ? $"{done} file(s) permanently deleted."
            : $"{done} deleted, {failed} failed (see console).";
    }

    /// <summary>
    /// Looks up the selected quarantined file on VirusTotal via the ORIGINAL file's
    /// SHA256. The stored copy is XOR-obfuscated, so the hash is recomputed from the
    /// de-obfuscated bytes (in memory only) to match what VT knows. Output goes to
    /// the console. Called from: XAML Click binding (Quarantine VirusTotal).
    /// </summary>
    private async void QuarantineVirusTotal_Click(object sender, RoutedEventArgs e)
    {
        var entries = SelectedQuarantineEntries("Select one or more files to check on VirusTotal.");
        if (entries.Count == 0) return;

        if (entries.Count > 4)
        {
            AppendSection("VIRUSTOTAL");
            AppendLine($"{entries.Count} lookups queued; the free VirusTotal tier allows 4 per minute, so this takes a while.");
        }

        foreach (var entry in entries)
        {
            var sha256 = QuarantineManager.ComputeOriginalSha256(entry, out var error);
            if (sha256 == null)
            {
                AppendSection("VIRUSTOTAL");
                AppendLine($"{entry.OriginalName}: could not read the quarantined file to hash it: {error}");
                continue;
            }
            var stored = System.IO.Path.Combine(AppPaths.QuarantineDir, entry.Id);
            await RunVirusTotalLookup(stored, entry.OriginalName, sha256);
        }
    }

    /// <summary>
    /// Opens the signature search window pre-seeded with the selected entry's threat name
    /// and immediately searches every database for it, so the user can see which databases
    /// carry that detection (and under which names). Read-only: it does not touch the
    /// quarantined file. Called from: the "Compare with databanks" button in the Quarantine
    /// tab (MainWindow.xaml).
    /// </summary>
    private void CompareWithDatabanks_Click(object sender, RoutedEventArgs e)
    {
        // Acts on the FIRST selected entry (one search window per signature).
        if (QuarantineList.SelectedItem is not QuarantineEntry entry)
        {
            QuarantineStatus.Text = "Select a file to compare with the databases.";
            return;
        }

        string threat = (entry.Threat ?? "").Trim();
        if (threat.Length == 0)
        {
            QuarantineStatus.Text = "This entry has no recorded threat name to search for.";
            return;
        }

        // libclamav appends ".UNOFFICIAL" to detections from UNSIGNED databases (plain
        // text .ndb/.hdb etc., i.e. anything that is not a signed .cvd/.cld container).
        // The suffix exists only in scan REPORTS, never inside the database files, so it
        // must be stripped or the search would find nothing.
        const string unofficial = ".UNOFFICIAL";
        if (threat.EndsWith(unofficial, StringComparison.OrdinalIgnoreCase))
            threat = threat[..^unofficial.Length];

        // Non-modal and ownerless (v1.0.3.6), like the Signatures tab's search
        // opener. The constructor runs the search.
        ToolWindows.Show(new SignatureSearchWindow(threat), this);
    }

    /// <summary>Opens the quarantine folder in Explorer. Called from: XAML Click binding.</summary>
    private void OpenQuarantineFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Diagnostics.Process.Start("explorer.exe", AppPaths.QuarantineDir);
        }
        catch (Exception ex)
        {
            QuarantineStatus.Text = $"Could not open folder: {ex.Message}";
        }
    }

    /// <summary>
    /// Restores the selected file(s) AND adds them to the whitelist so future scans
    /// ignore them (for confirmed false positives). One combined confirmation;
    /// restores first (per-file overwrite prompt as in a normal restore), then
    /// whitelists all restored files in ONE pass through the shared flow
    /// (ApplySignatureAddAsync: mutual exclusion with the blacklist + a History
    /// entry). No automatic daemon reload, only the DaemonReloadNote hint.
    /// Called from: XAML Click binding (Restore + whitelist).
    /// </summary>
    private async void RestoreWhitelistQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var entries = SelectedQuarantineEntries("Select one or more files to restore and whitelist.");
        if (entries.Count == 0) return;

        if (!Confirm("Restore and whitelist",
                $"Restore {entries.Count} file(s) to their original locations\n\n{QuarantinePreview(entries)}\n\n" +
                "and add them to the whitelist so future scans ignore these exact files. " +
                "Only do this if you are sure the detections are false positives.",
                "Restore + whitelist", "Cancel"))
            return;

        // Step 1 - restore each file, reusing the same per-file overwrite prompt as
        // a normal restore. Each success writes its own console line + History record.
        AppendSection("QUARANTINE");
        var restored = new List<QuarantineEntry>();
        foreach (var entry in entries)
            if (RestoreOneQuarantine(entry)) restored.Add(entry);
        BindQuarantine();

        // Step 2 - whitelist every restored file in ONE pass through the shared flow
        // (mutual exclusion with the blacklist + one "whitelist modified" History
        // entry + count refresh). The commit reports file NAMES, so results are
        // matched back by name.
        var paths = restored
            .Where(x => System.IO.File.Exists(x.OriginalPath))
            .Select(x => x.OriginalPath)
            .ToArray();
        foreach (var entry in restored.Where(x => !System.IO.File.Exists(x.OriginalPath)))
            AppendLine($"{entry.OriginalName}: restored, but the file was not found afterwards, so it was not whitelisted.");

        if (paths.Length == 0)
        {
            QuarantineStatus.Text = restored.Count == 0
                ? "Nothing was restored (see console)."
                : $"{restored.Count} restored, nothing whitelisted (see console).";
            return;
        }

        var result = await ApplySignatureAddAsync(
            CustomSignatureManager.ListKind.Whitelist, paths, this);

        var whitelistedNames = new HashSet<string>(
            result.Added.Concat(result.Moved).Concat(result.SkippedSameList),
            StringComparer.OrdinalIgnoreCase);
        int whitelisted = restored.Count(x => whitelistedNames.Contains(x.OriginalName));

        foreach (var name in result.SkippedConflict)
            AppendLine($"{name}: kept on the blacklist, not whitelisted.");
        foreach (var (path, reason) in result.Failed)
            AppendLine($"Whitelist failed for {path}: {reason}");
        if (result.Added.Count > 0 || result.Moved.Count > 0)
            AppendLine(DaemonReloadNote);

        QuarantineStatus.Text = $"{restored.Count} restored, {whitelisted} whitelisted (see console).";
    }
}