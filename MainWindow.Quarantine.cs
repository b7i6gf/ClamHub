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
    /// Restores the selected file to its original path, asking before
    /// overwriting an existing file. Called from: XAML Click binding.
    /// </summary>
    private void RestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineList.SelectedItem is not QuarantineEntry entry)
        {
            QuarantineStatus.Text = "Select a file to restore.";
            return;
        }

        if (!Confirm("Restore from quarantine",
                $"Restore \"{entry.OriginalName}\" to:\n{entry.OriginalPath}\n\n" +
                "This file was flagged as infected. Restore anyway?",
                "Restore", "Cancel"))
            return;

        if (!QuarantineManager.Restore(entry, overwrite: false, out var error))
        {
            // Offer overwrite when the only problem is an existing target file.
            if (error != null && error.Contains("already exists"))
            {
                if (!Confirm("Overwrite",
                        "A file already exists at the original location. Overwrite it?",
                        "Overwrite", "Cancel"))
                    return;

                if (QuarantineManager.Restore(entry, overwrite: true, out var overwriteError))
                    Finish(entry, "restored (overwritten)");
                else
                    QuarantineStatus.Text = overwriteError ?? "Restore failed.";
                return;
            }
            QuarantineStatus.Text = error ?? "Restore failed.";
            return;
        }
        Finish(entry, "restored");

        void Finish(QuarantineEntry en, string verb)
        {
            BindQuarantine();
            AppendSection("QUARANTINE");
            AppendLine($"{en.OriginalName} {verb} to {en.OriginalPath}");
            AddHistory("Quarantine action", en.OriginalPath, "", "Restored",
                $"Restored from quarantine.{Environment.NewLine}" +
                $"File: {en.OriginalName}{Environment.NewLine}" +
                $"To: {en.OriginalPath}" +
                (verb.Contains("overwritten") ? $"{Environment.NewLine}(an existing file was overwritten)" : ""));
        }
    }

    /// <summary>
    /// Permanently deletes the selected quarantined file after confirmation.
    /// Called from: XAML Click binding.
    /// </summary>
    private void DeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineList.SelectedItem is not QuarantineEntry entry)
        {
            QuarantineStatus.Text = "Select a file to delete.";
            return;
        }

        if (!Confirm("Delete from quarantine",
                $"Permanently delete \"{entry.OriginalName}\"?\nThis cannot be undone.",
                "Delete", "Cancel"))
            return;

        if (QuarantineManager.Delete(entry, out var error))
        {
            BindQuarantine();
            AppendSection("QUARANTINE");
            AppendLine($"{entry.OriginalName} permanently deleted.");
            AddHistory("Quarantine action", entry.OriginalPath, "", "Removed",
                $"Permanently removed from quarantine.{Environment.NewLine}" +
                $"File: {entry.OriginalName}{Environment.NewLine}" +
                $"Original path: {entry.OriginalPath}");
        }
        else
        {
            QuarantineStatus.Text = error ?? "Delete failed.";
        }
    }

    /// <summary>
    /// Looks up the selected quarantined file on VirusTotal via the ORIGINAL file's
    /// SHA256. The stored copy is XOR-obfuscated, so the hash is recomputed from the
    /// de-obfuscated bytes (in memory only) to match what VT knows. Output goes to
    /// the console. Called from: XAML Click binding (Quarantine VirusTotal).
    /// </summary>
    private async void QuarantineVirusTotal_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineList.SelectedItem is not QuarantineEntry entry)
        {
            QuarantineStatus.Text = "Select a file to check on VirusTotal.";
            return;
        }
        var sha256 = QuarantineManager.ComputeOriginalSha256(entry, out var error);
        if (sha256 == null)
        {
            AppendSection("VIRUSTOTAL");
            AppendLine($"Could not read the quarantined file to hash it: {error}");
            return;
        }
        var stored = System.IO.Path.Combine(AppPaths.QuarantineDir, entry.Id);
        await RunVirusTotalLookup(stored, entry.OriginalName, sha256);
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

        // Modal, like the Signatures tab's search opener. The constructor runs the search.
        new SignatureSearchWindow(threat) { Owner = this }.ShowDialog();
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
    /// Restores the selected file AND adds it to the whitelist so future scans ignore
    /// it (for confirmed false positives). Restores first (with the same overwrite
    /// prompt as a normal restore), then whitelists the restored file through the shared
    /// flow (ApplySignatureAddAsync: mutual exclusion with the blacklist + a History
    /// entry) and reloads the daemon reliably. Called from: XAML Click binding
    /// (Restore + whitelist).
    /// </summary>
    private async void RestoreWhitelistQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineList.SelectedItem is not QuarantineEntry entry)
        {
            QuarantineStatus.Text = "Select a file to restore and whitelist.";
            return;
        }

        if (!Confirm("Restore and whitelist",
                $"Restore \"{entry.OriginalName}\" to:\n{entry.OriginalPath}\n\n" +
                "and add it to the whitelist so future scans ignore this exact file. " +
                "Only do this if you are sure the detection is a false positive.",
                "Restore + whitelist", "Cancel"))
            return;

        // Step 1 - restore, reusing the same existing-file overwrite prompt as a normal restore.
        if (!QuarantineManager.Restore(entry, overwrite: false, out var error))
        {
            if (error != null && error.Contains("already exists"))
            {
                if (!Confirm("Overwrite",
                        "A file already exists at the original location. Overwrite it?",
                        "Overwrite", "Cancel"))
                    return;
                if (!QuarantineManager.Restore(entry, overwrite: true, out var overwriteError))
                {
                    QuarantineStatus.Text = overwriteError ?? "Restore failed.";
                    return;
                }
            }
            else
            {
                QuarantineStatus.Text = error ?? "Restore failed.";
                return;
            }
        }

        BindQuarantine();
        AppendSection("QUARANTINE");
        AppendLine($"{entry.OriginalName} restored to {entry.OriginalPath}");

        // Step 2 - whitelist the restored file via the shared flow (mutual exclusion
        // with the blacklist + a "whitelist modified" History entry + count refresh).
        string note;
        if (!System.IO.File.Exists(entry.OriginalPath))
        {
            note = "restored, but the file was not found afterwards, so it was not whitelisted";
            AppendLine($"Whitelist: {note}");
        }
        else
        {
            var result = await ApplySignatureAddAsync(
                CustomSignatureManager.ListKind.Whitelist, new[] { entry.OriginalPath }, this);

            if (result.Added.Count > 0 || result.Moved.Count > 0)
            {
                note = "restored and added to the whitelist";
                await ReloadDaemonAsync();
            }
            else if (result.SkippedSameList.Count > 0)
                note = "restored; it was already on the whitelist";
            else if (result.SkippedConflict.Count > 0)
                note = "restored; kept on the blacklist, not whitelisted";
            else
            {
                string reason = result.Failed.Count > 0 ? result.Failed[0].Error : "unknown error";
                note = $"restored, but whitelisting failed: {reason}";
            }
            AppendLine($"Whitelist: {note}");
        }

        // Separate quarantine record for the restore itself (the whitelist change has
        // its own "Signatures" History entry written by the shared flow).
        AddHistory("Quarantine action", entry.OriginalPath, "", "Restored",
            $"Restored from quarantine.{Environment.NewLine}" +
            $"File: {entry.OriginalName}{Environment.NewLine}" +
            $"To: {entry.OriginalPath}");

        QuarantineStatus.Text = $"{entry.OriginalName}: {note}";
    }
}
