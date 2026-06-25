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
            AddHistory("Quarantine action", en.OriginalPath, "", "restored",
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
            AddHistory("Quarantine action", entry.OriginalPath, "", "removed",
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
    /// Looks up the selected quarantined file on VirusTotal via its SHA256.
    /// The stored copy has the same content (and hash) as the original, so the
    /// verdict is meaningful. Output goes to the console.
    /// Called from: XAML Click binding (Quarantine VirusTotal).
    /// </summary>
    private async void QuarantineVirusTotal_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineList.SelectedItem is not QuarantineEntry entry)
        {
            QuarantineStatus.Text = "Select a file to check on VirusTotal.";
            return;
        }
        var stored = System.IO.Path.Combine(AppPaths.QuarantineDir, entry.Id);
        await RunVirusTotalLookup(stored, entry.OriginalName);
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
}
