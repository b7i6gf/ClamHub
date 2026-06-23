using System.Windows;
using System.Windows.Controls;
using ClamHub.Core;
using ClamHub.Models;

namespace ClamHub;

/// <summary>
/// History tab logic: shows past scans in a table and the infected files of the
/// selected entry. Partial class companion to MainWindow.xaml.cs, initialized
/// from InitializeAsync.
/// </summary>
public partial class MainWindow
{
    /// <summary>
    /// Loads history.json and binds it to the list.
    /// Called from: MainWindow.InitializeAsync.
    /// </summary>
    private void InitializeHistory()
    {
        HistoryManager.Load();
        BindHistory();
        // Recompute the fill on resize and when the tab becomes visible (its
        // width and viewport are 0 until first shown). Deferred to Loaded
        // priority so the ScrollViewer viewport is already measured.
        HistoryList.SizeChanged += (_, _) => ScheduleFill(HistoryList, HistoryGridView);
        HistoryList.IsVisibleChanged += (_, _) => ScheduleFill(HistoryList, HistoryGridView);
    }

    /// <summary>
    /// Queues a FillLastColumn pass at Loaded priority so layout and the
    /// ScrollViewer viewport are settled first. Called from: table SizeChanged,
    /// IsVisibleChanged and bind methods.
    /// </summary>
    private void ScheduleFill(System.Windows.Controls.ListView list,
        System.Windows.Controls.GridView grid)
        => Dispatcher.BeginInvoke(new Action(() => FillLastColumn(list, grid)),
            System.Windows.Threading.DispatcherPriority.Loaded);

    /// <summary>
    /// Resizes the final GridView column so the columns exactly fill the visible
    /// content width, removing the empty area WPF otherwise shows to the right of
    /// the last column. Uses the inner ScrollViewer's ViewportWidth (the exact
    /// width minus the actual scrollbar, which is narrower than the system
    /// metric), and the declared widths of the other columns. Shared by the
    /// History and Quarantine tables.
    /// Called from: SizeChanged/IsVisibleChanged handlers and after binding.
    /// </summary>
    private static void FillLastColumn(System.Windows.Controls.ListView list,
        System.Windows.Controls.GridView grid)
    {
        if (grid.Columns.Count == 0) return;

        double available = FindViewportWidth(list);
        if (available <= 0) available = list.ActualWidth - 12; // fallback: list minus thin scrollbar
        if (available <= 0) return;

        double used = 0;
        for (int i = 0; i < grid.Columns.Count - 1; i++)
        {
            var col = grid.Columns[i];
            used += double.IsNaN(col.Width) ? col.ActualWidth : col.Width;
        }

        double remaining = available - used;
        if (remaining > 60)
            grid.Columns[^1].Width = remaining;
    }

    /// <summary>
    /// Returns the horizontal viewport width of the ScrollViewer inside a control,
    /// i.e. the content area excluding the actual scrollbar. 0 if not measured yet.
    /// Called from: FillLastColumn.
    /// </summary>
    private static double FindViewportWidth(System.Windows.DependencyObject root)
    {
        int count = System.Windows.Media.VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(root, i);
            if (child is System.Windows.Controls.ScrollViewer sv && sv.ViewportWidth > 0)
                return sv.ViewportWidth;
            double nested = FindViewportWidth(child);
            if (nested > 0) return nested;
        }
        return 0;
    }

    /// <summary>
    /// Rebinds the list to the current in-memory history.
    /// Called from: InitializeHistory, RecordScan, Refresh and Clear handlers.
    /// </summary>
    private void BindHistory()
    {
        HistoryList.ItemsSource = HistoryManager.Entries;
        // The list raises no change notifications, so force the (sorted) default
        // view to re-read it; this makes the table reflect every add/delete
        // immediately, including the first one.
        System.Windows.Data.CollectionViewSource.GetDefaultView(HistoryManager.Entries)?.Refresh();
        ScheduleFill(HistoryList, HistoryGridView);
    }

    /// <summary>
    /// Persists one finished scan and refreshes the list.
    /// Called from: MainWindow.RunScanGuarded after the summary is printed.
    /// </summary>
    private void RecordScan(ScanEngine.ScanOptions options, ScanEngine.ScanResult result, TimeSpan duration)
    {
        HistoryManager.Add(new ScanHistoryEntry
        {
            Timestamp = DateTime.Now,
            Kind = options.Mode == ScanEngine.ScanMode.Memory ? "Memory scan" : "File/folder scan",
            Target = options.Mode == ScanEngine.ScanMode.Memory ? "Process memory" : options.TargetPath ?? "",
            Scanner = result.UsedDaemon ? "clamdscan (daemon)" : "clamscan",
            Duration = duration,
            InfectedCount = result.InfectedLines.Count,
            ExitCode = result.ExitCode,
            InfectedLines = result.InfectedLines
        });
        BindHistory();
    }

    /// <summary>
    /// Shows the infected file lines of the selected history entry.
    /// Called from: XAML SelectionChanged binding of HistoryList.
    /// </summary>
    private void HistoryList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (HistoryList.SelectedItem is not ScanHistoryEntry entry)
            return;

        if (entry.InfectedLines.Count == 0)
        {
            HistoryDetailBox.Text = entry.ExitCode >= 2
                ? "This scan ended with an error. See the scan log for details."
                : "No infected files were found in this scan.";
            return;
        }

        HistoryDetailBox.Text =
            $"Infected files ({entry.InfectedLines.Count}):{Environment.NewLine}{Environment.NewLine}"
            + string.Join(Environment.NewLine, entry.InfectedLines);
    }

    /// <summary>Reloads the history from disk. Called from: XAML Click binding.</summary>
    private void RefreshHistory_Click(object sender, RoutedEventArgs e)
    {
        HistoryManager.Load();
        BindHistory();
        HistoryDetailBox.Text = "Select a scan to see its infected files.";
    }

    /// <summary>
    /// Opens history.json in the default editor. Called from: XAML Click binding.
    /// </summary>
    private void OpenHistoryFile_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!System.IO.File.Exists(AppPaths.HistoryFile))
            {
                HistoryDetailBox.Text = "No history file yet, run a scan first.";
                return;
            }
            System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo { FileName = AppPaths.HistoryFile, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            HistoryDetailBox.Text = $"Could not open history file: {ex.Message}";
        }
    }

    /// <summary>Clears the history after confirmation. Called from: XAML Click binding.</summary>
    private void ClearHistory_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm("Clear history", "Delete the entire scan history?", "Delete", "Cancel"))
            return;

        HistoryManager.Clear();
        BindHistory();
        HistoryDetailBox.Text = "History cleared.";
    }

    /// <summary>
    /// Deletes the selected history entry. Called from: XAML Click binding
    /// (Delete entry button).
    /// </summary>
    private void DeleteHistoryEntry_Click(object sender, RoutedEventArgs e)
    {
        if (HistoryList.SelectedItem is not ScanHistoryEntry entry)
        {
            HistoryDetailBox.Text = "Select a history entry to delete.";
            return;
        }

        HistoryManager.Delete(entry);
        BindHistory();
        HistoryDetailBox.Text = "Entry deleted.";
    }

    /// <summary>
    /// Recomputes the last-column fill when the scrollbar appears or disappears
    /// (which changes the viewport width). Called from: ScrollViewer.ScrollChanged
    /// on both tables.
    /// </summary>
    private void Table_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (e.ViewportWidthChange == 0) return;
        if (sender is ListView list && list.View is GridView grid)
            ScheduleFill(list, grid);
    }

    /// <summary>Sorts the history table by the clicked column. Called from: XAML header Click.</summary>
    private void HistorySort_Click(object sender, RoutedEventArgs e)
        => SortByColumn(e.OriginalSource as GridViewColumnHeader, HistoryList);

    /// <summary>Sorts the quarantine table by the clicked column. Called from: XAML header Click.</summary>
    private void QuarantineSort_Click(object sender, RoutedEventArgs e)
        => SortByColumn(e.OriginalSource as GridViewColumnHeader, QuarantineList);

    /// <summary>
    /// Sorts a ListView by the property in the clicked header's Tag, toggling
    /// ascending/descending and keeping only one active sort column. Updates the
    /// up/down arrow on the headers. Shared by both tables.
    /// Called from: HistorySort_Click and QuarantineSort_Click.
    /// </summary>
    private static void SortByColumn(GridViewColumnHeader? header, ListView list)
    {
        // Ignore clicks on the padding header or the resize gripper.
        if (header?.Column?.Header is not TextBlock tb || tb.Tag is not string prop
            || string.IsNullOrEmpty(prop))
            return;

        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(list.ItemsSource);
        if (view == null) return;

        var dir = System.ComponentModel.ListSortDirection.Ascending;
        if (view.SortDescriptions.Count > 0
            && view.SortDescriptions[0].PropertyName == prop
            && view.SortDescriptions[0].Direction == System.ComponentModel.ListSortDirection.Ascending)
            dir = System.ComponentModel.ListSortDirection.Descending;

        view.SortDescriptions.Clear();
        view.SortDescriptions.Add(new System.ComponentModel.SortDescription(prop, dir));
        view.Refresh();
        UpdateSortArrows(list, prop, dir);
    }

    /// <summary>
    /// Sets an up/down arrow on the active column header and clears it from the
    /// others. Called from: SortByColumn.
    /// </summary>
    private static void UpdateSortArrows(ListView list, string prop,
        System.ComponentModel.ListSortDirection dir)
    {
        if (list.View is not GridView grid) return;
        foreach (var col in grid.Columns)
        {
            if (col.Header is not TextBlock t) continue;
            string baseTitle = t.Text.Replace(" \u25B2", "").Replace(" \u25BC", "");
            bool active = (t.Tag as string) == prop;
            t.Text = active
                ? baseTitle + (dir == System.ComponentModel.ListSortDirection.Ascending ? " \u25B2" : " \u25BC")
                : baseTitle;
        }
    }
}
