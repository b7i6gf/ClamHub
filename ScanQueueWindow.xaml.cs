using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using Microsoft.Win32;
using ClamHub.Core;
using ClamHub.Models;

namespace ClamHub;

/// <summary>
/// Dark modal window for managing the scan queue (files and folders) and saved
/// named queues. It does not run the scan itself: the caller reads Targets after
/// the window closes (always current) and, if ScanRequested is set, scans them.
/// Opened from: MainWindow Scan tab "Queue" button.
/// </summary>
public partial class ScanQueueWindow : Window
{
    /// <summary>The queued target paths as they currently stand (always up to date).</summary>
    public List<string> Targets => TargetList.Items.Cast<string>().ToList();

    /// <summary>True when the user pressed "Scan all" (the caller then runs the queue).</summary>
    public bool ScanRequested { get; private set; }

    public ScanQueueWindow(IEnumerable<string>? initial = null)
    {
        InitializeComponent();

        // Admin mode: restore drag and drop (UIPI blocks OLE drops); no-op otherwise.
        Loaded += (_, _) => ElevatedDropSupport.Enable(this,
            new ElevatedDropSupport.Target(TargetList, HandleDroppedPaths));
        if (initial != null)
            foreach (var p in initial) AddTarget(p);
        QueueProfileManager.Load();
        RefreshQueueProfileCombo();
        UpdateStatus();
    }

    /// <summary>
    /// Adds one path to the list if it exists and is not already present.
    /// Called from: the constructor, the add buttons, drag and drop, profile load.
    /// </summary>
    private void AddTarget(string raw)
    {
        var path = raw.Replace("\"", "").Trim().TrimEnd('\\');
        if (path.Length == 0) return;
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            StatusText.Text = $"Skipped (not found): {path}";
            return;
        }
        if (TargetList.Items.Cast<string>().Any(x => x.Equals(path, StringComparison.OrdinalIgnoreCase)))
            return;
        TargetList.Items.Add(path);
        UpdateStatus();
    }

    /// <summary>
    /// Refreshes the footer count and enables Scan all only when the queue is not
    /// empty. Called from: every list change.
    /// </summary>
    private void UpdateStatus()
    {
        int n = TargetList.Items.Count;
        StatusText.Text = n == 0 ? "Queue is empty." : $"{n} target(s) queued.";
        ScanAllButton.IsEnabled = n > 0;
    }

    /// <summary>Adds files via the system picker. Called from: Add files button.</summary>
    private void AddFiles_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Select files to add", Multiselect = true };
        if (dialog.ShowDialog(this) != true) return;
        foreach (var f in dialog.FileNames) AddTarget(f);
    }

    /// <summary>Adds a folder via the system picker. Called from: Add folder button.</summary>
    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select folder(s) to add", Multiselect = true };
        if (dialog.ShowDialog(this) != true) return;
        foreach (var d in dialog.FolderNames) AddTarget(d);
    }

    /// <summary>Removes the selected entries. Called from: Remove selected button.</summary>
    private void RemoveSelected_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in TargetList.SelectedItems.Cast<string>().ToList())
            TargetList.Items.Remove(item);
        UpdateStatus();
    }

    /// <summary>Empties the whole queue. Called from: Clear all button.</summary>
    private void ClearAll_Click(object sender, RoutedEventArgs e)
    {
        TargetList.Items.Clear();
        UpdateStatus();
    }

    /// <summary>Shows a copy cursor for file drops. Called from: list PreviewDragOver.</summary>
    private void TargetList_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    /// <summary>Adds dropped files and folders. Called from: list Drop.</summary>
    private void TargetList_Drop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        HandleDroppedPaths((string[])e.Data.GetData(DataFormats.FileDrop));
    }

    /// <summary>
    /// Path-based core of the drop handling, shared by the WPF Drop event and the
    /// elevated WM_DROPFILES hook. Called from: TargetList_Drop and
    /// ElevatedDropSupport.
    /// </summary>
    private void HandleDroppedPaths(string[] paths)
    {
        foreach (var p in paths) AddTarget(p);
    }

    /// <summary>Combo entry shown when no saved queue is selected.</summary>
    private const string NoQueueProfile = "(-)";

    /// <summary>Suppresses SelectionChanged side effects while the combo is rebuilt.</summary>
    private bool _queueComboUpdating;

    /// <summary>Selected real queue name, or null when "(-)" (none) is selected.</summary>
    private string? ActiveQueueProfile =>
        QueueProfileCombo.SelectedItem is string s && s != NoQueueProfile ? s : null;

    /// <summary>Reloads the saved-queue combo (with a leading "(-)"). Called from: ctor and save/delete.</summary>
    private void RefreshQueueProfileCombo()
    {
        string? selected = ActiveQueueProfile;
        _queueComboUpdating = true;
        QueueProfileCombo.Items.Clear();
        QueueProfileCombo.Items.Add(NoQueueProfile);
        foreach (var p in QueueProfileManager.Profiles)
            QueueProfileCombo.Items.Add(p.Name);
        QueueProfileCombo.SelectedItem =
            selected != null && QueueProfileCombo.Items.Contains(selected) ? selected : NoQueueProfile;
        _queueComboUpdating = false;
    }

    /// <summary>
    /// Selecting "(-)" empties the current queue; selecting a real entry does
    /// nothing until Load is pressed. Called from: combo SelectionChanged.
    /// </summary>
    private void QueueProfileCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_queueComboUpdating) return;
        if (QueueProfileCombo.SelectedItem is string s && s == NoQueueProfile)
        {
            TargetList.Items.Clear();
            UpdateStatus();
            StatusText.Text = "Queue cleared.";
        }
    }

    /// <summary>
    /// Saves the current queue under the typed name (or the selected one when the
    /// name box is empty). Called from: Save queue button.
    /// </summary>
    private void SaveQueueProfile_Click(object sender, RoutedEventArgs e)
    {
        string name = QueueProfileNameBox.Text.Trim();
        if (name.Length == 0) name = ActiveQueueProfile ?? "";
        if (name.Length == 0)
        {
            StatusText.Text = "Enter a name to save the queue under.";
            return;
        }
        if (TargetList.Items.Count == 0)
        {
            StatusText.Text = "Add at least one target before saving.";
            return;
        }
        QueueProfileManager.AddOrUpdate(new QueueProfile
        {
            Name = name,
            Paths = TargetList.Items.Cast<string>().ToList()
        });
        QueueProfileNameBox.Clear();
        RefreshQueueProfileCombo();
        QueueProfileCombo.SelectedItem = name;
        StatusText.Text = $"Saved queue \"{name}\".";
    }

    /// <summary>
    /// Replaces the current queue with the selected saved queue, skipping paths
    /// that no longer exist. Called from: Load button.
    /// </summary>
    private void LoadQueueProfile_Click(object sender, RoutedEventArgs e)
    {
        if (ActiveQueueProfile is not string name)
        {
            StatusText.Text = "Select a saved queue to load.";
            return;
        }
        var profile = QueueProfileManager.Profiles.FirstOrDefault(p =>
            p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (profile == null) return;

        TargetList.Items.Clear();
        int skipped = 0;
        foreach (var p in profile.Paths)
        {
            int before = TargetList.Items.Count;
            AddTarget(p);
            if (TargetList.Items.Count == before) skipped++;
        }
        UpdateStatus();
        StatusText.Text = skipped > 0
            ? $"Loaded \"{name}\" ({skipped} missing path(s) skipped)."
            : $"Loaded \"{name}\".";
    }

    /// <summary>Deletes the selected saved queue. Called from: Delete button.</summary>
    private void DeleteQueueProfile_Click(object sender, RoutedEventArgs e)
    {
        if (ActiveQueueProfile is not string name)
        {
            StatusText.Text = "Select a saved queue to delete.";
            return;
        }
        if (QueueProfileManager.Delete(name))
        {
            RefreshQueueProfileCombo();
            StatusText.Text = $"Deleted queue \"{name}\".";
        }
    }

    /// <summary>
    /// Flags that the queue should be scanned and closes; the caller reads Targets
    /// and ScanRequested. Called from: Scan all button.
    /// </summary>
    private void ScanAll_Click(object sender, RoutedEventArgs e)
    {
        if (TargetList.Items.Count == 0)
        {
            StatusText.Text = "Add at least one file or folder first.";
            return;
        }
        ScanRequested = true;
        Close();
    }

    /// <summary>Closes the window (edits are kept by the caller). Called from: Close buttons.</summary>
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
