using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using Microsoft.Win32;

namespace ClamHub;

/// <summary>
/// Dark modal window for building a list of scan targets (files and folders) and
/// starting a batch scan. It does not run the scan itself: the caller reads
/// Targets after DialogResult is true and scans them in the main console.
/// Opened from: MainWindow Scan tab "Queue..." button.
/// </summary>
public partial class ScanQueueWindow : Window
{
    /// <summary>The queued target paths, valid only when DialogResult is true.</summary>
    public List<string> Targets { get; private set; } = new();

    public ScanQueueWindow(IEnumerable<string>? initial = null)
    {
        InitializeComponent();
        if (initial != null)
            foreach (var p in initial) AddTarget(p);
        UpdateStatus();
    }

    /// <summary>
    /// Adds one path to the list if it exists and is not already present.
    /// Called from: the constructor, the add buttons and drag and drop.
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
        var dialog = new OpenFolderDialog { Title = "Select a folder to add" };
        if (dialog.ShowDialog(this) != true) return;
        AddTarget(dialog.FolderName);
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
        foreach (var p in (string[])e.Data.GetData(DataFormats.FileDrop)) AddTarget(p);
    }

    /// <summary>
    /// Captures the queued targets and closes positively so the caller can scan
    /// them. Called from: Scan all button.
    /// </summary>
    private void ScanAll_Click(object sender, RoutedEventArgs e)
    {
        if (TargetList.Items.Count == 0)
        {
            StatusText.Text = "Add at least one file or folder first.";
            return;
        }
        Targets = TargetList.Items.Cast<string>().ToList();
        DialogResult = true;
        Close();
    }

    /// <summary>Closes without scanning. Called from: Close and the title-bar close button.</summary>
    private void Close_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
