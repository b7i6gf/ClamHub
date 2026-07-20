using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using Microsoft.Win32;
using ClamHub.Core;

namespace ClamHub;

/// <summary>
/// Dark modal window for managing the File-Verifier queue. FILES ONLY (folders
/// cannot be verified), and unlike the scan queue there are no saved named
/// queues (kept intentionally simple). It does not run the verification itself:
/// the caller reads Files after the window closes (always current) and, if
/// VerifyRequested is set, runs them. Opened from: MainWindow File-Verifier tab
/// "Queue" button.
/// </summary>
public partial class VerifierQueueWindow : Window
{
    /// <summary>The queued file paths as they currently stand (always up to date).</summary>
    public List<string> Files => FileList.Items.Cast<string>().ToList();

    /// <summary>True when the user pressed "Verify all" (the caller runs them).</summary>
    public bool VerifyRequested { get; private set; }

    public VerifierQueueWindow(IEnumerable<string>? initial = null)
    {
        InitializeComponent();

        // Admin mode: restore drag and drop (UIPI blocks OLE drops); no-op otherwise.
        Loaded += (_, _) => ElevatedDropSupport.Enable(this,
            new ElevatedDropSupport.Target(FileList, HandleDroppedPaths));
        if (initial != null)
            foreach (var p in initial) AddFile(p);
        UpdateStatus();
    }

    /// <summary>
    /// Adds one path to the list if it is an existing FILE and not already
    /// present. Folders and missing paths are skipped with a status note.
    /// Called from: the constructor, Add files, drag and drop.
    /// </summary>
    private void AddFile(string raw)
    {
        var path = raw.Replace("\"", "").Trim().TrimEnd('\\');
        if (path.Length == 0) return;
        if (Directory.Exists(path))
        {
            StatusText.Text = $"Skipped (folders cannot be verified): {path}";
            return;
        }
        if (!File.Exists(path))
        {
            StatusText.Text = $"Skipped (not found): {path}";
            return;
        }
        if (FileList.Items.Cast<string>().Any(x => x.Equals(path, StringComparison.OrdinalIgnoreCase)))
            return;
        FileList.Items.Add(path);
        UpdateStatus();
    }

    /// <summary>Refreshes the footer count and enables Verify all only when the
    /// queue is not empty. Called from: every list change.</summary>
    private void UpdateStatus()
    {
        int n = FileList.Items.Count;
        StatusText.Text = n == 0 ? "Queue is empty." : $"{n} file(s) queued.";
        VerifyAllButton.IsEnabled = n > 0;
    }

    /// <summary>Adds files via the system picker. Called from: Add files button.</summary>
    private void AddFiles_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Select files to add", Multiselect = true };
        if (dialog.ShowDialog() != true) return;
        foreach (var f in dialog.FileNames) AddFile(f);
    }

    /// <summary>Removes the selected entries. Called from: Remove selected button.</summary>
    private void RemoveSelected_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in FileList.SelectedItems.Cast<string>().ToList())
            FileList.Items.Remove(item);
        UpdateStatus();
    }

    /// <summary>Empties the whole queue. Called from: Clear all button.</summary>
    private void ClearAll_Click(object sender, RoutedEventArgs e)
    {
        FileList.Items.Clear();
        UpdateStatus();
    }

    /// <summary>Shows a copy cursor for file drops. Called from: list PreviewDragOver.</summary>
    private void FileList_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    /// <summary>Adds dropped files (folders skipped by AddFile). Called from: list Drop.</summary>
    private void FileList_Drop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        HandleDroppedPaths((string[])e.Data.GetData(DataFormats.FileDrop));
    }

    /// <summary>
    /// Path-based core of the drop handling (folders skipped by AddFile), shared
    /// by the WPF Drop event and the elevated WM_DROPFILES hook. Called from:
    /// FileList_Drop and ElevatedDropSupport.
    /// </summary>
    private void HandleDroppedPaths(string[] paths)
    {
        foreach (var p in paths) AddFile(p);
    }

    /// <summary>
    /// Flags that the queue should be verified and closes; the caller reads Files
    /// and VerifyRequested. Called from: Verify all button.
    /// </summary>
    private void VerifyAll_Click(object sender, RoutedEventArgs e)
    {
        if (FileList.Items.Count == 0)
        {
            StatusText.Text = "Add at least one file first.";
            return;
        }
        VerifyRequested = true;
        Close();
    }

    /// <summary>Closes the window (edits are kept by the caller). Called from: Close buttons.</summary>
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
