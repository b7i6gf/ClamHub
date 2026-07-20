using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using ClamHub.Core;

namespace ClamHub;

/// <summary>
/// Generic editor for excluded directories, individual files and file
/// extensions. It does not persist anything itself: the caller passes the
/// initial lists and reads ResultDirectories / ResultFiles / ResultExtensions
/// after a successful save, then decides where to store them (persistent
/// settings vs temporary scan session). Files and folders can also be dropped
/// onto the window. Opened from the Settings page (defaults) and the Scan tab
/// (session).
/// </summary>
public partial class ExclusionsWindow : Window
{
    /// <summary>Edited directory list, valid only when DialogResult is true.</summary>
    public List<string> ResultDirectories { get; private set; } = new();

    /// <summary>Edited single-file list, valid only when DialogResult is true.</summary>
    public List<string> ResultFiles { get; private set; } = new();

    /// <summary>Edited extension list, valid only when DialogResult is true.</summary>
    public List<string> ResultExtensions { get; private set; } = new();

    public ExclusionsWindow(IEnumerable<string> dirs, IEnumerable<string> files,
                            IEnumerable<string> exts, string subtitle,
                            string windowTitle = "Scan exclusions")
    {
        InitializeComponent();

        // Admin mode: restore drag and drop (UIPI blocks OLE drops); no-op otherwise.
        Loaded += (_, _) => ElevatedDropSupport.Enable(this,
            new ElevatedDropSupport.Target(ContentGrid, HandleDroppedPaths));
        Title = windowTitle;
        HeaderText.Text = windowTitle;
        SubtitleText.Text = subtitle;
        foreach (var d in dirs) DirList.Items.Add(d);
        foreach (var f in files) FileList.Items.Add(f);
        foreach (var e in exts) ExtList.Items.Add(e);
    }

    /// <summary>Adds a directory to the list if new. Called from: AddFolder_Click and drop.</summary>
    private void AddDirToList(string raw)
    {
        var path = raw.TrimEnd('\\').Trim();
        if (path.Length == 0) return;
        if (DirList.Items.Cast<string>().Any(x => x.Equals(path, StringComparison.OrdinalIgnoreCase)))
            return;
        DirList.Items.Add(path);
    }

    /// <summary>Adds a file to the list if new. Called from: AddFile_Click and drop.</summary>
    private void AddFileToList(string raw)
    {
        var path = raw.Trim();
        if (path.Length == 0) return;
        if (FileList.Items.Cast<string>().Any(x => x.Equals(path, StringComparison.OrdinalIgnoreCase)))
            return;
        FileList.Items.Add(path);
    }

    /// <summary>Adds a folder via the system folder picker. Called from: Add folder button.</summary>
    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select folder(s) to exclude", Multiselect = true };
        if (dialog.ShowDialog(this) != true) return;
        foreach (var d in dialog.FolderNames) AddDirToList(d);
    }

    /// <summary>Removes the selected directory. Called from: Remove selected button.</summary>
    private void RemoveDir_Click(object sender, RoutedEventArgs e)
    {
        if (DirList.SelectedItem != null) DirList.Items.Remove(DirList.SelectedItem);
    }

    /// <summary>Clears the whole directory list. Called from: Remove all button.</summary>
    private void RemoveAllDir_Click(object sender, RoutedEventArgs e) => DirList.Items.Clear();

    /// <summary>Adds files via the system picker. Called from: Add file button.</summary>
    private void AddFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Select file(s) to exclude", Multiselect = true };
        if (dialog.ShowDialog(this) != true) return;
        foreach (var f in dialog.FileNames) AddFileToList(f);
    }

    /// <summary>Removes the selected file. Called from: Remove selected button.</summary>
    private void RemoveFile_Click(object sender, RoutedEventArgs e)
    {
        if (FileList.SelectedItem != null) FileList.Items.Remove(FileList.SelectedItem);
    }

    /// <summary>Clears the whole file list. Called from: Remove all button.</summary>
    private void RemoveAllFile_Click(object sender, RoutedEventArgs e) => FileList.Items.Clear();

    /// <summary>Shows a copy cursor for file drops. Called from: content PreviewDragOver.</summary>
    private void Content_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    /// <summary>Routes dropped folders to the directory list and files to the file list. Called from: content Drop.</summary>
    private void Content_Drop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        HandleDroppedPaths((string[])e.Data.GetData(DataFormats.FileDrop));
    }

    /// <summary>
    /// Path-based core of the drop handling (folders to the directory list, files
    /// to the file list), shared by the WPF Drop event and the elevated
    /// WM_DROPFILES hook. Called from: Content_Drop and ElevatedDropSupport.
    /// </summary>
    private void HandleDroppedPaths(string[] paths)
    {
        int dirs = 0, files = 0;
        foreach (var p in paths)
        {
            if (Directory.Exists(p)) { AddDirToList(p); dirs++; }
            else if (File.Exists(p)) { AddFileToList(p); files++; }
        }
        StatusText.Text = $"Added {dirs} folder(s) and {files} file(s) from the drop.";
    }

    /// <summary>Adds the typed extension on Enter. Called from: extension textbox KeyDown.</summary>
    private void ExtBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) AddExt_Click(sender, e);
    }

    /// <summary>
    /// Adds the extension(s) from the textbox after validation (letters and
    /// digits only). Accepts several separated by spaces or commas. Called from:
    /// Add button and Enter key.
    /// </summary>
    private void AddExt_Click(object sender, RoutedEventArgs e)
    {
        foreach (var raw in ExtBox.Text.Split(new[] { ' ', ',', ';' },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            var ext = raw.TrimStart('.').Trim().ToLowerInvariant();
            if (!Regex.IsMatch(ext, "^[a-z0-9]{1,10}$"))
            {
                StatusText.Text = $"Ignored invalid extension: {raw}";
                continue;
            }
            if (!ExtList.Items.Cast<string>().Any(x => x == ext))
                ExtList.Items.Add(ext);
        }
        ExtBox.Clear();
    }

    /// <summary>Removes the selected extension. Called from: Remove selected button.</summary>
    private void RemoveExt_Click(object sender, RoutedEventArgs e)
    {
        if (ExtList.SelectedItem != null) ExtList.Items.Remove(ExtList.SelectedItem);
    }

    /// <summary>Clears the whole extension list. Called from: Remove all button.</summary>
    private void RemoveAllExt_Click(object sender, RoutedEventArgs e) => ExtList.Items.Clear();

    /// <summary>
    /// Captures all three lists into the result properties and closes positively.
    /// Persistence is left to the caller. Called from: Save button.
    /// </summary>
    private void Save_Click(object sender, RoutedEventArgs e)
    {
        ResultDirectories = DirList.Items.Cast<string>().ToList();
        ResultFiles = FileList.Items.Cast<string>().ToList();
        ResultExtensions = ExtList.Items.Cast<string>().ToList();
        DialogResult = true;
        Close();
    }

    /// <summary>Closes without saving. Called from: Cancel and the close button.</summary>
    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
