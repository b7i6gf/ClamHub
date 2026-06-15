using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;

namespace ClamHub;

/// <summary>
/// Generic editor for a list of directories and a list of file extensions.
/// It does not persist anything itself: the caller passes the initial lists and
/// reads ResultDirectories / ResultExtensions after a successful save, then
/// decides where to store them (persistent settings vs temporary scan session).
/// Opened from the Settings page (defaults) and the Scan tab (session).
/// </summary>
public partial class ExclusionsWindow : Window
{
    /// <summary>Edited directory list, valid only when DialogResult is true.</summary>
    public List<string> ResultDirectories { get; private set; } = new();

    /// <summary>Edited extension list, valid only when DialogResult is true.</summary>
    public List<string> ResultExtensions { get; private set; } = new();

    public ExclusionsWindow(IEnumerable<string> dirs, IEnumerable<string> exts, string subtitle)
    {
        InitializeComponent();
        SubtitleText.Text = subtitle;
        foreach (var d in dirs) DirList.Items.Add(d);
        foreach (var e in exts) ExtList.Items.Add(e);
    }

    /// <summary>Adds a folder via the system folder picker. Called from: Add folder button.</summary>
    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select a folder to exclude" };
        if (dialog.ShowDialog(this) != true) return;

        var path = dialog.FolderName.TrimEnd('\\');
        if (DirList.Items.Cast<string>().Any(x => x.Equals(path, StringComparison.OrdinalIgnoreCase)))
            return;
        DirList.Items.Add(path);
    }

    /// <summary>Removes the selected directory. Called from: Remove selected button.</summary>
    private void RemoveDir_Click(object sender, RoutedEventArgs e)
    {
        if (DirList.SelectedItem != null) DirList.Items.Remove(DirList.SelectedItem);
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

    /// <summary>Removes the selected extension. Called from: Remove button.</summary>
    private void RemoveExt_Click(object sender, RoutedEventArgs e)
    {
        if (ExtList.SelectedItem != null) ExtList.Items.Remove(ExtList.SelectedItem);
    }

    /// <summary>
    /// Captures both lists into the result properties and closes positively.
    /// Persistence is left to the caller. Called from: Save button.
    /// </summary>
    private void Save_Click(object sender, RoutedEventArgs e)
    {
        ResultDirectories = DirList.Items.Cast<string>().ToList();
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
