using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using ClamHub.Core;

namespace ClamHub;

/// <summary>
/// Manage ClamHub's own ClamAV signature lists. Shows the blacklist and the whitelist
/// side by side; each list is an independent drag-and-drop target and has its own
/// "Add files", "Remove selected" and "Remove all" buttons. The heavy lifting (hashing,
/// mutual-exclusion move prompt, History, count refresh) is delegated to the owning
/// MainWindow via ApplySignatureAddAsync / ApplySignatureRemove, so this window only
/// collects input and shows the two lists. It sets Changed so MainWindow reloads the
/// daemon once after the window closes. Opened from: MainWindow.ManageSignatureLists_Click.
/// </summary>
public partial class SignaturesWindow : Window
{
    /// <summary>The owning main window that performs the shared add/remove logic.</summary>
    private readonly MainWindow _main;

    /// <summary>Guards against overlapping async add operations. Set by SetWorking.</summary>
    private bool _working;

    /// <summary>
    /// True when any list changed (add/move/remove). MainWindow reads this after
    /// ShowDialog to reload the daemon once for the whole session.
    /// </summary>
    public bool Changed { get; private set; }

    public SignaturesWindow(MainWindow main)
    {
        _main = main;
        Owner = main;
        InitializeComponent();
        RefreshLists();
    }

    /// <summary>
    /// Display wrapper for a signature entry. ToString drives the shown text; the
    /// wrapped Entry is used when removing. Kept in the window so the Core model stays
    /// free of UI formatting.
    /// </summary>
    private sealed class EntryRow
    {
        public CustomSignatureManager.SignatureEntry Entry { get; }
        public EntryRow(CustomSignatureManager.SignatureEntry entry) => Entry = entry;

        public override string ToString()
        {
            string h = Entry.Hash.Length <= 16 ? Entry.Hash : Entry.Hash[..16] + "...";
            return $"{Entry.Name}   ({h}, {Entry.Size} bytes)";
        }
    }

    /// <summary>
    /// Reloads both list boxes and their header counts from disk. Called from: the
    /// constructor and after every add/remove.
    /// </summary>
    private void RefreshLists()
    {
        BlacklistBox.Items.Clear();
        foreach (var e in CustomSignatureManager.Read(CustomSignatureManager.ListKind.Blacklist))
            BlacklistBox.Items.Add(new EntryRow(e));

        WhitelistBox.Items.Clear();
        foreach (var e in CustomSignatureManager.Read(CustomSignatureManager.ListKind.Whitelist))
            WhitelistBox.Items.Add(new EntryRow(e));

        BlacklistHeader.Text = $"Blacklist - {BlacklistBox.Items.Count}";
        WhitelistHeader.Text = $"Whitelist - {WhitelistBox.Items.Count}";
    }

    // ---- Adding files (browse or drop) ----

    /// <summary>Browses for files to add to the blacklist. Called from: blacklist Add files.</summary>
    private async void AddBlacklist_Click(object sender, RoutedEventArgs e)
        => await AddViaDialogAsync(CustomSignatureManager.ListKind.Blacklist);

    /// <summary>Browses for files to add to the whitelist. Called from: whitelist Add files.</summary>
    private async void AddWhitelist_Click(object sender, RoutedEventArgs e)
        => await AddViaDialogAsync(CustomSignatureManager.ListKind.Whitelist);

    /// <summary>Shows a multi-select file dialog and adds the chosen files. Called from: the Add buttons.</summary>
    private async Task AddViaDialogAsync(CustomSignatureManager.ListKind kind)
    {
        var dialog = new OpenFileDialog { Title = "Select file(s)", Multiselect = true };
        if (dialog.ShowDialog(this) != true) return;
        await AddPathsAsync(kind, dialog.FileNames);
    }

    /// <summary>Shows a copy cursor for file drops. Called from: both list PreviewDragOver.</summary>
    private void List_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    /// <summary>Adds dropped files to the blacklist. Called from: blacklist Border PreviewDrop.</summary>
    private async void BlacklistBox_Drop(object sender, DragEventArgs e)
        => await HandleDropAsync(CustomSignatureManager.ListKind.Blacklist, e);

    /// <summary>Adds dropped files to the whitelist. Called from: whitelist Border PreviewDrop.</summary>
    private async void WhitelistBox_Drop(object sender, DragEventArgs e)
        => await HandleDropAsync(CustomSignatureManager.ListKind.Whitelist, e);

    /// <summary>
    /// Extracts dropped FILES (folders and missing items are ignored, since a hash
    /// signature is per file) and adds them to the given list. Called from: the two
    /// drop handlers.
    /// </summary>
    private async Task HandleDropAsync(CustomSignatureManager.ListKind kind, DragEventArgs e)
    {
        e.Handled = true;
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;

        var files = ((string[])e.Data.GetData(DataFormats.FileDrop)).Where(File.Exists).ToArray();
        if (files.Length == 0)
        {
            StatusText.Text = "Nothing added: drop individual files (folders are ignored).";
            return;
        }
        await AddPathsAsync(kind, files);
    }

    /// <summary>
    /// Delegates the add to MainWindow (hashing, move prompt, History, counts), then
    /// refreshes the lists and shows a summary. Called from: AddViaDialogAsync and
    /// HandleDropAsync.
    /// </summary>
    private async Task AddPathsAsync(CustomSignatureManager.ListKind kind, IReadOnlyList<string> paths)
    {
        if (_working) return;
        SetWorking(true, $"Hashing {paths.Count} file(s)...");

        CustomSignatureManager.CommitResult result;
        try
        {
            result = await _main.ApplySignatureAddAsync(kind, paths, this);
        }
        catch (Exception ex)
        {
            SetWorking(false, $"Failed: {ex.Message}");
            return;
        }

        if (result.Added.Count > 0 || result.Moved.Count > 0) Changed = true;
        RefreshLists();

        string listName = kind == CustomSignatureManager.ListKind.Blacklist ? "Blacklist" : "Whitelist";
        SetWorking(false, Summarize(listName, result));
    }

    // ---- Removing entries ----

    /// <summary>Removes selected blacklist entries. Called from: blacklist Remove selected.</summary>
    private void RemoveBlacklist_Click(object sender, RoutedEventArgs e)
        => RemoveSelected(BlacklistBox, CustomSignatureManager.ListKind.Blacklist);

    /// <summary>Removes selected whitelist entries. Called from: whitelist Remove selected.</summary>
    private void RemoveWhitelist_Click(object sender, RoutedEventArgs e)
        => RemoveSelected(WhitelistBox, CustomSignatureManager.ListKind.Whitelist);

    /// <summary>
    /// Removes the entries selected in a list box (via MainWindow) and refreshes.
    /// Called from: RemoveBlacklist_Click and RemoveWhitelist_Click.
    /// </summary>
    private void RemoveSelected(ListBox box, CustomSignatureManager.ListKind kind)
    {
        var entries = box.SelectedItems.Cast<EntryRow>().Select(r => r.Entry).ToList();
        if (entries.Count == 0)
        {
            StatusText.Text = "Select one or more entries to remove.";
            return;
        }

        if (_main.ApplySignatureRemove(kind, entries)) Changed = true;
        RefreshLists();
        StatusText.Text = $"Removed {entries.Count} {Plural(entries.Count)}.";
    }

    /// <summary>Clears the blacklist after confirmation. Called from: blacklist Remove all.</summary>
    private void RemoveAllBlacklist_Click(object sender, RoutedEventArgs e)
        => RemoveAll(CustomSignatureManager.ListKind.Blacklist, "blacklist");

    /// <summary>Clears the whitelist after confirmation. Called from: whitelist Remove all.</summary>
    private void RemoveAllWhitelist_Click(object sender, RoutedEventArgs e)
        => RemoveAll(CustomSignatureManager.ListKind.Whitelist, "whitelist");

    /// <summary>
    /// Removes every entry of a list after a confirm dialog. Called from:
    /// RemoveAllBlacklist_Click and RemoveAllWhitelist_Click.
    /// </summary>
    private void RemoveAll(CustomSignatureManager.ListKind kind, string label)
    {
        var entries = CustomSignatureManager.Read(kind);
        if (entries.Count == 0)
        {
            StatusText.Text = $"The {label} is already empty.";
            return;
        }

        bool ok = new MessageDialog("Remove all",
            $"Remove all {entries.Count} {label} {Plural(entries.Count)}?",
            "Remove", "Cancel") { Owner = this }.ShowDialog() == true;
        if (!ok) return;

        if (_main.ApplySignatureRemove(kind, entries)) Changed = true;
        RefreshLists();
        StatusText.Text = $"Removed {entries.Count} {label} {Plural(entries.Count)}.";
    }

    // ---- Helpers ----

    /// <summary>Builds a one-line summary of a commit result. Called from: AddPathsAsync.</summary>
    private static string Summarize(string listName, CustomSignatureManager.CommitResult r)
    {
        var parts = new List<string>();
        if (r.Added.Count > 0) parts.Add($"added {r.Added.Count}");
        if (r.Moved.Count > 0) parts.Add($"moved {r.Moved.Count}");
        if (r.SkippedSameList.Count > 0) parts.Add($"{r.SkippedSameList.Count} already listed");
        if (r.SkippedConflict.Count > 0) parts.Add($"{r.SkippedConflict.Count} kept on other list");
        if (r.Failed.Count > 0) parts.Add($"{r.Failed.Count} failed");
        return parts.Count == 0
            ? $"{listName}: nothing to do."
            : $"{listName}: " + string.Join(", ", parts) + ".";
    }

    /// <summary>Singular/plural helper for "entry"/"entries". Called from: the remove handlers.</summary>
    private static string Plural(int n) => n == 1 ? "entry" : "entries";

    /// <summary>
    /// Toggles the busy state: shows/hides the working bar, disables the list add/remove
    /// buttons indirectly via _working and optionally sets a status line. Called from:
    /// AddPathsAsync.
    /// </summary>
    private void SetWorking(bool on, string? status)
    {
        _working = on;
        WorkBar.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        if (status != null) StatusText.Text = status;
    }

    /// <summary>Closes the window. Called from: Close button and the title-bar close button.</summary>
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
