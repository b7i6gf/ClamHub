using System.IO;
using System.Text.Json;
using ClamAVGui.Models;

namespace ClamAVGui.Core;

/// <summary>
/// Loads and saves the scan history (history.json next to the EXE), newest
/// first, capped to a fixed number of entries so the file stays small.
/// Called from: MainWindow.RunScanGuarded (Add) and MainWindow.History.cs.
/// </summary>
public static class HistoryManager
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>Maximum kept entries; older ones are dropped on Add.</summary>
    private const int MaxEntries = 200;

    /// <summary>In-memory history, newest first.</summary>
    public static List<ScanHistoryEntry> Entries { get; private set; } = new();

    /// <summary>
    /// Loads history.json, an invalid or missing file yields an empty list.
    /// Called from: MainWindow.InitializeAsync via InitializeHistory.
    /// </summary>
    public static void Load()
    {
        try
        {
            if (File.Exists(AppPaths.HistoryFile))
            {
                var json = File.ReadAllText(AppPaths.HistoryFile);
                Entries = JsonSerializer.Deserialize<List<ScanHistoryEntry>>(json, JsonOptions) ?? new();
            }
        }
        catch (Exception)
        {
            Entries = new();
        }
    }

    /// <summary>
    /// Inserts a finished scan at the top, trims to MaxEntries and saves.
    /// Called from: MainWindow.RunScanGuarded after each scan.
    /// </summary>
    public static void Add(ScanHistoryEntry entry)
    {
        Entries.Insert(0, entry);
        if (Entries.Count > MaxEntries)
            Entries.RemoveRange(MaxEntries, Entries.Count - MaxEntries);
        Save();
    }

    /// <summary>Removes one entry and saves. Called from: MainWindow.History.cs (Delete entry).</summary>
    public static void Delete(ScanHistoryEntry entry)
    {
        if (Entries.Remove(entry)) Save();
    }

    /// <summary>Clears the whole history and saves. Called from: MainWindow.History.cs.</summary>
    public static void Clear()
    {
        Entries.Clear();
        Save();
    }

    /// <summary>
    /// Writes the history to history.json (atomic). Reports the reason on
    /// failure instead of throwing. Called from: Add, Delete, Clear.
    /// </summary>
    private static void Save()
    {
        try
        {
            AtomicFile.WriteAllText(AppPaths.HistoryFile, JsonSerializer.Serialize(Entries, JsonOptions));
        }
        catch (Exception ex)
        {
            AppNotifications.ReportError($"Could not save scan history: {ex.Message}");
        }
    }
}
