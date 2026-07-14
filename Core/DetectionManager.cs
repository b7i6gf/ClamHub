using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Loads and saves the list of infected files reported by report-only scans
/// (Logs\detections.json), newest first, capped so the file stays small. The
/// Detections window works through this list (quarantine/remove/whitelist/
/// ignore/VirusTotal). Called from: MainWindow.ScanOneAsync (AddFindings) and
/// DetectionsWindow.
/// </summary>
public static class DetectionManager
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>Maximum kept entries; the oldest are dropped on Add.</summary>
    private const int MaxEntries = 500;

    /// <summary>
    /// In-memory detections, newest first. ObservableCollection so an open
    /// Detections window updates automatically.
    /// </summary>
    public static ObservableCollection<DetectionEntry> Entries { get; private set; } = new();

    /// <summary>
    /// Loads detections.json; an invalid or missing file yields an empty list.
    /// Called from: MainWindow.InitializeAsync.
    /// </summary>
    public static void Load()
    {
        try
        {
            if (File.Exists(AppPaths.DetectionsFile))
            {
                var json = File.ReadAllText(AppPaths.DetectionsFile);
                var list = JsonSerializer.Deserialize<List<DetectionEntry>>(json, JsonOptions) ?? new();
                Entries = new ObservableCollection<DetectionEntry>(list);
            }
        }
        catch (Exception)
        {
            Entries = new();
        }
    }

    /// <summary>
    /// Records the FOUND lines of a finished report-only scan. A pending entry
    /// for the same file + signature is refreshed (new timestamp) instead of
    /// duplicated, so rescanning the same folder does not flood the list.
    /// Returns how many NEW entries were added. Called from: MainWindow.ScanOneAsync.
    /// </summary>
    public static int AddFindings(IReadOnlyList<string> infectedLines)
    {
        int added = 0;
        bool changed = false;
        foreach (var line in infectedLines)
        {
            if (!ScanEngine.TryParseFoundLine(line, out var path, out var threat))
                continue;

            var existing = Entries.FirstOrDefault(e =>
                e.Status == DetectionStatus.Pending
                && string.Equals(e.FilePath, path, StringComparison.OrdinalIgnoreCase)
                && string.Equals(e.Signature, threat, StringComparison.OrdinalIgnoreCase));

            if (existing != null)
            {
                existing.DetectedAt = DateTime.Now;
                changed = true;
                continue;
            }

            Entries.Insert(0, new DetectionEntry
            {
                FilePath = path,
                Signature = threat,
                DetectedAt = DateTime.Now
            });
            added++;
            changed = true;
        }

        while (Entries.Count > MaxEntries)
            Entries.RemoveAt(Entries.Count - 1);

        if (changed) Save();
        return added;
    }

    /// <summary>Removes one entry and saves. Called from: DetectionsWindow (Delete entry).</summary>
    public static void Delete(DetectionEntry entry)
    {
        if (Entries.Remove(entry)) Save();
    }

    /// <summary>
    /// Removes several entries with a single save. Called from: DetectionsWindow
    /// (Delete entry with a multi-selection).
    /// </summary>
    public static int DeleteMany(IEnumerable<DetectionEntry> entries)
    {
        int removed = 0;
        foreach (var entry in entries.ToList())
            if (Entries.Remove(entry)) removed++;
        if (removed > 0) Save();
        return removed;
    }

    /// <summary>
    /// Removes every entry that is no longer Pending (already quarantined, removed,
    /// whitelisted or ignored) and saves. Returns how many were removed.
    /// Called from: DetectionsWindow (Delete managed entries).
    /// </summary>
    public static int DeleteManaged()
    {
        int removed = 0;
        for (int i = Entries.Count - 1; i >= 0; i--)
        {
            if (Entries[i].Status == DetectionStatus.Pending) continue;
            Entries.RemoveAt(i);
            removed++;
        }
        if (removed > 0) Save();
        return removed;
    }

    /// <summary>Removes every entry and saves. Called from: DetectionsWindow (Delete all entries).</summary>
    public static void Clear()
    {
        if (Entries.Count == 0) return;
        Entries.Clear();
        Save();
    }

    /// <summary>
    /// Writes the list to detections.json (atomic). Reports the reason on failure
    /// instead of throwing. Called from: AddFindings, Delete and DetectionsWindow
    /// after a status/VirusTotal change.
    /// </summary>
    public static void Save()
    {
        try
        {
            AtomicFile.WriteAllText(AppPaths.DetectionsFile,
                JsonSerializer.Serialize(Entries.ToList(), JsonOptions));
        }
        catch (Exception ex)
        {
            AppNotifications.ReportError($"Could not save the detections list: {ex.Message}");
        }
    }
}
