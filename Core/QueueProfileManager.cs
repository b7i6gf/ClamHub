using System.IO;
using System.Text.Json;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Loads and saves named scan queues (queues.json next to the EXE). Names are
/// unique; saving an existing name overwrites that queue.
/// Called from: ScanQueueWindow (combo fill, save, load, delete).
/// </summary>
public static class QueueProfileManager
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>In-memory queue-profile list, sorted by name.</summary>
    public static List<QueueProfile> Profiles { get; private set; } = new();

    /// <summary>
    /// Loads queues.json, an invalid or missing file yields an empty list.
    /// Called from: ScanQueueWindow construction.
    /// </summary>
    public static void Load()
    {
        try
        {
            if (File.Exists(AppPaths.QueueProfilesFile))
            {
                var json = File.ReadAllText(AppPaths.QueueProfilesFile);
                Profiles = JsonSerializer.Deserialize<List<QueueProfile>>(json, JsonOptions) ?? new();
            }
        }
        catch (Exception)
        {
            Profiles = new();
        }
        SortByName();
    }

    /// <summary>
    /// Adds a new queue or overwrites the one with the same name, then saves.
    /// Called from: ScanQueueWindow SaveQueueProfile_Click.
    /// </summary>
    public static void AddOrUpdate(QueueProfile profile)
    {
        Profiles.RemoveAll(p => string.Equals(p.Name, profile.Name, StringComparison.OrdinalIgnoreCase));
        Profiles.Add(profile);
        SortByName();
        Save();
    }

    /// <summary>
    /// Deletes a queue by name and saves. Returns true when one was removed.
    /// Called from: ScanQueueWindow DeleteQueueProfile_Click.
    /// </summary>
    public static bool Delete(string name)
    {
        int removed = Profiles.RemoveAll(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
        if (removed > 0) Save();
        return removed > 0;
    }

    /// <summary>
    /// Writes the current list to queues.json (atomic). Reports the reason on
    /// failure instead of throwing. Called from: AddOrUpdate, Delete.
    /// </summary>
    private static void Save()
    {
        try
        {
            AtomicFile.WriteAllText(AppPaths.QueueProfilesFile, JsonSerializer.Serialize(Profiles, JsonOptions));
        }
        catch (Exception ex)
        {
            AppNotifications.ReportError($"Could not save scan queues: {ex.Message}");
        }
    }

    private static void SortByName()
        => Profiles.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
}
