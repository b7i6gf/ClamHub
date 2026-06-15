using System.IO;
using System.Text.Json;
using ClamAVGui.Models;

namespace ClamAVGui.Core;

/// <summary>
/// Manages the quarantine folder and its index (quarantine.json). Unlike
/// ClamAV's --move, the GUI moves infected files here itself so it can keep
/// the exact original path for a reliable restore. Stored files are renamed to
/// a unique id to avoid name collisions.
/// Called from: MainWindow.RunScanGuarded (quarantine after scan) and the
/// Quarantine tab (MainWindow.Quarantine.cs).
/// </summary>
public static class QuarantineManager
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>In-memory index, newest first.</summary>
    public static List<QuarantineEntry> Entries { get; private set; } = new();

    /// <summary>
    /// Loads quarantine.json, an invalid or missing file yields an empty list.
    /// Called from: MainWindow.InitializeAsync via InitializeQuarantine.
    /// </summary>
    public static void Load()
    {
        try
        {
            if (File.Exists(AppPaths.QuarantineIndexFile))
            {
                var json = File.ReadAllText(AppPaths.QuarantineIndexFile);
                Entries = JsonSerializer.Deserialize<List<QuarantineEntry>>(json, JsonOptions) ?? new();
            }
        }
        catch (Exception)
        {
            Entries = new();
        }
    }

    /// <summary>
    /// Moves one infected file into the quarantine folder and records it.
    /// Returns false (with a reason) when the move fails, e.g. missing rights.
    /// Called from: MainWindow.QuarantineInfectedFiles after a scan.
    /// </summary>
    public static bool Quarantine(string originalPath, string threat, out string? error)
    {
        error = null;
        try
        {
            if (!File.Exists(originalPath))
            {
                error = $"File no longer exists: {originalPath}";
                return false;
            }

            var id = $"{DateTime.Now:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}".Substring(0, 30) + ".quar";
            var dest = Path.Combine(AppPaths.QuarantineDir, id);
            long size = new FileInfo(originalPath).Length;

            File.Move(originalPath, dest);

            Entries.Insert(0, new QuarantineEntry
            {
                Id = id,
                OriginalPath = originalPath,
                Threat = threat,
                QuarantinedAt = DateTime.Now,
                SizeBytes = size
            });
            Save();
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Restores a quarantined file to its original path. By default it refuses
    /// to overwrite an existing file at the target unless overwrite is true.
    /// Called from: MainWindow.Quarantine.cs Restore button.
    /// </summary>
    public static bool Restore(QuarantineEntry entry, bool overwrite, out string? error)
    {
        error = null;
        try
        {
            var stored = Path.Combine(AppPaths.QuarantineDir, entry.Id);
            if (!File.Exists(stored))
            {
                error = "Quarantined file is missing from the quarantine folder.";
                return false;
            }
            if (File.Exists(entry.OriginalPath) && !overwrite)
            {
                error = "A file already exists at the original location.";
                return false;
            }

            var dir = Path.GetDirectoryName(entry.OriginalPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            File.Move(stored, entry.OriginalPath, overwrite);
            Entries.RemoveAll(e => e.Id == entry.Id);
            Save();
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Permanently deletes a quarantined file and its index entry.
    /// Called from: MainWindow.Quarantine.cs Delete button.
    /// </summary>
    public static bool Delete(QuarantineEntry entry, out string? error)
    {
        error = null;
        try
        {
            var stored = Path.Combine(AppPaths.QuarantineDir, entry.Id);
            if (File.Exists(stored)) File.Delete(stored);
            Entries.RemoveAll(e => e.Id == entry.Id);
            Save();
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    // Atomic write so the quarantine index cannot be truncated on a crash or a
    // pulled USB stick. The action methods (Quarantine/Restore/Delete) wrap this
    // in their own try/catch and report a failure to the user.
    private static void Save()
        => AtomicFile.WriteAllText(AppPaths.QuarantineIndexFile,
            JsonSerializer.Serialize(Entries, JsonOptions));
}
