using System.IO;
using System.Text.Json;
using ClamHub.Models;

namespace ClamHub.Core;

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

    /// <summary>
    /// Byte the stored .quar files are XORed with, so a scanner on the same machine
    /// does not match a signature against the quarantined copy. This is signature
    /// neutralization, NOT encryption; the file is trivially recoverable by design.
    /// </summary>
    private const byte ObfuscationKey = 0xFF;

    /// <summary>In-memory index, newest first.</summary>
    public static List<QuarantineEntry> Entries { get; private set; } = new();

    // Serializes all mutating operations. Since the 2026-07-18 cleanup the heavy file work runs
    // on worker threads (Task.Run via the *Async wrappers), so without this lock
    // two concurrent actions could interleave their Entries updates and Saves.
    // Before, everything ran on the UI thread and was implicitly serialized.
    private static readonly object _gate = new();

    /// <summary>
    /// Streams source to destination flipping every byte with ObfuscationKey. XOR is
    /// symmetric, so the same call obfuscates when quarantining and restores when
    /// releasing. destMode is CreateNew (never clobber) or Create (overwrite allowed).
    /// Called from: Quarantine and Restore.
    /// </summary>
    private static void CopyXor(string source, string destination, FileMode destMode)
    {
        using var src = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var dst = new FileStream(destination, destMode, FileAccess.Write, FileShare.None);
        var buffer = new byte[1 << 16];
        int read;
        while ((read = src.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < read; i++) buffer[i] ^= ObfuscationKey;
            dst.Write(buffer, 0, read);
        }
    }

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
    /// Called from: MainWindow.QuarantineInfectedFilesAsync after a scan.
    /// </summary>
    public static bool Quarantine(string originalPath, string threat, out string? error)
    {
        lock (_gate)
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

                // Write the stored copy XORed so a usable malware file is never on disk
                // (co-resident AV would otherwise grab it), then remove the original. On
                // any failure delete the half-written copy and keep the original intact.
                try
                {
                    CopyXor(originalPath, dest, FileMode.CreateNew);
                    File.Delete(originalPath);
                }
                catch
                {
                    try { if (File.Exists(dest)) File.Delete(dest); } catch { /* best effort */ }
                    throw;
                }

                Entries.Insert(0, new QuarantineEntry
                {
                    Id = id,
                    OriginalPath = originalPath,
                    Threat = threat,
                    QuarantinedAt = DateTime.Now,
                    SizeBytes = size,
                    Obfuscated = true
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
    }

    /// <summary>
    /// Runs Quarantine on a worker thread so a large file's XOR copy never blocks
    /// the UI. Called from: MainWindow.QuarantineInfectedFilesAsync and
    /// DetectionsWindow.Quarantine_Click.
    /// </summary>
    public static Task<(bool Ok, string? Error)> QuarantineAsync(string originalPath, string threat)
        => Task.Run(() =>
        {
            bool ok = Quarantine(originalPath, threat, out var error);
            return (ok, error);
        });

    /// <summary>
    /// Restores a quarantined file to its original path. By default it refuses
    /// to overwrite an existing file at the target unless overwrite is true.
    /// Called from: MainWindow.Quarantine.cs Restore button.
    /// </summary>
    public static bool Restore(QuarantineEntry entry, bool overwrite, out string? error)
    {
        lock (_gate)
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

                if (entry.Obfuscated)
                {
                    // Reverse the XOR back to the original bytes, then drop the stored
                    // copy. CreateNew unless overwrite, as a guard against a file that
                    // appeared at the target after the check above.
                    CopyXor(stored, entry.OriginalPath, overwrite ? FileMode.Create : FileMode.CreateNew);
                    File.Delete(stored);
                }
                else
                {
                    // Legacy entry stored plaintext (before obfuscation): move as-is.
                    File.Move(stored, entry.OriginalPath, overwrite);
                }

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
    }

    /// <summary>
    /// Runs Restore on a worker thread (see QuarantineAsync). Called from:
    /// MainWindow.RestoreOneQuarantineAsync.
    /// </summary>
    public static Task<(bool Ok, string? Error)> RestoreAsync(QuarantineEntry entry, bool overwrite)
        => Task.Run(() =>
        {
            bool ok = Restore(entry, overwrite, out var error);
            return (ok, error);
        });

    /// <summary>
    /// Computes the SHA256 of a quarantined entry's ORIGINAL content. It streams the
    /// stored .quar file and, for an obfuscated entry, reverses the XOR IN MEMORY
    /// (block by block, straight into the hasher) before hashing, so the result
    /// matches the original file WITHOUT ever writing a usable/de-obfuscated copy to
    /// disk. Returns the uppercase hex hash, or null with an error.
    /// Called from: MainWindow.QuarantineVirusTotal_Click.
    /// </summary>
    public static string? ComputeOriginalSha256(QuarantineEntry entry, out string? error)
    {
        error = null;
        try
        {
            var stored = Path.Combine(AppPaths.QuarantineDir, entry.Id);
            using var sha = System.Security.Cryptography.SHA256.Create();
            using var src = new FileStream(stored, FileMode.Open, FileAccess.Read, FileShare.Read);
            var buffer = new byte[1 << 16];
            int read;
            while ((read = src.Read(buffer, 0, buffer.Length)) > 0)
            {
                // Reverse the XOR only in this transient buffer, never on disk.
                if (entry.Obfuscated)
                    for (int i = 0; i < read; i++) buffer[i] ^= ObfuscationKey;
                sha.TransformBlock(buffer, 0, read, null, 0);
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return Convert.ToHexString(sha.Hash!);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return null;
        }
    }

    /// <summary>
    /// Runs ComputeOriginalSha256 on a worker thread (a full read pass of the
    /// stored file). Called from: MainWindow.QuarantineVirusTotal_Click.
    /// </summary>
    public static Task<(string? Sha256, string? Error)> ComputeOriginalSha256Async(QuarantineEntry entry)
        => Task.Run(() =>
        {
            var sha = ComputeOriginalSha256(entry, out var error);
            return (sha, error);
        });

    /// <summary>
    /// Permanently deletes a quarantined file and its index entry.
    /// Called from: MainWindow.Quarantine.cs Delete button.
    /// </summary>
    public static bool Delete(QuarantineEntry entry, out string? error)
    {
        lock (_gate)
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
    }

    /// <summary>
    /// Runs Delete on a worker thread (see QuarantineAsync). Called from:
    /// MainWindow.DeleteQuarantine_Click.
    /// </summary>
    public static Task<(bool Ok, string? Error)> DeleteAsync(QuarantineEntry entry)
        => Task.Run(() =>
        {
            bool ok = Delete(entry, out var error);
            return (ok, error);
        });

    // Atomic write so the quarantine index cannot be truncated on a crash or a
    // pulled USB stick. The action methods (Quarantine/Restore/Delete) wrap this
    // in their own try/catch and report a failure to the user.
    private static void Save()
        => AtomicFile.WriteAllText(AppPaths.QuarantineIndexFile,
            JsonSerializer.Serialize(Entries, JsonOptions));
}
