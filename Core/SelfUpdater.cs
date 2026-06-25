using System.IO;
using System.IO.Compression;
using System.Net.Http;

namespace ClamHub.Core;

/// <summary>
/// Replaces the running ClamHub executable with a freshly downloaded one. Windows
/// permits renaming a running .exe, so the swap is: download the new exe next to the
/// current one, rename the current one to "&lt;name&gt;.old.exe", move the new one
/// into its place, relaunch, and delete the leftover on the next start. Called from:
/// UpdateCheckWindow (ClamHub "Upgrade" button) and App startup (leftover cleanup).
/// </summary>
public static class SelfUpdater
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(10) };

    /// <summary>Path of the running executable (its launch path), or "" if unknown.</summary>
    public static string CurrentExe => Environment.ProcessPath ?? "";

    private static string Dir => Path.GetDirectoryName(CurrentExe) ?? "";
    private static string BaseName => Path.GetFileNameWithoutExtension(CurrentExe);
    private static string OldExe => Path.Combine(Dir, BaseName + ".old.exe");
    private static string StagingExe => Path.Combine(Dir, BaseName + ".update.exe");

    /// <summary>
    /// Downloads the new ClamHub build next to the current exe (extracting the .exe
    /// from a zip when isZip). Reports byte progress via onProgress and status text
    /// via onOutput. Returns the staged exe path, or null on error/cancel (message
    /// via onOutput). Called from: UpdateCheckWindow.UpgradeClamHubAsync.
    /// </summary>
    public static async Task<string?> PrepareUpdateAsync(string url, bool isZip, long knownSize,
        Action<string> onOutput, Action<long, long?> onProgress, CancellationToken cancel = default)
    {
        if (string.IsNullOrEmpty(CurrentExe))
        {
            onOutput("Cannot determine the current executable path.");
            return null;
        }
        string tempZip = Path.Combine(Path.GetTempPath(), $"clamhub_dl_{Guid.NewGuid():N}.zip");
        try
        {
            try { if (File.Exists(StagingExe)) File.Delete(StagingExe); } catch { /* replaced below */ }

            onOutput("Downloading ClamHub...");
            await DownloadAsync(url, isZip ? tempZip : StagingExe, knownSize, onProgress, cancel);

            if (isZip)
            {
                onOutput("Extracting...");
                onProgress(-1, null); // animated/indeterminate bar during extraction
                using var archive = ZipFile.OpenRead(tempZip);
                var entry = archive.Entries.FirstOrDefault(e =>
                                e.Name.ToLowerInvariant().EndsWith(".exe")
                                && e.Name.ToLowerInvariant().Contains("clamhub"))
                            ?? archive.Entries.FirstOrDefault(e => e.Name.ToLowerInvariant().EndsWith(".exe"));
                if (entry == null)
                {
                    onOutput("No .exe found in the downloaded package.");
                    return null;
                }
                entry.ExtractToFile(StagingExe, overwrite: true);
            }

            if (!File.Exists(StagingExe) || new FileInfo(StagingExe).Length == 0)
            {
                onOutput("The downloaded file is empty.");
                return null;
            }
            return StagingExe;
        }
        catch (OperationCanceledException)
        {
            onOutput("Upgrade cancelled.");
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            onOutput("Cannot write to the application folder (it may be read-only). Run as admin or move ClamHub to a writable folder.");
            return null;
        }
        catch (Exception ex)
        {
            onOutput($"Download failed: {ex.Message}");
            return null;
        }
        finally
        {
            try { if (File.Exists(tempZip)) File.Delete(tempZip); } catch { /* temp file */ }
        }
    }

    /// <summary>Chunked download to destPath with byte progress. Called from: PrepareUpdateAsync.</summary>
    private static async Task DownloadAsync(string url, string destPath, long knownSize,
        Action<long, long?> onProgress, CancellationToken cancel)
    {
        using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancel);
        resp.EnsureSuccessStatusCode();
        long? total = resp.Content.Headers.ContentLength ?? (knownSize > 0 ? knownSize : (long?)null);
        await using var src = await resp.Content.ReadAsStreamAsync(cancel);
        await using var dst = File.Create(destPath);

        var buffer = new byte[81920];
        long copied = 0;
        int read;
        var lastReport = DateTime.MinValue;
        onProgress(0, total);
        while ((read = await src.ReadAsync(buffer.AsMemory(0, buffer.Length), cancel)) > 0)
        {
            await dst.WriteAsync(buffer.AsMemory(0, read), cancel);
            copied += read;
            var now = DateTime.UtcNow;
            if ((now - lastReport).TotalMilliseconds >= 100)
            {
                onProgress(copied, total);
                lastReport = now;
            }
        }
        onProgress(copied, total); // final value
    }

    /// <summary>
    /// Renames the running exe to "&lt;name&gt;.old.exe" and moves newExePath into
    /// its place. Returns (true, null) on success or (false, message) on failure,
    /// restoring the running exe so the app still works. Does not relaunch or exit;
    /// the caller does that. Called from: UpdateCheckWindow.UpgradeClamHubAsync.
    /// </summary>
    public static (bool ok, string? error) TrySwap(string newExePath)
    {
        if (string.IsNullOrEmpty(CurrentExe))
            return (false, "Cannot determine the current executable path.");
        try
        {
            try { if (File.Exists(OldExe)) File.Delete(OldExe); } catch { /* overwritten below */ }
            File.Move(CurrentExe, OldExe); // Windows allows renaming a running exe
            try
            {
                File.Move(newExePath, CurrentExe);
            }
            catch
            {
                try { File.Move(OldExe, CurrentExe); } catch { /* best effort restore */ }
                return (false, "Could not place the new version (the folder may be read-only).");
            }
            return (true, null);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>
    /// Deletes a leftover "&lt;name&gt;.old.exe" from a previous upgrade, retrying
    /// while the old process finishes exiting. Safe no-op when none exists. Called
    /// from: App startup (background task).
    /// </summary>
    public static void CleanupOldExe()
    {
        if (string.IsNullOrEmpty(CurrentExe)) return;
        for (int i = 0; i < 10; i++)
        {
            if (!File.Exists(OldExe)) return;
            try { File.Delete(OldExe); return; }
            catch { System.Threading.Thread.Sleep(300); }
        }
    }
}
