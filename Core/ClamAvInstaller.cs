using System.IO;
using System.IO.Compression;
using System.Net.Http;

namespace ClamHub.Core;

/// <summary>
/// Downloads a ClamAV portable release zip and extracts the executables and
/// libraries the app needs into the ClamAV folder, so ClamAV can be set up
/// without manual copying. Called from: UpdateCheckWindow (and the first-run
/// setup prompt).
/// </summary>
public static class ClamAvInstaller
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(10) };

    /// <summary>
    /// Returns the single top-level folder shared by every zip entry (ClamAV zips
    /// wrap everything in e.g. "clamav-1.4.3.win.x64/") so it can be stripped, or
    /// "" when there is no single common root. Called from: DownloadAndExtractAsync.
    /// </summary>
    private static string CommonRootFolder(ZipArchive archive)
    {
        string? root = null;
        foreach (var e in archive.Entries)
        {
            string full = e.FullName.Replace('\\', '/');
            int slash = full.IndexOf('/');
            if (slash < 0) return ""; // a file sits at the zip root -> no common wrapper
            string first = full.Substring(0, slash + 1);
            if (root == null) root = first;
            else if (!string.Equals(root, first, StringComparison.OrdinalIgnoreCase)) return "";
        }
        return root ?? "";
    }

    /// <summary>
    /// Downloads the zip at downloadUrl to a temp file (reporting byte progress via
    /// onProgress), verifies its SHA256 against expectedDigest ("sha256:hex"; a
    /// missing digest only logs "cannot verify"), then extracts the full package into
    /// AppPaths.ClamAvDir. Reports status text via onOutput. Returns true only if all
    /// required executables ended up in place. The caller must stop any running ClamAV
    /// process first so the files are not locked. knownSize (the asset size from
    /// GitHub) is used as the total when the server sends no Content-Length.
    /// Called from: UpdateCheckWindow and MainWindow's first-run setup prompt.
    /// </summary>
    public static async Task<bool> DownloadAndExtractAsync(string downloadUrl, long knownSize,
        string? expectedDigest, Action<string> onOutput, Action<long, long?> onProgress,
        CancellationToken cancel = default)
    {
        string tempZip = Path.Combine(Path.GetTempPath(), $"clamav_dl_{Guid.NewGuid():N}.zip");
        try
        {
            onOutput("Downloading ClamAV package...");
            using (var resp = await Http.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead, cancel))
            {
                resp.EnsureSuccessStatusCode();
                long? total = resp.Content.Headers.ContentLength ?? (knownSize > 0 ? knownSize : (long?)null);
                await using var src = await resp.Content.ReadAsStreamAsync(cancel);
                await using var dst = File.Create(tempZip);

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

            // Verify the downloaded package against the published SHA256 before
            // extracting, so a corrupted or tampered zip is never unpacked into the
            // ClamAV folder. A missing digest only logs "cannot verify" and continues.
            onProgress(-1, null);
            if (!await HashTool.VerifyFileDigestAsync(tempZip, expectedDigest, onOutput, cancel))
                return false;

            Directory.CreateDirectory(AppPaths.ClamAvDir);
            onOutput("Extracting ClamAV...");
            onProgress(-1, null); // switch the bar to the animated/indeterminate look
            int extracted = 0;
            using (var archive = ZipFile.OpenRead(tempZip))
            {
                // ClamAV ships exes, DLLs AND a certs\ folder (needed to verify the
                // signed databases). Extract EVERYTHING, just strip the wrapper
                // folder so the binaries land directly in the ClamAV folder.
                string root = CommonRootFolder(archive);
                string baseFull = Path.GetFullPath(AppPaths.ClamAvDir);
                foreach (var entry in archive.Entries)
                {
                    cancel.ThrowIfCancellationRequested();
                    string rel = entry.FullName.Replace('\\', '/');
                    if (root.Length > 0 && rel.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                        rel = rel.Substring(root.Length);
                    if (rel.Length == 0) continue;
                    rel = rel.Replace('/', Path.DirectorySeparatorChar);
                    string target = Path.Combine(AppPaths.ClamAvDir, rel);

                    // zip-slip guard: never write outside the ClamAV folder.
                    string targetFull = Path.GetFullPath(target);
                    if (!targetFull.Equals(baseFull, StringComparison.OrdinalIgnoreCase)
                        && !targetFull.StartsWith(baseFull + Path.DirectorySeparatorChar,
                            StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (entry.Name.Length == 0) // directory entry
                    {
                        Directory.CreateDirectory(target);
                        continue;
                    }
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);

                    // Buffered copy (1 MB) rather than ExtractToFile's smaller default,
                    // and cancellable mid-file.
                    await using (var es = entry.Open())
                    await using (var fs = new FileStream(target, FileMode.Create, FileAccess.Write,
                                     FileShare.None, 1 << 20, FileOptions.SequentialScan))
                        await es.CopyToAsync(fs, 1 << 20, cancel);
                    extracted++;
                }
            }
            onOutput($"Extracted {extracted} files into the ClamAV folder.");

            if (!AppPaths.ContainsClamAvBinaries(AppPaths.ClamAvDir))
            {
                onOutput("The required ClamAV executables are still missing after extraction.");
                return false;
            }

            onOutput("ClamAV is ready.");
            return true;
        }
        catch (OperationCanceledException)
        {
            onOutput("Setup cancelled.");
            return false;
        }
        catch (Exception ex)
        {
            onOutput("Setup failed: " + ex.Message);
            return false;
        }
        finally
        {
            try { if (File.Exists(tempZip)) File.Delete(tempZip); } catch { /* temp cleanup is best effort */ }
        }
    }
}
