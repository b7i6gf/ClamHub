using System.IO;
using System.Security.Cryptography;

namespace ClamHub.Core;

/// <summary>
/// Computes file hashes with .NET crypto classes instead of shelling out to
/// certutil like the old CHECKSUM batch section. The "all hashes" path reads the
/// file only once and feeds every block to all hashers, and the CPU work runs off
/// the UI thread, so even large files stay responsive.
/// Called from: MainWindow hash tab handlers.
/// </summary>
public static class HashTool
{
    /// <summary>Supported algorithms, order matches the UI combo box and the "All" output.</summary>
    public static readonly string[] Algorithms =
        { "MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512" };

    /// <summary>Streaming read buffer (1 MB): large enough to keep the disk busy.</summary>
    private const int BufferSize = 1 << 20;

    /// <summary>
    /// True when the algorithm can run on this machine. The classic algorithms are
    /// always available; the SHA-3 family needs a recent Windows build (its .NET
    /// wrappers expose IsSupported and throw when constructed on older systems).
    /// Called from: ComputeAsync, ComputeAllAsync and MainWindow's hash output.
    /// </summary>
    public static bool IsSupported(string algorithm) => algorithm switch
    {
        "SHA3-256" => SHA3_256.IsSupported,
        "SHA3-384" => SHA3_384.IsSupported,
        "SHA3-512" => SHA3_512.IsSupported,
        _ => true
    };

    /// <summary>
    /// Maps an algorithm name to a fresh HashAlgorithm instance. Kept in one place
    /// so the single-hash and all-hashes paths stay in sync.
    /// Called from: ComputeAsync and ComputeAllAsync.
    /// </summary>
    private static HashAlgorithm CreateHasher(string algorithm) => algorithm switch
    {
        "MD5" => MD5.Create(),
        "SHA1" => SHA1.Create(),
        "SHA256" => SHA256.Create(),
        "SHA384" => SHA384.Create(),
        "SHA512" => SHA512.Create(),
        "SHA3-256" => SHA3_256.Create(),
        "SHA3-384" => SHA3_384.Create(),
        "SHA3-512" => SHA3_512.Create(),
        _ => throw new ArgumentException($"Unknown algorithm: {algorithm}")
    };

    /// <summary>
    /// Opens a file for hashing: read-only, sharing read+write so a file still open
    /// in another process can be hashed, with a sequential-scan hint for throughput.
    /// Called from: ComputeAsync and ComputeAllAsync.
    /// </summary>
    private static FileStream OpenForHashing(string filePath)
        => new(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
               BufferSize, FileOptions.SequentialScan);

    /// <summary>
    /// Computes a single hash and returns it as an uppercase hex string, or null
    /// when the file cannot be read or the algorithm is unsupported on this system.
    /// Reports 0..1 progress via progress and can be cancelled via cancel.
    /// Called from: MainWindow ComputeHashAsync and RunVirusTotalLookup.
    /// </summary>
    public static async Task<string?> ComputeAsync(string filePath, string algorithm,
        IProgress<double>? progress = null, CancellationToken cancel = default)
    {
        if (!IsSupported(algorithm)) return null;
        using var hasher = CreateHasher(algorithm);
        try
        {
            await RunHashersAsync(filePath, new[] { hasher }, progress, cancel);
            return Convert.ToHexString(hasher.Hash!);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads the file ONCE on a background thread and feeds every block to all
    /// given hashers (TransformBlock), finalizing them at the end. Reports 0..1
    /// progress (throttled) from the file size and honors cancellation between
    /// blocks. Shared by the single- and all-hash paths. On success each hasher's
    /// Hash is populated. Called from: ComputeAsync and ComputeAllAsync.
    /// </summary>
    private static Task RunHashersAsync(string filePath, IReadOnlyList<HashAlgorithm> hashers,
        IProgress<double>? progress, CancellationToken cancel)
        => Task.Run(() =>
        {
            long total = 0;
            try { total = new FileInfo(filePath).Length; } catch { total = 0; }

            using var stream = OpenForHashing(filePath);
            var buffer = new byte[BufferSize];
            long done = 0;
            var lastReport = DateTime.MinValue;
            int read;
            progress?.Report(0);
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancel.ThrowIfCancellationRequested();
                for (int i = 0; i < hashers.Count; i++)
                    hashers[i].TransformBlock(buffer, 0, read, null, 0);

                done += read;
                var now = DateTime.UtcNow;
                if (total > 0 && (now - lastReport).TotalMilliseconds >= 50)
                {
                    progress?.Report((double)done / total);
                    lastReport = now;
                }
            }
            for (int i = 0; i < hashers.Count; i++)
                hashers[i].TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            progress?.Report(1);
        }, cancel);

    /// <summary>
    /// Computes all supported hashes for one file in a SINGLE pass over the data:
    /// each block read is handed to every hasher via TransformBlock, so the file is
    /// read once instead of once per algorithm (roughly 8x less I/O). Reports 0..1
    /// progress and honors cancellation. A read failure, and any SHA-3 variant
    /// unsupported on this Windows build, map to null. A cancelled token aborts with
    /// OperationCanceledException.
    /// Called from: MainWindow ComputeHashAsync when "All" is selected.
    /// </summary>
    public static async Task<Dictionary<string, string?>> ComputeAllAsync(string filePath,
        IProgress<double>? progress = null, CancellationToken cancel = default)
    {
        // One hasher per supported algorithm; unsupported variants are null up front.
        var results = new Dictionary<string, string?>();
        var hashers = new List<HashAlgorithm>();
        var names = new List<string>();
        foreach (var name in Algorithms)
        {
            if (IsSupported(name)) { hashers.Add(CreateHasher(name)); names.Add(name); }
            else results[name] = null;
        }

        try
        {
            await RunHashersAsync(filePath, hashers, progress, cancel);
            for (int i = 0; i < hashers.Count; i++)
                results[names[i]] = Convert.ToHexString(hashers[i].Hash!);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Read failure: every algorithm still without a result becomes null.
            foreach (var name in Algorithms)
                results.TryAdd(name, null);
        }
        finally
        {
            foreach (var h in hashers) h.Dispose();
        }

        // Return in the canonical Algorithms order (the UI relies on it).
        return Algorithms.ToDictionary(a => a, a => results.GetValueOrDefault(a));
    }

    /// <summary>
    /// Verifies a file's SHA256 against a GitHub asset digest of the form
    /// "sha256:hex". Returns true when it matches OR when no digest was supplied
    /// (cannot verify; a note is sent via onStatus), and false only on a real
    /// mismatch or an unreadable file. Shared so the ClamHub self-update and the
    /// ClamAV installer verify downloads the same way.
    /// Called from: SelfUpdater.PrepareUpdateAsync and ClamAvInstaller.DownloadAndExtractAsync.
    /// </summary>
    public static async Task<bool> VerifyFileDigestAsync(string filePath, string? expectedDigest,
        Action<string>? onStatus = null, CancellationToken cancel = default)
    {
        if (string.IsNullOrWhiteSpace(expectedDigest) ||
            !expectedDigest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
        {
            onStatus?.Invoke("No SHA256 published for this download; cannot verify integrity, continuing.");
            return true;
        }
        string expected = expectedDigest["sha256:".Length..].Trim();

        onStatus?.Invoke("Verifying SHA256...");
        string? actual = await ComputeAsync(filePath, "SHA256", null, cancel);
        if (actual == null)
        {
            onStatus?.Invoke("Could not read the download to verify its SHA256. Aborting.");
            return false;
        }
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            onStatus?.Invoke("SHA256 mismatch: the download does not match the published checksum. Aborting.");
            return false;
        }
        onStatus?.Invoke("SHA256 verified.");
        return true;
    }

    /// <summary>
    /// Compares a computed hash with a user supplied expected value, ignoring
    /// case, spaces and surrounding quotes.
    /// Called from: MainWindow ComputeHashAsync when an expected hash is given.
    /// </summary>
    public static bool Matches(string computed, string expected)
    {
        static string Normalize(string s) => s.Replace(" ", "").Replace("\"", "").Trim();
        return string.Equals(Normalize(computed), Normalize(expected),
            StringComparison.OrdinalIgnoreCase);
    }
}
