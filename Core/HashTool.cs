using System.IO;
using System.Security.Cryptography;

namespace ClamHub.Core;

/// <summary>
/// Computes file hashes with .NET crypto classes instead of shelling out to
/// certutil like the old CHECKSUM batch section. Async so large files do not
/// block the UI thread.
/// Called from: MainWindow hash tab handlers.
/// </summary>
public static class HashTool
{
    /// <summary>Supported algorithms, order matches the UI combo box.</summary>
    public static readonly string[] Algorithms = { "SHA256", "SHA1", "SHA384", "SHA512", "MD5" };

    /// <summary>
    /// Computes a single hash and returns it as an uppercase hex string,
    /// or null when the file cannot be read.
    /// Called from: MainWindow ComputeHash_Click and ComputeAllAsync.
    /// </summary>
    public static async Task<string?> ComputeAsync(string filePath, string algorithm,
        CancellationToken cancel = default)
    {
        try
        {
            using HashAlgorithm hasher = algorithm switch
            {
                "SHA1" => SHA1.Create(),
                "SHA256" => SHA256.Create(),
                "SHA384" => SHA384.Create(),
                "SHA512" => SHA512.Create(),
                "MD5" => MD5.Create(),
                _ => throw new ArgumentException($"Unknown algorithm: {algorithm}")
            };

            await using var stream = File.OpenRead(filePath);
            var hash = await hasher.ComputeHashAsync(stream, cancel);
            return Convert.ToHexString(hash);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Computes all supported hashes for one file. Failed algorithms map to null.
    /// Called from: MainWindow ComputeHash_Click when "All" is selected.
    /// </summary>
    public static async Task<Dictionary<string, string?>> ComputeAllAsync(string filePath,
        CancellationToken cancel = default)
    {
        var results = new Dictionary<string, string?>();
        foreach (var algo in Algorithms)
            results[algo] = await ComputeAsync(filePath, algo, cancel);
        return results;
    }

    /// <summary>
    /// Compares a computed hash with a user supplied expected value, ignoring
    /// case, spaces and surrounding quotes.
    /// Called from: MainWindow ComputeHash_Click when an expected hash is given.
    /// </summary>
    public static bool Matches(string computed, string expected)
    {
        static string Normalize(string s) => s.Replace(" ", "").Replace("\"", "").Trim();
        return string.Equals(Normalize(computed), Normalize(expected),
            StringComparison.OrdinalIgnoreCase);
    }
}
