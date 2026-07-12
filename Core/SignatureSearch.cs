using System.IO;
using System.Text.RegularExpressions;

namespace ClamHub.Core;

/// <summary>
/// Searches ClamAV signatures across selected databases and streams the hits back.
/// Two sources are used on purpose:
///  - PLAIN TEXT databases (.ndb/.hdb/.hsb/.ldb/...) are read directly from disk. That is
///    exact, needs no sigtool and yields the full raw signature line (so it can be decoded).
///  - CONTAINER databases (.cvd/.cld) are only readable through sigtool, so their signature
///    NAMES come from "sigtool --list-sigs"; the raw line is fetched lazily per signature
///    (FindRawLineAsync) when the user wants to decode one.
/// Nothing is buffered here: every hit is handed to a callback on a worker thread, and the
/// whole run is cancellable, because a full listing of daily.cvd is millions of signatures.
/// Called from: SignatureSearchWindow.
/// </summary>
public static class SignatureSearch
{
    /// <summary>
    /// One signature found in a database. RawLine is null for container databases, where
    /// only the name is listed; FindRawLineAsync can fetch it on demand.
    /// Consumed by: the signature-search window (results table and decoding).
    /// </summary>
    public sealed record SigHit(string Database, string Name, string? RawLine);

    /// <summary>Database extensions whose signatures are plain text lines we can read ourselves.</summary>
    private static readonly HashSet<string> TextDbExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".hdb", ".hsb", ".mdb", ".msb", ".ndb", ".ldb", ".sdb", ".fp", ".sfp", ".idb",
        ".cdb", ".crb", ".gdb", ".pdb", ".wdb", ".ign", ".ign2", ".imp", ".pwdb", ".ftm"
    };

    /// <summary>True when the file's signatures can be read directly instead of via sigtool.</summary>
    public static bool IsTextDatabase(string path) => TextDbExtensions.Contains(Path.GetExtension(path));

    /// <summary>
    /// Extracts the malware name from a raw ClamAV signature line. The name's position
    /// depends on the database type: logical signatures (.ldb) are "Name;...", hash
    /// signatures (.hdb/.hsb/.fp/...) are "hash:size:Name", and everything else
    /// (.ndb and friends) starts with the name. Called from: SearchAsync, FindRawLineAsync
    /// and the duplicate detection.
    /// </summary>
    public static string ExtractName(string rawLine)
    {
        int semi = rawLine.IndexOf(';');
        int colon = rawLine.IndexOf(':');

        // Logical signature: the name ends at the first ';' and contains no ':' before it.
        if (semi >= 0 && (colon < 0 || semi < colon)) return rawLine[..semi];
        if (colon < 0) return rawLine;

        var parts = rawLine.Split(':');
        if (parts.Length >= 3 && LooksLikeHash(parts[0]) && (parts[1] == "*" || long.TryParse(parts[1], out _)))
            return parts[2];
        return parts[0];
    }

    /// <summary>True for a 32/40/64 character hex string (MD5, SHA1, SHA256).</summary>
    private static bool LooksLikeHash(string s)
        => s.Length is 32 or 40 or 64 && s.All(Uri.IsHexDigit);

    /// <summary>
    /// Extracts the detection PAYLOAD of a raw signature line, i.e. everything that is not
    /// the malware name: the hash and file size for hash databases, the pattern part for
    /// .ndb and the logical body for .ldb. Two signatures with the same payload detect
    /// exactly the same thing under (possibly) different names, which is what the
    /// "duplicates by content" mode groups on. Mirrors the type detection of ExtractName.
    /// Returns the whole line when it cannot be split. Called from: the duplicate scan.
    /// </summary>
    public static string ExtractContent(string rawLine)
    {
        int semi = rawLine.IndexOf(';');
        int colon = rawLine.IndexOf(':');

        // Logical signature "Name;target;expression;subsigs": drop the leading name.
        if (semi >= 0 && (colon < 0 || semi < colon)) return rawLine[(semi + 1)..];
        if (colon < 0) return rawLine;

        var parts = rawLine.Split(':');
        // Hash signature "hash:size:Name": the payload is the hash and the size.
        if (parts.Length >= 3 && LooksLikeHash(parts[0]) && (parts[1] == "*" || long.TryParse(parts[1], out _)))
            return parts[0] + ":" + parts[1];

        // Everything else ("Name:target:offset:hexsig..."): drop the leading name.
        return rawLine[(colon + 1)..];
    }

    /// <summary>
    /// Streams every signature of the given databases whose name (or, when matchRawLine is
    /// true, whose whole raw line) matches the pattern. A null pattern matches everything,
    /// which is how "list all signatures of this database" works. onHit runs on a WORKER
    /// thread, once per signature, and must be cheap; onStatus reports the database being
    /// read. Container databases never produce a RawLine, so matchRawLine cannot apply to
    /// them and they are matched by name. Honors cancellation between signatures.
    /// onStatus receives the plain file name of the database being read (the caller formats
    /// the status text). Called from: the signature-search window (search, list and
    /// duplicate scan).
    /// </summary>
    public static async Task SearchAsync(
        IEnumerable<string> databasePaths,
        Regex? pattern,
        bool matchRawLine,
        Action<SigHit> onHit,
        Action<string>? onStatus = null,
        CancellationToken cancel = default)
    {
        foreach (var path in databasePaths)
        {
            cancel.ThrowIfCancellationRequested();
            string dbName = Path.GetFileName(path);
            onStatus?.Invoke(dbName);

            if (IsTextDatabase(path))
                SearchTextDatabase(path, dbName, pattern, matchRawLine, onHit, cancel);
            else
                await SearchContainerDatabaseAsync(path, dbName, pattern, onHit, cancel);
        }
    }

    /// <summary>
    /// Reads a plain-text database line by line (never loading it whole) and reports the
    /// matching signatures with their raw line. Blank lines and comments are skipped.
    /// Called from: SearchAsync.
    /// </summary>
    private static void SearchTextDatabase(string path, string dbName, Regex? pattern,
        bool matchRawLine, Action<SigHit> onHit, CancellationToken cancel)
    {
        IEnumerable<string> lines;
        try { lines = File.ReadLines(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }

        foreach (var raw in lines)
        {
            cancel.ThrowIfCancellationRequested();
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;

            string name = ExtractName(line);
            if (pattern != null && !pattern.IsMatch(matchRawLine ? line : name)) continue;
            onHit(new SigHit(dbName, name, line));
        }
    }

    /// <summary>
    /// Lists a container database's signature names through sigtool and reports the
    /// matching ones (without a raw line). Lines that cannot be signature names (blank,
    /// comments, or anything containing whitespace, which a ClamAV name never does) are
    /// ignored, so stray sigtool banner output does not become a result.
    /// Called from: SearchAsync.
    /// </summary>
    private static async Task SearchContainerDatabaseAsync(string path, string dbName, Regex? pattern,
        Action<SigHit> onHit, CancellationToken cancel)
    {
        await SigTool.ListSignaturesAsync(path, line =>
        {
            var name = line.Trim();
            if (name.Length == 0 || name.StartsWith(';') || name.StartsWith('#')) return;
            if (name.Any(char.IsWhiteSpace)) return;
            if (pattern != null && !pattern.IsMatch(name)) return;
            onHit(new SigHit(dbName, name, null));
        }, cancel);
    }

    /// <summary>
    /// Fetches the raw signature line for one signature name of a container database, by
    /// asking sigtool to find that exact name across the database folder and keeping the
    /// first output line that really carries this signature. sigtool may prefix the line
    /// with the source database, which is stripped. Returns null when nothing usable came
    /// back (the caller then reports that the signature cannot be decoded).
    /// Called from: the signature-search window before decoding a container signature.
    /// </summary>
    public static async Task<string?> FindRawLineAsync(string signatureName, CancellationToken cancel = default)
    {
        string? found = null;
        string pattern = "^" + Regex.Escape(signatureName) + "$";

        await SigTool.FindSignaturesAsync(pattern, line =>
        {
            if (found != null) return;
            var text = line.Trim();
            if (text.Length == 0 || text.StartsWith(';') || text.StartsWith('#')) return;

            // sigtool may print "<database>: <signature line>"; keep only the signature.
            string candidate = StripDatabasePrefix(text);
            if (ExtractName(candidate).Equals(signatureName, StringComparison.Ordinal))
                found = candidate;
        }, cancel);

        return found;
    }

    /// <summary>
    /// Removes a leading "&lt;database file&gt;: " prefix from a sigtool output line, if any.
    /// A real signature line never starts with a database file name followed by ": ".
    /// Called from: FindRawLineAsync.
    /// </summary>
    private static string StripDatabasePrefix(string line)
    {
        int sep = line.IndexOf(": ", StringComparison.Ordinal);
        if (sep <= 0) return line;

        string head = line[..sep];
        return head.Contains('.') && !head.Contains(' ') && TextDbExtensions.Contains(Path.GetExtension(head))
            ? line[(sep + 2)..]
            : line;
    }
}
