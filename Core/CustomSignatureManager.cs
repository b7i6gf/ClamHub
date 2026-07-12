using System.IO;
using System.Text;

namespace ClamHub.Core;

/// <summary>
/// Manages ClamHub's own ClamAV signature files: a blacklist that makes the
/// scanner DETECT chosen files (SHA256 hash signatures in clamhub-custom.hsb) and
/// an allow-list that makes it IGNORE chosen files (false-positive SHA256 hashes
/// in clamhub-whitelist.sfp). Both files live in the ClamAV database folder next
/// to the official databases, so clamscan loads them on every run automatically
/// (active immediately, no reload) and the daemon loads them after a RELOAD (see
/// the Signatures tab reload button, added in a later batch). freshclam never
/// touches them. Signature lines use ClamAV's hash format "sha256:filesize:name";
/// the name is "ClamHub.Custom.&lt;file&gt;". No sigtool is needed - a SHA256 line
/// is built from HashTool. Entries are de-duplicated by hash. The two files are the
/// single source of truth (no side database). Writes are atomic (AtomicFile).
/// Called from: the Signatures tab/window, the context-menu block/whitelist actions
/// and the quarantine "Restore + Whitelist" action (later batches).
/// </summary>
public static class CustomSignatureManager
{
    /// <summary>Which of the two managed lists an operation targets.</summary>
    public enum ListKind { Blacklist, Whitelist }

    /// <summary>
    /// One parsed signature line. Hash is the lowercase SHA256, Size the recorded
    /// byte length, Name the signature label. RawLine is the exact source line so a
    /// removal can rewrite the file without it. Consumed by: the management UI.
    /// </summary>
    public sealed record SignatureEntry(string Hash, long Size, string Name, string RawLine);

    /// <summary>
    /// Outcome of adding files: the signature names actually written, the files
    /// skipped because their hash was already listed, and the files that failed
    /// (path + reason). Consumed by: the callers that report per file.
    /// </summary>
    public sealed record AddResult(
        IReadOnlyList<string> Added,
        IReadOnlyList<string> Duplicates,
        IReadOnlyList<(string Path, string Error)> Failed);

    /// <summary>
    /// How a file relates to the two lists during analysis. New = not in either list;
    /// DuplicateSameList = already in the target list (adding is a silent no-op);
    /// ConflictOtherList = currently in the OTHER list (needs a move decision); Failed
    /// = could not be read/hashed. Consumed by: the MainWindow add flow.
    /// </summary>
    public enum AddStatus { New, DuplicateSameList, ConflictOtherList, Failed }

    /// <summary>
    /// A file analysed for adding to a list: its hash/size/signature name, the status
    /// versus both lists, the matching entry in the other list (only when
    /// ConflictOtherList, so a move can delete it) and an error (only when Failed).
    /// Produced by AnalyzeAsync, consumed by Commit and the UI.
    /// </summary>
    public sealed record AnalyzedFile(
        string Path,
        string? Hash,
        long Size,
        string Name,
        AddStatus Status,
        SignatureEntry? OtherListEntry,
        string? Error);

    /// <summary>Result of AnalyzeAsync: the target list and one AnalyzedFile per input path.</summary>
    public sealed record AddPlan(ListKind Kind, IReadOnlyList<AnalyzedFile> Files);

    /// <summary>
    /// What Commit actually did: names newly added, names moved in from the other list,
    /// files skipped because already in the target list (silent), files left in the
    /// other list because the move was declined, and files that failed. Consumed by:
    /// the callers that report and write history.
    /// </summary>
    public sealed record CommitResult(
        IReadOnlyList<string> Added,
        IReadOnlyList<string> Moved,
        IReadOnlyList<string> SkippedSameList,
        IReadOnlyList<string> SkippedConflict,
        IReadOnlyList<(string Path, string Error)> Failed);

    /// <summary>Absolute path of the file backing a list. Called from: all methods.</summary>
    private static string PathFor(ListKind kind) => kind == ListKind.Blacklist
        ? AppPaths.CustomBlacklistDb
        : AppPaths.CustomWhitelistDb;

    /// <summary>The opposite list. Called from: AnalyzeAsync and Commit (cross-list moves).</summary>
    private static ListKind OtherKind(ListKind kind)
        => kind == ListKind.Blacklist ? ListKind.Whitelist : ListKind.Blacklist;

    /// <summary>
    /// Reads and parses the entries of a list in file order. Blank lines, comments
    /// (#) and lines that are not "hash:size:name" are ignored. Never throws;
    /// returns an empty list when the file is missing or unreadable.
    /// Called from: the management UI, Count and the add/remove helpers.
    /// </summary>
    public static IReadOnlyList<SignatureEntry> Read(ListKind kind)
    {
        var entries = new List<SignatureEntry>();
        string path = PathFor(kind);
        string[] lines;
        try
        {
            if (!File.Exists(path)) return entries;
            lines = File.ReadAllLines(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return entries;
        }

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;

            var parts = line.Split(':');
            if (parts.Length < 3) continue;
            if (!long.TryParse(parts[1], out long size)) continue;

            // The name we write never contains a colon; parts[2..] is only rejoined
            // defensively so a hand-edited line with a ':' in the name still parses.
            string name = string.Join(':', parts.Skip(2));
            entries.Add(new SignatureEntry(parts[0].Trim().ToLowerInvariant(), size, name, raw));
        }
        return entries;
    }

    /// <summary>Number of valid entries in a list. Called from: the Signatures tab summary.</summary>
    public static int Count(ListKind kind) => Read(kind).Count;

    /// <summary>
    /// Adds one or more files to a list. Each file's SHA256 and byte size become a
    /// "sha256:size:ClamHub.Custom.&lt;file&gt;" line; a file whose hash is already
    /// listed (in the file or earlier in this batch) is skipped and reported as a
    /// duplicate, an unreadable file is reported as failed. The file is rewritten
    /// once, atomically, only when something changed. Returns a per-file breakdown.
    /// Callers should offer a daemon reload afterwards (clamscan picks the change up
    /// on its next run without a reload). Honors cancellation.
    /// Called from: the Signatures window (multi file), the context-menu actions and
    /// the quarantine "Restore + Whitelist".
    /// </summary>
    public static async Task<AddResult> AddFilesAsync(ListKind kind, IEnumerable<string> paths,
        CancellationToken cancel = default)
    {
        var added = new List<string>();
        var duplicates = new List<string>();
        var failed = new List<(string, string)>();

        // Seed the seen-set from the file so we de-dupe against existing entries and
        // against repeats within this batch.
        var seen = Read(kind).Select(e => e.Hash).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var newLines = new List<string>();

        foreach (var rawPath in paths)
        {
            cancel.ThrowIfCancellationRequested();
            string path = rawPath.Trim().Trim('"');

            if (!File.Exists(path)) { failed.Add((path, "Not a file")); continue; }

            long size;
            try { size = new FileInfo(path).Length; }
            catch (Exception ex) { failed.Add((path, ex.Message)); continue; }

            string? hash = await HashTool.ComputeAsync(path, "SHA256", null, cancel);
            if (hash == null) { failed.Add((path, "Could not read the file to hash it")); continue; }
            hash = hash.ToLowerInvariant();

            if (!seen.Add(hash)) { duplicates.Add(path); continue; }

            string name = BuildSignatureName(path);
            newLines.Add($"{hash}:{size}:{name}");
            added.Add(name);
        }

        if (newLines.Count > 0)
            AppendLines(kind, newLines);

        return new AddResult(added, duplicates, failed);
    }

    /// <summary>
    /// Removes the given entries from a list by matching their exact source line and
    /// rewrites the file atomically. Returns the number removed; an empty result
    /// leaves the file untouched. When the list becomes empty the file is deleted.
    /// Called from: the management UI delete button.
    /// </summary>
    public static int Remove(ListKind kind, IEnumerable<SignatureEntry> toRemove)
    {
        var kill = toRemove.Select(e => e.RawLine).ToHashSet(StringComparer.Ordinal);
        if (kill.Count == 0) return 0;

        string path = PathFor(kind);
        if (!File.Exists(path)) return 0;

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 0; }

        var kept = lines.Where(l => !kill.Contains(l)).ToList();
        int removed = lines.Length - kept.Count;
        if (removed == 0) return 0;

        WriteAll(path, kept);
        return removed;
    }

    /// <summary>
    /// Hashes each file ONCE and classifies it for adding to a list: New,
    /// DuplicateSameList (already in the target), ConflictOtherList (currently in the
    /// other list) or Failed. Within-batch repeats of a hash collapse to
    /// DuplicateSameList so a hash is written only once. Nothing is written here; pass
    /// the plan to Commit. Honors cancellation. Called from: the MainWindow add flow
    /// (window drops, context menu, quarantine restore+whitelist).
    /// </summary>
    public static async Task<AddPlan> AnalyzeAsync(ListKind kind, IEnumerable<string> paths,
        CancellationToken cancel = default)
    {
        var targetHashes = Read(kind).Select(e => e.Hash).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var otherByHash = new Dictionary<string, SignatureEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in Read(OtherKind(kind)))
            otherByHash[e.Hash] = e; // duplicates in the file are equivalent; last wins

        var files = new List<AnalyzedFile>();
        foreach (var rawPath in paths)
        {
            cancel.ThrowIfCancellationRequested();
            string path = rawPath.Trim().Trim('"');
            string name = BuildSignatureName(path);

            if (!File.Exists(path))
            {
                files.Add(new AnalyzedFile(path, null, 0, name, AddStatus.Failed, null, "Not a file"));
                continue;
            }

            long size;
            try { size = new FileInfo(path).Length; }
            catch (Exception ex)
            {
                files.Add(new AnalyzedFile(path, null, 0, name, AddStatus.Failed, null, ex.Message));
                continue;
            }

            string? hash = await HashTool.ComputeAsync(path, "SHA256", null, cancel);
            if (hash == null)
            {
                files.Add(new AnalyzedFile(path, null, size, name, AddStatus.Failed, null,
                    "Could not read the file to hash it"));
                continue;
            }
            hash = hash.ToLowerInvariant();

            // Adding to the set also de-dupes within this batch (Add returns false the
            // second time a hash is seen). Target membership takes priority over the
            // other list, so a file already on the target is a silent no-op.
            AddStatus status;
            SignatureEntry? other = null;
            if (!targetHashes.Add(hash))
                status = AddStatus.DuplicateSameList;
            else if (otherByHash.TryGetValue(hash, out other))
                status = AddStatus.ConflictOtherList;
            else
                status = AddStatus.New;

            files.Add(new AnalyzedFile(path, hash, size, name, status, other, null));
        }

        return new AddPlan(kind, files);
    }

    /// <summary>
    /// Applies a plan from AnalyzeAsync. New files are written to the target list.
    /// ConflictOtherList files are written to the target AND removed from the other
    /// list only when moveConflicts is true; otherwise they stay in the other list
    /// (reported as SkippedConflict). DuplicateSameList and Failed are never written.
    /// No hashing here (hashes come from the plan); both files are rewritten atomically
    /// and only when they actually change. Returns a categorised result for reporting
    /// and history. Called from: the MainWindow add flow.
    /// </summary>
    public static CommitResult Commit(AddPlan plan, bool moveConflicts)
    {
        var added = new List<string>();
        var moved = new List<string>();
        var skippedSame = new List<string>();
        var skippedConflict = new List<string>();
        var failed = new List<(string, string)>();

        var newLines = new List<string>();
        var removeFromOther = new List<SignatureEntry>();

        foreach (var f in plan.Files)
        {
            switch (f.Status)
            {
                case AddStatus.New:
                    newLines.Add($"{f.Hash}:{f.Size}:{f.Name}");
                    added.Add(f.Name);
                    break;

                case AddStatus.ConflictOtherList when moveConflicts:
                    newLines.Add($"{f.Hash}:{f.Size}:{f.Name}");
                    if (f.OtherListEntry != null) removeFromOther.Add(f.OtherListEntry);
                    moved.Add(f.Name);
                    break;

                case AddStatus.ConflictOtherList:
                    skippedConflict.Add(f.Name);
                    break;

                case AddStatus.DuplicateSameList:
                    skippedSame.Add(f.Name);
                    break;

                default: // Failed
                    failed.Add((f.Path, f.Error ?? "unknown error"));
                    break;
            }
        }

        // Remove moved entries from the other list first, then append to the target.
        if (removeFromOther.Count > 0)
            Remove(OtherKind(plan.Kind), removeFromOther);
        if (newLines.Count > 0)
            AppendLines(plan.Kind, newLines);

        return new CommitResult(added, moved, skippedSame, skippedConflict, failed);
    }

    /// <summary>
    /// Builds the signature name for a file: "ClamHub.Custom." plus the file name
    /// with every character outside [A-Za-z0-9._-] replaced by '_', so the name can
    /// never contain the ':' field separator or whitespace. Called from: AddFilesAsync.
    /// </summary>
    private static string BuildSignatureName(string path)
    {
        string file = Path.GetFileName(path);
        var sb = new StringBuilder(file.Length);
        foreach (char c in file)
            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '_');

        string safe = sb.ToString().Trim('.');
        if (safe.Length == 0) safe = "file";
        return "ClamHub.Custom." + safe;
    }

    /// <summary>
    /// Appends new signature lines to a list file, creating it when missing and
    /// preserving existing content. Writes the whole file atomically.
    /// Called from: AddFilesAsync.
    /// </summary>
    private static void AppendLines(ListKind kind, IReadOnlyList<string> newLines)
    {
        string path = PathFor(kind);
        var all = new List<string>();
        try { if (File.Exists(path)) all.AddRange(File.ReadAllLines(path)); }
        catch { /* start fresh on a read error rather than lose the new entries */ }

        // Drop trailing blank lines so gaps do not accumulate across appends.
        while (all.Count > 0 && all[^1].Trim().Length == 0) all.RemoveAt(all.Count - 1);

        all.AddRange(newLines);
        WriteAll(path, all);
    }

    /// <summary>
    /// Writes all lines to a signature file with '\n' endings and a trailing newline
    /// (ClamAV expects newline-terminated signature lines), atomically and without a
    /// BOM. An empty list deletes the file instead of leaving a 0-byte database (an
    /// empty .hsb/.sfp can make clamd warn or refuse to load). Called from:
    /// AppendLines and Remove.
    /// </summary>
    private static void WriteAll(string path, IReadOnlyList<string> lines)
    {
        if (lines.Count == 0)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { /* best effort */ }
            return;
        }
        string content = string.Join('\n', lines) + "\n";
        AtomicFile.WriteAllText(path, content);
    }
}
