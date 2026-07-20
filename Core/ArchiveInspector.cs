using System.IO;
using System.Text;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Structural inspector for archives. ZIP-family containers (zip, jar, apk and
/// anything else with the PK signature) are parsed from the CENTRAL DIRECTORY
/// by hand rather than through ZipArchive, for three reasons: it works on
/// archives ZipArchive refuses to open, it exposes the general-purpose flag bit
/// that marks ENCRYPTED entries (which the framework API does not surface), and
/// it never touches entry data, so nothing is decompressed or written.
///
/// Reported facts: entry count, sizes and compression ratio (zip-bomb signal),
/// executable/script members, double extensions and hidden bidi characters in
/// member names, path traversal or absolute paths (an archive that would escape
/// its extraction directory in other tools), encryption, and nested archives.
///
/// RAR/7z/CAB are NOT enumerated (that needs format-specific unpackers). For
/// those the section says so plainly and points at the ClamAV stage, which does
/// unpack them: an honest limit beats a silent gap.
/// Called from: DocumentAnalyzer.Analyze.
/// </summary>
public static class ArchiveInspector
{
    private const int MaxEntriesParsed = 20000;
    private const int MaxListed = 25;
    private const long MaxTailScan = 128 * 1024;      // EOCD search window
    private const int SuspiciousRatio = 100;          // uncompressed:compressed

    private const uint EocdSignature = 0x06054B50;
    private const uint Zip64EocdSignature = 0x06064B50;
    private const uint CentralFileHeader = 0x02014B50;

    private static readonly string[] ExecutableExts =
    {
        "exe", "dll", "scr", "com", "pif", "cpl", "sys", "msi", "msp", "jar",
        "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
        "hta", "lnk", "reg", "inf", "scf", "sct", "application", "appref-ms"
    };

    private static readonly string[] DocumentLookExts =
    {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
        "jpg", "jpeg", "png", "gif", "mp4", "mp3", "htm", "html"
    };

    private static readonly string[] NestedArchiveExts =
    { "zip", "rar", "7z", "gz", "bz2", "xz", "tar", "cab", "iso", "img" };

    /// <summary>
    /// Entry metadata read from the central directory (no entry data touched).
    /// </summary>
    private sealed record Entry(string Name, ulong Compressed, ulong Uncompressed,
        bool Encrypted, ushort Method);

    /// <summary>
    /// Inspects the archive. ZIP-family gets a full central-directory walk;
    /// other formats get an explicit "not enumerated" note. Never throws.
    /// Called from: DocumentAnalyzer.Analyze.
    /// </summary>
    public static void Inspect(string path, string extension,
        IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        sec.Format = "Archive";

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (!IsZipFamily(fs))
        {
            sec.Description = $"{extension.ToUpperInvariant()} archive";
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "archive-not-enumerated",
                Detail = $"{extension.ToUpperInvariant()} archives are not enumerated by this stage (that needs a format-specific unpacker). Enable the ClamAV stage: it unpacks and scans these formats."
            });
            return;
        }

        sec.Description = "ZIP-family archive";
        var entries = ReadCentralDirectory(fs, sec, cancel);
        if (entries.Count == 0)
        {
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "archive-empty",
                Detail = "no entries could be read from the central directory (empty, damaged or non-standard archive)."
            });
            return;
        }

        ulong totalComp = 0, totalUncomp = 0;
        int encrypted = 0;
        var executables = new List<string>();
        var nested = new List<string>();
        var doubleExt = new List<string>();
        var traversal = new List<string>();
        var hiddenChars = new List<string>();

        foreach (var e in entries)
        {
            cancel.ThrowIfCancellationRequested();
            totalComp += e.Compressed;
            totalUncomp += e.Uncompressed;
            if (e.Encrypted) encrypted++;

            string name = e.Name;
            string lower = name.ToLowerInvariant();
            bool isDirectory = name.EndsWith('/') || name.EndsWith('\\');

            // Path traversal / absolute path: this archive would write outside a
            // target directory in any tool that extracts it naively.
            if (name.Contains("../") || name.Contains("..\\")
                || name.StartsWith('/') || name.StartsWith('\\')
                || (name.Length > 1 && name[1] == ':'))
                traversal.Add(name);

            // Hidden bidi/format characters used to fake a member's extension.
            foreach (char c in name)
                if (c is '\u200B' or '\u200C' or '\u200D' or '\u200E' or '\u200F'
                    or (>= '\u202A' and <= '\u202E') or (>= '\u2066' and <= '\u2069') or '\uFEFF')
                {
                    hiddenChars.Add(name);
                    break;
                }

            if (isDirectory) continue;

            string ext = GetExt(lower);
            if (Array.IndexOf(ExecutableExts, ext) >= 0) executables.Add(name);
            if (Array.IndexOf(NestedArchiveExts, ext) >= 0) nested.Add(name);

            var parts = lower.Split('.');
            if (parts.Length >= 3
                && Array.IndexOf(ExecutableExts, parts[^1]) >= 0
                && Array.IndexOf(DocumentLookExts, parts[^2]) >= 0)
                doubleExt.Add(name);
        }

        sec.Items.Add(new IntegrityReport.DocumentItem
        {
            Kind = "archive-stats",
            Detail = $"{entries.Count:N0} entr{(entries.Count == 1 ? "y" : "ies")}, "
                     + $"{totalComp:N0} bytes stored, {totalUncomp:N0} bytes uncompressed."
        });

        if (encrypted > 0)
        {
            sec.Encrypted = true;
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "archive-encrypted",
                Detail = $"{encrypted} of {entries.Count} entries are password protected: their content cannot be inspected or scanned, which is also why attackers use encrypted archives to get past mail and AV filters."
            });
        }

        if (totalComp > 0 && totalUncomp / Math.Max(1UL, totalComp) > SuspiciousRatio && totalUncomp > 50_000_000)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "archive-bomb",
                Detail = $"the archive expands roughly {totalUncomp / Math.Max(1UL, totalComp)}x to {totalUncomp:N0} bytes: possible decompression bomb."
            });

        Emit(sec, "archive-executable", executables,
            n => $"executable/script member: {n}",
            count => $"{count} executable/script members in total");
        Emit(sec, "archive-doubleext", doubleExt,
            n => $"double extension inside the archive: {n}",
            count => $"{count} members with a faked document extension");
        Emit(sec, "archive-traversal", traversal,
            n => $"path traversal or absolute path in a member name: {n}",
            count => $"{count} members would extract outside the target directory");
        Emit(sec, "archive-hiddenchar", hiddenChars,
            n => $"member name contains hidden Unicode control characters: {n}",
            count => $"{count} member names contain hidden control characters");
        Emit(sec, "archive-nested", nested,
            n => $"nested archive: {n}",
            count => $"{count} nested archives (content not inspected recursively)");

        // A single executable in an otherwise empty archive is the classic
        // mail-attachment dropper shape; worth stating explicitly.
        if (executables.Count == 1 && entries.Count(e => !e.Name.EndsWith('/')) == 1)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "archive-single-exe",
                Detail = "the archive contains exactly one member and that member is executable: the typical shape of a mailed dropper."
            });

        if (sec.Items.Count == 1) // only the stats line
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "clean-structure",
                Detail = "no executable members, encryption, traversal paths or bomb characteristics found."
            });
    }

    /// <summary>Adds up to MaxListed individual items plus a summary line when
    /// there are more. Called from: Inspect.</summary>
    private static void Emit(IntegrityReport.DocumentSection sec, string kind,
        List<string> names, Func<string, string> one, Func<int, string> many)
    {
        if (names.Count == 0) return;
        foreach (var n in names.Take(MaxListed))
            sec.Items.Add(new IntegrityReport.DocumentItem { Kind = kind, Detail = one(Trim(n)) });
        if (names.Count > MaxListed)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = kind,
                Detail = many(names.Count) + $" (showing the first {MaxListed})"
            });
    }

    /// <summary>True when the file starts with a ZIP local-file or empty-archive
    /// signature. Called from: Inspect.</summary>
    private static bool IsZipFamily(FileStream fs)
    {
        try
        {
            fs.Position = 0;
            Span<byte> head = stackalloc byte[4];
            if (fs.Read(head) < 4) return false;
            return head[0] == 0x50 && head[1] == 0x4B
                && (head[2] == 0x03 || head[2] == 0x05 || head[2] == 0x07);
        }
        catch { return false; }
    }

    /// <summary>
    /// Locates the End Of Central Directory record in the file tail and walks
    /// the central directory, returning one Entry per member. Reads metadata
    /// only. ZIP64 is handled far enough to find the directory; per-entry ZIP64
    /// size extensions are read from the extra field when the 32-bit fields are
    /// saturated (0xFFFFFFFF). Called from: Inspect.
    /// </summary>
    private static List<Entry> ReadCentralDirectory(FileStream fs,
        IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        var result = new List<Entry>();
        try
        {
            long len = fs.Length;
            int tail = (int)Math.Min(len, MaxTailScan);
            var buf = new byte[tail];
            fs.Position = len - tail;
            int got = 0;
            while (got < tail)
            {
                int n = fs.Read(buf, got, tail - got);
                if (n <= 0) break;
                got += n;
            }

            int eocd = -1;
            for (int i = got - 22; i >= 0; i--)
                if (BitConverter.ToUInt32(buf, i) == EocdSignature) { eocd = i; break; }
            if (eocd < 0) return result;

            long cdOffset = BitConverter.ToUInt32(buf, eocd + 16);
            int cdCount = BitConverter.ToUInt16(buf, eocd + 10);

            // ZIP64: the 32-bit fields are saturated, the real values live in the
            // ZIP64 EOCD record found via its locator right before the EOCD.
            if (cdOffset == 0xFFFFFFFF || cdCount == 0xFFFF)
            {
                long z64 = FindZip64Eocd(fs, len);
                if (z64 >= 0)
                {
                    var rec = new byte[56];
                    fs.Position = z64;
                    if (fs.Read(rec, 0, rec.Length) == rec.Length
                        && BitConverter.ToUInt32(rec, 0) == Zip64EocdSignature)
                    {
                        cdCount = (int)Math.Min(int.MaxValue, BitConverter.ToUInt64(rec, 32));
                        cdOffset = (long)BitConverter.ToUInt64(rec, 48);
                    }
                }
            }

            if (cdOffset <= 0 || cdOffset >= len) return result;

            fs.Position = cdOffset;
            using var reader = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
            int parsed = 0;
            while (parsed < MaxEntriesParsed && fs.Position + 46 <= len)
            {
                cancel.ThrowIfCancellationRequested();
                if (reader.ReadUInt32() != CentralFileHeader) break;

                reader.ReadUInt16();                       // version made by
                reader.ReadUInt16();                       // version needed
                ushort flags = reader.ReadUInt16();
                ushort method = reader.ReadUInt16();
                reader.ReadUInt16();                       // mod time
                reader.ReadUInt16();                       // mod date
                reader.ReadUInt32();                       // crc32
                ulong compressed = reader.ReadUInt32();
                ulong uncompressed = reader.ReadUInt32();
                ushort nameLen = reader.ReadUInt16();
                ushort extraLen = reader.ReadUInt16();
                ushort commentLen = reader.ReadUInt16();
                reader.ReadUInt16();                       // disk number start
                reader.ReadUInt16();                       // internal attributes
                reader.ReadUInt32();                       // external attributes
                reader.ReadUInt32();                       // local header offset

                if (nameLen > 4096 || fs.Position + nameLen > len) break;
                var nameBytes = reader.ReadBytes(nameLen);
                // Bit 11 marks UTF-8 names; otherwise the spec says CP437, and
                // Latin1 is the closest lossless stand-in for a report.
                string name = (flags & 0x0800) != 0
                    ? Encoding.UTF8.GetString(nameBytes)
                    : Encoding.Latin1.GetString(nameBytes);

                var extra = extraLen > 0 && fs.Position + extraLen <= len
                    ? reader.ReadBytes(extraLen)
                    : Array.Empty<byte>();
                if (commentLen > 0 && fs.Position + commentLen <= len)
                    reader.ReadBytes(commentLen);

                if (uncompressed == 0xFFFFFFFF || compressed == 0xFFFFFFFF)
                    ReadZip64Extra(extra, ref uncompressed, ref compressed);

                // General purpose bit 0 = the entry is encrypted; method 99 = AES.
                bool enc = (flags & 0x0001) != 0 || method == 99;
                result.Add(new Entry(name, compressed, uncompressed, enc, method));
                parsed++;
            }

            if (parsed >= MaxEntriesParsed)
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "archive-anomaly",
                    Detail = $"the archive declares more than {MaxEntriesParsed:N0} entries; only the first {MaxEntriesParsed:N0} were inspected."
                });
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            // A damaged directory still leaves whatever was parsed usable.
        }
        return result;
    }

    /// <summary>Scans the tail for the ZIP64 end-of-central-directory record.
    /// Called from: ReadCentralDirectory.</summary>
    private static long FindZip64Eocd(FileStream fs, long len)
    {
        try
        {
            int tail = (int)Math.Min(len, MaxTailScan);
            var buf = new byte[tail];
            fs.Position = len - tail;
            int got = 0;
            while (got < tail)
            {
                int n = fs.Read(buf, got, tail - got);
                if (n <= 0) break;
                got += n;
            }
            for (int i = got - 56; i >= 0; i--)
                if (BitConverter.ToUInt32(buf, i) == Zip64EocdSignature)
                    return len - tail + i;
        }
        catch { }
        return -1;
    }

    /// <summary>Pulls the real 64-bit sizes out of the ZIP64 extra field (header
    /// id 0x0001) when the 32-bit fields are saturated.
    /// Called from: ReadCentralDirectory.</summary>
    private static void ReadZip64Extra(byte[] extra, ref ulong uncompressed, ref ulong compressed)
    {
        int pos = 0;
        while (pos + 4 <= extra.Length)
        {
            ushort id = BitConverter.ToUInt16(extra, pos);
            ushort size = BitConverter.ToUInt16(extra, pos + 2);
            pos += 4;
            if (pos + size > extra.Length) break;
            if (id == 0x0001)
            {
                int p = pos;
                if (uncompressed == 0xFFFFFFFF && p + 8 <= extra.Length)
                {
                    uncompressed = BitConverter.ToUInt64(extra, p);
                    p += 8;
                }
                if (compressed == 0xFFFFFFFF && p + 8 <= extra.Length)
                    compressed = BitConverter.ToUInt64(extra, p);
                return;
            }
            pos += size;
        }
    }

    private static string GetExt(string lowerName)
    {
        int dot = lowerName.LastIndexOf('.');
        int slash = Math.Max(lowerName.LastIndexOf('/'), lowerName.LastIndexOf('\\'));
        return dot > slash && dot >= 0 ? lowerName[(dot + 1)..] : "";
    }

    private static string Trim(string s, int max = 160)
        => s.Length <= max ? s : s.Substring(0, max) + "...";
}
