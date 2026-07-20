using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Structural inspector for OOXML (zip-based Office: docx/xlsx/pptx and their
/// macro-enabled variants). Reads the zip entry LIST and a few small XML parts
/// in memory only; it never extracts to disk and never uses a path stored in
/// the archive (zip-slip safe, since nothing is written). Reports the facts an
/// analyst cares about: a VBA project, Excel 4.0 (XLM) macro sheets, remote
/// template injection, external relationships, embedded OLE/ActiveX objects,
/// DDE, and whether the package is encrypted (which blocks any deeper look).
/// Guards against zip bombs via entry-count, per-entry and total-size caps.
/// Called from: DocumentAnalyzer.Analyze.
/// </summary>
public static class OoxmlInspector
{
    private const int MaxEntries = 5000;              // refuse absurd archives
    private const long MaxEntryBytes = 16L * 1024 * 1024;  // per XML part we actually read
    private const long MaxTotalUncompressed = 512L * 1024 * 1024; // zip-bomb ceiling
    private const int MaxCompressionRatio = 200;      // per entry, flags a bomb

    /// <summary>
    /// Fills the section from the OOXML package. Encryption is detected first
    /// (an encrypted OOXML is actually an OLE compound file, not a zip, so the
    /// zip open fails: that is the signal, not an error). Never throws; parse
    /// problems bubble up to DocumentAnalyzer as Failed. Called from: DocumentAnalyzer.Analyze.
    /// </summary>
    public static void Inspect(string path, IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        sec.Format = "OOXML";
        sec.Description = "Office Open XML package";

        // An ECMA-376 encrypted document is an OLE compound file with an
        // "EncryptionInfo" stream, so it will not open as a zip. Detect that
        // shape up front and report it honestly.
        if (LooksLikeEncryptedOoxml(path))
        {
            sec.Encrypted = true;
            sec.Description = "encrypted Office document (content not analyzable)";
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "encrypted",
                Detail = "the package is password/encryption protected; its parts cannot be inspected."
            });
            return;
        }

        using var zip = ZipFile.OpenRead(path);

        if (zip.Entries.Count > MaxEntries)
        {
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "archive-anomaly",
                Detail = $"unusually many package parts ({zip.Entries.Count}); analysis limited to the first {MaxEntries}."
            });
        }

        long totalUncompressed = 0;
        int seen = 0;
        var names = new List<string>();

        foreach (var entry in zip.Entries)
        {
            cancel.ThrowIfCancellationRequested();
            if (++seen > MaxEntries) break;
            names.Add(entry.FullName);

            totalUncompressed += entry.Length;
            if (totalUncompressed > MaxTotalUncompressed)
            {
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "archive-bomb",
                    Detail = "the package expands to an implausibly large size (possible zip bomb); analysis stopped early."
                });
                break;
            }
            if (entry.CompressedLength > 0 && entry.Length / Math.Max(1, entry.CompressedLength) > MaxCompressionRatio
                && entry.Length > 1_000_000)
            {
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "archive-bomb",
                    Detail = $"package part '{Trim(entry.FullName)}' has an extreme compression ratio (possible zip bomb)."
                });
            }
        }

        DetectMacros(names, sec);
        DetectEmbeddings(names, sec);
        InspectRelationships(zip, names, sec, cancel);
        InspectSettingsForTemplateInjection(zip, names, sec, cancel);
        DetectDde(zip, names, sec, cancel);

        if (sec.Items.Count == 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "clean-structure",
                Detail = "no macros, external references, embedded objects or DDE found in the package structure."
            });
    }

    /// <summary>Flags VBA projects and Excel 4.0 (XLM) macro sheets from the
    /// entry names. XLM is called out separately: it is old, powerful and
    /// frequently missed by naive scanners. Called from: Inspect.</summary>
    private static void DetectMacros(List<string> names, IntegrityReport.DocumentSection sec)
    {
        if (names.Any(n => n.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "vba",
                Detail = "contains a VBA macro project (vbaProject.bin). Macros can run code; enable them only from a trusted source."
            });

        // XLM macro sheets appear as xl/macrosheets/* or a macrosheet content type.
        if (names.Any(n => n.Contains("macrosheet", StringComparison.OrdinalIgnoreCase)))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "xlm",
                Detail = "contains an Excel 4.0 (XLM) macro sheet: an old macro type often used to bypass scanners."
            });
    }

    /// <summary>Flags embedded OLE objects and ActiveX controls, both common
    /// carriers for exploit payloads. Called from: Inspect.</summary>
    private static void DetectEmbeddings(List<string> names, IntegrityReport.DocumentSection sec)
    {
        int ole = names.Count(n => n.Contains("/embeddings/", StringComparison.OrdinalIgnoreCase)
                                   || n.Contains("oleObject", StringComparison.OrdinalIgnoreCase));
        if (ole > 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "ole-embed",
                Detail = $"{ole} embedded OLE object(s): can hold another file or an exploit; check what they are."
            });

        int activeX = names.Count(n => n.Contains("activeX", StringComparison.OrdinalIgnoreCase));
        if (activeX > 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "activex",
                Detail = $"{activeX} ActiveX control(s) embedded in the document."
            });
    }

    /// <summary>Reads every .rels part and lists relationships whose TargetMode
    /// is External and target is an http(s)/file/unc URL: the mechanism behind
    /// remote template/content loading. Called from: Inspect.</summary>
    private static void InspectRelationships(ZipArchive zip, List<string> names,
        IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        var rels = names.Where(n => n.EndsWith(".rels", StringComparison.OrdinalIgnoreCase));
        var externalTargets = new List<string>();

        foreach (var relName in rels)
        {
            cancel.ThrowIfCancellationRequested();
            string xml = ReadEntryText(zip, relName);
            if (xml.Length == 0) continue;

            foreach (Match m in Regex.Matches(xml,
                "<Relationship\\b[^>]*>", RegexOptions.IgnoreCase))
            {
                string tag = m.Value;
                if (!tag.Contains("External", StringComparison.OrdinalIgnoreCase)) continue;
                var target = Regex.Match(tag, "Target=\"([^\"]*)\"", RegexOptions.IgnoreCase);
                if (!target.Success) continue;
                string url = target.Groups[1].Value;
                if (Regex.IsMatch(url, "^(https?:|ftp:|file:|\\\\\\\\)", RegexOptions.IgnoreCase))
                    externalTargets.Add(url);
            }
        }

        foreach (var url in externalTargets.Distinct().Take(20))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "external-url",
                Detail = $"external reference: {Trim(url, 200)}"
            });
    }

    /// <summary>Detects remote template injection: word/settings.xml (or the
    /// ppt/xls equivalent) with an attachedTemplate/reference relationship that
    /// resolves to an external URL. A very common first-stage loader.
    /// Called from: Inspect.</summary>
    private static void InspectSettingsForTemplateInjection(ZipArchive zip, List<string> names,
        IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        var settings = names.FirstOrDefault(n =>
            n.EndsWith("word/settings.xml", StringComparison.OrdinalIgnoreCase));
        if (settings == null) return;
        cancel.ThrowIfCancellationRequested();

        string xml = ReadEntryText(zip, settings);
        if (xml.Contains("attachedTemplate", StringComparison.OrdinalIgnoreCase))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "template-ref",
                Detail = "the document attaches an external template (attachedTemplate). Combined with an external relationship target this is a known remote-template-injection loader."
            });
    }

    /// <summary>Scans document parts for DDE / DDEAUTO field codes, an older
    /// code-execution trick that needs no macro. Called from: Inspect.</summary>
    private static void DetectDde(ZipArchive zip, List<string> names,
        IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        var docParts = names.Where(n =>
            n.EndsWith("document.xml", StringComparison.OrdinalIgnoreCase)
            || n.Contains("/worksheets/", StringComparison.OrdinalIgnoreCase));
        foreach (var part in docParts.Take(20))
        {
            cancel.ThrowIfCancellationRequested();
            string xml = ReadEntryText(zip, part);
            if (Regex.IsMatch(xml, "\\bDDEAUTO\\b|\\bDDE\\b", RegexOptions.IgnoreCase))
            {
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "dde",
                    Detail = "a DDE/DDEAUTO field is present: can launch programs without a macro."
                });
                return;
            }
        }
    }

    /// <summary>
    /// True when the file is an ECMA-376 encrypted Office document: an OLE
    /// compound file (magic D0 CF 11 E0) rather than a zip (PK). Cheap 8-byte
    /// header read. Called from: Inspect.
    /// </summary>
    private static bool LooksLikeEncryptedOoxml(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            Span<byte> head = stackalloc byte[8];
            return fs.Read(head) == 8
                && head[0] == 0xD0 && head[1] == 0xCF && head[2] == 0x11 && head[3] == 0xE0
                && head[4] == 0xA1 && head[5] == 0xB1 && head[6] == 0x1A && head[7] == 0xE1;
        }
        catch { return false; }
    }

    /// <summary>Reads one zip entry as UTF-8 text with a size cap. Returns ""
    /// on any problem or when the entry is too large. Called from: the XML scans.</summary>
    private static string ReadEntryText(ZipArchive zip, string name)
    {
        try
        {
            var entry = zip.GetEntry(name);
            if (entry == null || entry.Length > MaxEntryBytes) return "";
            using var stream = entry.Open();
            using var reader = new StreamReader(stream, Encoding.UTF8, true, 8192, leaveOpen: false);
            var buffer = new char[(int)Math.Min(entry.Length, MaxEntryBytes)];
            int total = 0;
            while (total < buffer.Length)
            {
                int n = reader.Read(buffer, total, buffer.Length - total);
                if (n <= 0) break;
                total += n;
            }
            return new string(buffer, 0, total);
        }
        catch { return ""; }
    }

    private static string Trim(string s, int max = 120)
        => s.Length <= max ? s : s.Substring(0, max) + "...";
}
