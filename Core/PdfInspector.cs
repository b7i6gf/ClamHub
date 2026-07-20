using System.IO;
using System.Text;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Structural inspector for PDF documents. Deliberately NOT a full PDF parser:
/// malicious PDFs are routinely malformed on purpose, and a strict parser is
/// exactly what they defeat. Instead this scans the raw bytes for the
/// constructs that can execute code or reach out (JavaScript, automatic
/// actions, /Launch, embedded files, forms, external references) and reports
/// their presence and count.
///
/// PRECISION DETAIL: PDF names may hex-escape any character (/JavaScript can be
/// written /J#61vaScript), a standard evasion. Every chunk is normalized by
/// decoding "#XX" sequences BEFORE matching, and the presence of such escapes is
/// itself reported. Scanning is chunked with an overlap so a keyword split
/// across a chunk boundary is still found.
///
/// KNOWN LIMIT (stated in the report): content inside compressed streams
/// (FlateDecode) and inside object streams is not decompressed here, so a
/// payload can hide there. That is why the section reports structure and the
/// verdict stays with ClamAV/VirusTotal.
/// Called from: DocumentAnalyzer.Analyze.
/// </summary>
public static class PdfInspector
{
    private const int ChunkSize = 1024 * 1024;
    private const int Overlap = 64;                        // longest keyword + margin
    private const long MaxScanBytes = 128L * 1024 * 1024;

    /// <summary>Keyword, item kind and the wording used in the report.</summary>
    private sealed record Marker(string Keyword, string Kind, string Detail);

    private static readonly Marker[] Markers =
    {
        new("/JavaScript", "pdf-js", "JavaScript is present: PDF JavaScript is the usual vehicle for reader exploits."),
        new("/JS", "pdf-js", "a /JS JavaScript entry is present."),
        new("/OpenAction", "pdf-openaction", "an OpenAction runs automatically when the document is opened."),
        new("/AA", "pdf-autoaction", "additional automatic actions (/AA) are defined (triggered by page open, focus, etc.)."),
        new("/Launch", "pdf-launch", "a /Launch action can start an external program."),
        new("/EmbeddedFile", "pdf-embed", "the PDF carries an embedded file."),
        new("/Filespec", "pdf-filespec", "a file specification is present (used with embedded or external files)."),
        new("/RichMedia", "pdf-richmedia", "rich media (Flash/video) is embedded: a legacy exploit surface."),
        new("/SubmitForm", "pdf-submitform", "a form can submit data to a remote address."),
        new("/GoToR", "pdf-remotegoto", "a remote go-to action references another document."),
        new("/URI", "pdf-uri", "external URI reference(s) are present."),
        new("/XFA", "pdf-xfa", "an XFA form is present: a large, historically vulnerable parser surface."),
        new("/ObjStm", "pdf-objstm", "object streams are used: objects are stored compressed, so their content is not visible to a surface scan."),
        new("/Encrypt", "pdf-encrypted", "the document is encrypted."),
    };

    /// <summary>
    /// Scans the PDF and fills the section. Never throws; read errors surface as
    /// Failed via DocumentAnalyzer. Called from: DocumentAnalyzer.Analyze.
    /// </summary>
    public static void Inspect(string path, IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        sec.Format = "PDF";
        sec.Description = "PDF document";

        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        int eofMarkers = 0, objCount = 0, hexEscapes = 0;
        bool suspiciousEscape = false;
        string version = "";

        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            long budget = Math.Min(fs.Length, MaxScanBytes);
            var buffer = new byte[ChunkSize + Overlap];
            int carried = 0;
            long done = 0;

            while (done < budget)
            {
                cancel.ThrowIfCancellationRequested();
                int want = (int)Math.Min(ChunkSize, budget - done);
                int read = 0;
                while (read < want)
                {
                    int n = fs.Read(buffer, carried + read, want - read);
                    if (n <= 0) break;
                    read += n;
                }
                if (read == 0) break;
                int filled = carried + read;

                // Latin-1 keeps a 1:1 byte-to-char mapping, which is what a
                // structural scan needs (PDF syntax is ASCII).
                string text = Encoding.Latin1.GetString(buffer, 0, filled);
                if (version.Length == 0 && done == 0)
                    version = ReadVersion(text);

                hexEscapes += CountHexEscapedNames(text, carried);
                string normalized = NormalizeNames(text);
                // Did decoding REVEAL a suspicious keyword that was not already
                // present verbatim in this chunk? That is the difference between
                // real evasion and a generator that just hex-escapes ordinary
                // names (very common, e.g. Claude/Chromium PDF export).
                if (text.IndexOf('#') >= 0)
                    foreach (var marker in Markers)
                        if (CountOccurrences(normalized, marker.Keyword) > CountOccurrences(text, marker.Keyword))
                        { suspiciousEscape = true; break; }
                // NormalizeNames SHRINKS the text (#61 -> a), so the raw carried
                // length does not address the same position in the normalized
                // string. Normalizing just the carried prefix gives the matching
                // bound (cheap: the prefix is at most Overlap bytes).
                int normalizedCarried = carried > 0
                    ? NormalizeNames(text.Substring(0, Math.Min(carried, text.Length))).Length
                    : 0;

                // Anything starting before (carried - keyword length + 1) was
                // already counted in the previous chunk: the overlap exists only
                // so a keyword SPANNING the boundary is found, not so the tail
                // gets counted twice.
                foreach (var marker in Markers)
                    counts[marker.Keyword] = counts.GetValueOrDefault(marker.Keyword)
                        + CountOccurrences(normalized, marker.Keyword, normalizedCarried - marker.Keyword.Length + 1);

                eofMarkers += CountOccurrences(text, "%%EOF", carried - "%%EOF".Length + 1);
                objCount += CountOccurrences(text, " obj", carried - " obj".Length + 1);

                carried = Math.Min(Overlap, filled);
                Array.Copy(buffer, filled - carried, buffer, 0, carried);
                done += read;
            }

            if (fs.Length > MaxScanBytes)
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "pdf-truncated-scan",
                    Detail = $"only the first {MaxScanBytes / (1024 * 1024)} MB were scanned; the file is larger."
                });
        }

        if (version.Length > 0)
            sec.Description = $"PDF document (version {version})";

        // /JS is a subset signal of /JavaScript: report once, with the higher count.
        int js = Math.Max(counts.GetValueOrDefault("/JavaScript"), counts.GetValueOrDefault("/JS"));
        foreach (var marker in Markers)
        {
            if (marker.Kind == "pdf-js") continue;   // handled below in one place
            int n = counts.GetValueOrDefault(marker.Keyword);
            if (n <= 0) continue;
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = marker.Kind,
                Detail = $"{marker.Detail} ({n} occurrence{(n == 1 ? "" : "s")})"
            });
            if (marker.Kind == "pdf-encrypted") sec.Encrypted = true;
        }
        if (js > 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "pdf-js",
                Detail = $"JavaScript is present ({js} occurrence{(js == 1 ? "" : "s")}): PDF JavaScript is the usual vehicle for reader exploits."
            });

        if (hexEscapes > 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                // Only call it evasion when decoding actually uncovered a
                // suspicious keyword; otherwise it is benign generator output
                // and belongs at Info, not Medium.
                Kind = suspiciousEscape ? "pdf-name-obfuscation" : "pdf-name-escapes",
                Detail = suspiciousEscape
                    ? $"{hexEscapes} PDF name(s) use #XX hex escapes AND decoding revealed a keyword of interest (e.g. /J#61vaScript for /JavaScript): a known scanner-evasion technique. All names were decoded before matching."
                    : $"{hexEscapes} PDF name(s) use #XX hex escapes. This is legal PDF syntax and common in normal generator output; none of them decoded to a keyword of interest here."
            });

        // More than one %%EOF means the file was appended to after its first
        // version: legitimate for edited/signed PDFs, also a way to add content.
        if (eofMarkers > 1)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "pdf-incremental",
                Detail = $"{eofMarkers} end-of-file markers: the document was updated incrementally {eofMarkers - 1} time(s); appended revisions can add objects to an already-signed file."
            });

        if (objCount > 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "pdf-objects",
                Detail = $"about {objCount} indirect object(s) in the visible structure."
            });

        // Always state the surface-scan limit so nobody reads silence as safety.
        sec.Items.Add(new IntegrityReport.DocumentItem
        {
            Kind = "pdf-scan-limit",
            Detail = "compressed streams and object streams were not decompressed: content hidden there is not visible to this structural scan."
        });
    }

    /// <summary>Reads the "%PDF-1.x" version from the file start.
    /// Called from: Inspect.</summary>
    private static string ReadVersion(string head)
    {
        int i = head.IndexOf("%PDF-", StringComparison.Ordinal);
        if (i < 0 || i + 8 > head.Length) return "";
        return head.Substring(i + 5, 3).Trim();
    }

    /// <summary>
    /// Decodes "#XX" hex escapes inside PDF names so obfuscated keywords match.
    /// Only sequences after a '/' are relevant, but decoding them everywhere is
    /// harmless for a presence scan and much cheaper. Called from: Inspect.
    /// </summary>
    private static string NormalizeNames(string text)
    {
        if (text.IndexOf('#') < 0) return text;
        var sb = new StringBuilder(text.Length);
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] == '#' && i + 2 < text.Length
                && IsHex(text[i + 1]) && IsHex(text[i + 2]))
            {
                sb.Append((char)Convert.ToInt32(text.Substring(i + 1, 2), 16));
                i += 2;
            }
            else sb.Append(text[i]);
        }
        return sb.ToString();
    }

    /// <summary>Counts "#XX" escapes that directly follow a name token, i.e. the
    /// obfuscation pattern worth reporting. Called from: Inspect.</summary>
    private static int CountHexEscapedNames(string text, int carried)
    {
        int count = 0;
        // Same overlap rule as CountOccurrences: an escape fully inside the
        // carried tail was already counted for the previous chunk.
        int start = Math.Max(1, carried - 2);
        for (int i = start; i < text.Length - 2; i++)
        {
            if (text[i] != '#' || !IsHex(text[i + 1]) || !IsHex(text[i + 2])) continue;
            // Walk back over name characters to see whether this sits in a /Name.
            int j = i - 1;
            while (j >= 0 && (char.IsLetterOrDigit(text[j]) || text[j] == '#')) j--;
            if (j >= 0 && text[j] == '/') count++;
        }
        return count;
    }

    private static bool IsHex(char c)
        => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

    /// <summary>
    /// Counts non-overlapping occurrences of a literal, ignoring matches that
    /// START before minStart. That bound is what keeps the chunk overlap from
    /// double-counting a keyword that ends inside the carried-over tail (the
    /// off-by-one this guards against was found by a boundary test).
    /// Called from: Inspect.
    /// </summary>
    private static int CountOccurrences(string haystack, string needle, int minStart = 0)
    {
        int count = 0;
        int index = Math.Max(0, minStart);
        while (index <= haystack.Length - needle.Length
               && (index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }
        return count;
    }
}
