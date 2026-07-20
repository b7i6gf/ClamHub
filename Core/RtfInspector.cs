using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Structural inspector for RTF documents. RTF has no macros, so its abuse is
/// almost entirely about EMBEDDED OBJECTS: \object/\objdata blocks carry a
/// hex-encoded OLE payload, \objupdate makes the object load without a click,
/// and Equation Editor objects are the classic exploit carrier. The format is
/// also famously permissive, which attackers exploit: readers accept a header
/// that is not exactly "{\rtf1", ignore junk control words and tolerate broken
/// nesting, so parsers that insist on the spec see nothing while Word still
/// opens the file.
///
/// This scans the raw text for those constructs and decodes just enough of an
/// \objdata hex blob to identify what is embedded (an OLE2 container, a PE, a
/// package with a file name). Size-capped, streaming, never executes anything.
/// Called from: DocumentAnalyzer.Analyze.
/// </summary>
public static class RtfInspector
{
    private const long MaxRtfBytes = 64L * 1024 * 1024;
    private const int HexProbeChars = 4096;   // how much of an objdata blob to decode

    private static readonly RegexOptions Opts =
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    /// <summary>
    /// Scans the RTF and fills the section. Never throws.
    /// Called from: DocumentAnalyzer.Analyze.
    /// </summary>
    public static void Inspect(string path, IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        sec.Format = "RTF";
        sec.Description = "RTF document";

        string text;
        long fileLen;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            fileLen = fs.Length;
            int take = (int)Math.Min(fileLen, MaxRtfBytes);
            var buffer = new byte[take];
            int total = 0;
            while (total < take)
            {
                int n = fs.Read(buffer, total, take - total);
                if (n <= 0) break;
                total += n;
            }
            // RTF is 7-bit ASCII by definition; Latin1 keeps a 1:1 byte mapping.
            text = Encoding.Latin1.GetString(buffer, 0, total);
            if (fileLen > MaxRtfBytes)
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "rtf-truncated-scan",
                    Detail = $"only the first {MaxRtfBytes / (1024 * 1024)} MB were analyzed; the file is larger."
                });
        }
        cancel.ThrowIfCancellationRequested();

        // A conforming file starts with "{\rtf1". Readers accept variations,
        // which is exactly why a deviation is worth reporting.
        string head = text.Length >= 6 ? text[..6] : text;
        if (!head.StartsWith("{\\rtf1", StringComparison.OrdinalIgnoreCase))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-malformed-header",
                Detail = $"the file does not start with the standard \"{{\\rtf1\" header (starts with \"{Escape(head)}\"): Word still opens such files, but strict parsers and some scanners do not."
            });

        int objects = Regex.Matches(text, @"\\object\b", Opts).Count;
        int objdata = Regex.Matches(text, @"\\objdata\b", Opts).Count;
        int objupdate = Regex.Matches(text, @"\\objupdate\b", Opts).Count;
        int objautlink = Regex.Matches(text, @"\\objautlink\b", Opts).Count;
        int objlink = Regex.Matches(text, @"\\objlink\b", Opts).Count;

        if (objects > 0 || objdata > 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-object",
                Detail = $"{Math.Max(objects, objdata)} embedded object(s) with {objdata} \\objdata payload block(s)."
            });

        if (objupdate > 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-objupdate",
                Detail = "\\objupdate is set: the embedded object is loaded automatically when the document opens, without the user clicking it."
            });

        if (objautlink > 0 || objlink > 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-objlink",
                Detail = "the document links to an external object (\\objlink/\\objautlink): content is fetched from outside the file."
            });

        // Identify what the first payload blobs actually are.
        foreach (Match m in Regex.Matches(text, @"\\objdata\b", Opts).Take(5))
        {
            cancel.ThrowIfCancellationRequested();
            IdentifyPayload(text, m.Index + m.Length, sec);
        }

        // Equation Editor: by class name or by its CLSID appearing in the blob
        // (0002CE02-0000-0000-C000-000000000046, little-endian in the OLE header).
        bool equation = Regex.IsMatch(text, @"Equation\.[23]|Equation Native|Microsoft Equation", Opts)
                        || text.Contains("02ce0200", StringComparison.OrdinalIgnoreCase);
        if (equation)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-equation",
                Detail = "references the Equation Editor: the component exploited by CVE-2017-11882 and CVE-2018-0802, which are still widely used in RTF attacks."
            });

        if (Regex.IsMatch(text, @"\\objocx\b|OLE2Link|htmlfile|\bhttp://schemas\b", Opts)
            || text.Contains("0003000C", StringComparison.OrdinalIgnoreCase))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-ole2link",
                Detail = "contains an OLE2Link/OCX style object reference: the pattern used by remote-content loaders such as CVE-2017-0199."
            });

        // \bin lets a document embed raw binary directly, bypassing hex encoding.
        int binCount = Regex.Matches(text, @"\\bin\d+", Opts).Count;
        if (binCount > 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-bin",
                Detail = $"{binCount} \\bin block(s) embed raw binary data directly (a way to hide payloads from text-based scanning)."
            });

        // Control-word obfuscation: RTF readers ignore unknown words, so
        // attackers pad payloads with junk to break signature matching.
        var junk = Regex.Matches(text, @"\\\*\\[a-z]{1,32}\d*", Opts).Count;
        if (junk > 200)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-obfuscation",
                Detail = $"{junk:N0} ignorable control groups (\\*\\...): heavy padding of this kind is typical of signature evasion."
            });

        foreach (var url in Regex.Matches(text, @"(https?|ftp)://[^\s""'{}\\]{4,200}", Opts)
                     .Select(m => m.Value).Distinct(StringComparer.OrdinalIgnoreCase).Take(10))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-url",
                Detail = $"URL: {url}"
            });

        sec.Items.Add(new IntegrityReport.DocumentItem
        {
            Kind = "rtf-stats",
            Detail = $"{fileLen:N0} bytes, {objdata} \\objdata block(s), {binCount} \\bin block(s)."
        });

        if (!sec.Items.Any(i => i.Kind is "rtf-object" or "rtf-objupdate" or "rtf-objlink"
                or "rtf-equation" or "rtf-ole2link" or "rtf-bin" or "rtf-payload" or "rtf-obfuscation"))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "clean-structure",
                Detail = "no embedded objects, binary blocks or exploit-related references found."
            });
    }

    /// <summary>
    /// Decodes the first hex characters after an \objdata control word and
    /// identifies what the payload is: an OLE2 compound file, a PE image, or an
    /// OLE Package (whose original file name is recoverable). Whitespace and
    /// braces inside the blob are skipped, as readers do. Called from: Inspect.
    /// </summary>
    private static void IdentifyPayload(string text, int start, IntegrityReport.DocumentSection sec)
    {
        var hex = new StringBuilder(HexProbeChars);
        for (int i = start; i < text.Length && hex.Length < HexProbeChars; i++)
        {
            char c = text[i];
            if (Uri.IsHexDigit(c)) hex.Append(c);
            else if (c is ' ' or '\r' or '\n' or '\t') continue;
            else break;   // end of the blob (a brace or the next control word)
        }
        if (hex.Length < 32) return;

        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.ToString(i * 2, 2), 16);

        string ascii = Encoding.Latin1.GetString(bytes);

        // The OLE1 header names the class of the embedded object.
        if (ascii.Contains("OLE2Link", StringComparison.OrdinalIgnoreCase))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-payload",
                Detail = "the embedded object declares class OLE2Link (remote content loader)."
            });
        if (ascii.Contains("Equation", StringComparison.OrdinalIgnoreCase))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-payload",
                Detail = "the embedded object declares an Equation class."
            });

        // Nested OLE2 compound file inside the payload.
        int ole2 = IndexOfPattern(bytes, new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 });
        if (ole2 >= 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-payload",
                Detail = $"the \\objdata payload contains a nested OLE compound document (at byte {ole2} of the blob)."
            });

        // A PE image inside a document payload is never routine.
        int mz = IndexOfPattern(bytes, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
        if (mz >= 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-payload-pe",
                Detail = $"the \\objdata payload contains a Windows executable header (MZ at byte {mz} of the blob)."
            });

        // OLE Package objects carry the original file name as ANSI text.
        if (ascii.Contains("Package", StringComparison.OrdinalIgnoreCase))
        {
            var name = Regex.Match(ascii, @"[A-Za-z]:\\[^\0]{1,120}|[\w\-. ]{1,80}\.(exe|scr|js|vbs|bat|cmd|ps1|hta|dll|lnk)",
                RegexOptions.IgnoreCase);
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "rtf-payload",
                Detail = name.Success
                    ? $"the embedded object is an OLE Package containing: {name.Value.Trim()}"
                    : "the embedded object is an OLE Package (an arbitrary file embedded in the document)."
            });
        }
    }

    /// <summary>Finds a byte pattern, or -1. Called from: IdentifyPayload.</summary>
    private static int IndexOfPattern(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++)
                if (haystack[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    /// <summary>Makes a header fragment printable for the report.
    /// Called from: Inspect.</summary>
    private static string Escape(string s)
    {
        var sb = new StringBuilder();
        foreach (char c in s)
            sb.Append(c is >= ' ' and < (char)127 ? c : '.');
        return sb.ToString();
    }
}
