using System.IO;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Detects a file's real type from its magic bytes, checks whether the
/// extension is consistent with it, and scans the FILE NAME for classic
/// social-engineering tricks (double extension, hidden bidi/format characters,
/// space padding). Deliberately a small curated table, not a libmagic port:
/// an unknown magic yields "unknown" with NO verdict. Everything here reports
/// facts; the severity grading happens in IntegrityScanner.EvaluateFindings.
/// Reads at most 4 KB. Called from: IntegrityScanner.RunAsync (stage 1, always
/// on) and rendered by IntegrityReportWriter.RenderFileType.
/// </summary>
public static class FileTypeDetector
{
    private const int SampleSize = 4096;

    /// <summary>One magic entry: bytes at offset 0, type name, whether the
    /// content executes code when opened, and the usual extensions.</summary>
    private sealed record Magic(byte[] Bytes, string Type, bool Executable, string[] Extensions);

    // Ordered longest/most-specific first so short magics (BMP "BM") cannot
    // shadow longer ones. All checked at offset 0.
    private static readonly Magic[] Table =
    {
        new(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A },
            "PNG image", false, new[] { "png" }),
        new(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 },
            "OLE compound document (legacy Office, MSI, MSG)", false,
            new[] { "doc", "xls", "ppt", "msi", "msg", "msp", "mst" }),
        new(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 },
            "RAR archive", false, new[] { "rar" }),
        new(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C },
            "7-Zip archive", false, new[] { "7z" }),
        new(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 },
            "XZ archive", false, new[] { "xz" }),
        new("SQLite format 3\0"u8.ToArray(),
            "SQLite database", false, new[] { "db", "sqlite", "sqlite3", "db3" }),
        new(new byte[] { 0x7B, 0x5C, 0x72, 0x74, 0x66 },          // {\rtf
            "RTF document", false, new[] { "rtf" }),
        new(new byte[] { 0x7F, 0x45, 0x4C, 0x46 },                 // \x7FELF
            "ELF executable", true, new[] { "elf", "so", "o", "bin", "axf" }),
        new(new byte[] { 0x50, 0x4B, 0x03, 0x04 },                 // PK..
            "ZIP container (also docx/xlsx/pptx, jar, apk, ...)", false,
            new[] { "zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods", "odp",
                    "epub", "vsix", "nupkg", "xpi", "war", "crx", "appx", "msix" }),
        new(new byte[] { 0x25, 0x50, 0x44, 0x46 },                 // %PDF
            "PDF document", false, new[] { "pdf" }),
        new(new byte[] { 0x4D, 0x53, 0x43, 0x46 },                 // MSCF
            "CAB archive", false, new[] { "cab" }),
        new(new byte[] { 0x47, 0x49, 0x46, 0x38 },                 // GIF8
            "GIF image", false, new[] { "gif" }),
        new(new byte[] { 0x00, 0x61, 0x73, 0x6D },                 // \0asm
            "WebAssembly module", false, new[] { "wasm" }),
        new(new byte[] { 0xFF, 0xD8, 0xFF },
            "JPEG image", false, new[] { "jpg", "jpeg", "jfif", "jpe" }),
        new(new byte[] { 0x42, 0x5A, 0x68 },                       // BZh
            "BZip2 archive", false, new[] { "bz2", "tbz2" }),
        new(new byte[] { 0x1F, 0x8B },
            "GZip archive", false, new[] { "gz", "tgz" }),
        new(new byte[] { 0x42, 0x4D },                             // BM
            "BMP image", false, new[] { "bmp", "dib" }),
    };

    // Extensions that launch code on double-click; used for the double-extension
    // filename check ("invoice.pdf.exe").
    private static readonly string[] LaunchableExts =
    {
        "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe",
        "wsf", "wsh", "ps1", "msi", "hta", "lnk", "cpl"
    };

    // Document/media extensions people trust; the first half of a double extension.
    private static readonly string[] HarmlessLookExts =
    {
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "csv",
        "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "avi", "mkv", "mov",
        "zip", "rar", "7z", "htm", "html", "odt", "ods"
    };

    /// <summary>
    /// Runs magic detection, extension consistency and filename checks. Never
    /// throws: read errors yield Status=Failed with the message.
    /// Called from: IntegrityScanner.RunAsync.
    /// </summary>
    public static IntegrityReport.FileTypeSection Detect(string path)
    {
        var sec = new IntegrityReport.FileTypeSection
        {
            ActualExtension = Path.GetExtension(path).TrimStart('.').ToLowerInvariant()
        };
        CheckFileName(Path.GetFileName(path), sec.NameAnomalies);

        byte[] sample;
        int read;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            sample = new byte[(int)Math.Min(SampleSize, Math.Max(1, stream.Length))];
            read = stream.Read(sample, 0, sample.Length);
        }
        catch (Exception ex)
        {
            sec.Status = StageStatus.Failed;
            sec.Error = ex.Message;
            return sec;
        }
        if (read <= 0)
        {
            sec.DetectedType = "empty file";
            return sec;
        }

        // MZ/PE first: verify the PE\0\0 header via e_lfanew when it lies inside
        // the sample, so a stray "MZ" text file is not called an executable.
        if (read >= 2 && sample[0] == 0x4D && sample[1] == 0x5A)
        {
            bool peVerified = false;
            if (read >= 0x40)
            {
                int lfanew = BitConverter.ToInt32(sample, 0x3C);
                if (lfanew > 0 && lfanew + 4 <= read)
                    peVerified = sample[lfanew] == 0x50 && sample[lfanew + 1] == 0x45
                              && sample[lfanew + 2] == 0x00 && sample[lfanew + 3] == 0x00;
                else if (lfanew >= read)
                    peVerified = true; // header beyond the sample: accept, PE stage verifies fully
            }
            sec.DetectedType = peVerified ? "Windows executable (PE)" : "MZ executable (DOS or malformed PE)";
            sec.IsExecutableContent = true;
            sec.ExpectedExtensions.AddRange(new[]
                { "exe", "dll", "sys", "scr", "ocx", "cpl", "drv", "efi", "mui", "ax", "acm", "tsp", "com" });
            sec.ExtensionMatches = sec.ExpectedExtensions.Contains(sec.ActualExtension);
            return sec;
        }

        // Windows shortcut: 4-byte header length 0x4C + the LinkCLSID at offset 4.
        if (read >= 20 && sample[0] == 0x4C && sample[1] == 0 && sample[2] == 0 && sample[3] == 0
            && sample[4] == 0x01 && sample[5] == 0x14 && sample[6] == 0x02 && sample[7] == 0x00
            && sample[16] == 0xC0 && sample[19] == 0x46)
        {
            sec.DetectedType = "Windows shortcut (LNK)";
            sec.IsExecutableContent = true; // a shortcut launches whatever it points at
            sec.ExpectedExtensions.Add("lnk");
            sec.ExtensionMatches = sec.ActualExtension == "lnk";
            return sec;
        }

        foreach (var magic in Table)
        {
            if (read < magic.Bytes.Length) continue;
            bool match = true;
            for (int i = 0; i < magic.Bytes.Length; i++)
                if (sample[i] != magic.Bytes[i]) { match = false; break; }
            if (!match) continue;

            sec.DetectedType = magic.Type;
            sec.IsExecutableContent = magic.Executable;
            sec.ExpectedExtensions.AddRange(magic.Extensions);
            sec.ExtensionMatches = magic.Extensions.Contains(sec.ActualExtension);
            return sec;
        }

        // Text fallback: mostly printable bytes = text/script. Extensions for
        // text are endless, so no consistency verdict (ExtensionMatches stays null).
        int printable = 0;
        for (int i = 0; i < read; i++)
        {
            byte b = sample[i];
            if (b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x20 && b < 0x7F) || b >= 0x80)
                printable++;
        }
        if (printable >= read * 0.95)
            sec.DetectedType = "text (script, config or plain text)";
        return sec;
    }

    /// <summary>
    /// Scans the file NAME for deterministic anomalies: hidden Unicode
    /// bidi/format characters (RTL override etc.), double extensions that fake a
    /// document type, and space padding that pushes the real extension out of
    /// view. Homoglyph detection is deliberately omitted (too false-positive
    /// prone for non-Latin filenames). Called from: Detect.
    /// </summary>
    private static void CheckFileName(string name, List<string> anomalies)
    {
        foreach (char c in name)
        {
            // LRM/RLM, LRE..RLO (incl. U+202E RTL override), LRI..PDI, zero-width
            // space/joiners and the BOM: none of these belong in a filename, and
            // U+202E is a known trick to visually reverse the extension.
            if (c is '\u200B' or '\u200C' or '\u200D' or '\u200E' or '\u200F'
                or (>= '\u202A' and <= '\u202E') or (>= '\u2066' and <= '\u2069') or '\uFEFF')
            {
                anomalies.Add($"hidden Unicode control character U+{(int)c:X4} in the file name" +
                              (c == '\u202E' ? " (right-to-left override: the visible extension is reversed)" : ""));
                break; // one line is enough; the exact count adds nothing
            }
        }

        var parts = name.ToLowerInvariant().Split('.');
        if (parts.Length >= 3)
        {
            string last = parts[^1].Trim();
            string secondLast = parts[^2].Trim();
            if (LaunchableExts.Contains(last) && HarmlessLookExts.Contains(secondLast))
                anomalies.Add($"double extension: looks like .{secondLast} but is .{last}");
        }

        if (name.Contains("   "))
            anomalies.Add("space padding in the file name (can push the real extension out of view)");
    }
}
