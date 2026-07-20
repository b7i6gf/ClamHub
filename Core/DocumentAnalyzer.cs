using System.IO;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// DOCUMENT ANALYSIS stage: picks the right structural inspector for the file
/// (OOXML/OLE Office, PDF, RTF, LNK shortcut, script, archive) and returns the
/// collected active-content facts. Reports STRUCTURE, never a malware verdict:
/// "has a VBA macro", "auto-runs on open", "references an external URL". The
/// grading into findings happens in IntegrityScanner.EvaluateDocumentFindings;
/// the actual detection stays with ClamAV/VirusTotal.
///
/// Every inspector parses HOSTILE input, so all of them: read the file with a
/// hard size cap, never write to disk, never trust a path from inside an
/// archive, bound recursion/entry counts, honor cancellation, and turn any
/// parse error into Status=Failed instead of throwing. A skipped file kind
/// (Status=Skipped) is normal and not an error.
///
/// Shipped inspectors: OOXML (batch 1), LNK and PDF (batch 2), scripts and
/// archives (batch 3), legacy OLE/CFBF and RTF (batch 4). Every planned format
/// now has a real inspector; unhandled kinds simply skip the stage.
/// Called from: IntegrityScanner.RunAsync (stage between PE and signature).
/// </summary>
public static class DocumentAnalyzer
{
    /// <summary>Never read more than this from any single file/stream (256 MB).</summary>
    internal const long MaxReadBytes = 256L * 1024 * 1024;

    /// <summary>
    /// Runs the matching inspector based on the already-detected file type and
    /// the extension. Returns a Skipped section for kinds handled by no
    /// inspector. Never throws. Called from: IntegrityScanner.RunAsync.
    /// </summary>
    public static IntegrityReport.DocumentSection Analyze(
        string path, IntegrityReport.FileTypeSection? fileType, CancellationToken cancel)
    {
        var sec = new IntegrityReport.DocumentSection();
        string ext = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
        string detected = fileType?.DetectedType ?? "";

        try
        {
            // OOXML and legacy OLE share Office extensions; the magic decides.
            // "ZIP container" from FileTypeDetector = the OOXML zip; the OLE
            // compound magic = legacy .doc/.xls/.ppt.
            if (IsOoxml(ext, detected))
                OoxmlInspector.Inspect(path, sec, cancel);
            else if (detected.StartsWith("OLE compound") || IsLegacyOffice(ext))
                OleInspector.Inspect(path, sec, cancel);
            else if (detected.StartsWith("PDF") || ext == "pdf")
                PdfInspector.Inspect(path, sec, cancel);
            else if (detected.StartsWith("RTF") || ext == "rtf")
                RtfInspector.Inspect(path, sec, cancel);
            else if (detected.Contains("shortcut") || ext == "lnk")
                LnkInspector.Inspect(path, sec, cancel);
            else if (IsScript(ext))
                ScriptInspector.Inspect(path, ext, sec, cancel);
            else if (IsArchive(ext, detected))
                ArchiveInspector.Inspect(path, ext, sec, cancel);
            else
            {
                sec.Status = StageStatus.Skipped;
                sec.Error = "no document/script/archive structure to analyze";
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sec.Status = StageStatus.Failed;
            sec.Error = ex.Message;
        }
        return sec;
    }

    /// <summary>True for OOXML (zip-based Office) by extension or detected type.
    /// Called from: Analyze.</summary>
    private static bool IsOoxml(string ext, string detected)
    {
        string[] oox =
        {
            "docx", "docm", "dotx", "dotm",
            "xlsx", "xlsm", "xltx", "xltm", "xlsb",
            "pptx", "pptm", "potx", "potm", "ppsx", "ppsm"
        };
        // A .zip whose content is really OOXML is caught by the inspector itself
        // (it looks for [Content_Types].xml); here we go by the Office extension
        // plus the zip magic to avoid analyzing every plain .zip as a document.
        return Array.IndexOf(oox, ext) >= 0 && detected.StartsWith("ZIP");
    }

    private static bool IsLegacyOffice(string ext)
        => ext is "doc" or "dot" or "xls" or "xlt" or "ppt" or "pot" or "pps" or "msg";

    private static bool IsScript(string ext)
        => ext is "ps1" or "psm1" or "bat" or "cmd" or "vbs" or "vbe" or "js"
            or "jse" or "wsf" or "wsh" or "hta";

    private static bool IsArchive(string ext, string detected)
        => ext is "zip" or "rar" or "7z" or "cab"
           || detected.StartsWith("ZIP") || detected.StartsWith("RAR")
           || detected.StartsWith("7-Zip") || detected.StartsWith("CAB");
}
