using System.Text;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Structural inspector for legacy OLE Office documents (.doc/.xls/.ppt/.msg),
/// built on the OleCompoundFile container reader. Reports the storages and
/// streams that carry active content: a VBA project, Excel 4.0 (XLM) macro
/// sheets, embedded OLE objects, Ole10Native payloads (which name the embedded
/// file), Equation Editor objects (the CVE-2017-11882 exploit carrier) and
/// encryption. Facts only; grading happens in IntegrityScanner.
/// Called from: DocumentAnalyzer.Analyze.
/// </summary>
public static class OleInspector
{
    /// <summary>
    /// Enumerates the container and reports what it holds. Never throws.
    /// Called from: DocumentAnalyzer.Analyze.
    /// </summary>
    public static void Inspect(string path, IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        sec.Format = "OLE";
        sec.Description = "legacy OLE compound document";

        using var cf = new OleCompoundFile(path);
        if (!cf.IsValid)
        {
            sec.Status = StageStatus.Failed;
            sec.Error = "the OLE compound structure could not be read (damaged or non-standard)";
            return;
        }
        cancel.ThrowIfCancellationRequested();

        var names = cf.Entries.Select(e => e.Name).ToList();
        bool Has(string n) => names.Any(x => x.Equals(n, StringComparison.OrdinalIgnoreCase));
        bool HasPart(string part) => names.Any(x => x.Contains(part, StringComparison.OrdinalIgnoreCase));

        // Identify the application from the well-known main stream.
        if (Has("WordDocument")) sec.Description = "legacy Word document (.doc)";
        else if (Has("Workbook") || Has("Book")) sec.Description = "legacy Excel workbook (.xls)";
        else if (HasPart("PowerPoint Document")) sec.Description = "legacy PowerPoint presentation (.ppt)";
        else if (HasPart("__substg1.0")) sec.Description = "Outlook message (.msg)";

        // Encryption: an encrypted OOXML is also an OLE container, and legacy
        // Office stores its encryption info the same way.
        if (Has("EncryptedPackage") || Has("EncryptionInfo"))
        {
            sec.Encrypted = true;
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "encrypted",
                Detail = "the document is encrypted (EncryptedPackage/EncryptionInfo present); its content cannot be inspected."
            });
        }

        // VBA project: the storage is named "Macros" (Word) or "_VBA_PROJECT_CUR"
        // (Excel/PowerPoint); the module container stream is "_VBA_PROJECT".
        if (Has("Macros") || Has("_VBA_PROJECT_CUR") || Has("_VBA_PROJECT") || HasPart("VBA"))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "vba",
                Detail = "contains a VBA macro project: macros can run code when enabled."
            });

        // Embedded objects live in ObjectPool; each child is one object.
        if (Has("ObjectPool"))
        {
            int objects = names.Count(n => n.StartsWith("_", StringComparison.Ordinal)
                                           && n.Length > 1 && char.IsDigit(n[1]));
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "ole-embed",
                Detail = objects > 0
                    ? $"contains an ObjectPool with about {objects} embedded object(s)."
                    : "contains an ObjectPool (embedded objects)."
            });
        }

        // Ole10Native holds a raw embedded file and, helpfully, its original
        // name: the fastest way to see that a "document" carries an executable.
        foreach (var entry in cf.Entries.Where(e => e.Type == 2
            && e.Name.Contains("Ole10Native", StringComparison.OrdinalIgnoreCase)).Take(10))
        {
            cancel.ThrowIfCancellationRequested();
            string? embedded = ReadOle10NativeName(cf, entry);
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "ole-native",
                Detail = embedded != null
                    ? $"embedded native file: {embedded} ({entry.Size:N0} bytes). A packaged file inside a document runs whatever it is when the user opens it."
                    : $"embedded native file object ({entry.Size:N0} bytes)."
            });
        }

        // Equation Editor objects: the classic CVE-2017-11882/2018-0802 carrier.
        if (names.Any(n => n.Contains("Equation", StringComparison.OrdinalIgnoreCase)))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "ole-equation",
                Detail = "contains an Equation Editor object: the component behind several widely exploited Office vulnerabilities."
            });

        // Excel 4.0 macro sheets are declared in the Workbook stream's BOUNDSHEET
        // records, not by a storage name, so the stream has to be scanned.
        var workbook = cf.Entries.FirstOrDefault(e => e.Type == 2
            && (e.Name.Equals("Workbook", StringComparison.OrdinalIgnoreCase)
                || e.Name.Equals("Book", StringComparison.OrdinalIgnoreCase)));
        if (workbook != null)
        {
            cancel.ThrowIfCancellationRequested();
            var (macroSheets, hiddenSheets) = ScanBoundSheets(cf, workbook);
            if (macroSheets > 0)
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "xlm",
                    Detail = $"{macroSheets} Excel 4.0 (XLM) macro sheet(s) declared: an old macro type frequently used to bypass scanners."
                });
            if (hiddenSheets > 0)
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "xls-hidden-sheet",
                    Detail = $"{hiddenSheets} sheet(s) are hidden or very hidden: macro sheets are usually hidden so the user never sees them."
                });
        }

        sec.Items.Add(new IntegrityReport.DocumentItem
        {
            Kind = "ole-stats",
            Detail = $"{cf.Entries.Count(e => e.Type == 2)} stream(s) and "
                     + $"{cf.Entries.Count(e => e.Type == 1)} storage(s) in the container."
        });

        if (!sec.Items.Any(i => i.Kind is "vba" or "xlm" or "ole-embed" or "ole-native"
                or "ole-equation" or "encrypted" or "xls-hidden-sheet"))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "clean-structure",
                Detail = "no macro project, embedded objects or encryption found in the container."
            });
    }

    /// <summary>
    /// Reads the original file name from an Ole10Native stream. Layout: a 4-byte
    /// total size, a 2-byte flag, then a NUL-terminated ANSI file name.
    /// Returns null when the stream is too short or the name is implausible.
    /// Called from: Inspect.
    /// </summary>
    private static string? ReadOle10NativeName(OleCompoundFile cf, OleCompoundFile.DirEntry entry)
    {
        var data = cf.ReadStream(entry, 4096);
        if (data == null || data.Length < 10) return null;
        int start = 6;
        int end = Array.IndexOf(data, (byte)0, start);
        if (end <= start || end - start > 260) return null;
        string name = Encoding.Latin1.GetString(data, start, end - start).Trim();
        return name.Length is > 0 and <= 260 ? name : null;
    }

    /// <summary>
    /// Scans a BIFF Workbook stream for BOUNDSHEET records (type 0x0085) and
    /// counts Excel 4.0 macro sheets and hidden sheets. Record layout: type (2),
    /// length (2), then position (4), hidden state (1), sheet type (1) where
    /// 0x01 = Excel 4.0 macro sheet, and hidden state 1/2 = hidden/very hidden.
    /// Walking the record chain (rather than searching for the signature) avoids
    /// matching those bytes inside cell data. Called from: Inspect.
    /// </summary>
    private static (int MacroSheets, int HiddenSheets) ScanBoundSheets(
        OleCompoundFile cf, OleCompoundFile.DirEntry workbook)
    {
        int macro = 0, hidden = 0;
        var data = cf.ReadStream(workbook, 4 * 1024 * 1024);
        if (data == null || data.Length < 4) return (0, 0);

        int pos = 0, guard = 0;
        while (pos + 4 <= data.Length && guard++ < 200_000)
        {
            ushort type = BitConverter.ToUInt16(data, pos);
            ushort len = BitConverter.ToUInt16(data, pos + 2);
            int body = pos + 4;
            if (body + len > data.Length) break;

            if (type == 0x0085 && len >= 6)
            {
                byte hiddenState = (byte)(data[body + 4] & 0x03);
                byte sheetType = data[body + 5];
                if (sheetType == 0x01) macro++;
                if (hiddenState is 1 or 2) hidden++;
            }
            // EOF of the workbook globals substream: sheet declarations are done.
            if (type == 0x000A && macro + hidden > 0) break;

            pos = body + len;
        }
        return (macro, hidden);
    }
}
