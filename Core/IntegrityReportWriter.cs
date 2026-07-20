using System.Globalization;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Renders an IntegrityReport as plain text: one method per section (streamed
/// into the console as each stage completes) plus RenderAll for the History
/// entry summary. Pure formatting, no I/O and no UI access. Keeping all report
/// wording here means a future export feature (md/json, deferred by the user
/// until the feature is proven) reuses the exact same data without touching the
/// scanner. Called from: Core.IntegrityScanner (per-stage) and
/// MainWindow.FileVerifier.cs (history summary).
/// </summary>
public static class IntegrityReportWriter
{
    /// <summary>
    /// Invariant-culture interpolation. The report is English, so all numbers
    /// use "." decimals and "," thousands regardless of the OS locale (a German
    /// system previously rendered "6,73 bits/byte"). Called from: every render
    /// method with numeric output.
    /// </summary>
    private static string Inv(FormattableString f) => FormattableString.Invariant(f);

    /// <summary>
    /// Lines of the FILE section (metadata). Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderMetadata(IntegrityReport report)
    {
        var m = report.Metadata;
        var lines = new List<string>();
        if (m == null) return lines;
        if (m.Status == StageStatus.Failed)
        {
            lines.Add($"File metadata not readable: {m.Error}");
            return lines;
        }

        lines.Add(Inv($"Size       : {FormatSize(m.SizeBytes)} ({m.SizeBytes:N0} bytes)"));
        lines.Add(LocalAndUtc("Created    ", m.Created));
        lines.Add(LocalAndUtc("Modified   ", m.Modified));
        lines.Add(LocalAndUtc("Accessed   ", m.Accessed));
        lines.Add($"Attributes : {m.Attributes}");
        if (m.HardLinkCount > 1)
            lines.Add($"Hard links : {m.HardLinkCount} (the same data appears under multiple paths)");
        if (m.IsReparsePoint)
            lines.Add($"Link       : reparse point{(m.LinkTarget != null ? $" -> {m.LinkTarget}" : "")}");
        lines.Add($"File system: {m.FileSystemFormat} ({m.DriveType})");
        return lines;
    }

    /// <summary>
    /// Lines of the FILE TYPE section: magic-byte type, extension consistency
    /// and filename anomalies. Facts only; the graded findings come from
    /// IntegrityScanner.EvaluateFindings. Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderFileType(IntegrityReport report)
    {
        var ft = report.FileType;
        var lines = new List<string>();
        if (ft == null) return lines;
        if (ft.Status == StageStatus.Failed)
        {
            lines.Add($"File type not detected: {ft.Error}");
            return lines;
        }

        lines.Add($"Detected   : {ft.DetectedType}");
        lines.Add($"Extension  : {(ft.ActualExtension.Length > 0 ? "." + ft.ActualExtension : "(none)")}");
        if (ft.ExtensionMatches is bool m)
            lines.Add(m
                ? "Consistency: extension matches the detected type"
                : $"Consistency: MISMATCH, .{(ft.ActualExtension.Length > 0 ? ft.ActualExtension : "(none)")} is unusual for {ft.DetectedType} " +
                  $"(common: {string.Join(", ", ft.ExpectedExtensions.Take(8).Select(x => "." + x))})");
        else
            lines.Add("Consistency: not checked (no extension expectation for this type)");
        foreach (var a in ft.NameAnomalies)
            lines.Add($"Name       : {a}");
        return lines;
    }

    /// <summary>
    /// Lines of the DOCUMENT ANALYSIS section: format, encryption note and each
    /// structural fact/indicator. Facts only; grading is in EvaluateFindings.
    /// Called from: IntegrityScanner and RenderAll.
    /// </summary>
    public static List<string> RenderDocument(IntegrityReport report)
    {
        var d = report.Document;
        var lines = new List<string>();
        if (d == null || d.Status == StageStatus.Skipped) return lines;
        if (d.Status == StageStatus.Failed)
        {
            lines.Add($"Document analysis failed: {d.Error}");
            return lines;
        }

        lines.Add($"Format     : {d.Format}{(d.Description.Length > 0 ? $" ({d.Description})" : "")}");
        if (d.Encrypted)
            lines.Add("Encrypted  : yes (protected content cannot be inspected; a clean structure here does NOT mean the file is safe)");
        foreach (var item in d.Items)
            lines.Add($"  [{item.Kind}] {item.Detail}");
        return lines;
    }

    /// <summary>
    /// Lines of the INDICATORS section for a non-PE document run (reuses the
    /// grouped strings collected into Document.Indicators). Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderDocumentIndicators(IntegrityReport report)
    {
        var d = report.Document;
        var lines = new List<string>();
        if (d == null || d.Indicators.Count == 0) return lines;
        lines.Add("Indicators (extracted from the raw file, NOT validated):");
        foreach (var line in d.Indicators) lines.Add(line);
        return lines;
    }

    /// <summary>
    /// Lines of the HASHES section, matching the established hash output format
    /// ("NAME    : HEX", MATCH/MISMATCH verdicts) plus the entropy line.
    /// Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderHashes(IntegrityReport report)
    {
        var h = report.Hashes;
        var lines = new List<string>();
        if (h == null) return lines;
        if (h.Status == StageStatus.Failed)
        {
            lines.Add($"Hashes not computed: {h.Error}");
            return lines;
        }

        // Distinguish a genuine read failure from a SHA-3 variant that this
        // Windows build cannot run (SHA-3 needs a recent Windows).
        static string FailMsg(string a) => HashTool.IsSupported(a)
            ? "FAILED (file locked or unreadable)"
            : "not supported on this Windows build";

        foreach (var (name, hash) in h.Values)
            lines.Add($"{name,-8}: {hash ?? FailMsg(name)}");

        if (!string.IsNullOrWhiteSpace(h.Expected))
        {
            lines.Add($"Expected: {h.Expected.Trim()}");
            if (h.Matched == true)
                lines.Add(h.Values.Count > 1
                    ? $"MATCH: expected hash equals the {h.MatchedAlgorithm} hash."
                    : "MATCH: computed hash equals the expected value.");
            else
                lines.Add(h.Values.Count > 1
                    ? "MISMATCH: expected hash matches none of the computed hashes."
                    : $"MISMATCH: expected {h.Expected.Trim()}");
        }

        if (h.EntropyBitsPerByte is double e)
            lines.Add(Inv($"Entropy : {e:0.00} bits/byte ({EntropyInterpretation(e)})"));
        return lines;
    }

    /// <summary>
    /// Lines of the FILE SYSTEM section: owner, DACL, ADS and Mark of the Web.
    /// Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderFileSystem(IntegrityReport report)
    {
        var fs = report.FileSystem;
        var lines = new List<string>();
        if (fs == null) return lines;
        if (fs.Status == StageStatus.Skipped)
        {
            lines.Add($"Skipped: {fs.Error}");
            return lines;
        }

        if (fs.Status == StageStatus.Failed)
            lines.Add($"Partial data: {fs.Error}");

        if (!string.IsNullOrEmpty(fs.Owner))
            lines.Add($"Owner: {fs.Owner}");

        if (fs.AccessRules.Count > 0)
        {
            lines.Add("Access control (DACL):");
            foreach (var rule in fs.AccessRules)
                lines.Add($"  {rule.Type,-5}  {rule.Identity} : {rule.Rights}" +
                          (rule.Inherited ? " (inherited)" : ""));
        }

        if (fs.AlternateStreams.Count == 0)
        {
            lines.Add("Alternate data streams: none");
        }
        else
        {
            lines.Add($"Alternate data streams ({fs.AlternateStreams.Count}):");
            foreach (var s in fs.AlternateStreams)
                lines.Add(Inv($"  {s.Name} ({s.SizeBytes:N0} bytes)"));
        }

        if (fs.MotwZoneId is int zone)
        {
            lines.Add($"Mark of the Web: {FileSystemInspector.ZoneName(zone)} (ZoneId {zone})");
            if (!string.IsNullOrEmpty(fs.MotwHost)) lines.Add($"  Source  : {fs.MotwHost}");
            if (!string.IsNullOrEmpty(fs.MotwReferrer)) lines.Add($"  Referrer: {fs.MotwReferrer}");
        }
        return lines;
    }

    /// <summary>
    /// Lines of the FINDINGS section, or the explicit all-clear line. Findings
    /// are informational indicators, never a malware verdict.
    /// Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderFindings(IntegrityReport report)
    {
        if (report.Findings.Count == 0)
            return new List<string> { "No findings from the executed checks." };
        return report.Findings
            .OrderByDescending(f => f.Severity)
            .Select(f => $"[{f.Severity}] {f.Text}")
            .ToList();
    }

    /// <summary>
    /// Lines of the PE ANALYSIS section. Skipped (non-PE) and Failed states
    /// render a single explanatory line. Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderPe(IntegrityReport report)
    {
        var pe = report.Pe;
        var lines = new List<string>();
        if (pe == null) return lines;
        if (pe.Status == StageStatus.Skipped)
        {
            lines.Add($"Skipped: {pe.Error}");
            return lines;
        }
        if (pe.Status == StageStatus.Failed)
        {
            lines.Add($"PE parsing failed: {pe.Error}");
            if (pe.Sections.Count == 0) return lines;
            lines.Add("Partial data:");
        }

        lines.Add($"Type       : {pe.FileType}, {pe.Machine} ({(pe.IsPe32Plus ? "PE32+" : "PE32")}), subsystem {pe.Subsystem}");

        if (pe.TimestampRaw == 0)
            lines.Add("Linked     : timestamp not set");
        else if (pe.TimestampPlausible)
            lines.Add($"Linked     : {pe.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC" +
                      (pe.DebugReproducible ? " (build marked reproducible)" : ""));
        else if (pe.DebugReproducible)
            lines.Add($"Linked     : raw 0x{pe.TimestampRaw:X8} (reproducible build: the field holds a hash, not a time)");
        else if (pe.TimestampUtc > DateTime.UtcNow.AddDays(2))
            lines.Add($"Linked     : {pe.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC lies in the FUTURE (tampered or reproducible-build hash)");
        else if (pe.TimestampUtc < new DateTime(1993, 1, 1))
            lines.Add($"Linked     : {pe.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC predates the PE format (tampered or reproducible-build hash)");
        else
            lines.Add($"Linked     : raw 0x{pe.TimestampRaw:X8}, not a plausible date " +
                      "(reproducible build: the field holds a hash, not a time)");

        lines.Add($"Compiler   : {pe.CompilerGuess} [heuristic]" +
                  (pe.RichHeaderPresent ? $" (Rich header present, {pe.RichHeaderEntries} entries)" : ""));
        if (pe.RichHeaderPresent && pe.RichChecksumValid != null)
        {
            lines.Add($"Rich header: checksum {(pe.RichChecksumValid == true ? "PASS (matches the DOS stub)" : "FAIL (header edited or copied from another binary)")}");
            if (pe.RichEntrySummaries.Count > 0)
                lines.Add("             tools: " + string.Join(", ", pe.RichEntrySummaries));
        }
        if (pe.PackerSigns.Count > 0)
            lines.Add("Packer     : " + string.Join("; ", pe.PackerSigns) + " [heuristic]");

        if (pe.EntryPointRva == 0)
            lines.Add("Entry point: none (RVA 0)");
        else if (pe.EntryPointSection == null)
            lines.Add($"Entry point: 0x{pe.EntryPointRva:X} OUTSIDE all sections");
        else
            lines.Add($"Entry point: 0x{pe.EntryPointRva:X} in {pe.EntryPointSection}" +
                      (pe.EntryPointExecutable ? "" : " (section is NOT executable)"));

        var mit = new List<string>
        {
            $"ASLR {(pe.Aslr ? pe.HighEntropyVa ? "yes (high-entropy VA)" : "yes" : "NO")}",
            $"DEP {(pe.Dep ? "yes" : "NO")}",
            $"CFG {(pe.ControlFlowGuard ? "yes" : "no")}"
        };
        if (pe.NoSeh) mit.Add("SEH disabled");
        if (pe.AppContainer) mit.Add("AppContainer");
        if (pe.ForceIntegrity) mit.Add("ForceIntegrity");
        lines.Add($"Mitigations: {string.Join(", ", mit)}");

        if (pe.IsDotNet)
            lines.Add($"CLR        : .NET assembly" +
                      (pe.ClrMetadataVersion != null ? $", metadata {pe.ClrMetadataVersion}" : "") +
                      (pe.ClrIlOnly ? ", IL-only" : "") +
                      (pe.Clr32BitRequired ? ", 32-bit required" : ""));

        if (pe.CheckSumStored == 0)
            lines.Add("Checksum   : stored 0x00000000 (not set; normal for applications)");
        else if (pe.CheckSumStored == pe.CheckSumComputed)
            lines.Add($"Checksum   : stored 0x{pe.CheckSumStored:X8}, matches the computed value");
        else
            lines.Add($"Checksum   : stored 0x{pe.CheckSumStored:X8} does NOT match computed 0x{pe.CheckSumComputed:X8}");

        lines.Add(pe.SignatureDataSize > 0
            ? Inv($"Signature  : embedded signature data present ({pe.SignatureDataSize:N0} bytes; ") +
              "the SIGNATURE section verifies it when the Signature check is enabled)"
            : "Signature  : no embedded signature data (unsigned, or catalog-signed like most Windows files)");

        if (pe.OverlayBytes > 0)
        {
            double pct = pe.FileSizeBytes > 0 ? 100.0 * pe.OverlayBytes / pe.FileSizeBytes : 0;
            string entropyPart = pe.OverlayEntropy is double oe
                ? Inv($", entropy {oe:0.00}: {EntropyInterpretation(oe)}") : "";
            lines.Add(Inv($"Overlay    : {FormatSize(pe.OverlayBytes)} ({pe.OverlayBytes:N0} bytes, ") +
                      Inv($"{pct:0.0}% of the file{entropyPart}) beyond the last section (excluding signature data)"));
            if (pe.DotNetBundle)
                lines.Add(Inv($"Overlay is : a .NET single-file bundle (marker verified, header at 0x{pe.DotNetBundleHeaderOffset:X}); ") +
                          "the high-entropy overlay is the bundled app, not hidden data");
        }
        else
        {
            lines.Add("Overlay    : none");
        }

        if (pe.TlsCallbackCount > 0)
            lines.Add($"TLS        : {pe.TlsCallbackCount} callback(s), executed BEFORE the entry point");

        var ver = new List<string>();
        if (pe.VersionCompany.Length > 0) ver.Add($"CompanyName \"{pe.VersionCompany}\"");
        if (pe.VersionProduct.Length > 0) ver.Add($"ProductName \"{pe.VersionProduct}\"");
        if (pe.VersionFileVersion.Length > 0) ver.Add($"FileVersion \"{pe.VersionFileVersion}\"");
        if (pe.VersionOriginalFilename.Length > 0) ver.Add($"OriginalFilename \"{pe.VersionOriginalFilename}\"");
        if (pe.VersionDescription.Length > 0) ver.Add($"Description \"{pe.VersionDescription}\"");
        lines.Add(ver.Count > 0 ? $"Version res: {string.Join("; ", ver)}"
                                : "Version res: none");

        if (pe.PdbPath != null)
            lines.Add($"Debug PDB  : {pe.PdbPath}");

        if (pe.HasManifest)
        {
            var man = new List<string>();
            if (pe.ManifestExecutionLevel != null) man.Add($"requested privilege {pe.ManifestExecutionLevel}");
            if (pe.ManifestUiAccess == true) man.Add("uiAccess true");
            if (pe.ManifestAutoElevate == true) man.Add("autoElevate true");
            if (pe.ManifestDpiAware != null) man.Add($"dpiAware {pe.ManifestDpiAware}");
            if (pe.ManifestLongPathAware != null) man.Add($"longPathAware {(pe.ManifestLongPathAware == true ? "true" : "false")}");
            lines.Add("Manifest   : " + (man.Count > 0 ? string.Join(", ", man) : "present"));
        }

        if (pe.DelayImports.Count > 0)
            lines.Add($"Delay imp. : {string.Join(", ", pe.DelayImports)}");

        if (pe.Imports.Count == 0)
        {
            lines.Add("Imports    : none");
        }
        else
        {
            lines.Add(Inv($"Imports    : {pe.Imports.Count} DLLs, {pe.TotalImportedFunctions} functions"));
            foreach (var (label, dlls) in GroupImports(pe.Imports))
            {
                const int perLine = 4;
                for (int i = 0; i < dlls.Count; i += perLine)
                {
                    string head = i == 0 ? $"  {label,-12}: " : new string(' ', 16);
                    lines.Add(head + string.Join(", ", dlls.Skip(i).Take(perLine)
                        .Select(d => Inv($"{d.Name} ({d.FunctionCount})"))));
                }
            }
            if (pe.Imphash != null)
                lines.Add($"Imphash    : {pe.Imphash} (searchable on VirusTotal)");
        }

        if (pe.ExportCount > 0 || pe.ExportDllName != null)
        {
            lines.Add($"Exports    : {pe.ExportCount} named export(s)" +
                      (pe.ExportDllName != null ? $", internal name {pe.ExportDllName}" : ""));
            if (pe.ExportNames.Count > 0)
            {
                const int perLine = 6;
                for (int i = 0; i < pe.ExportNames.Count; i += perLine)
                    lines.Add("             " + string.Join(", ", pe.ExportNames.Skip(i).Take(perLine)));
            }
        }

        if (pe.Sections.Count > 0)
        {
            lines.Add($"Sections ({pe.Sections.Count}):");
            lines.Add("  name       virt addr     raw size      entropy  flags");
            foreach (var s in pe.Sections)
            {
                string flags = $"{(s.Readable ? "r" : "-")}{(s.Writable ? "w" : "-")}{(s.Executable ? "x" : "-")}" +
                               (s.ContainsCode ? " code" : "");
                string ent = s.Entropy is double e ? Inv($"{e:0.00}") : "n/a";
                // A single very-high-entropy section stands out much more than
                // the whole-file entropy; tag it so the eye lands on it.
                string note = s.Entropy is >= 7.2 ? "  [very high: compressed or encrypted]" : "";
                lines.Add(Inv($"  {s.Name,-10} 0x{s.VirtualAddress:X8}  {s.RawSize,12:N0}  {ent,7}  {flags}") + note);
            }
        }

        if (pe.SectionAnomalies.Count > 0)
        {
            lines.Add("Section anomalies:");
            foreach (var a in pe.SectionAnomalies) lines.Add($"  {a}");
        }
        return lines;
    }

    /// <summary>
    /// Lines of the CAPABILITIES section: behavioral capabilities inferred from
    /// the imports plus any extracted indicator strings. Both are informational
    /// (the header text says so); the APIs and strings are common in legitimate
    /// software. Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderCapabilities(IntegrityReport report)
    {
        var pe = report.Pe;
        var lines = new List<string>();
        if (pe == null) return lines;

        if (pe.NotableImports.Count > 0)
        {
            lines.Add("Notable imports (informational; common in legitimate software):");
            foreach (var c in pe.NotableImports) lines.Add($"  {c}");
        }
        if (pe.Indicators.Count > 0)
        {
            if (lines.Count > 0) lines.Add("");
            lines.Add("Indicators (extracted from strings, NOT validated):");
            lines.AddRange(pe.Indicators);
        }
        return lines;
    }

    /// <summary>
    /// Lines of the SIGNATURE section: where the signature lives (embedded or
    /// catalog), the Windows trust verdict and the signing certificate.
    /// Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderSignature(IntegrityReport report)
    {
        var sig = report.Signature;
        if (sig == null) return new();
        if (sig.Status == StageStatus.Failed)
            return new List<string> { $"Signature check failed: {sig.Error}" };

        var lines = new List<string>();
        if (sig.Trusted == null)
        {
            lines.Add("Not signed: no embedded signature and no catalog contains the file's hash.");
            return lines;
        }

        lines.Add(sig.Location == "embedded"
            ? "Location   : embedded in the file"
            : $"Location   : Windows security catalog{(sig.CatalogFile != null ? $" ({sig.CatalogFile})" : "")}");
        lines.Add($"Verdict    : {(sig.Trusted == true ? "VALID, " : "NOT TRUSTED: ")}{sig.TrustText}");
        if (sig.SignerSubject.Length > 0)
        {
            lines.Add($"Signer     : {sig.SignerSubject} (issued by {sig.SignerIssuer})");
            if (sig.SignerNotBefore != null && sig.SignerNotAfter != null)
                lines.Add($"Cert valid : {sig.SignerNotBefore:yyyy-MM-dd} to {sig.SignerNotAfter:yyyy-MM-dd}");
            lines.Add($"Thumbprint : {sig.SignerThumbprint}");
        }
        if (sig.SignedAt is DateTime ts)
            lines.Add($"Signed at  : {ts:yyyy-MM-dd HH:mm:ss} UTC ({sig.TimestampSource} timestamp)");
        else if (sig.Location == "embedded")
            lines.Add("Signed at  : no timestamp (the signature dies with the certificate's expiry)");
        lines.Add("Revocation : not checked online (offline verification, cached data only)");
        return lines;
    }

    /// <summary>
    /// Lines of the CLAMAV section (report-only single-file scan).
    /// Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderClamAv(IntegrityReport report)
    {
        var av = report.ClamAv;
        if (av == null) return new();
        if (av.Status == StageStatus.Skipped)
            return new List<string> { $"Skipped: {av.Error}." };
        if (av.Status == StageStatus.Failed)
            return new List<string> { $"Scan failed: {av.Error}" };

        var lines = new List<string>
        {
            $"Engine     : {(av.UsedDaemon ? "clamdscan (daemon)" : "clamscan (standalone)")}"
        };
        if (av.Threats.Count == 0)
            lines.Add("Result     : clean, no signature matched");
        else
        {
            lines.Add($"Result     : {av.Threats.Count} detection(s), report-only (nothing was removed)");
            foreach (var t in av.Threats.Distinct())
                lines.Add($"  {t}");
            lines.Add("The finding was added to the Detections list for follow-up.");
        }
        return lines;
    }

    /// <summary>
    /// Lines of the VIRUSTOTAL section (hash lookup only, the file never leaves
    /// the machine). Called from: IntegrityScanner.
    /// </summary>
    public static List<string> RenderVirusTotal(IntegrityReport report)
    {
        var vt = report.VirusTotal;
        if (vt == null) return new();
        if (vt.Status == StageStatus.Skipped)
            return new List<string> { $"Skipped: {vt.Error}." };
        if (vt.Status == StageStatus.Failed)
            return new List<string> { $"Lookup failed: {vt.Error}" };

        var lines = new List<string> { $"SHA256     : {vt.Sha256}" };
        if (vt.NotFound)
        {
            lines.Add("Result     : hash unknown to VirusTotal (never submitted there)");
            lines.Add("Note: unknown does not mean safe, only that no one uploaded it yet.");
            return lines;
        }
        int total = vt.Malicious + vt.Suspicious + vt.Harmless + vt.Undetected;
        lines.Add($"Result     : {vt.Malicious}/{total} engines malicious" +
                  (vt.Suspicious > 0 ? $", {vt.Suspicious} suspicious" : ""));
        lines.Add($"Details    : https://www.virustotal.com/gui/file/{vt.Sha256.ToLowerInvariant()}");
        return lines;
    }

    /// <summary>
    /// The complete report as one text block for the History entry summary:
    /// the file path followed by every executed section under a plain header.
    /// Called from: MainWindow.FileVerifier.cs after a run.
    /// </summary>
    public static string RenderAll(IntegrityReport report)
    {
        var blocks = new List<string> { $"File: {report.FilePath}" };

        void Add(string title, List<string> lines)
        {
            if (lines.Count > 0)
                blocks.Add(string.Join(Environment.NewLine, ConsoleSections.Banner(title))
                    + Environment.NewLine + string.Join(Environment.NewLine, lines));
        }

        Add("FILE", RenderMetadata(report));
        Add("FILE TYPE", RenderFileType(report));
        Add("HASHES", RenderHashes(report));
        Add("FILE SYSTEM", RenderFileSystem(report));
        Add("PE ANALYSIS", RenderPe(report));
        Add("NOTABLE IMPORTS & INDICATORS", RenderCapabilities(report));
        Add("DOCUMENT ANALYSIS", RenderDocument(report));
        Add("INDICATORS", RenderDocumentIndicators(report));
        Add("SIGNATURE", RenderSignature(report));
        Add("CLAMAV", RenderClamAv(report));
        Add("VIRUSTOTAL", RenderVirusTotal(report));
        Add("FINDINGS", RenderFindings(report));
        Add("SUMMARY", RenderSummary(report));

        return string.Join(Environment.NewLine + Environment.NewLine, blocks);
    }

    /// <summary>
    /// Short label summarizing the findings for the History result column,
    /// e.g. "no findings" or "1 warning, 2 notices". Called from:
    /// MainWindow.FileVerifier.cs.
    /// </summary>
    /// <summary>
    /// Lines of the SUMMARY section: one ASCII-marked verdict line per executed
    /// check plus the findings tally. Markers: [OK] fine, [!] needs attention,
    /// [i] informational, [--] skipped/not applicable. Deliberately NO numeric
    /// risk score: a single number would suggest a calibration the heuristics
    /// do not have; the findings list carries the grading instead.
    /// Called from: IntegrityScanner (last streamed section) and RenderAll.
    /// </summary>
    public static List<string> RenderSummary(IntegrityReport report)
    {
        var lines = new List<string>();

        // Hash comparison (only when the user supplied an expected hash).
        if (report.Hashes is { } h && !string.IsNullOrWhiteSpace(h.Expected))
            lines.Add(h.Matched == true
                ? "[OK] Expected hash matches the file."
                : "[!]  Expected hash MISMATCH: not the file the hash belongs to, or it was modified.");

        // Download origin.
        if (report.FileSystem is { MotwZoneId: 3 or 4 } fsm)
            lines.Add($"[i]  Downloaded from the Internet (Mark of the Web{(string.IsNullOrEmpty(fsm.MotwHost) ? "" : $", source {fsm.MotwHost}")}).");

        // PE essentials.
        if (report.Pe is { Status: StageStatus.Ok } pe)
        {
            if (pe.CheckSumStored != 0)
                lines.Add(pe.CheckSumStored == pe.CheckSumComputed
                    ? "[OK] PE checksum valid."
                    : "[!]  PE checksum mismatch (modified after linking or never fixed up).");
            if (pe.TlsCallbackCount > 0)
                lines.Add(Inv($"[!]  {pe.TlsCallbackCount} TLS callback(s) run before the entry point."));
            if (pe.Sections.Any(x => x.Writable && x.Executable))
                lines.Add("[!]  Writable and executable section present.");
        }

        // Signature.
        if (report.Signature is { Status: StageStatus.Ok } sig)
        {
            if (sig.Trusted == true)
                lines.Add($"[OK] Authenticode signature valid ({sig.Location}" +
                          (sig.SignerSubject.Length > 0 ? $", signer {sig.SignerSubject}" : "") + ").");
            else if (sig.Trusted == false)
                lines.Add($"[!]  Authenticode signature does NOT verify: {sig.TrustText}.");
            else
                lines.Add("[i]  Not signed (no embedded signature, no catalog entry).");
        }
        else if (report.Signature is { } sigf)
            lines.Add($"[--] Signature check failed: {sigf.Error}.");

        // ClamAV.
        if (report.ClamAv is { } av)
        {
            if (av.Status == StageStatus.Ok)
                lines.Add(av.Threats.Count == 0
                    ? "[OK] ClamAV: clean, no signature matched."
                    : $"[!]  ClamAV detects: {string.Join(", ", av.Threats.Distinct())}.");
            else
                lines.Add($"[--] ClamAV: {(av.Status == StageStatus.Skipped ? "skipped" : "failed")} ({av.Error}).");
        }

        // VirusTotal.
        if (report.VirusTotal is { } vt)
        {
            if (vt.Status == StageStatus.Ok && !vt.NotFound)
            {
                int total = vt.Malicious + vt.Suspicious + vt.Harmless + vt.Undetected;
                lines.Add(vt.Malicious == 0
                    ? Inv($"[OK] VirusTotal: 0/{total} engines flag this file.")
                    : Inv($"[!]  VirusTotal: {vt.Malicious}/{total} engines flag this file as malicious."));
            }
            else if (vt.Status == StageStatus.Ok)
                lines.Add("[i]  VirusTotal: hash unknown (never submitted; unknown does not mean safe).");
            else
                lines.Add($"[--] VirusTotal: {(vt.Status == StageStatus.Skipped ? "skipped" : "failed")} ({vt.Error}).");
        }

        if (lines.Count == 0)
            lines.Add("[i]  No summary-relevant checks were executed.");

        lines.Add("");
        lines.Add(report.Findings.Count == 0
            ? "Findings: none from the executed checks."
            : $"Findings: {FindingsLabel(report)} " +
              $"(highest: {report.Findings.Max(f => f.Severity)})");
        return lines;
    }

    /// <summary>
    /// Buckets import DLLs into readable categories (Network, Cryptography,
    /// Graphics, UI, System, Other) so 40+ DLL lists scan at a glance. Purely
    /// presentational; unknown and api-ms-* set DLLs count as System.
    /// Called from: RenderPe.
    /// </summary>
    private static List<(string Label, List<IntegrityReport.PeImportDll> Dlls)> GroupImports(
        List<IntegrityReport.PeImportDll> imports)
    {
        static string Cat(string dll)
        {
            string n = dll.ToLowerInvariant();
            if (n.StartsWith("api-ms-") || n.StartsWith("ext-ms-")) return "System";
            string b = n.EndsWith(".dll") ? n[..^4] : n;
            return b switch
            {
                "ws2_32" or "wsock32" or "winhttp" or "wininet" or "iphlpapi" or "wldap32"
                    or "netapi32" or "mpr" or "dnsapi" or "urlmon" or "ndfapi" or "webio"
                    or "winrm" or "mswsock" => "Network",
                "crypt32" or "bcrypt" or "ncrypt" or "secur32" or "wintrust" or "cryptui"
                    or "sspicli" or "cryptsp" or "rsaenh" or "cryptnet" => "Cryptography",
                "d3d9" or "d3d10" or "d3d11" or "d3d12" or "dxgi" or "opengl32" or "glu32"
                    or "gdi32" or "gdiplus" or "dwrite" or "d2d1" or "dcomp" or "vulkan-1" => "Graphics",
                "user32" or "comctl32" or "comdlg32" or "uxtheme" or "dwmapi" or "imm32"
                    or "uiautomationcore" or "shcore" or "msimg32" or "oleacc" => "UI",
                _ => "System"
            };
        }

        var order = new[] { "Network", "Cryptography", "Graphics", "UI", "System" };
        var groups = imports.GroupBy(d => Cat(d.Name)).ToDictionary(g => g.Key, g => g.ToList());
        var result = new List<(string, List<IntegrityReport.PeImportDll>)>();
        foreach (var label in order)
            if (groups.TryGetValue(label, out var list)) result.Add((label, list));
        return result;
    }

    public static string FindingsLabel(IntegrityReport report)
    {
        if (report.Findings.Count == 0) return "no findings";
        var parts = new List<string>();
        foreach (var sev in new[] { FindingSeverity.Critical, FindingSeverity.High,
                     FindingSeverity.Medium, FindingSeverity.Low, FindingSeverity.Info })
        {
            int c = report.Findings.Count(f => f.Severity == sev);
            if (c > 0) parts.Add($"{c} {sev.ToString().ToLowerInvariant()}");
        }
        return string.Join(", ", parts);
    }

    /// <summary>
    /// Neutral wording for an entropy value. High entropy is only an indicator
    /// (installers and media are also high), so the text stays descriptive.
    /// Called from: RenderHashes and IntegrityScanner (findings).
    /// </summary>
    public static string EntropyInterpretation(double bitsPerByte) => bitsPerByte switch
    {
        < 5.0 => "low: text or sparse data",
        < 6.5 => "typical binary data",
        < 7.2 => "high: compressed media or partly packed data",
        _ => "very high: compressed, packed or encrypted data"
    };

    /// <summary>Human readable size in binary units (B/KiB/MiB/GiB), invariant
    /// decimals. Called from: RenderMetadata and RenderPe (overlay).</summary>
    private static string FormatSize(long bytes)
    {
        double v = bytes;
        string[] units = { "B", "KiB", "MiB", "GiB", "TiB" };
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? Inv($"{bytes} B") : Inv($"{v:0.00} {units[u]}");
    }

    /// <summary>One timestamp line showing local and UTC time. Called from:
    /// RenderMetadata.</summary>
    private static string LocalAndUtc(string label, DateTime local)
        => $"{label}: {local:yyyy-MM-dd HH:mm:ss} local ({local.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC)";
}
