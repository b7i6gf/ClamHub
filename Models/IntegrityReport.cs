namespace ClamHub.Models;

/// <summary>
/// Outcome of one File-Verifier stage. Ok = ran and produced data, Skipped =
/// deliberately not run (unchecked, or not applicable like ACLs on FAT32),
/// Failed = attempted but errored (the report continues with the next stage).
/// Used by: the section classes below; set by Core.IntegrityScanner.
/// </summary>
public enum StageStatus
{
    Ok,
    Skipped,
    Failed
}

/// <summary>
/// Severity of one finding in the FINDINGS section (five levels since the
/// batch-D output redesign; previously Info/Notice/Warning). Purely
/// informational grading, never a malware verdict (that stays with
/// ClamAV/VirusTotal). Ordered so numeric comparison means "more severe".
/// </summary>
public enum FindingSeverity
{
    /// <summary>Context worth knowing, nothing wrong (MotW, overlay present).</summary>
    Info,
    /// <summary>Slightly unusual, common in legitimate software (missing ASLR, renamed file).</summary>
    Low,
    /// <summary>Deserves a look (signature does not verify for a benign-looking reason).</summary>
    Medium,
    /// <summary>Strong indicator of tampering or malice (hash mismatch, W+X section).</summary>
    High,
    /// <summary>Hard evidence (ClamAV detection, digest broken after signing).</summary>
    Critical
}

/// <summary>
/// One entry of the FINDINGS section: a severity plus a one-line description.
/// Produced by: Core.IntegrityScanner stage evaluation; rendered by
/// Core.IntegrityReportWriter.
/// </summary>
public sealed class IntegrityFinding
{
    public FindingSeverity Severity { get; set; } = FindingSeverity.Info;
    public string Text { get; set; } = "";
}

/// <summary>
/// Result of one File-Verifier run over a single file. Sections are null when
/// their stage did not run at all; a section that ran but failed carries
/// Status=Failed plus an Error text. Filled by Core.IntegrityScanner, rendered
/// by Core.IntegrityReportWriter, shown in the console and stored as a History
/// entry summary. The model is JSON-serializable by design so a later batch can
/// add export and baseline comparison without format changes.
/// </summary>
public sealed class IntegrityReport
{
    /// <summary>Absolute path of the verified file.</summary>
    public string FilePath { get; set; } = "";

    /// <summary>Local start time of the run.</summary>
    public DateTime StartedAt { get; set; }

    /// <summary>Basic file metadata; always collected (stage has no checkbox).</summary>
    public MetadataSection? Metadata { get; set; }

    /// <summary>Hash results; null when the Hashes check was disabled.</summary>
    public HashSection? Hashes { get; set; }

    /// <summary>NTFS details; null when the File system check was disabled.</summary>
    public FileSystemSection? FileSystem { get; set; }

    /// <summary>PE analysis; null when the PE check was disabled (batch B, v1.0.3.8).</summary>
    public PeAnalysisSection? Pe { get; set; }

    /// <summary>Authenticode result, null = stage not run (batch C).</summary>
    public SignatureSection? Signature { get; set; }

    /// <summary>ClamAV single-file scan result, null = stage not run (batch C).</summary>
    public ClamAvSection? ClamAv { get; set; }

    /// <summary>VirusTotal hash lookup result, null = stage not run (batch C).</summary>
    public VirusTotalSection? VirusTotal { get; set; }

    /// <summary>Magic-byte file type, extension consistency and filename
    /// anomaly checks; always on (cheap). Filled by Core.FileTypeDetector.</summary>
    public FileTypeSection? FileType { get; set; }

    /// <summary>Structural analysis of documents, shortcuts, scripts and
    /// archives (the active-content facts, never a verdict). Null when the
    /// stage was off or the file is none of these. Filled by Core.DocumentAnalyzer.</summary>
    public DocumentSection? Document { get; set; }

    /// <summary>Findings gathered across all executed stages.</summary>
    public List<IntegrityFinding> Findings { get; set; } = new();

    /// <summary>
    /// Basic file metadata: size, timestamps, attributes, link information and
    /// the file system the file lives on. Collected by
    /// Core.FileSystemInspector.CollectMetadata.
    /// </summary>
    public sealed class MetadataSection
    {
        public StageStatus Status { get; set; } = StageStatus.Ok;
        public string? Error { get; set; }

        public long SizeBytes { get; set; }
        public DateTime Created { get; set; }
        public DateTime Modified { get; set; }
        public DateTime Accessed { get; set; }
        public string Attributes { get; set; } = "";
        public bool IsReparsePoint { get; set; }
        /// <summary>Symlink/junction target when the file is a link, else null.</summary>
        public string? LinkTarget { get; set; }
        /// <summary>NTFS hard link count (1 = no additional links); 0 = unknown.</summary>
        public uint HardLinkCount { get; set; }
        /// <summary>File system format of the hosting volume ("NTFS", "FAT32", ...).</summary>
        public string FileSystemFormat { get; set; } = "";
        /// <summary>Drive type ("Fixed", "Removable", "Network", ...).</summary>
        public string DriveType { get; set; } = "";
    }

    /// <summary>
    /// Hash stage result: the computed hashes (algorithm name to uppercase hex,
    /// null = failed/unsupported), the optional expected-value comparison and the
    /// whole-file Shannon entropy measured in the same read pass.
    /// Computed by Core.HashTool.ComputeSelectedAsync via Core.IntegrityScanner.
    /// </summary>
    /// <summary>
    /// Magic-byte detection result plus filename anomaly checks. DetectedType is
    /// a curated table (executables, archives, documents, images), never a full
    /// libmagic port; unknown magics stay "unknown" with no verdict.
    /// Filled by Core.FileTypeDetector; rendered by Core.IntegrityReportWriter.
    /// </summary>
    public sealed class FileTypeSection
    {
        public StageStatus Status { get; set; } = StageStatus.Ok;
        public string? Error { get; set; }

        /// <summary>Human name of the detected type, "unknown" when no magic matched.</summary>
        public string DetectedType { get; set; } = "unknown";
        /// <summary>True when the detected content can execute code when opened
        /// (PE, ELF, shortcut). Drives the mismatch severity.</summary>
        public bool IsExecutableContent { get; set; }
        /// <summary>Lower-case extensions (no dot) commonly used for the type.</summary>
        public List<string> ExpectedExtensions { get; set; } = new();
        /// <summary>The file's actual extension, lower-case without the dot ("" = none).</summary>
        public string ActualExtension { get; set; } = "";
        /// <summary>True/false = extension checked against ExpectedExtensions;
        /// null = no expectation (unknown magic or plain text).</summary>
        public bool? ExtensionMatches { get; set; }
        /// <summary>Filename anomaly descriptions (double extension, hidden
        /// bidi/format characters, space padding). Empty = nothing found.</summary>
        public List<string> NameAnomalies { get; set; } = new();
    }

    /// <summary>
    /// One structural fact or active-content indicator from a document, shortcut,
    /// script or archive. Neutral by design: "has a VBA macro", "auto-runs on
    /// open", "references an external URL". Severity is assigned later in
    /// IntegrityScanner.EvaluateDocumentFindings, never here.
    /// </summary>
    public sealed class DocumentItem
    {
        /// <summary>Machine-readable kind, e.g. "vba", "autorun", "external-url",
        /// "ole-embed", "pdf-js", "pdf-launch", "lnk-target", "script-obfuscation",
        /// "archive-exe", "encrypted". Drives the finding severity.</summary>
        public string Kind { get; set; } = "";
        /// <summary>Human-readable one-line detail for the report.</summary>
        public string Detail { get; set; } = "";
    }

    /// <summary>
    /// Result of the DOCUMENT ANALYSIS stage: OOXML/OLE Office, PDF, RTF,
    /// Windows shortcuts (LNK), scripts and archives. Structural facts only
    /// (see DocumentItem); the malware verdict stays with ClamAV/VirusTotal.
    /// Skipped (Status=Skipped) for file kinds this stage does not handle.
    /// Filled by Core.DocumentAnalyzer; rendered by Core.IntegrityReportWriter.
    /// </summary>
    public sealed class DocumentSection
    {
        public StageStatus Status { get; set; } = StageStatus.Ok;
        public string? Error { get; set; }

        /// <summary>Analyzer family that ran: "OOXML", "OLE", "PDF", "RTF",
        /// "LNK", "Script", "Archive". Empty when skipped.</summary>
        public string Format { get; set; } = "";
        /// <summary>Short type description shown at the top of the section.</summary>
        public string Description { get; set; } = "";
        /// <summary>True when the content is encrypted/password-protected, so a
        /// deeper look is impossible: the report must say so instead of implying
        /// the file is clean.</summary>
        public bool Encrypted { get; set; }
        /// <summary>All collected structural facts and indicators.</summary>
        public List<DocumentItem> Items { get; set; } = new();
        /// <summary>IOC strings (URLs, autostart keys, shell commands) extracted
        /// from the raw file when the Strings/IOCs stage runs for a non-PE file.
        /// Grouped/de-duplicated by StringExtractor.ExtractInto.</summary>
        public List<string> Indicators { get; set; } = new();
    }

    public sealed class HashSection
    {
        public StageStatus Status { get; set; } = StageStatus.Ok;
        public string? Error { get; set; }

        /// <summary>Algorithm requested in the UI ("All" or a single name).</summary>
        public string RequestedAlgorithm { get; set; } = "All";
        /// <summary>Computed hashes in canonical order; null value = not computable.</summary>
        public Dictionary<string, string?> Values { get; set; } = new();
        /// <summary>The user-supplied expected hash, empty when none was given.</summary>
        public string Expected { get; set; } = "";
        /// <summary>Algorithm whose hash matched the expected value, null = no match.</summary>
        public string? MatchedAlgorithm { get; set; }
        /// <summary>True/false when an expected value was compared, null otherwise.</summary>
        public bool? Matched { get; set; }
        /// <summary>Whole-file Shannon entropy in bits per byte (0..8), null = not measured.</summary>
        public double? EntropyBitsPerByte { get; set; }
    }

    /// <summary>
    /// File system stage result: owner, DACL entries, alternate data streams and
    /// the parsed Mark-of-the-Web (Zone.Identifier). Collected by
    /// Core.FileSystemInspector.CollectFileSystemInfo. On non-NTFS volumes the
    /// stage is Skipped with an explanatory Error text.
    /// </summary>
    public sealed class FileSystemSection
    {
        public StageStatus Status { get; set; } = StageStatus.Ok;
        public string? Error { get; set; }

        /// <summary>File owner as DOMAIN\name, or the raw SID when unmappable.</summary>
        public string Owner { get; set; } = "";
        public List<AclEntry> AccessRules { get; set; } = new();
        public List<StreamEntry> AlternateStreams { get; set; } = new();

        /// <summary>Zone id from the Zone.Identifier stream, null = no MotW.</summary>
        public int? MotwZoneId { get; set; }
        /// <summary>ReferrerUrl from the Zone.Identifier stream, if present.</summary>
        public string? MotwReferrer { get; set; }
        /// <summary>HostUrl (usually the download URL) from Zone.Identifier, if present.</summary>
        public string? MotwHost { get; set; }
    }

    /// <summary>One DACL entry of the file, translated for display.</summary>
    public sealed class AclEntry
    {
        /// <summary>Account the rule applies to (DOMAIN\name or raw SID).</summary>
        public string Identity { get; set; } = "";
        /// <summary>"Allow" or "Deny".</summary>
        public string Type { get; set; } = "";
        /// <summary>Rights, e.g. "FullControl" or "ReadAndExecute" (Synchronize stripped).</summary>
        public string Rights { get; set; } = "";
        /// <summary>True when the rule is inherited from a parent folder.</summary>
        public bool Inherited { get; set; }
    }

    /// <summary>One alternate data stream (the main ::$DATA stream is excluded).</summary>
    public sealed class StreamEntry
    {
        /// <summary>Display name without the ":...:$DATA" decoration, e.g. "Zone.Identifier".</summary>
        public string Name { get; set; } = "";
        public long SizeBytes { get; set; }
    }

    /// <summary>
    /// PE analysis stage result (EXE/DLL/SYS): headers, security mitigation
    /// flags, CLR info, imports with the pefile/VirusTotal-compatible imphash,
    /// exports, sections with per-section entropy, overlay and checksum.
    /// Non-PE files yield Status=Skipped. Filled by Core.PeAnalyzer.
    /// </summary>
    public sealed class PeAnalysisSection
    {
        public StageStatus Status { get; set; } = StageStatus.Ok;
        public string? Error { get; set; }

        /// <summary>"EXE (GUI)", "EXE (console)", "DLL", "Driver (native)" etc.</summary>
        public string FileType { get; set; } = "";
        /// <summary>"x86", "x64", "ARM64", ... plus PE32/PE32+ distinction.</summary>
        public string Machine { get; set; } = "";
        public bool IsPe32Plus { get; set; }
        public string Subsystem { get; set; } = "";

        /// <summary>Raw COFF TimeDateStamp value (seconds since 1970, or a hash).</summary>
        public uint TimestampRaw { get; set; }
        /// <summary>Decoded UTC link time; null when TimestampRaw is 0.</summary>
        public DateTime? TimestampUtc { get; set; }
        /// <summary>False when the value cannot be a real date (reproducible builds).</summary>
        public bool TimestampPlausible { get; set; } = true;

        /// <summary>Linker version "major.minor" from the optional header.</summary>
        public string LinkerVersion { get; set; } = "";
        /// <summary>Best-effort toolchain guess; ALWAYS labelled heuristic in output.</summary>
        public string CompilerGuess { get; set; } = "";
        public bool RichHeaderPresent { get; set; }
        public int RichHeaderEntries { get; set; }

        public uint EntryPointRva { get; set; }
        /// <summary>Section containing the entry point, null = EP outside all sections.</summary>
        public string? EntryPointSection { get; set; }
        /// <summary>True when the EP section is executable (false is suspicious).</summary>
        public bool EntryPointExecutable { get; set; } = true;

        public uint CheckSumStored { get; set; }
        public uint CheckSumComputed { get; set; }

        // Security mitigation opt-ins from DllCharacteristics.
        public bool Aslr { get; set; }
        public bool HighEntropyVa { get; set; }
        public bool Dep { get; set; }
        public bool ControlFlowGuard { get; set; }
        public bool NoSeh { get; set; }
        public bool AppContainer { get; set; }
        public bool ForceIntegrity { get; set; }

        public bool IsDotNet { get; set; }
        public string? ClrMetadataVersion { get; set; }
        public bool ClrIlOnly { get; set; }
        public bool Clr32BitRequired { get; set; }

        /// <summary>Size of the Authenticode signature data directory (0 = unsigned file
        /// or catalog-signed; actual VERIFICATION comes with the Signature check in batch C).</summary>
        public uint SignatureDataSize { get; set; }
        /// <summary>Bytes after the last section, excluding the signature blob.</summary>
        /// <summary>Total file size; basis for the overlay percentage.</summary>
        public long FileSizeBytes { get; set; }
        public long OverlayBytes { get; set; }
        /// <summary>True when the .NET single-file bundle marker was found with a
        /// plausible header offset: the overlay IS a .NET bundle (deterministic
        /// marker check, not a heuristic). Set by PeAnalyzer.DetectDotNetBundle.</summary>
        public bool DotNetBundle { get; set; }
        /// <summary>File offset of the bundle header when DotNetBundle is true.</summary>
        public long DotNetBundleHeaderOffset { get; set; }
        /// <summary>Shannon entropy of the overlay bytes, null when no overlay.</summary>
        public double? OverlayEntropy { get; set; }

        // ---- batch E additions ------------------------------------------------

        /// <summary>Packer indicators: known packer section names plus the
        /// entropy/import heuristic. Empty = nothing detected. Always heuristic;
        /// packers are trivially renamed.</summary>
        public List<string> PackerSigns { get; set; } = new();

        /// <summary>Section layout anomalies found while parsing (overlapping
        /// raw ranges, non-printable section names). Rendered under the section
        /// table and turned into findings.</summary>
        public List<string> SectionAnomalies { get; set; } = new();

        /// <summary>PDB path from the CodeView (RSDS) debug entry, null when
        /// absent. Build paths often reveal project or user names.</summary>
        public string? PdbPath { get; set; }

        /// <summary>True when a REPRO debug entry marks the file as a
        /// reproducible build (the header timestamp is a hash by design).</summary>
        public bool DebugReproducible { get; set; }

        /// <summary>True when an embedded RT_MANIFEST resource exists.</summary>
        public bool HasManifest { get; set; }
        /// <summary>requestedExecutionLevel from the manifest (asInvoker,
        /// highestAvailable, requireAdministrator), null when not declared.</summary>
        public string? ManifestExecutionLevel { get; set; }
        public bool? ManifestUiAccess { get; set; }
        /// <summary>autoElevate element value; true is unusual outside
        /// Windows-signed binaries.</summary>
        public bool? ManifestAutoElevate { get; set; }
        /// <summary>dpiAware / dpiAwareness manifest value, null when absent.</summary>
        public string? ManifestDpiAware { get; set; }
        /// <summary>longPathAware manifest value (true enables >260 char paths),
        /// null when not declared.</summary>
        public bool? ManifestLongPathAware { get; set; }

        /// <summary>Delay-loaded DLL names (data directory 13).</summary>
        public List<string> DelayImports { get; set; } = new();

        /// <summary>Rich header checksum verdict: true PASS, false FAIL
        /// (tampered or copied header), null when no Rich header exists.</summary>
        public bool? RichChecksumValid { get; set; }
        /// <summary>Raw Rich entries as "0xPPPP.BBBBB xCOUNT" strings (tool id,
        /// build number, use count), capped.</summary>
        public List<string> RichEntrySummaries { get; set; } = new();

        /// <summary>Notable imported APIs grouped by technical function
        /// (e.g. "Memory/threads: WriteProcessMemory, ..."). Purely descriptive:
        /// the actual API names are listed, with NO capability verdict, because
        /// these APIs are common in legitimate software (updaters, installers,
        /// debuggers). Each entry is one ready-to-print group line.</summary>
        public List<string> NotableImports { get; set; } = new();

        /// <summary>Indicators of compromise extracted from the file's strings
        /// (URLs, IPs, registry Run keys, shell/PowerShell command fragments).
        /// Extracted, NOT validated. Grouped and capped by StringExtractor.</summary>
        public List<string> Indicators { get; set; } = new();
        public int TlsCallbackCount { get; set; }

        // Version resource (empty strings when absent).
        public string VersionCompany { get; set; } = "";
        public string VersionProduct { get; set; } = "";
        public string VersionFileVersion { get; set; } = "";
        public string VersionOriginalFilename { get; set; } = "";
        public string VersionDescription { get; set; } = "";

        public List<PeImportDll> Imports { get; set; } = new();
        public int TotalImportedFunctions { get; set; }
        /// <summary>pefile/VirusTotal-compatible import hash (lowercase MD5 hex), null = no imports.</summary>
        public string? Imphash { get; set; }

        /// <summary>Internal DLL name from the export directory, null = no exports.</summary>
        public string? ExportDllName { get; set; }
        /// <summary>Number of NAMED exports.</summary>
        public int ExportCount { get; set; }
        /// <summary>Sample of exported function names (capped). Empty for EXEs
        /// and DLLs that export only by ordinal.</summary>
        public List<string> ExportNames { get; set; } = new();

        public List<PeSectionInfo> Sections { get; set; } = new();
    }

    /// <summary>One imported DLL with its function count (names are not listed
    /// in the console to keep the report readable; the imphash covers them).</summary>
    public sealed class PeImportDll
    {
        public string Name { get; set; } = "";
        public int FunctionCount { get; set; }
    }

    /// <summary>One PE section with size, flags and Shannon entropy of its raw data.</summary>
    public sealed class PeSectionInfo
    {
        public string Name { get; set; } = "";
        public uint VirtualAddress { get; set; }
        public uint VirtualSize { get; set; }
        public uint RawSize { get; set; }
        /// <summary>Entropy of the raw data in bits/byte, null when RawSize is 0.</summary>
        public double? Entropy { get; set; }
        public bool Readable { get; set; }
        public bool Writable { get; set; }
        public bool Executable { get; set; }
        public bool ContainsCode { get; set; }
    }

    /// <summary>
    /// Result of the Authenticode check (batch C). Windows verifies both
    /// signature styles: a signature embedded in the file itself and a
    /// signature via a security catalog (how most Windows system files are
    /// signed). Verification is offline (cached revocation data only).
    /// Filled by: AuthenticodeInspector.Inspect.
    /// </summary>
    public sealed class SignatureSection
    {
        public StageStatus Status { get; set; } = StageStatus.Ok;
        public string? Error { get; set; }

        /// <summary>"embedded", "catalog" or "none".</summary>
        public string Location { get; set; } = "none";
        /// <summary>True = WinVerifyTrust accepts the signature. Null = unsigned.</summary>
        public bool? Trusted { get; set; }
        /// <summary>Raw WinVerifyTrust HRESULT (0 = trusted).</summary>
        public int TrustHResult { get; set; }
        /// <summary>Human wording for TrustHResult ("valid", "untrusted root", ...).</summary>
        public string TrustText { get; set; } = "";

        // Signer leaf certificate (empty when unsigned or unreadable).
        public string SignerSubject { get; set; } = "";
        public string SignerIssuer { get; set; } = "";
        public string SignerThumbprint { get; set; } = "";
        public DateTime? SignerNotBefore { get; set; }
        public DateTime? SignerNotAfter { get; set; }

        /// <summary>Signing time from the signature's timestamp (RFC 3161 token
        /// or legacy countersignature), UTC. Null = no timestamp or unreadable.
        /// Embedded signatures only. Set by AuthenticodeInspector.</summary>
        public DateTime? SignedAt { get; set; }
        /// <summary>"RFC 3161" or "countersignature" when SignedAt is set.</summary>
        public string? TimestampSource { get; set; }

        /// <summary>Full path of the catalog file for catalog signatures.</summary>
        public string? CatalogFile { get; set; }
    }

    /// <summary>
    /// Result of the report-only ClamAV scan of the single file (batch C).
    /// Findings additionally land in the Detections list (MainWindow does that,
    /// DetectionManager touches UI collections). Filled by: IntegrityScanner.
    /// </summary>
    public sealed class ClamAvSection
    {
        public StageStatus Status { get; set; } = StageStatus.Ok;
        public string? Error { get; set; }

        /// <summary>clamscan/clamdscan exit code: 0 clean, 1 found, 2+ error.</summary>
        public int ExitCode { get; set; }
        public bool UsedDaemon { get; set; }
        /// <summary>Threat names parsed from the FOUND lines.</summary>
        public List<string> Threats { get; set; } = new();
        /// <summary>Raw FOUND lines, handed to DetectionManager.AddFindings.</summary>
        public List<string> RawFoundLines { get; set; } = new();
    }

    /// <summary>
    /// Result of the VirusTotal SHA256 lookup (batch C). Only the hash is sent,
    /// never the file. Filled by: IntegrityScanner from VirusTotalClient.
    /// </summary>
    public sealed class VirusTotalSection
    {
        public StageStatus Status { get; set; } = StageStatus.Ok;
        public string? Error { get; set; }

        public string Sha256 { get; set; } = "";
        /// <summary>True = VirusTotal has never seen this hash.</summary>
        public bool NotFound { get; set; }
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Harmless { get; set; }
        public int Undetected { get; set; }
    }
}
