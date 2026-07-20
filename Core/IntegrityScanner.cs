using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Orchestrates one File-Verifier run: executes the selected stages in order
/// (FILE metadata always; HASHES, FILE SYSTEM, PE ANALYSIS, SIGNATURE, CLAMAV
/// and VIRUSTOTAL per options), collects findings and streams every finished
/// section as rendered text lines to the caller via onSection. Stages are
/// independent: a failed stage becomes an error section and the run continues.
/// Everything is report-only; ClamAV finds are ADDITIONALLY recorded in the
/// Detections list by MainWindow (UI thread), not here. onSection/onStatus may
/// be invoked from worker threads; the callbacks must marshal before touching
/// UI (MainWindow.AppendLine already does).
/// Called from: MainWindow.FileVerifier.cs (RunFileVerifierAsync).
/// </summary>
public static class IntegrityScanner
{
    /// <summary>
    /// Which stages to run and the hash parameters. The Include* flags mirror
    /// the File-Verifier checkboxes; HashAlgorithm is "All" or one name from
    /// HashTool.Algorithms; ExpectedHash is the optional comparison value.
    /// IncludeVirusTotal sends the SHA256 (never the file) to virustotal.com
    /// and therefore defaults to off everywhere. IncludeStrings runs a second
    /// full read to extract indicator strings (URLs/IPs/registry/commands) and
    /// is off by default because of the extra read on large files.
    /// </summary>
    public record IntegrityOptions(
        bool IncludeHashes,
        bool IncludeFileSystem,
        bool IncludePe,
        string HashAlgorithm,
        string ExpectedHash,
        bool IncludeSignature = false,
        bool IncludeClamAv = false,
        bool IncludeVirusTotal = false,
        bool IncludeStrings = false,
        bool IncludeDocument = false);

    /// <summary>
    /// Runs the verification and returns the filled report. hashProgress
    /// reports 0..1 while hashing (the only long-running stage in batch A);
    /// cancellation aborts with OperationCanceledException (partial sections
    /// already streamed stay in the console). Called from: RunFileVerifierAsync.
    /// </summary>
    public static async Task<IntegrityReport> RunAsync(string path, IntegrityOptions options,
        IProgress<double>? hashProgress, Action<string, IReadOnlyList<string>> onSection,
        Action<string>? onStatus = null, Action<string>? onStage = null,
        CancellationToken cancel = default)
    {
        var report = new IntegrityReport { FilePath = path, StartedAt = DateTime.Now };

        // Stage 1: FILE metadata (always on; cheap and the anchor of the report).
        report.Metadata = await Task.Run(() => FileSystemInspector.CollectMetadata(path), cancel);
        onSection($"FILE VERIFIER  {path}", IntegrityReportWriter.RenderMetadata(report));
        cancel.ThrowIfCancellationRequested();

        // Stage 1b: FILE TYPE (always on like the metadata; reads at most 4 KB).
        // Magic-byte type, extension consistency and filename anomaly checks.
        report.FileType = await Task.Run(() => FileTypeDetector.Detect(path), cancel);
        onSection("FILE TYPE", IntegrityReportWriter.RenderFileType(report));
        cancel.ThrowIfCancellationRequested();

        // Stage 2: HASHES (+ whole-file entropy from the same read pass).
        if (options.IncludeHashes)
        {
            onStage?.Invoke("hashes");
            var h = new IntegrityReport.HashSection
            {
                RequestedAlgorithm = options.HashAlgorithm,
                Expected = options.ExpectedHash?.Trim() ?? ""
            };
            report.Hashes = h;

            var computed = await HashTool.ComputeSelectedAsync(
                path, options.HashAlgorithm, withEntropy: true, hashProgress, cancel);
            h.Values = computed.Hashes;
            h.EntropyBitsPerByte = computed.EntropyBitsPerByte;

            if (h.Values.Count > 0 && h.Values.All(kv => kv.Value == null)
                && h.Values.Keys.Any(HashTool.IsSupported))
            {
                // Every supported algorithm failed: the file was not readable.
                h.Status = StageStatus.Failed;
                h.Error = "file locked or unreadable";
            }
            else if (!string.IsNullOrWhiteSpace(h.Expected))
            {
                var match = h.Values.FirstOrDefault(kv =>
                    kv.Value != null && HashTool.Matches(kv.Value, h.Expected));
                h.MatchedAlgorithm = match.Key;
                h.Matched = match.Key != null;
            }

            onSection("HASHES", IntegrityReportWriter.RenderHashes(report));
            cancel.ThrowIfCancellationRequested();
        }

        // Stage 3: FILE SYSTEM (owner, DACL, ADS, Mark of the Web).
        if (options.IncludeFileSystem)
        {
            onStage?.Invoke("filesystem");
            report.FileSystem = await Task.Run(
                () => FileSystemInspector.CollectFileSystemInfo(path), cancel);
            onSection("FILE SYSTEM", IntegrityReportWriter.RenderFileSystem(report));
            cancel.ThrowIfCancellationRequested();
        }

        // Stage 4: PE ANALYSIS (EXE/DLL/SYS only; non-PE files self-skip).
        if (options.IncludePe)
        {
            onStage?.Invoke("pe");
            report.Pe = await Task.Run(() => PeAnalyzer.Analyze(path, hashProgress, cancel), cancel);
            onSection("PE ANALYSIS", IntegrityReportWriter.RenderPe(report));
            cancel.ThrowIfCancellationRequested();

            // Capabilities are cheap (already parsed from the imports) and print
            // with the PE section; extracting indicator strings is a second full
            // read, so it only runs when the user opts in via IncludeStrings.
            if (options.IncludeStrings && report.Pe?.Status == StageStatus.Ok)
            {
                onStage?.Invoke("strings");
                await Task.Run(() => StringExtractor.Extract(report, cancel), cancel);
            }
            if (report.Pe?.Status == StageStatus.Ok
                && (report.Pe.NotableImports.Count > 0 || report.Pe.Indicators.Count > 0))
                onSection("NOTABLE IMPORTS & INDICATORS", IntegrityReportWriter.RenderCapabilities(report));
            cancel.ThrowIfCancellationRequested();
        }

        // Stage 4b: DOCUMENT ANALYSIS (Office/PDF/RTF/LNK/script/archive). Runs
        // for the file kinds PE analysis skips; self-skips for anything else.
        if (options.IncludeDocument)
        {
            onStage?.Invoke("document");
            report.Document = await Task.Run(
                () => DocumentAnalyzer.Analyze(path, report.FileType, cancel), cancel);
            if (report.Document.Status != StageStatus.Skipped)
                onSection("DOCUMENT ANALYSIS", IntegrityReportWriter.RenderDocument(report));

            // IOC extraction is no longer PE-only: a document that parsed also
            // gets its indicator strings pulled (URLs, autostart keys, commands).
            if (options.IncludeStrings && report.Document.Status == StageStatus.Ok
                && report.Pe?.Status != StageStatus.Ok)
            {
                onStage?.Invoke("strings");
                await Task.Run(() => StringExtractor.ExtractInto(
                    path, report.Document.Indicators, cancel), cancel);
                if (report.Document.Indicators.Count > 0)
                    onSection("INDICATORS", IntegrityReportWriter.RenderDocumentIndicators(report));
            }
            cancel.ThrowIfCancellationRequested();
        }

        // Stage 5: SIGNATURE (Authenticode, embedded and catalog, offline).
        if (options.IncludeSignature)
        {
            onStage?.Invoke("signature");
            report.Signature = await Task.Run(() => AuthenticodeInspector.Inspect(path), cancel);
            onSection("SIGNATURE", IntegrityReportWriter.RenderSignature(report));
            cancel.ThrowIfCancellationRequested();
        }

        // Stage 6: CLAMAV (report-only single-file scan; skipped when another
        // scan is running so the two never contend for the engine).
        if (options.IncludeClamAv)
        {
            onStage?.Invoke("clamav");
            report.ClamAv = await RunClamAvStageAsync(path, onStatus, cancel);
            onSection("CLAMAV", IntegrityReportWriter.RenderClamAv(report));
            cancel.ThrowIfCancellationRequested();
        }

        // Stage 7: VIRUSTOTAL (hash-only lookup; requires an API key).
        if (options.IncludeVirusTotal)
        {
            onStage?.Invoke("virustotal");
            report.VirusTotal = await RunVirusTotalStageAsync(path, report, onStatus, cancel);
            onSection("VIRUSTOTAL", IntegrityReportWriter.RenderVirusTotal(report));
            cancel.ThrowIfCancellationRequested();
        }

        // Findings from everything that ran, then the closing section.
        EvaluateFindings(report);
        onSection("FINDINGS", IntegrityReportWriter.RenderFindings(report));
        onSection("SUMMARY", IntegrityReportWriter.RenderSummary(report));

        return report;
    }

    /// <summary>
    /// Report-only ClamAV scan of the single file. Skips (never errors) when a
    /// scan is already in progress; engine or database problems become a Failed
    /// stage with the engine's message. Called from: RunAsync.
    /// </summary>
    private static async Task<IntegrityReport.ClamAvSection> RunClamAvStageAsync(
        string path, Action<string>? onStatus, CancellationToken cancel)
    {
        var sec = new IntegrityReport.ClamAvSection();
        if (ScanEngine.ScanInProgress)
        {
            sec.Status = StageStatus.Skipped;
            sec.Error = "another scan is running";
            return sec;
        }

        var result = await ScanEngine.RunScanAsync(
            new ScanEngine.ScanOptions(
                ScanEngine.ScanMode.Path, path,
                InfectedFileAction.ReportOnly,
                MultiScan: false,
                IncludeExtensions: null,
                StopInfectedProcesses: false),
            line => onStatus?.Invoke(line),
            cancel);

        if (!result.Started || result.ExitCode >= 2)
        {
            sec.Status = StageStatus.Failed;
            sec.Error = result.Error
                ?? (result.ErrorLines.Count > 0 ? result.ErrorLines[0] : $"exit code {result.ExitCode}");
            return sec;
        }

        sec.ExitCode = result.ExitCode;
        sec.UsedDaemon = result.UsedDaemon;
        foreach (var line in result.InfectedLines)
        {
            sec.RawFoundLines.Add(line);
            if (ScanEngine.TryParseFoundLine(line, out _, out var threat))
                sec.Threats.Add(threat);
        }
        return sec;
    }

    /// <summary>
    /// VirusTotal SHA256 lookup. Reuses the hash from the HASHES stage when it
    /// ran, otherwise computes SHA256 now; only the hash leaves the machine.
    /// Skips without an API key. Called from: RunAsync.
    /// </summary>
    private static async Task<IntegrityReport.VirusTotalSection> RunVirusTotalStageAsync(
        string path, IntegrityReport report, Action<string>? onStatus, CancellationToken cancel)
    {
        var sec = new IntegrityReport.VirusTotalSection();

        SettingsManager.Load();
        var apiKey = SettingsManager.Current.VirusTotalApiKey;
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            sec.Status = StageStatus.Skipped;
            sec.Error = "no API key configured (add it in Settings; free at virustotal.com)";
            return sec;
        }

        string? sha256 = report.Hashes?.Values.GetValueOrDefault("SHA256");
        if (sha256 == null)
        {
            onStatus?.Invoke("Computing SHA256 for the VirusTotal lookup...");
            sha256 = await HashTool.ComputeAsync(path, "SHA256", null, cancel);
        }
        if (sha256 == null)
        {
            sec.Status = StageStatus.Failed;
            sec.Error = "SHA256 computation failed (file locked or unreadable)";
            return sec;
        }
        sec.Sha256 = sha256;

        var result = await VirusTotalClient.LookupAsync(sha256, apiKey,
            s => onStatus?.Invoke(s), cancel);
        if (!result.Success)
        {
            sec.Status = StageStatus.Failed;
            sec.Error = result.Error ?? "lookup failed";
            return sec;
        }
        sec.NotFound = result.NotFound;
        sec.Malicious = result.Malicious;
        sec.Suspicious = result.Suspicious;
        sec.Harmless = result.Harmless;
        sec.Undetected = result.Undetected;
        return sec;
    }

    /// <summary>
    /// Derives the batch-A findings from the collected sections: hash mismatch,
    /// Mark of the Web, unexpected alternate streams and reparse points. Later
    /// batches add PE/signature/scan rules here. Wording stays neutral: these
    /// are indicators for the user to interpret, not verdicts.
    /// Called from: RunAsync.
    /// </summary>
    private static void EvaluateFindings(IntegrityReport report)
    {
        void Add(FindingSeverity severity, string text)
            => report.Findings.Add(new IntegrityFinding { Severity = severity, Text = text });

        if (report.Hashes is { Matched: false })
            Add(FindingSeverity.High,
                "The expected hash does not match: the file is not the one the hash belongs to, or it was modified.");

        var fs = report.FileSystem;
        if (fs != null && fs.Status != StageStatus.Skipped)
        {
            if (fs.MotwZoneId is 3 or 4)
                Add(FindingSeverity.Info,
                    $"Mark of the Web present ({FileSystemInspector.ZoneName(fs.MotwZoneId.Value)}): " +
                    "the file was downloaded" +
                    (string.IsNullOrEmpty(fs.MotwHost) ? "." : $" from {fs.MotwHost}."));

            var extraStreams = fs.AlternateStreams
                .Where(s => !IsBenignStream(s.Name))
                .ToList();
            if (extraStreams.Count > 0)
                Add(FindingSeverity.Low,
                    $"{extraStreams.Count} alternate data stream(s) beyond the usual Windows streams: " +
                    string.Join(", ", extraStreams.Select(s => s.Name)) +
                    ". ADS can carry hidden data; review whether they are expected.");
        }

        if (report.Metadata is { IsReparsePoint: true })
            Add(FindingSeverity.Low,
                "The path is a reparse point (symlink/junction): checks describe the link target, " +
                "and the target can be changed without touching this path.");

        EvaluateFileTypeFindings(report, Add);
        EvaluateDocumentFindings(report, Add);
        EvaluatePeFindings(report, Add);
        EvaluateSignatureFindings(report, Add);
        EvaluateScanFindings(report, Add);
    }

    /// <summary>
    /// DOCUMENT findings for every shipped inspector (OOXML, LNK, PDF).
    /// Active content that can execute code carries the
    /// weight: VBA/XLM macros, DDE and remote-template injection are Medium
    /// (real code-execution vectors, but legitimate documents use macros too, so
    /// not High on their own); a combined attachedTemplate + external URL is
    /// High (the classic loader pattern); embedded OLE/ActiveX and external
    /// references are Low; zip-bomb/anomaly signs are Medium. An encrypted
    /// document is Info (cannot be inspected, explicitly not a clean verdict).
    /// A purely clean structure produces no finding.
    /// LNK: a LOLBin target or download-style arguments are Medium, hidden
    /// window/elevation/long args are Low, an oversized shortcut or icon
    /// disguise Medium. PDF: /Launch is High, JavaScript/auto-actions/embedded
    /// files/name obfuscation Medium, the rest Low/Info. Two COMBINATIONS
    /// escalate to High because they are the classic attack shapes: JavaScript
    /// plus an automatic open action, and a LOLBin shortcut with download
    /// arguments. Called from: EvaluateFindings.
    /// </summary>
    private static void EvaluateDocumentFindings(IntegrityReport report,
        Action<FindingSeverity, string> add)
    {
        var d = report.Document;
        if (d == null || d.Status != StageStatus.Ok) return;

        bool hasTemplateRef = d.Items.Any(i => i.Kind == "template-ref");
        bool hasExternalUrl = d.Items.Any(i => i.Kind == "external-url");

        foreach (var item in d.Items)
        {
            switch (item.Kind)
            {
                case "vba":
                    add(FindingSeverity.Medium, "Document contains a VBA macro project: it can run code when macros are enabled.");
                    break;
                case "xlm":
                    add(FindingSeverity.Medium, "Document contains an Excel 4.0 (XLM) macro sheet: a code-execution vector often used to evade scanners.");
                    break;
                case "dde":
                    add(FindingSeverity.Medium, "Document uses a DDE/DDEAUTO field: can launch programs without a macro.");
                    break;
                case "template-ref":
                    // Escalated below when paired with an external URL.
                    if (!hasExternalUrl)
                        add(FindingSeverity.Medium, "Document attaches an external template (attachedTemplate): a remote-template-injection loader when the target is remote.");
                    break;
                case "ole-embed":
                    add(FindingSeverity.Low, $"Document has embedded OLE object(s): {item.Detail}");
                    break;
                case "activex":
                    add(FindingSeverity.Low, $"Document embeds ActiveX control(s): {item.Detail}");
                    break;
                case "external-url":
                    add(FindingSeverity.Low, $"Document references an external URL: {item.Detail}");
                    break;
                case "archive-bomb":
                    add(FindingSeverity.Medium, $"Possible archive/zip bomb: {item.Detail}");
                    break;
                case "archive-anomaly":
                    add(FindingSeverity.Low, item.Detail);
                    break;
                case "encrypted":
                    add(FindingSeverity.Info, "The document is encrypted: its content cannot be inspected, so a lack of findings here is not an all-clear.");
                    break;

                // ---- LNK shortcuts ------------------------------------------
                case "lnk-lolbin":
                    add(FindingSeverity.Medium, item.Detail);
                    break;
                case "lnk-args-suspicious":
                    add(FindingSeverity.Medium, "Shortcut arguments contain download/execution patterns: " + item.Detail);
                    break;
                case "lnk-args-long":
                    add(FindingSeverity.Low, "Shortcut: " + item.Detail);
                    break;
                case "lnk-hidden":
                    add(FindingSeverity.Low, "Shortcut: " + item.Detail);
                    break;
                case "lnk-runas":
                    add(FindingSeverity.Low, "Shortcut: " + item.Detail);
                    break;
                case "lnk-icon-disguise":
                    add(FindingSeverity.Medium, "Shortcut: " + item.Detail);
                    break;
                case "lnk-oversize":
                    add(FindingSeverity.Medium, "Shortcut: " + item.Detail);
                    break;
                case "lnk-malformed":
                    add(FindingSeverity.Low, "Shortcut: " + item.Detail);
                    break;

                // ---- PDF ----------------------------------------------------
                case "pdf-launch":
                    add(FindingSeverity.High, "PDF: a /Launch action can start an external program. Legitimate documents almost never need this.");
                    break;
                case "pdf-js":
                    add(FindingSeverity.Medium, "PDF: " + item.Detail);
                    break;
                case "pdf-openaction":
                    add(FindingSeverity.Medium, "PDF: an action runs automatically when the file is opened.");
                    break;
                case "pdf-autoaction":
                    // /AA alone is common in ordinary PDFs (form fields, page
                    // transitions). It is only a real concern together with
                    // JavaScript or a launch/embedded payload, so grade it by
                    // that context instead of always Medium.
                    if (d.Items.Any(i => i.Kind is "pdf-js" or "pdf-launch" or "pdf-embed"))
                        add(FindingSeverity.Medium, "PDF: automatic actions (/AA) fire on events such as opening a page, together with active content below.");
                    else
                        add(FindingSeverity.Low, "PDF: automatic actions (/AA) are defined (fire on events like page open). Common in forms, but worth noting.");
                    break;
                case "pdf-embed":
                    add(FindingSeverity.Medium, "PDF: " + item.Detail);
                    break;
                case "pdf-name-obfuscation":
                    add(FindingSeverity.Medium, "PDF: " + item.Detail);
                    break;
                case "pdf-name-escapes":
                    add(FindingSeverity.Info, "PDF: " + item.Detail);
                    break;
                case "pdf-xfa":
                    add(FindingSeverity.Low, "PDF: " + item.Detail);
                    break;
                case "pdf-richmedia":
                    add(FindingSeverity.Low, "PDF: " + item.Detail);
                    break;
                case "pdf-submitform":
                    add(FindingSeverity.Low, "PDF: " + item.Detail);
                    break;
                case "pdf-remotegoto":
                    add(FindingSeverity.Low, "PDF: " + item.Detail);
                    break;
                case "pdf-incremental":
                    add(FindingSeverity.Low, "PDF: " + item.Detail);
                    break;
                case "pdf-encrypted":
                    add(FindingSeverity.Info, "PDF: the document is encrypted, so its objects cannot be inspected fully.");
                    break;
                case "pdf-truncated-scan":
                    add(FindingSeverity.Info, "PDF: " + item.Detail + " The structural analysis is therefore incomplete.");
                    break;

                // ---- Scripts -------------------------------------------------
                case "script-injection":
                    add(FindingSeverity.High, "Script: " + item.Detail + ". Scripts calling injection APIs directly are rare outside offensive tooling.");
                    break;
                case "script-destructive":
                    add(FindingSeverity.High, "Script: " + item.Detail + ".");
                    break;
                case "script-vbe":
                    add(FindingSeverity.High, "Script: " + item.Detail + ".");
                    break;
                case "script-encoded":
                case "script-download":
                case "script-execute":
                case "script-inmemory":
                case "script-persistence":
                case "script-defense":
                    add(FindingSeverity.Medium, "Script: " + item.Detail + ".");
                    break;
                case "script-charcode":
                case "script-stringbuild":
                case "script-hidden":
                case "script-bypass":
                case "script-longline":
                case "script-base64blob":
                case "script-entropy":
                case "script-escapes":
                case "script-batchsubstr":
                    add(FindingSeverity.Low, "Script: " + item.Detail);
                    break;
                case "script-truncated-scan":
                    add(FindingSeverity.Info, "Script: " + item.Detail);
                    break;

                // ---- Archives ------------------------------------------------
                case "archive-traversal":
                    add(FindingSeverity.High, "Archive: " + item.Detail + " (a naive extractor would write outside the target folder).");
                    break;
                case "archive-hiddenchar":
                    add(FindingSeverity.High, "Archive: " + item.Detail);
                    break;
                case "archive-doubleext":
                    add(FindingSeverity.Medium, "Archive: " + item.Detail);
                    break;
                case "archive-encrypted":
                    add(FindingSeverity.Medium, "Archive: " + item.Detail);
                    break;
                case "archive-single-exe":
                    add(FindingSeverity.Medium, "Archive: " + item.Detail);
                    break;
                case "archive-executable":
                    add(FindingSeverity.Low, "Archive: " + item.Detail);
                    break;
                case "archive-nested":
                    add(FindingSeverity.Low, "Archive: " + item.Detail);
                    break;
                case "archive-not-enumerated":
                    add(FindingSeverity.Info, "Archive: " + item.Detail);
                    break;

                // ---- Legacy OLE Office ---------------------------------------
                case "ole-equation":
                    add(FindingSeverity.High, "Document: " + item.Detail);
                    break;
                case "ole-native":
                    add(FindingSeverity.High, "Document: " + item.Detail);
                    break;
                case "xls-hidden-sheet":
                    add(FindingSeverity.Low, "Document: " + item.Detail);
                    break;

                // ---- RTF -----------------------------------------------------
                case "rtf-payload-pe":
                    add(FindingSeverity.High, "RTF: " + item.Detail + " An executable inside a document payload has no legitimate purpose.");
                    break;
                case "rtf-equation":
                    add(FindingSeverity.High, "RTF: " + item.Detail);
                    break;
                case "rtf-ole2link":
                    add(FindingSeverity.High, "RTF: " + item.Detail);
                    break;
                case "rtf-objupdate":
                    add(FindingSeverity.Medium, "RTF: " + item.Detail);
                    break;
                case "rtf-objlink":
                    add(FindingSeverity.Medium, "RTF: " + item.Detail);
                    break;
                case "rtf-payload":
                    add(FindingSeverity.Medium, "RTF: " + item.Detail);
                    break;
                case "rtf-bin":
                    add(FindingSeverity.Medium, "RTF: " + item.Detail);
                    break;
                case "rtf-obfuscation":
                    add(FindingSeverity.Medium, "RTF: " + item.Detail);
                    break;
                case "rtf-object":
                    add(FindingSeverity.Low, "RTF: " + item.Detail);
                    break;
                case "rtf-malformed-header":
                    add(FindingSeverity.Low, "RTF: " + item.Detail);
                    break;
                case "rtf-truncated-scan":
                    add(FindingSeverity.Info, "RTF: " + item.Detail);
                    break;
            }
        }

        // An RTF whose object loads on open AND carries a real payload is the
        // finished exploit shape, not just a document with an attachment.
        bool rtfAuto = d.Items.Any(i => i.Kind == "rtf-objupdate");
        bool rtfPayload = d.Items.Any(i => i.Kind is "rtf-payload" or "rtf-payload-pe"
            or "rtf-equation" or "rtf-ole2link");
        if (rtfAuto && rtfPayload)
            add(FindingSeverity.High,
                "RTF: an embedded object loads automatically on open AND a payload/exploit-related class was identified. This is the shape of a weaponized RTF.");

        // Download plus execution in one script is the dropper pattern; either
        // alone is ordinary administration.
        bool sDownload = d.Items.Any(i => i.Kind == "script-download");
        // "Executes" means running constructed content (IEX/eval/Start-Process)
        // or injection. Add-Type/Assembly.Load (script-inmemory) is NOT counted
        // here: countless legitimate admin scripts use it just to declare a
        // P/Invoke helper, so pairing it with a download does not make a dropper.
        bool sExecute = d.Items.Any(i => i.Kind is "script-execute" or "script-injection");
        bool sInMemory = d.Items.Any(i => i.Kind == "script-inmemory");
        // Entropy is deliberately NOT part of this set (see ScriptInspector):
        // it is a weak signal, and its one reliable case is already covered by
        // script-base64blob.
        bool sObfuscated = d.Items.Any(i => i.Kind is "script-encoded" or "script-charcode"
            or "script-base64blob" or "script-escapes" or "script-batchsubstr");
        if (sDownload && sExecute)
            add(FindingSeverity.High,
                "Script: it both downloads remote content AND executes code. That combination is the standard downloader/dropper pattern.");
        else if (sObfuscated && sExecute)
            add(FindingSeverity.High,
                "Script: it hides its content (encoding/obfuscation) AND executes code. Legitimate scripts rarely need to conceal what they run.");
        else if (sDownload && sInMemory)
            add(FindingSeverity.Medium,
                "Script: it downloads remote content and also loads .NET code in memory. Common in legitimate admin scripts, but the same building blocks a downloader uses.");

        // A PDF that both auto-runs something and carries JavaScript is the
        // classic exploit-delivery shape; call that pairing out explicitly.
        bool pdfAuto = d.Items.Any(i => i.Kind is "pdf-openaction" or "pdf-autoaction");
        bool pdfJs = d.Items.Any(i => i.Kind == "pdf-js");
        if (pdfAuto && pdfJs)
            add(FindingSeverity.High,
                "PDF: JavaScript combined with an automatic open action. This pairing is how exploit PDFs execute code without user interaction.");

        // A shortcut that runs an interpreter with download/execute arguments is
        // effectively a dropper, regardless of how harmless the icon looks.
        bool lnkLol = d.Items.Any(i => i.Kind == "lnk-lolbin");
        bool lnkBadArgs = d.Items.Any(i => i.Kind == "lnk-args-suspicious");
        if (lnkLol && lnkBadArgs)
            add(FindingSeverity.High,
                "Shortcut: it launches a system interpreter AND its arguments contain download/execution patterns. This is the standard shape of a malicious shortcut.");

        if (hasTemplateRef && hasExternalUrl)
            add(FindingSeverity.High,
                "Remote template injection pattern: the document attaches an external template AND references a remote URL. This is a common first-stage malware loader.");
    }

    /// <summary>
    /// FILE TYPE findings. Severity follows the danger direction, not the mere
    /// mismatch: EXECUTABLE content behind a trusted-looking document extension
    /// is Medium (disguise), a plain unusual extension on an executable is Low
    /// (renaming is common and the enum's own example for Low), any other
    /// mismatch is Info. Filename: a hidden bidi/format character is High (no
    /// legitimate use in filenames, classic extension-reversal trick), a double
    /// extension Medium, space padding Low. Called from: EvaluateFindings.
    /// </summary>
    private static void EvaluateFileTypeFindings(IntegrityReport report,
        Action<FindingSeverity, string> add)
    {
        var ft = report.FileType;
        if (ft == null || ft.Status != StageStatus.Ok) return;

        if (ft.ExtensionMatches == false)
        {
            bool trustedLook = ft.ActualExtension.Length > 0 && new[]
            {
                "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf",
                "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "csv", "htm", "html"
            }.Contains(ft.ActualExtension);

            if (ft.IsExecutableContent && trustedLook)
                add(FindingSeverity.Medium,
                    $"The file is {ft.DetectedType} but named .{ft.ActualExtension}: executable content behind a document/media extension is a common disguise.");
            else if (ft.IsExecutableContent)
                add(FindingSeverity.Low,
                    $"The file is {ft.DetectedType} with the unusual extension .{(ft.ActualExtension.Length > 0 ? ft.ActualExtension : "(none)")}: often just a renamed or staged file.");
            else
                add(FindingSeverity.Info,
                    $"The extension .{(ft.ActualExtension.Length > 0 ? ft.ActualExtension : "(none)")} does not match the detected type ({ft.DetectedType}).");
        }

        foreach (var anomaly in ft.NameAnomalies)
        {
            if (anomaly.StartsWith("hidden Unicode"))
                add(FindingSeverity.High, $"File name: {anomaly}.");
            else if (anomaly.StartsWith("double extension"))
                add(FindingSeverity.Medium, $"File name: {anomaly}: a classic way to make an executable look like a document.");
            else
                add(FindingSeverity.Low, $"File name: {anomaly}.");
        }
    }

    /// <summary>
    /// Signature findings: a broken digest (file modified AFTER signing) is
    /// Critical, every other non-verifying signature Medium, an unsigned file
    /// that came from the Internet Low. A valid signature produces no finding;
    /// the SIGNATURE and SUMMARY sections already show it. Called from:
    /// EvaluateFindings.
    /// </summary>
    private static void EvaluateSignatureFindings(IntegrityReport report,
        Action<FindingSeverity, string> add)
    {
        var sig = report.Signature;
        if (sig == null || sig.Status != StageStatus.Ok) return;

        if (sig.Trusted == false)
        {
            // A broken digest means the bytes changed AFTER signing: hard
            // evidence of tampering. Other reasons (untrusted root, expired)
            // are common with self-signed or internal certificates.
            bool badDigest = sig.TrustHResult == unchecked((int)0x80096010);
            add(badDigest ? FindingSeverity.Critical : FindingSeverity.Medium,
                $"The {sig.Location} Authenticode signature does NOT verify: {sig.TrustText}.");
        }
        else if (sig.Trusted == null && report.FileSystem?.MotwZoneId is 3 or 4
                 && LooksExecutable(report.FilePath))
            add(FindingSeverity.Low,
                "The file is not signed and carries the Mark of the Web: an unsigned executable from the Internet deserves extra scrutiny.");
    }

    /// <summary>
    /// ClamAV and VirusTotal findings. A ClamAV detection is Critical (and
    /// MainWindow additionally records it in Detections); VirusTotal verdicts
    /// scale with the engine count (3+ malicious = High, 1-2 = Medium since
    /// single engines often false-positive, suspicious-only = Low, unknown
    /// hash = Info). Called from: EvaluateFindings.
    /// </summary>
    private static void EvaluateScanFindings(IntegrityReport report,
        Action<FindingSeverity, string> add)
    {
        var av = report.ClamAv;
        if (av is { Status: StageStatus.Ok } && av.Threats.Count > 0)
            add(FindingSeverity.Critical,
                $"ClamAV detects: {string.Join(", ", av.Threats.Distinct())}. The finding was added to the Detections list.");

        var vt = report.VirusTotal;
        if (vt is { Status: StageStatus.Ok, NotFound: false })
        {
            int total = vt.Malicious + vt.Suspicious + vt.Harmless + vt.Undetected;
            if (vt.Malicious > 0)
                // 1-2 engines are frequently false positives; 3+ rarely are.
                add(vt.Malicious >= 3 ? FindingSeverity.High : FindingSeverity.Medium,
                    $"VirusTotal: {vt.Malicious}/{total} engines flag this file as malicious.");
            else if (vt.Suspicious > 0)
                add(FindingSeverity.Low,
                    $"VirusTotal: {vt.Suspicious}/{total} engines flag this file as suspicious (none as malicious).");
        }
        else if (vt is { Status: StageStatus.Ok, NotFound: true })
            add(FindingSeverity.Info,
                "The hash is unknown to VirusTotal: nobody submitted this file yet. Unknown does not mean safe.");
    }

    /// <summary>True for extensions Windows executes directly; used to scope the
    /// unsigned-download notice to files where a signature is expected.
    /// Called from: EvaluateSignatureFindings.</summary>
    private static bool LooksExecutable(string path)
    {
        string ext = System.IO.Path.GetExtension(path).ToLowerInvariant();
        return ext is ".exe" or ".dll" or ".sys" or ".msi" or ".scr" or ".com"
            or ".ocx" or ".cpl" or ".efi";
    }

    /// <summary>
    /// PE-specific findings (batch B): entropy of executable sections, writable
    /// AND executable sections, entry point placement, checksum mismatch,
    /// missing modern mitigations, TLS callbacks, overlay and a renamed binary.
    /// Neutral wording; these are indicators, not verdicts. Called from:
    /// EvaluateFindings.
    /// </summary>
    private static void EvaluatePeFindings(IntegrityReport report,
        Action<FindingSeverity, string> add)
    {
        var pe = report.Pe;
        if (pe == null || pe.Status == StageStatus.Skipped) return;
        if (pe.Status == StageStatus.Failed)
        {
            add(FindingSeverity.Low,
                "The PE headers could not be fully parsed: the file may be corrupted, truncated or deliberately malformed.");
            return;
        }

        foreach (var s in pe.Sections)
        {
            if (s.Writable && s.Executable)
                add(FindingSeverity.High,
                    $"Section {s.Name} is both writable and executable: unusual for normal builds and typical of self-modifying or packed code.");
            if (s.Executable && s.Entropy is > 7.2)
                add(FindingSeverity.Low,
                    FormattableString.Invariant($"Executable section {s.Name} has very high entropy ({s.Entropy:0.00} bits/byte): the code may be packed or encrypted."));
        }

        if (pe.EntryPointRva != 0 && pe.EntryPointSection == null)
            add(FindingSeverity.High,
                "The entry point lies outside every section: a strong sign of a manipulated or packed file.");
        else if (pe.EntryPointRva != 0 && !pe.EntryPointExecutable)
            add(FindingSeverity.High,
                "The entry point is in a non-executable section: unusual and possibly manipulated.");

        if (pe.CheckSumStored != 0 && pe.CheckSumStored != pe.CheckSumComputed)
            add(FindingSeverity.Low,
                "The stored PE checksum does not match the file: the file was modified after linking, or the checksum was never fixed up. Drivers require a correct checksum.");

        if (!pe.IsDotNet)
        {
            if (!pe.Aslr)
                add(FindingSeverity.Low, "ASLR is not enabled (no dynamic base): an older or deliberately weakened build.");
            if (!pe.Dep)
                add(FindingSeverity.Low, "DEP/NX is not enabled: an older or deliberately weakened build.");
        }

        if (pe.TlsCallbackCount > 0)
            add(FindingSeverity.Low,
                $"{pe.TlsCallbackCount} TLS callback(s) run before the entry point: legitimate for some runtimes but also a known anti-analysis technique.");

        if (pe.OverlayBytes > 0)
        {
            // A verified .NET single-file bundle EXPLAINS the overlay (and its
            // high entropy), so the wording drops the hidden-payload caveat.
            if (pe.DotNetBundle)
                add(FindingSeverity.Info,
                    FormattableString.Invariant($"{pe.OverlayBytes:N0} bytes of overlay data are a verified .NET single-file bundle (the app's own assemblies)."));
            else
                add(FindingSeverity.Info,
                    FormattableString.Invariant($"{pe.OverlayBytes:N0} bytes of overlay data follow the PE image: common for installers and self-extracting archives, but also a place to hide payloads."));
        }

        // ---- batch E signals ------------------------------------------------

        if (pe.PackerSigns.Count > 0)
            add(FindingSeverity.Low,
                "Packer indicators present (" + string.Join("; ", pe.PackerSigns) +
                "): packed code is normal for some commercial software but also hides malware. [heuristic]");

        foreach (var anomaly in pe.SectionAnomalies)
            add(FindingSeverity.Medium, "Section anomaly: " + anomaly + ".");

        if (pe.RichChecksumValid == false)
            add(FindingSeverity.Medium,
                "The Rich header checksum does not match the DOS stub: the header was edited or transplanted from another binary.");

        if (pe.PdbPath != null)
            add(FindingSeverity.Info,
                $"Build path (PDB) is embedded: {pe.PdbPath}. Useful for identification; may leak a user or project name.");

        if (pe.ManifestAutoElevate == true)
            add(FindingSeverity.Low,
                "The manifest requests autoElevate: outside Windows-signed binaries this is a way to bypass UAC prompts.");
        if (pe.ManifestUiAccess == true)
            add(FindingSeverity.Low,
                "The manifest requests uiAccess: the process may drive other windows (accessibility), which malware abuses.");

        if (pe.TimestampRaw != 0 && !pe.DebugReproducible)
        {
            if (pe.TimestampUtc > DateTime.UtcNow.AddDays(2))
                add(FindingSeverity.Low, "The compile timestamp lies in the future: tampered, or a reproducible-build hash in that field.");
            else if (pe.TimestampUtc < new DateTime(1993, 1, 1))
                add(FindingSeverity.Low, "The compile timestamp predates the PE format: tampered, or a reproducible-build hash in that field.");
        }

        // Renamed binary: OriginalFilename differs from the actual file name.
        // Suppressed when it matches the export directory's internal name or ends
        // with .mui (localized resource companions carry the .mui name; seeing it
        // here means a fallback read the MUI data, not that the file was renamed).
        if (pe.VersionOriginalFilename.Length > 0)
        {
            string actual = System.IO.Path.GetFileName(report.FilePath);
            string orig = pe.VersionOriginalFilename;
            bool sameStem = string.Equals(
                System.IO.Path.GetFileNameWithoutExtension(actual),
                System.IO.Path.GetFileNameWithoutExtension(orig),
                StringComparison.OrdinalIgnoreCase);
            bool matchesExportName = pe.ExportDllName != null &&
                string.Equals(pe.ExportDllName, orig, StringComparison.OrdinalIgnoreCase);
            bool isMuiName = orig.EndsWith(".mui", StringComparison.OrdinalIgnoreCase);
            if (!string.Equals(actual, orig, StringComparison.OrdinalIgnoreCase)
                && !sameStem && !matchesExportName && !isMuiName)
                add(FindingSeverity.Low,
                    $"The file is named \"{actual}\" but its version resource says OriginalFilename \"{orig}\": the file may have been renamed.");
        }
    }

    /// <summary>
    /// True for alternate data streams Windows itself creates and that carry no
    /// hidden user payload (Zone.Identifier = Mark of the Web, SmartScreen =
    /// reputation cache). Called from: EvaluateFindings.
    /// </summary>
    private static bool IsBenignStream(string name) =>
        name.Equals("Zone.Identifier", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("SmartScreen", StringComparison.OrdinalIgnoreCase);
}
