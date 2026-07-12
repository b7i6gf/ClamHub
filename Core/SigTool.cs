using System.IO;

namespace ClamHub.Core;

/// <summary>
/// Thin wrapper around ClamAV's sigtool.exe. Used ONLY for the operations that
/// actually need sigtool, i.e. reading signature-database metadata
/// (sigtool --info): the version, build date, signature count, builder and the
/// digital-signature verification result of the official CVD/CLD databases. Custom
/// hash signatures are built by CustomSignatureManager WITHOUT sigtool (a SHA256
/// line is trivial), so this class stays optional: sigtool.exe is not in
/// AppPaths.RequiredBinaries and IsAvailable is false when it is missing (the UI
/// then shows a hint instead of failing).
/// Called from: the Signatures tab database-info panel (added in a later batch).
/// </summary>
public static class SigTool
{
    /// <summary>
    /// Parsed result of "sigtool --info &lt;db&gt;" for one database file. Ok is
    /// false when sigtool is missing, the file is absent or sigtool exits non-zero
    /// (Error then holds the reason). Verified reflects the "Verification OK" line.
    /// Consumed by: the Signatures tab.
    /// </summary>
    public sealed record DbInfo(
        string FileName,
        string? Version,
        string? BuildTime,
        string? Signatures,
        string? FunctionalityLevel,
        string? Builder,
        bool Verified,
        bool Ok,
        string? Error);

    /// <summary>The official database stems to probe, in display order.</summary>
    private static readonly string[] DatabaseStems = { "main", "daily", "bytecode" };

    /// <summary>True when sigtool.exe is present next to the other ClamAV binaries.</summary>
    public static bool IsAvailable => File.Exists(AppPaths.SigToolExe);

    /// <summary>
    /// Runs "sigtool --info" for every official database present in the database
    /// folder (main/daily/bytecode, each as .cvd or .cld) and returns one DbInfo per
    /// file found. Returns an empty list when sigtool is missing (caller shows a
    /// hint) or no database exists yet. Never throws (except honoring cancellation).
    /// Called from: the Signatures tab refresh.
    /// </summary>
    public static async Task<IReadOnlyList<DbInfo>> GetDatabaseInfoAsync(CancellationToken cancel = default)
    {
        var list = new List<DbInfo>();
        if (!IsAvailable) return list;

        foreach (var stem in DatabaseStems)
        {
            string? path = FindDatabaseFile(stem);
            if (path == null) continue;
            list.Add(await ReadInfoAsync(path, cancel));
        }
        return list;
    }

    /// <summary>
    /// Runs "sigtool --info" for ONE database file at an arbitrary path (used for the
    /// full DB-folder listing, e.g. third-party .cvd/.cld). Returns Ok=false with a
    /// reason when sigtool is missing. Never throws (except honoring cancellation).
    /// Called from: the Signatures tab (per-file rows).
    /// </summary>
    public static async Task<DbInfo> GetInfoAsync(string dbPath, CancellationToken cancel = default)
    {
        if (!IsAvailable) return Failed(Path.GetFileName(dbPath), "sigtool.exe not found");
        return await ReadInfoAsync(dbPath, cancel);
    }

    /// <summary>
    /// Locates a database file for a stem, preferring the compressed .cvd over the
    /// uncompressed .cld that freshclam may leave after applying diffs. Returns null
    /// when neither exists. Called from: GetDatabaseInfoAsync.
    /// </summary>
    private static string? FindDatabaseFile(string stem)
    {
        string cvd = Path.Combine(AppPaths.DatabaseDir, stem + ".cvd");
        if (File.Exists(cvd)) return cvd;
        string cld = Path.Combine(AppPaths.DatabaseDir, stem + ".cld");
        return File.Exists(cld) ? cld : null;
    }

    /// <summary>
    /// Runs "sigtool --info &lt;path&gt;", captures stdout/stderr and parses the
    /// "Key: Value" lines into a DbInfo. A non-zero exit or an unreadable file yields
    /// Ok=false with the captured text as Error. Called from: GetDatabaseInfoAsync.
    /// </summary>
    private static async Task<DbInfo> ReadInfoAsync(string dbPath, CancellationToken cancel)
    {
        string fileName = Path.GetFileName(dbPath);
        var lines = new List<string>();

        ProcessRunner.RunResult result;
        try
        {
            // sigtool writes info to stdout and errors to stderr; ProcessRunner sends
            // both to this callback. It can fire from two threads, so lock the list.
            result = await ProcessRunner.RunAsync(
                AppPaths.SigToolExe,
                $"--info \"{dbPath}\"",
                line => { lock (lines) lines.Add(line); },
                cancel);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return Failed(fileName, ex.Message);
        }

        if (!result.Started)
            return Failed(fileName, result.StartError ?? "sigtool could not be started.");

        // Output is complete once the process has exited.
        string? Value(string key) => lines
            .FirstOrDefault(l => l.StartsWith(key + ":", StringComparison.OrdinalIgnoreCase))
            ?.Split(':', 2)[1].Trim();

        bool verified = lines.Any(l =>
            l.Contains("Verification OK", StringComparison.OrdinalIgnoreCase));

        if (result.ExitCode != 0)
        {
            // A database that was DISABLED (renamed to ".disabled") always fails sigtool's
            // extension-based verification even though sigtool still printed the real
            // header fields. Keep those fields and drop the misleading cl_cvdverify error,
            // so the details panel shows the full info. The file is only READ here (never
            // renamed), so it stays disabled. A genuinely unreadable file has no Version
            // line and still falls through to the error path below.
            bool disabled = dbPath.EndsWith(ConfigManager.DisabledSuffix, StringComparison.OrdinalIgnoreCase);
            if (disabled && Value("Version") != null)
                return new DbInfo(fileName, Value("Version"), Value("Build time"),
                    Value("Signatures"), Value("Functionality level"), Value("Builder"),
                    false, true, null);

            string err = lines.Count > 0
                ? string.Join(" ", lines)
                : $"sigtool exited with code {result.ExitCode}.";
            return new DbInfo(fileName, null, null, null, null, null, verified, false, err);
        }

        return new DbInfo(
            fileName,
            Value("Version"),
            Value("Build time"),
            Value("Signatures"),
            Value("Functionality level"),
            Value("Builder"),
            verified,
            true,
            null);
    }

    /// <summary>Builds a failed DbInfo with just a file name and reason. Called from: ReadInfoAsync.</summary>
    private static DbInfo Failed(string fileName, string error)
        => new(fileName, null, null, null, null, null, false, false, error);

    // ---- Signature search (used by the signature-search window) ----

    /// <summary>
    /// Outcome of a streaming sigtool run: whether it started, its exit code and the
    /// error text when it could not start. The output itself was already delivered line
    /// by line to the caller's callback. Consumed by: the signature-search window.
    /// </summary>
    public sealed record RunOutcome(bool Ok, string? Error);

    /// <summary>
    /// Streams the signature NAMES of one database ("sigtool --list-sigs FILE"), one
    /// line per callback invocation. Works for container (.cvd/.cld) and text databases.
    /// The output can be very large (daily has millions of signatures), so nothing is
    /// buffered here: the caller decides what to keep and can cancel at any time. The
    /// callback runs on a worker thread. Called from: the signature-search window
    /// (list a database, and duplicate detection by name).
    /// </summary>
    public static Task<RunOutcome> ListSignaturesAsync(string dbPath, Action<string> onLine,
        CancellationToken cancel = default)
        => RunStreamingAsync($"--list-sigs=\"{dbPath}\"", onLine, cancel);

    /// <summary>
    /// Streams the full signature LINES whose name matches a regular expression, across
    /// every database in the database folder ("sigtool --find-sigs REGEX"). sigtool
    /// prefixes/annotates the output so the source database can be told apart; parsing is
    /// left to the caller because the exact shape depends on the sigtool version. Not
    /// buffered, cancellable. Called from: the signature-search window (search).
    /// </summary>
    public static Task<RunOutcome> FindSignaturesAsync(string regex, Action<string> onLine,
        CancellationToken cancel = default)
        => RunStreamingAsync($"--datadir=\"{AppPaths.DatabaseDir}\" --find-sigs=\"{regex}\"", onLine, cancel);

    /// <summary>
    /// Decodes one raw signature line into a human-readable description by piping it to
    /// "sigtool --decode-sigs" on standard input. Returns the collected output lines (or
    /// a single error line when sigtool is missing or failed). This output is small, so
    /// unlike the streaming calls it is buffered and returned. Called from: the
    /// signature-search window when a result row is selected.
    /// </summary>
    public static async Task<IReadOnlyList<string>> DecodeSignatureAsync(string rawLine,
        CancellationToken cancel = default)
    {
        if (!IsAvailable) return new[] { "sigtool.exe not found; cannot decode the signature." };

        var lines = new List<string>();
        ProcessRunner.RunResult result;
        try
        {
            result = await ProcessRunner.RunWithInputAsync(
                AppPaths.SigToolExe, "--decode-sigs", rawLine,
                line => { lock (lines) lines.Add(line); }, cancel);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new[] { $"Could not decode the signature: {ex.Message}" };
        }

        if (!result.Started)
            return new[] { result.StartError ?? "sigtool could not be started." };
        if (lines.Count == 0)
            return new[] { $"sigtool produced no output (exit code {result.ExitCode})." };
        return lines;
    }

    /// <summary>
    /// Shared helper for the streaming sigtool calls: checks that sigtool exists, runs it
    /// with the given arguments and forwards every stdout/stderr line to onLine (locked,
    /// because the two streams raise events on different threads). Never throws except on
    /// cancellation. Called from: ListSignaturesAsync and FindSignaturesAsync.
    /// </summary>
    private static async Task<RunOutcome> RunStreamingAsync(string arguments, Action<string> onLine,
        CancellationToken cancel)
    {
        if (!IsAvailable) return new RunOutcome(false, "sigtool.exe not found in the ClamAV folder.");

        var gate = new object();
        ProcessRunner.RunResult result;
        try
        {
            result = await ProcessRunner.RunAsync(AppPaths.SigToolExe, arguments,
                line => { lock (gate) onLine(line); }, cancel);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new RunOutcome(false, ex.Message);
        }

        if (!result.Started)
            return new RunOutcome(false, result.StartError ?? "sigtool could not be started.");

        // A non-zero exit with no output usually means "no matches" or a bad regex; the
        // caller reports it, since an empty result is not necessarily an error.
        return new RunOutcome(result.ExitCode == 0, result.ExitCode == 0
            ? null
            : $"sigtool exited with code {result.ExitCode}.");
    }
}
