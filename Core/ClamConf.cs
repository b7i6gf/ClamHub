using System.IO;

namespace ClamHub.Core;

/// <summary>
/// Thin wrapper around clamconf.exe, ClamAV's configuration and diagnostics tool.
/// Used to dump engine, build, database and config information and (later) to
/// validate the generated config files. clamconf is optional: when it is missing
/// the call is skipped gracefully. Called from: MainWindow diagnostics and, in a
/// later step, the config-validation hooks.
/// </summary>
public static class ClamConf
{
    /// <summary>True when clamconf.exe is present in the ClamAV folder.</summary>
    public static bool Available => File.Exists(AppPaths.ClamConfExe);

    /// <summary>
    /// Runs clamconf with the given arguments and streams its output line by line
    /// via onOutput. Pass "" for a plain engine/build/database dump, or a
    /// config-dir argument to validate the config files. Returns the process
    /// result, or a synthetic failure when clamconf.exe is absent. The working
    /// directory is the ClamAV folder (ProcessRunner sets it), so clamconf finds
    /// the bundled libraries. Called from: MainWindow.RunDiagnostics_Click (and the
    /// config-validation hooks in a later step).
    /// </summary>
    public static async Task<ProcessRunner.RunResult> RunAsync(
        string arguments, Action<string> onOutput, CancellationToken cancel = default)
    {
        if (!Available)
        {
            onOutput("clamconf.exe was not found in the ClamAV folder; this step is skipped.");
            return new ProcessRunner.RunResult(-1, false, "clamconf.exe not found");
        }
        return await ProcessRunner.RunAsync(AppPaths.ClamConfExe, arguments, onOutput, cancel);
    }

    /// <summary>
    /// Argument that points clamconf at the app's config folder so it reads and
    /// validates the bundled clamd.conf/freshclam.conf. Called from: ValidateAsync
    /// and the diagnostics dump.
    /// </summary>
    public static string ConfigDirArg => $"--config-dir=\"{AppPaths.ClamAvDir}\"";

    /// <summary>Parsed outcome of a clamconf validation run.</summary>
    public record ConfReport(
        bool Ran,
        int ExitCode,
        IReadOnlyList<string> Issues,
        IReadOnlyList<string> Signatures,
        IReadOnlyList<string> Features);

    /// <summary>
    /// Runs clamconf against the config folder, collects its output and parses out
    /// problems (error/warning lines), per-database signature lines and the
    /// compiled-in feature line. Returns Ran=false when clamconf is missing or did
    /// not start. Called from: MainWindow.ValidateConfigAndReportAsync.
    /// </summary>
    public static async Task<ConfReport> ValidateAsync(CancellationToken cancel = default)
    {
        if (!Available)
            return new ConfReport(false, -1, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>());

        var lines = new List<string>();
        var result = await ProcessRunner.RunAsync(
            AppPaths.ClamConfExe, ConfigDirArg,
            line => { lock (lines) lines.Add(line); }, cancel);

        if (!result.Started)
            return new ConfReport(false, result.ExitCode, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>());

        var issues = new List<string>();
        var signatures = new List<string>();
        var features = new List<string>();
        foreach (var raw in lines)
        {
            string line = raw.Trim();
            if (line.Length == 0) continue;
            string lower = line.ToLowerInvariant();

            if (lower.StartsWith("error") || lower.StartsWith("warning")
                || lower.Contains("can't ") || lower.Contains("parse error")
                || lower.Contains("unknown option") || lower.Contains("invalid ")
                || lower.Contains("fatal"))
                issues.Add(line);

            if (lower.Contains("sigs:"))
                signatures.Add(line);

            if (lower.Contains("optional features") || lower.Contains("features supported"))
                features.Add(line);
        }

        return new ConfReport(true, result.ExitCode, issues, signatures, features);
    }
}
