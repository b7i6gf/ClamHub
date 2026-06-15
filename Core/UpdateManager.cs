using System.IO;
using System.Text;

namespace ClamHub.Core;

/// <summary>
/// Runs freshclam signature updates and queries the installed ClamAV version.
/// Replaces the UPDATE / UPDATESTART sections of the old batch scripts.
/// Called from: MainWindow (update button, optional update on start, version label).
/// </summary>
public static class UpdateManager
{
    /// <summary>True while an update is running, prevents parallel freshclam runs.</summary>
    public static bool UpdateInProgress { get; private set; }

    /// <summary>
    /// Runs freshclam with the portable config and streams its output.
    /// freshclam.conf contains NotifyClamd, so a running daemon reloads the
    /// new signatures automatically after the update.
    /// Called from: MainWindow update button and startup (UpdateOnStart setting).
    /// </summary>
    public static async Task<bool> RunUpdateAsync(Action<string> onOutput, CancellationToken cancel = default)
    {
        if (UpdateInProgress)
        {
            onOutput("An update is already running.");
            return false;
        }

        UpdateInProgress = true;
        try
        {
            onOutput("Starting signature update (freshclam)...");
            var result = await ProcessRunner.RunAsync(
                AppPaths.FreshClamExe,
                $"--config-file=\"{AppPaths.FreshClamConf}\"",
                onOutput,
                cancel);

            if (!result.Started)
            {
                onOutput(result.StartError ?? "freshclam could not be started.");
                return false;
            }

            onOutput(result.ExitCode == 0
                ? "Update finished successfully."
                : $"freshclam exited with code {result.ExitCode}. Check Logs\\freshclam.log.");
            return result.ExitCode == 0;
        }
        finally
        {
            UpdateInProgress = false;
        }
    }

    /// <summary>
    /// Returns the ClamAV version string (clamscan --version) or null on error.
    /// Called from: GetVersionInfoAsync.
    /// </summary>
    public static async Task<string?> GetVersionAsync()
    {
        string? version = null;
        var result = await ProcessRunner.RunAsync(
            AppPaths.ClamScanExe,
            "--version",
            line => version ??= line);
        return result.Started && result.ExitCode == 0 ? version : null;
    }

    /// <summary>The ClamAV engine version plus the version of each signature database.</summary>
    /// <summary>One signature database: the file actually in use and its version (e.g. "daily.cld", "28032").</summary>
    public record DbVersion(string File, string Version);

    /// <summary>ClamAV engine version, each database (file + version), and the daily build date.</summary>
    public record VersionInfo(string Engine, DbVersion? Daily, DbVersion? Main, DbVersion? Bytecode, string BuildTime);

    /// <summary>
    /// Collects the ClamAV engine version (from clamscan --version, with the
    /// daily build date) and each database's file and version, read from the
    /// actual database file headers. Whichever file is in use (.cld after
    /// incremental updates, otherwise .cvd) is detected at runtime, so no
    /// version number or file name is hard coded. Returns null when the binaries
    /// are missing. Called from: MainWindow on startup, after an update, and the About box.
    /// </summary>
    public static async Task<VersionInfo?> GetVersionInfoAsync()
    {
        var raw = await GetVersionAsync();
        if (raw == null) return null;

        // clamscan --version: "ClamAV 1.5.2/28032/Sat Jun 14 09:12:00 2026"
        var parts = raw.Split('/');
        string engine = parts.Length > 0 ? parts[0].Trim() : raw.Trim();
        string buildTime = parts.Length > 2 ? parts[2].Trim() : "";

        return new VersionInfo(engine, ReadDb("daily"), ReadDb("main"), ReadDb("bytecode"), buildTime);
    }

    /// <summary>
    /// Reads one ClamAV database file (file name + version). Prefers the patched
    /// .cld file, falls back to .cvd. The header is an ASCII line
    /// "ClamAV-VDB:&lt;build time&gt;:&lt;version&gt;:..." in the first bytes of the file.
    /// Returns null when no readable database file exists. Called from: GetVersionInfoAsync.
    /// </summary>
    private static DbVersion? ReadDb(string baseName)
    {
        foreach (var ext in new[] { ".cld", ".cvd" })
        {
            var file = baseName + ext;
            var path = Path.Combine(AppPaths.DatabaseDir, file);
            if (!File.Exists(path)) continue;
            try
            {
                var buffer = new byte[512];
                using (var stream = File.OpenRead(path))
                    _ = stream.Read(buffer, 0, buffer.Length);

                var header = Encoding.ASCII.GetString(buffer);
                int end = header.IndexOf('\0');
                if (end >= 0) header = header.Substring(0, end);
                if (!header.StartsWith("ClamAV-VDB:")) continue;

                // Fields: ClamAV-VDB : build time : version : sigs : flevel : ...
                var fields = header.Split(':');
                if (fields.Length >= 3 && !string.IsNullOrWhiteSpace(fields[2]))
                    return new DbVersion(file, fields[2].Trim());
            }
            catch
            {
                // Unreadable file: try the next extension.
            }
        }
        return null;
    }
}
