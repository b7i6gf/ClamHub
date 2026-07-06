using System.IO;
using System.Linq;
using System.Text;

namespace ClamHub.Core;

/// <summary>
/// Maintains the persistent infected file report (Logs\INFECTED_FILES.txt) and
/// handles log housekeeping. Replaces LOGSCAN / CLEAN / CLEANLOGS of the old
/// batch scripts. The report survives scans and log cleanups are explicit, so
/// infected file paths can always be found again later, as required.
/// Called from: MainWindow (after scans and via the log buttons).
/// </summary>
public static class LogManager
{
    /// <summary>
    /// Appends FOUND lines from a finished scan to the report, prefixed with a
    /// timestamp and a short scan description.
    /// Called from: MainWindow.RunScanGuarded when a scan reports infections.
    /// </summary>
    public static void AppendInfected(IEnumerable<string> infectedLines, string scanDescription)
    {
        var lines = infectedLines.ToList();
        if (lines.Count == 0) return;

        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {scanDescription} " +
                      new string('-', 30));
        foreach (var line in lines)
            sb.AppendLine(line);

        // Never let a logging failure (missing/read-only Logs folder, full disk,
        // momentary lock) bubble up and abort the scan finish (summary, history,
        // quarantine move); report it as a console line instead.
        try
        {
            File.AppendAllText(AppPaths.InfectedFilesReport, sb.ToString());
        }
        catch (Exception ex)
        {
            AppNotifications.ReportError($"Could not write the infected-files report: {ex.Message}");
        }
    }

    /// <summary>
    /// Scans all .log files in the Logs folder for " FOUND" lines and appends
    /// any entries not yet present to the report. Useful to recover findings
    /// from daemon background activity (clamd.log) or older scan logs.
    /// Returns the number of newly added lines.
    /// Called from: MainWindow Extract button.
    /// </summary>
    public static int ExtractFromLogs()
    {
        var existing = new HashSet<string>();
        if (File.Exists(AppPaths.InfectedFilesReport))
        {
            foreach (var line in ReadLinesShared(AppPaths.InfectedFilesReport))
                existing.Add(line);
        }

        var found = new List<string>();
        IEnumerable<string> logFiles;
        try
        {
            logFiles = Directory.EnumerateFiles(AppPaths.LogsDir, "*.log").ToList();
        }
        catch
        {
            return 0;
        }

        foreach (var logFile in logFiles)
        {
            // clamd.log and the active scan log may be open in another process,
            // so read with a shared handle and skip any file that still fails.
            foreach (var line in ReadLinesShared(logFile))
            {
                // existing.Add returns false when the line is already in the report
                // OR was already collected this run, so it deduplicates in O(1)
                // (was an O(n) found.Contains scan) while keeping log order in found.
                if (line.Contains(" FOUND") && existing.Add(line))
                    found.Add(line);
            }
        }

        if (found.Count > 0)
            AppendInfected(found, "Extracted from log files");

        return found.Count;
    }

    /// <summary>
    /// Reads all lines from a file while allowing other processes to keep it
    /// open for reading and writing (clamd holds clamd.log open). Returns an
    /// empty sequence if the file cannot be read. Called from: ExtractFromLogs.
    /// </summary>
    private static IEnumerable<string> ReadLinesShared(string path)
    {
        var lines = new List<string>();
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            string? line;
            while ((line = reader.ReadLine()) != null)
                lines.Add(line);
        }
        catch
        {
            // Locked or unreadable file: skip it rather than crashing.
        }
        return lines;
    }

    /// <summary>
    /// Returns the report content or null when no report exists yet.
    /// Called from: MainWindow Show report button.
    /// </summary>
    public static string? ReadReport()
        => File.Exists(AppPaths.InfectedFilesReport)
            ? File.ReadAllText(AppPaths.InfectedFilesReport)
            : null;

    /// <summary>
    /// Deletes the infected file report. Returns true when a file was removed.
    /// Called from: MainWindow Clear report button.
    /// </summary>
    public static bool ClearReport()
    {
        if (!File.Exists(AppPaths.InfectedFilesReport)) return false;
        File.Delete(AppPaths.InfectedFilesReport);
        return true;
    }

    /// <summary>
    /// Deletes all .log files in the Logs folder. The infected report is kept
    /// on purpose; use ClearReport for that. Skips files locked by a running
    /// daemon. Returns the number of deleted files.
    /// Called from: MainWindow Clear logs button.
    /// </summary>
    public static int ClearAllLogs()
    {
        int count = 0;
        foreach (var logFile in Directory.EnumerateFiles(AppPaths.LogsDir, "*.log"))
        {
            try
            {
                File.Delete(logFile);
                count++;
            }
            catch (IOException)
            {
                // Locked (e.g. clamd.log while the daemon runs), skip silently.
            }
        }
        return count;
    }
}
