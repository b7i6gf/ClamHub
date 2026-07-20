using System.IO;
using System.Linq;
using System.Text;

namespace ClamHub.Core;

/// <summary>
/// Maintains the persistent infected file report (Logs\INFECTED_FILES.txt):
/// every scan with findings appends its FOUND lines there, so infected file
/// paths can always be found again later, as required. The report is a plain
/// text file the user opens from the Logs folder; the app itself only appends.
/// (ReadReport/ExtractFromLogs/ClearReport/ClearAllLogs and their buttons were
/// removed in the 2026-07-18 cleanup as dead code.)
/// Called from: MainWindow.RunScanGuarded (after scans with findings).
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
}
