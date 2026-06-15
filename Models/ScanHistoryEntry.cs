namespace ClamAVGui.Models;

/// <summary>
/// One recorded scan, persisted in history.json by Core.HistoryManager and
/// shown in the History tab. Holds the infected file lines so a past finding
/// can be reviewed without re-scanning.
/// </summary>
public class ScanHistoryEntry
{
    /// <summary>When the scan finished (local time).</summary>
    public DateTime Timestamp { get; set; }

    /// <summary>"File/folder scan", "Memory scan", etc.</summary>
    public string Kind { get; set; } = "";

    /// <summary>Scanned target path, or "Process memory" for memory scans.</summary>
    public string Target { get; set; } = "";

    /// <summary>"clamdscan (daemon)" or "clamscan".</summary>
    public string Scanner { get; set; } = "";

    /// <summary>Wall clock duration of the scan.</summary>
    public TimeSpan Duration { get; set; }

    /// <summary>Number of infected files found.</summary>
    public int InfectedCount { get; set; }

    /// <summary>Process exit code: 0 clean, 1 infections, 2+ error.</summary>
    public int ExitCode { get; set; }

    /// <summary>Raw "FOUND" lines, shown when the entry is selected.</summary>
    public List<string> InfectedLines { get; set; } = new();

    /// <summary>Short result label derived from the exit code. Used by the History tab.</summary>
    public string ResultLabel => ExitCode switch
    {
        0 => "Clean",
        1 => $"{InfectedCount} infected",
        _ => "Error"
    };
}
