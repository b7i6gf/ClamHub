namespace ClamHub.Models;

/// <summary>
/// One recorded action (a scan, a VirusTotal lookup, a quarantine action or a
/// hash operation), persisted in history.json by Core.HistoryManager and shown
/// in the History tab. Summary holds the full multi-line detail shown when the
/// entry is selected (URLs become clickable in the detail pane).
/// </summary>
public class ScanHistoryEntry
{
    /// <summary>When the action happened (local time).</summary>
    public DateTime Timestamp { get; set; }

    /// <summary>
    /// "File/folder scan", "Memory scan", "VirusTotal scan", "Quarantine action",
    /// "Hash compute" or "Hash comparison".
    /// </summary>
    public string Kind { get; set; } = "";

    /// <summary>The scanned target / root folder / file, or the subject of the action.</summary>
    public string Target { get; set; } = "";

    /// <summary>
    /// The ClamAV executable that ran (clamdscan.exe / clamscan.exe), "VirusTotal"
    /// for VirusTotal lookups, or empty for hash and quarantine actions.
    /// </summary>
    public string Process { get; set; } = "";

    /// <summary>Short result text shown in the Result column (set per source).</summary>
    public string ResultLabel { get; set; } = "";

    /// <summary>Full multi-line detail shown when the entry is selected.</summary>
    public string Summary { get; set; } = "";
}
