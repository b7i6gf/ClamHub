using System.ComponentModel;
using System.Text.Json.Serialization;

namespace ClamHub.Models;

/// <summary>Lifecycle of one detection in the Detections window.</summary>
public enum DetectionStatus
{
    Pending,     // reported by a scan, nothing done yet
    Clean,       // a rescan no longer reports it (whitelisted meanwhile, DB update, ...)
    Quarantined, // moved into the GUI quarantine
    Removed,     // deleted from disk
    Whitelisted, // added to clamhub-whitelist.sfp (confirmed false positive)
    Ignored      // user decided to leave it alone
}

/// <summary>
/// One infected file reported by a scan (report-only scans; quarantined/removed
/// findings are already handled and tracked elsewhere). Persisted by
/// DetectionManager (Logs\detections.json) and shown/worked through in the
/// Detections window. Implements INotifyPropertyChanged so the VirusTotal and
/// Status columns update live in the ListView.
/// </summary>
public class DetectionEntry : INotifyPropertyChanged
{
    /// <summary>Stable id of this entry.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>Full path of the infected file as reported by ClamAV.</summary>
    public string FilePath { get; set; } = "";

    /// <summary>Signature/threat name from the FOUND line.</summary>
    public string Signature { get; set; } = "";

    /// <summary>When the scan reported the file (local time).</summary>
    public DateTime DetectedAt { get; set; }

    private string _virusTotal = "";
    /// <summary>Short VirusTotal verdict ("3/70 malicious"), filled by the VT lookup.</summary>
    public string VirusTotal
    {
        get => _virusTotal;
        set { _virusTotal = value; OnChanged(nameof(VirusTotal)); }
    }

    /// <summary>
    /// Link to the VirusTotal report page for the file's SHA256, set together with
    /// VirusTotal by the lookup; the VirusTotal column cell opens it on click.
    /// </summary>
    public string VirusTotalUrl { get; set; } = "";

    private string _database = "";
    /// <summary>
    /// Database file(s) the signature was traced to by "Find database" (comma
    /// separated when several carry it), or "not found". Empty until resolved;
    /// the FOUND line itself never names the database.
    /// </summary>
    public string Database
    {
        get => _database;
        set { _database = value; OnChanged(nameof(Database)); }
    }

    private DetectionStatus _status = DetectionStatus.Pending;
    /// <summary>What has been done with the file so far.</summary>
    public DetectionStatus Status
    {
        get => _status;
        set { _status = value; OnChanged(nameof(Status)); }
    }

    /// <summary>File name only, for the list column. Not persisted.</summary>
    [JsonIgnore]
    public string FileName => System.IO.Path.GetFileName(FilePath);

    /// <summary>Directory only, for the list column. Not persisted.</summary>
    [JsonIgnore]
    public string Directory => System.IO.Path.GetDirectoryName(FilePath) ?? "";

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Raises PropertyChanged. Called from: the VirusTotal/Status setters.</summary>
    private void OnChanged(string name)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
