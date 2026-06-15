namespace ClamHub.Models;

/// <summary>
/// One quarantined file, tracked in quarantine.json so it can be restored to
/// its exact original location or deleted. Created by Core.QuarantineManager
/// when the GUI moves an infected file into the Quarantine folder.
/// </summary>
public class QuarantineEntry
{
    /// <summary>Stable id, also the stored file name inside the Quarantine folder.</summary>
    public string Id { get; set; } = "";

    /// <summary>Full original path the file was moved from (restore target).</summary>
    public string OriginalPath { get; set; } = "";

    /// <summary>Virus/signature name reported by ClamAV.</summary>
    public string Threat { get; set; } = "";

    /// <summary>When the file was quarantined (local time).</summary>
    public DateTime QuarantinedAt { get; set; }

    /// <summary>File size in bytes at quarantine time.</summary>
    public long SizeBytes { get; set; }

    /// <summary>Original file name without the directory, shown in the list.</summary>
    public string OriginalName =>
        string.IsNullOrEmpty(OriginalPath) ? Id : System.IO.Path.GetFileName(OriginalPath);
}
