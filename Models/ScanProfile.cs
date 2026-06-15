namespace ClamAVGui.Models;

/// <summary>
/// A named, reusable scan configuration (e.g. "Quick Downloads check").
/// Persisted in profiles.json by Core.ProfileManager, applied to and captured
/// from the scan tab controls in MainWindow.Profiles.cs.
/// </summary>
public class ScanProfile
{
    /// <summary>Unique display name, also the combo box entry.</summary>
    public string Name { get; set; } = "";

    /// <summary>File, folder or drive root to scan.</summary>
    public string TargetPath { get; set; } = "";

    /// <summary>Action applied to infected files.</summary>
    public InfectedFileAction Action { get; set; } = InfectedFileAction.ReportOnly;

    /// <summary>Use --multiscan when the daemon handles the scan.</summary>
    public bool MultiScan { get; set; } = true;

    /// <summary>Raw extension filter text, e.g. "exe dll sys". Empty scans everything.</summary>
    public string Extensions { get; set; } = "";
}
