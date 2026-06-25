namespace ClamHub.Models;

/// <summary>
/// A named, reusable scan queue: a saved list of target paths (files/folders).
/// Persisted in queues.json by Core.QueueProfileManager, managed in the scan
/// queue window.
/// </summary>
public class QueueProfile
{
    /// <summary>Unique display name, also the combo box entry.</summary>
    public string Name { get; set; } = "";

    /// <summary>The saved target paths, in order.</summary>
    public List<string> Paths { get; set; } = new();
}
