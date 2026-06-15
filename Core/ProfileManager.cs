using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClamAVGui.Models;

namespace ClamAVGui.Core;

/// <summary>
/// Loads and saves scan profiles (profiles.json next to the EXE). Profile
/// names are unique; saving an existing name overwrites that profile.
/// Called from: MainWindow.Profiles.cs (combo fill, save, delete).
/// </summary>
public static class ProfileManager
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>In-memory profile list, sorted by name.</summary>
    public static List<ScanProfile> Profiles { get; private set; } = new();

    /// <summary>
    /// Loads profiles.json, an invalid or missing file yields an empty list.
    /// Called from: MainWindow.InitializeAsync via InitializeProfiles.
    /// </summary>
    public static void Load()
    {
        try
        {
            if (File.Exists(AppPaths.ProfilesFile))
            {
                var json = File.ReadAllText(AppPaths.ProfilesFile);
                Profiles = JsonSerializer.Deserialize<List<ScanProfile>>(json, JsonOptions) ?? new();
            }
        }
        catch (Exception)
        {
            Profiles = new();
        }
        SortByName();
    }

    /// <summary>
    /// Adds a new profile or overwrites the one with the same name, then saves.
    /// Called from: MainWindow.Profiles.cs SaveProfile_Click.
    /// </summary>
    public static void AddOrUpdate(ScanProfile profile)
    {
        Profiles.RemoveAll(p => string.Equals(p.Name, profile.Name, StringComparison.OrdinalIgnoreCase));
        Profiles.Add(profile);
        SortByName();
        Save();
    }

    /// <summary>
    /// Deletes a profile by name and saves. Returns true when one was removed.
    /// Called from: MainWindow.Profiles.cs DeleteProfile_Click.
    /// </summary>
    public static bool Delete(string name)
    {
        int removed = Profiles.RemoveAll(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
        if (removed > 0) Save();
        return removed > 0;
    }

    /// <summary>Writes the current list to profiles.json. Called from: AddOrUpdate, Delete.</summary>
    private static void Save()
        => File.WriteAllText(AppPaths.ProfilesFile, JsonSerializer.Serialize(Profiles, JsonOptions));

    private static void SortByName()
        => Profiles.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
}
