using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClamAVGui.Models;

namespace ClamAVGui.Core;

/// <summary>
/// Loads and saves settings.json. Creates the file with defaults when missing,
/// so the user always has an editable settings file next to the EXE.
/// Called from: App.xaml.cs (startup), settings UI (save), ConfigManager (read values).
/// </summary>
public static class SettingsManager
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>Currently active settings instance, shared across the app.</summary>
    public static AppSettings Current { get; private set; } = new();

    /// <summary>
    /// Loads settings.json or creates it with defaults when missing or invalid.
    /// Called from: App.xaml.cs before the main window opens.
    /// </summary>
    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(AppPaths.SettingsFile))
            {
                var json = File.ReadAllText(AppPaths.SettingsFile);
                Current = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
            }
            else
            {
                Current = new AppSettings();
                Save();
            }
        }
        catch (Exception)
        {
            // Corrupt file: fall back to defaults but do not overwrite the broken
            // file automatically, the user may want to fix it manually.
            Current = new AppSettings();
        }
        return Current;
    }

    /// <summary>
    /// Persists the current settings to settings.json.
    /// Called from: Load (first run) and the settings page when the user saves.
    /// </summary>
    public static void Save()
    {
        var json = JsonSerializer.Serialize(Current, JsonOptions);
        File.WriteAllText(AppPaths.SettingsFile, json);
    }
}
