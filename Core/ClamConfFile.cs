using System.IO;

namespace ClamHub.Core;

/// <summary>
/// Minimal editor model for ClamAV conf files (freshclam.conf, clamd.conf).
/// Format: "Key Value" per line, '#' comments. All comments, blank lines and
/// unknown parameters are preserved unchanged; only edited keys are touched.
/// Called from: the settings tab (MainWindow.Settings.cs) to read and write
/// individual parameters.
/// </summary>
public class ClamConfFile
{
    private readonly List<string> _lines;

    /// <summary>Path the file was loaded from, used by Save.</summary>
    public string Path { get; }

    private ClamConfFile(string path, List<string> lines)
    {
        Path = path;
        _lines = lines;
    }

    /// <summary>
    /// Loads a conf file, or starts an empty model when the file is missing.
    /// Called from: settings tab initialization and Reload button.
    /// </summary>
    public static ClamConfFile Load(string path)
        => new(path, File.Exists(path) ? File.ReadAllLines(path).ToList() : new List<string>());

    /// <summary>
    /// Returns the value of the first occurrence of a key, or null when the
    /// key is not set. Surrounding quotes are stripped.
    /// Called from: settings tab row builder to prefill controls.
    /// </summary>
    public string? GetValue(string key)
    {
        foreach (var line in _lines)
        {
            if (TryParse(line, out var k, out var v) && k == key)
                return v;
        }
        return null;
    }

    /// <summary>
    /// Sets a key to a value: replaces the first occurrence or appends a new
    /// line at the end. Values containing spaces are quoted.
    /// Called from: settings tab save handlers.
    /// </summary>
    public void SetValue(string key, string value)
    {
        var formatted = value.Contains(' ') && !value.StartsWith('"')
            ? $"{key} \"{value}\""
            : $"{key} {value}";

        for (int i = 0; i < _lines.Count; i++)
        {
            if (TryParse(_lines[i], out var k, out _) && k == key)
            {
                _lines[i] = formatted;
                return;
            }
        }
        _lines.Add(formatted);
    }

    /// <summary>
    /// Removes all occurrences of a key, so ClamAV falls back to its built-in
    /// default for that parameter.
    /// Called from: settings tab save handlers when a field is cleared.
    /// </summary>
    public void Remove(string key)
        => _lines.RemoveAll(line => TryParse(line, out var k, out _) && k == key);

    /// <summary>
    /// Returns every value of a key in file order, for keys that may appear multiple
    /// times (e.g. DatabaseCustomURL). Called from: the custom-database-URL window.
    /// </summary>
    public IEnumerable<string> GetValues(string key)
    {
        foreach (var line in _lines)
            if (TryParse(line, out var k, out var v) && k == key)
                yield return v;
    }

    /// <summary>
    /// Appends a new "Key Value" line without touching existing occurrences, for keys
    /// that may appear multiple times. Values with spaces are quoted. Called from: the
    /// custom-database-URL window when writing the URL list.
    /// </summary>
    public void AddValue(string key, string value)
    {
        _lines.Add(value.Contains(' ') && !value.StartsWith('"')
            ? $"{key} \"{value}\""
            : $"{key} {value}");
    }

    /// <summary>
    /// Writes the (modified) lines back to disk.
    /// Called from: settings tab save handlers.
    /// </summary>
    public void Save() => File.WriteAllLines(Path, _lines);

    /// <summary>
    /// Returns every "Key Value" pair in file order (comments and blank lines
    /// skipped), so a rebuild can carry the user's settings into a fresh file.
    /// Called from: ConfigManager.RebuildConfig.
    /// </summary>
    public IEnumerable<(string Key, string Value)> AllValues()
    {
        foreach (var line in _lines)
            if (TryParse(line, out var k, out var v))
                yield return (k, v);
    }

    /// <summary>
    /// Parses one line into key and unquoted value. Returns false for blank
    /// lines and comments. Called from: GetValue, SetValue, Remove.
    /// </summary>
    private static bool TryParse(string line, out string key, out string value)
    {
        key = "";
        value = "";
        var trimmed = line.Trim();
        if (trimmed.Length == 0 || trimmed.StartsWith('#')) return false;

        int split = trimmed.IndexOfAny(new[] { ' ', '\t' });
        if (split < 0)
        {
            key = trimmed;
            return true;
        }
        key = trimmed[..split];
        value = trimmed[(split + 1)..].Trim().Trim('"');
        return true;
    }
}
