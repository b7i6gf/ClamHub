using System.IO;
using System.Text;

namespace ClamHub.Core;

/// <summary>
/// Writes text files atomically: the content goes into a temporary file that is
/// flushed to disk and then renamed over the target in a single step. This
/// prevents half written or truncated files when the app is killed or a USB
/// stick is pulled mid write. Throws on failure so the caller can report it;
/// nothing partial is ever left at the target path.
/// Called from: the JSON Save methods of SettingsManager, HistoryManager,
/// ProfileManager and QuarantineManager.
/// </summary>
public static class AtomicFile
{
    /// <summary>
    /// Atomically writes <paramref name="content"/> as UTF-8 to
    /// <paramref name="path"/>. Called from: the JSON managers' Save methods.
    /// </summary>
    public static void WriteAllText(string path, string content)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var tmp = path + ".tmp";
        using (var stream = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
        {
            writer.Write(content);
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }

        // Same volume rename. The OS guarantees this is atomic, so the target is
        // always either the old or the new complete file, never a fragment.
        File.Move(tmp, path, overwrite: true);
    }
}
