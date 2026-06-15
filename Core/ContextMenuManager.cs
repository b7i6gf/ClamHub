using System.IO;
using Microsoft.Win32;

namespace ClamAVGui.Core;

/// <summary>
/// Registers and removes a "Scan with ClamHub" entry in the Windows context
/// menu for files and folders. Writes under HKEY_CURRENT_USER\Software\Classes
/// so no administrator rights are needed. The entry passes the clicked path to
/// the EXE via the --scan argument and uses an icon from the ClamAV folder.
/// Because the portable folder can move, the stored command embeds the current
/// EXE path; IsRegistered/NeedsRepair detect a stale entry after a move.
/// Called from: the settings tab (MainWindow.Settings.cs) checkbox.
/// </summary>
public static class ContextMenuManager
{
    private const string MenuLabel = "Scan with ClamHub";

    // Shell verb keys for the three relevant classes.
    private const string FileKey = @"Software\Classes\*\shell\ClamAVGuiScan";
    private const string DirectoryKey = @"Software\Classes\Directory\shell\ClamAVGuiScan";
    private const string DirectoryBgKey = @"Software\Classes\Directory\Background\shell\ClamAVGuiScan";

    /// <summary>
    /// Absolute path to the running EXE, used in the shell command.
    /// Called from: Register and the repair check.
    /// </summary>
    private static string ExePath => Environment.ProcessPath ?? "";

    /// <summary>
    /// Picks the icon for the menu entry. Prefers ClamHub.ico next to the EXE,
    /// then the embedded EXE icon. Called from: Register.
    /// </summary>
    private static string IconPath()
    {
        if (File.Exists(AppPaths.IconFile)) return AppPaths.IconFile;
        // The EXE embeds the same icon; ",0" selects its first icon resource.
        return ExePath.Length > 0 ? $"{ExePath},0" : ExePath;
    }

    /// <summary>
    /// True when the context menu entry exists for files.
    /// Called from: settings tab to set the checkbox state.
    /// </summary>
    public static bool IsRegistered()
        => Registry.CurrentUser.OpenSubKey(FileKey) != null;

    /// <summary>
    /// True when the entry exists but points at a different EXE path than the
    /// one currently running (portable folder was moved). Called from: settings tab.
    /// </summary>
    public static bool NeedsRepair()
    {
        using var key = Registry.CurrentUser.OpenSubKey(FileKey + @"\command");
        if (key?.GetValue(null) is not string command) return false;
        return !command.Contains($"\"{ExePath}\"", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Creates (or refreshes) the context menu entry for files and folders.
    /// Re-running it after a folder move repairs the stored paths.
    /// Called from: settings tab when the checkbox is enabled or Repair is used.
    /// </summary>
    public static void Register(out string? error)
    {
        error = null;
        try
        {
            string icon = IconPath();
            string command = $"\"{ExePath}\" --scan \"%1\"";

            WriteVerb(FileKey, command, icon);
            WriteVerb(DirectoryKey, command, icon);
            // Background entry scans the folder currently open in Explorer (%V).
            WriteVerb(DirectoryBgKey, $"\"{ExePath}\" --scan \"%V\"", icon);
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }
    }

    /// <summary>
    /// Removes the context menu entry from all three classes.
    /// Called from: settings tab when the checkbox is disabled.
    /// </summary>
    public static void Unregister(out string? error)
    {
        error = null;
        try
        {
            DeleteTree(FileKey);
            DeleteTree(DirectoryKey);
            DeleteTree(DirectoryBgKey);
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }
    }

    /// <summary>
    /// Writes one shell verb: label, icon and the command subkey.
    /// Called from: Register.
    /// </summary>
    private static void WriteVerb(string verbKey, string command, string icon)
    {
        using var key = Registry.CurrentUser.CreateSubKey(verbKey);
        key.SetValue(null, MenuLabel);
        key.SetValue("Icon", icon);
        using var cmd = key.CreateSubKey("command");
        cmd.SetValue(null, command);
    }

    /// <summary>Deletes a verb key and its subkeys if present. Called from: Unregister.</summary>
    private static void DeleteTree(string verbKey)
    {
        if (Registry.CurrentUser.OpenSubKey(verbKey) != null)
            Registry.CurrentUser.DeleteSubKeyTree(verbKey);
    }
}
