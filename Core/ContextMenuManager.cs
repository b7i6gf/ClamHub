using System.IO;
using ClamHub.Models;
using Microsoft.Win32;

namespace ClamHub.Core;

/// <summary>
/// Registers and removes ClamHub's Windows context menu entries for files and
/// folders. Everything is written under HKEY_CURRENT_USER\Software\Classes so no
/// administrator rights are needed. The set of entries is data driven (see the
/// Actions table) so new options can be added in one place; each leaf launches the
/// EXE with "--action &lt;id&gt; [--infected &lt;a&gt;] --path &lt;path&gt;". The
/// menu is built from a small recursive node model, so an entry can itself be a
/// submenu: when settings.ContextMenuScanActionSelectable is on, "Scan with ClamHub"
/// expands into a Report / Quarantine / Remove submenu. Multiple entries are shown
/// either nested under one cascading "ClamHub" submenu or inline
/// (settings.ContextMenuGrouping); a single applicable entry is always written flat.
/// Which entries appear is OPT-IN: only ids in settings.ContextMenuEnabledActions are
/// written (the VirusTotal entry additionally needs an API key). SyncToSettings()
/// makes the registry match the settings at startup (and repairs a moved folder).
/// Called from: App.OnStartup (sync) and the settings tab (MainWindow.Settings.cs).
/// </summary>
public static class ContextMenuManager
{
    /// <summary>
    /// Which Explorer right-click targets an action applies to. File = a selected
    /// file (* class), Directory = a selected folder, Background = the empty area
    /// inside an open folder (Directory\Background). Combined as flags.
    /// </summary>
    [Flags]
    public enum ContextScope
    {
        None = 0,
        File = 1,
        Directory = 2,
        Background = 4
    }

    /// <summary>
    /// One entry that can appear in the context menu. Id is stable and used both as
    /// the registry subkey suffix and the "--action" argument; Label is the menu
    /// text; Hint is the description shown as a tooltip in the ClamHub settings
    /// (Explorer itself does not show tooltips for custom verbs); Scopes limits where
    /// it applies; Order controls the position; RequiresVirusTotalKey gates the
    /// VirusTotal entry behind a configured API key.
    /// </summary>
    public sealed record ContextAction(
        string Id,
        string Label,
        string Hint,
        ContextScope Scopes,
        int Order,
        bool RequiresVirusTotalKey = false);

    /// <summary>
    /// The complete set of context menu actions. Add a new option here and add a
    /// matching branch in MainWindow.DispatchContextAction; nothing else needs to
    /// change. Consumed by: Register (what to write) and the settings UI (the
    /// per-action checkboxes and their tooltips).
    /// </summary>
    public static readonly ContextAction[] Actions =
    {
        new("scan", "Scan with ClamHub",
            "Scan the file or folder with ClamHub.",
            ContextScope.File | ContextScope.Directory | ContextScope.Background, 10),

        new("queue", "Add to Queue",
            "Add the file or folder to ClamHub's scan queue without scanning.",
            ContextScope.File | ContextScope.Directory | ContextScope.Background, 20),

        new("hash", "Compute Hash",
            "Compute the file's hashes in ClamHub (single files only).",
            ContextScope.File, 30),

        new("vt", "VirusTotal Report",
            "Look up the file's SHA256 on VirusTotal from ClamHub.",
            ContextScope.File, 40, RequiresVirusTotalKey: true),

        new("signature", "Put on list",
            "Blacklist or whitelist the file with ClamHub's own signatures (adds a Blacklist/Whitelist submenu).",
            ContextScope.File, 45),

        new("exclude", "Exclude Path",
            "Add the file or folder to ClamHub's permanent exclusions.",
            ContextScope.File | ContextScope.Directory | ContextScope.Background, 50),
    };

    // Shell subkey roots for the three relevant classes.
    private const string FileRoot = @"Software\Classes\*\shell";
    private const string DirectoryRoot = @"Software\Classes\Directory\shell";
    private const string BackgroundRoot = @"Software\Classes\Directory\Background\shell";

    /// <summary>
    /// A node in the context menu tree built for the registry: a leaf (has a
    /// Command) or a submenu (has Children). Order sets the position within its
    /// parent. Built by BuildNode / WriteScope, consumed by WriteNode.
    /// </summary>
    private sealed class MenuNode
    {
        public string Id = "";
        public int Order;
        public string Label = "";
        public string? Command;          // leaf: the shell command line
        public List<MenuNode>? Children; // submenu: child nodes (null for a leaf)
    }

    /// <summary>
    /// Absolute path to the running EXE, used in the shell command.
    /// Called from: the command builders and the repair check.
    /// </summary>
    private static string ExePath => Environment.ProcessPath ?? "";

    /// <summary>
    /// Picks the icon for the menu entries. Prefers ClamHub.ico next to the EXE,
    /// then the embedded EXE icon. Called from: WriteNode.
    /// </summary>
    private static string IconPath()
    {
        if (File.Exists(AppPaths.IconFile)) return AppPaths.IconFile;
        return ExePath.Length > 0 ? $"{ExePath},0" : ExePath;
    }

    /// <summary>
    /// True when any ClamHub context menu entry exists for files (submenu parent or
    /// inline verb). Called from: settings tab and SyncToSettings.
    /// </summary>
    public static bool IsRegistered()
    {
        using var shell = Registry.CurrentUser.OpenSubKey(FileRoot);
        if (shell == null) return false;
        foreach (var name in shell.GetSubKeyNames())
            if (IsClamHubKey(name)) return true;
        return false;
    }

    /// <summary>
    /// True when an entry exists but points at a different EXE path than the one
    /// currently running (portable folder was moved). Called from: settings tab and
    /// SyncToSettings.
    /// </summary>
    public static bool NeedsRepair()
    {
        string? command = FirstCommand(FileRoot);
        if (command == null) return false;
        return !command.Contains($"\"{ExePath}\"", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Makes the registry match the current settings: writes the enabled entries
    /// when any are selected (also fixing a moved-folder path or a changed layout),
    /// or removes everything when none are. Best effort. Called from: App.OnStartup
    /// on the primary instance.
    /// </summary>
    public static void SyncToSettings()
    {
        try
        {
            var s = SettingsManager.Current;
            bool hasVtKey = !string.IsNullOrWhiteSpace(s.VirusTotalApiKey);
            bool anyEnabled = EnabledActions(s, hasVtKey).Count > 0;

            if (anyEnabled) Register(out _);
            else if (IsRegistered()) Unregister(out _);
        }
        catch
        {
            // Startup sync is best effort; a failure must not block launch.
        }
    }

    /// <summary>
    /// Creates (or refreshes) all context menu entries per the current settings
    /// (which actions are enabled, submenu vs. inline, the scan-action submenu,
    /// VirusTotal key presence). Existing ClamHub keys are removed first so any
    /// change is applied cleanly. When no action is enabled this simply removes
    /// everything. Called from: settings tab on a change and SyncToSettings.
    /// </summary>
    public static void Register(out string? error)
    {
        error = null;
        try
        {
            var s = SettingsManager.Current;
            bool hasVtKey = !string.IsNullOrWhiteSpace(s.VirusTotalApiKey);
            var enabled = EnabledActions(s, hasVtKey);

            RemoveAll();

            WriteScope(FileRoot, "%1", ContextScope.File, enabled, s);
            WriteScope(DirectoryRoot, "%1", ContextScope.Directory, enabled, s);
            // The background entry acts on the folder currently open in Explorer (%V).
            WriteScope(BackgroundRoot, "%V", ContextScope.Background, enabled, s);
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }
    }

    /// <summary>
    /// Removes every ClamHub context menu entry from all three classes.
    /// Called from: settings tab (when no entry is selected) and SyncToSettings.
    /// </summary>
    public static void Unregister(out string? error)
    {
        error = null;
        try { RemoveAll(); }
        catch (Exception ex) { error = ex.Message; }
    }

    /// <summary>
    /// The actions to write: every action the user has enabled (opt-in), minus the
    /// VirusTotal entry when no API key is set, ordered by Order. Called from:
    /// Register and SyncToSettings.
    /// </summary>
    private static List<ContextAction> EnabledActions(AppSettings s, bool hasVtKey)
    {
        var on = s.ContextMenuEnabledActions;
        return Actions
            .Where(a => on.Contains(a.Id, StringComparer.OrdinalIgnoreCase))
            .Where(a => hasVtKey || !a.RequiresVirusTotalKey)
            .OrderBy(a => a.Order)
            .ToList();
    }

    /// <summary>
    /// Writes the entries for one shell root using only the actions applicable to
    /// that scope: nothing when none apply, a single flat verb when exactly one
    /// applies (grouping ignored), otherwise a cascading "ClamHub" submenu or a set
    /// of inline verbs per the grouping setting. Called from: Register.
    /// </summary>
    private static void WriteScope(string root, string pathToken, ContextScope scope,
        List<ContextAction> enabled, AppSettings s)
    {
        var applicable = enabled.Where(a => a.Scopes.HasFlag(scope)).ToList();
        if (applicable.Count == 0) return;

        var nodes = applicable.Select(a => BuildNode(a, pathToken, s)).ToList();

        if (nodes.Count == 1)
        {
            WriteTopNode(root, nodes[0]);
        }
        else if (s.ContextMenuGrouping == ContextMenuGrouping.Inline)
        {
            foreach (var node in nodes) WriteTopNode(root, node);
        }
        else
        {
            var parent = new MenuNode { Id = "ClamHub", Label = "ClamHub", Children = nodes };
            WriteTopNode(root, parent, keyNameOverride: "ClamHub");
        }
    }

    /// <summary>
    /// Turns one action into a menu node: normally a leaf, but the scan action
    /// becomes a Report / Quarantine / Remove submenu when the setting is on.
    /// Called from: WriteScope.
    /// </summary>
    private static MenuNode BuildNode(ContextAction action, string pathToken, AppSettings s)
    {
        if (action.Id == "scan" && s.ContextMenuScanActionSelectable)
        {
            return new MenuNode
            {
                Id = action.Id,
                Order = action.Order,
                Label = action.Label,
                Children = new List<MenuNode>
                {
                    new() { Id = "report",     Order = 10, Label = "Report",     Command = ScanCommand("report", pathToken) },
                    new() { Id = "quarantine", Order = 20, Label = "Quarantine", Command = ScanCommand("quarantine", pathToken) },
                    new() { Id = "remove",     Order = 30, Label = "Remove",     Command = ScanCommand("remove", pathToken) },
                }
            };
        }

        if (action.Id == "signature")
        {
            // Always a Blacklist / Whitelist submenu (unlike scan, this is not gated
            // by a setting). Each leaf launches "--action blacklist|whitelist --path".
            return new MenuNode
            {
                Id = action.Id,
                Order = action.Order,
                Label = action.Label,
                Children = new List<MenuNode>
                {
                    new() { Id = "blacklist", Order = 10, Label = "Blacklist file", Command = CommandFor("blacklist", pathToken) },
                    new() { Id = "whitelist", Order = 20, Label = "Whitelist file", Command = CommandFor("whitelist", pathToken) },
                }
            };
        }

        return new MenuNode
        {
            Id = action.Id,
            Order = action.Order,
            Label = action.Label,
            Command = CommandFor(action.Id, pathToken)
        };
    }

    /// <summary>
    /// Writes a node as a top-level entry ("ClamHub.&lt;id&gt;", or a caller-supplied
    /// name for the synthetic "ClamHub" submenu parent). Called from: WriteScope.
    /// </summary>
    private static void WriteTopNode(string shellPath, MenuNode node, string? keyNameOverride = null)
        => WriteNode(shellPath, keyNameOverride ?? $"ClamHub.{node.Id}", node);

    /// <summary>
    /// Writes one node (leaf or submenu) under shellPath\keyName, recursing child
    /// nodes into keyName\shell. A submenu uses the registry SubCommands="" cascade
    /// (auto-populated from the child shell), which works nested and needs no admin;
    /// child key names are prefixed with the order so the position is controlled.
    /// Called from: WriteTopNode and itself (recursion).
    /// </summary>
    private static void WriteNode(string shellPath, string keyName, MenuNode node)
    {
        string icon = IconPath();
        string keyPath = $@"{shellPath}\{keyName}";

        if (node.Children == null)
        {
            using var key = Registry.CurrentUser.CreateSubKey(keyPath);
            key.SetValue(null, node.Label);   // (default) value = the displayed text
            key.SetValue("Icon", icon);
            using var cmd = key.CreateSubKey("command");
            cmd.SetValue(null, node.Command ?? "");
            return;
        }

        using (var key = Registry.CurrentUser.CreateSubKey(keyPath))
        {
            key.SetValue("MUIVerb", node.Label);
            key.SetValue("Icon", icon);
            key.SetValue("SubCommands", "");
        }

        string childShell = $@"{keyPath}\shell";
        foreach (var child in node.Children)
            WriteNode(childShell, $"{child.Order:D3}_{child.Id}", child);
    }

    /// <summary>
    /// Builds the shell command for a leaf action: the EXE plus "--action &lt;id&gt;"
    /// and the path (%1 for a selected file/folder, %V for a folder background).
    /// Called from: BuildNode.
    /// </summary>
    private static string CommandFor(string id, string pathToken)
        => $"\"{ExePath}\" --action {id} --path \"{pathToken}\"";

    /// <summary>
    /// Builds the shell command for a scan with a specific infected-file action
    /// (report / quarantine / remove). Called from: BuildNode.
    /// </summary>
    private static string ScanCommand(string infected, string pathToken)
        => $"\"{ExePath}\" --action scan --infected {infected} --path \"{pathToken}\"";

    /// <summary>
    /// Deletes every ClamHub key (submenu parents, inline verbs and any legacy
    /// single "Scan with ClamHub" verb) from all three scopes. Called from: Register
    /// and Unregister.
    /// </summary>
    private static void RemoveAll()
    {
        RemoveScope(FileRoot);
        RemoveScope(DirectoryRoot);
        RemoveScope(BackgroundRoot);
    }

    /// <summary>
    /// Removes all ClamHub subkeys from one shell root. Called from: RemoveAll.
    /// </summary>
    private static void RemoveScope(string root)
    {
        using var shell = Registry.CurrentUser.OpenSubKey(root, writable: true);
        if (shell == null) return;
        foreach (var name in shell.GetSubKeyNames())
            if (IsClamHubKey(name))
                shell.DeleteSubKeyTree(name, throwOnMissingSubKey: false);
    }

    /// <summary>
    /// True when a shell subkey name belongs to ClamHub: the submenu parent /
    /// legacy single verb ("ClamHub") or an inline verb ("ClamHub.&lt;id&gt;").
    /// Called from: IsRegistered, RemoveScope and FirstCommand.
    /// </summary>
    private static bool IsClamHubKey(string name)
        => name.Equals("ClamHub", StringComparison.OrdinalIgnoreCase)
           || name.StartsWith("ClamHub.", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Returns the first command string found under any ClamHub key in the given
    /// scope (searches submenu children and inline verbs), or null when none exists.
    /// Used to detect a stale EXE path after the folder was moved. Called from:
    /// NeedsRepair.
    /// </summary>
    private static string? FirstCommand(string root)
    {
        using var shell = Registry.CurrentUser.OpenSubKey(root);
        if (shell == null) return null;
        foreach (var name in shell.GetSubKeyNames())
        {
            if (!IsClamHubKey(name)) continue;
            using var sub = shell.OpenSubKey(name);
            var cmd = FindCommandRecursive(sub);
            if (cmd != null) return cmd;
        }
        return null;
    }

    /// <summary>
    /// Walks a key and its subkeys and returns the first "command" default value
    /// found (works for flat verbs and nested submenus). Called from: FirstCommand.
    /// </summary>
    private static string? FindCommandRecursive(RegistryKey? key)
    {
        if (key == null) return null;
        using (var command = key.OpenSubKey("command"))
            if (command?.GetValue(null) is string direct) return direct;

        foreach (var childName in key.GetSubKeyNames())
        {
            using var child = key.OpenSubKey(childName);
            var found = FindCommandRecursive(child);
            if (found != null) return found;
        }
        return null;
    }
}
