using System.Windows;
using System.Windows.Controls;
using ClamHub.Core;
using ClamHub.Models;

namespace ClamHub;

/// <summary>
/// Settings tab logic: GUI options (settings.json) and the typed editors for
/// clamd.conf and freshclam.conf. Kept as a partial class so MainWindow.xaml.cs
/// stays focused on daemon/scan/hash handling.
/// Created by: same instance as MainWindow; initialized from InitializeAsync.
/// </summary>
public partial class MainWindow
{
    private ClamConfFile? _clamdConf;
    private ClamConfFile? _freshConf;
    private readonly Dictionary<string, FrameworkElement> _clamdInputs = new();
    private readonly Dictionary<string, FrameworkElement> _freshInputs = new();

    /// <summary>Placeholder shown in the API key box once a key is stored.</summary>
    private const string VtKeyMask = "****************";

    /// <summary>Suppresses dirty marking while controls are filled programmatically.</summary>
    private bool _settingsLoading;

    /// <summary>
    /// Sets the colored save indicator at the bottom of the Settings tab.
    /// brushKey is a resource key (OkBrush/WarnBrush/DangerBrush) or null to clear.
    /// Called from: MarkSettingsDirty and all save/reload/context handlers.
    /// </summary>
    private void SetSettingsStatus(string text, string? brushKey)
    {
        SettingsStatusText.Text = text;
        SettingsStatusDot.Fill = brushKey == null
            ? System.Windows.Media.Brushes.Transparent
            : (System.Windows.Media.Brush)FindResource(brushKey);
        SettingsStatusText.Foreground = brushKey == null
            ? (System.Windows.Media.Brush)FindResource("MutedTextBrush")
            : (System.Windows.Media.Brush)FindResource(brushKey);
    }

    /// <summary>
    /// Marks the Settings tab as having unsaved edits (orange indicator).
    /// Called from: every settings input change, unless we are loading values.
    /// </summary>
    private void MarkSettingsDirty()
    {
        if (_settingsLoading) return;
        SetSettingsStatus("Unsaved changes", "WarnBrush");
    }

    /// <summary>
    /// Fills the GUI settings controls and builds both conf editors.
    /// Called from: MainWindow.InitializeAsync.
    /// </summary>
    private void InitializeSettingsTab()
    {
        _settingsLoading = true;

        var s = SettingsManager.Current;
        SetUseDaemon.IsChecked = s.UseDaemon;
        SetAutoStart.IsChecked = s.AutoStartDaemon;
        SetUpdateOnStart.IsChecked = s.UpdateOnStart;
        SetSound.IsChecked = s.SoundOnDetection;
        SetCountFiles.IsChecked = s.CountFilesOnDaemonScan;
        SetMultiScan.IsChecked = s.MultiScan;
        SetDefaultAction.SelectedIndex = (int)s.DefaultAction;
        // Show a mask instead of the stored key, both on load and after saving.
        SetVtKey.Text = string.IsNullOrEmpty(s.VirusTotalApiKey) ? "" : VtKeyMask;

        RefreshContextMenuState();
        LoadConfEditors();

        // GUI settings auto save: every change writes settings.json immediately.
        // Checkbox Click fires only on user interaction, not on the programmatic
        // IsChecked above, so the initial load does not save. The combo
        // SelectionChanged and the key field LostFocus are guarded by
        // _settingsLoading inside the save methods.
        SetUseDaemon.Click += (_, _) => AutoSaveGuiSettings();
        SetAutoStart.Click += (_, _) => AutoSaveGuiSettings();
        SetUpdateOnStart.Click += (_, _) => AutoSaveGuiSettings();
        SetSound.Click += (_, _) => AutoSaveGuiSettings();
        SetCountFiles.Click += (_, _) => AutoSaveGuiSettings();
        SetMultiScan.Click += (_, _) => AutoSaveGuiSettings();
        SetDefaultAction.SelectionChanged += (_, _) => AutoSaveGuiSettings();
        SetVtKey.LostFocus += (_, _) => SaveVtKeyOnBlur();

        _settingsLoading = false;
        SetSettingsStatus("", null);
    }

    /// <summary>
    /// Updates the context menu checkbox and the repair hint from the registry.
    /// Called from: InitializeSettingsTab and after every context menu action.
    /// </summary>
    private void RefreshContextMenuState()
    {
        bool registered = ContextMenuManager.IsRegistered();
        // Avoid firing the Click handler while setting the state programmatically.
        SetContextMenu.Click -= ContextMenu_Click;
        SetContextMenu.IsChecked = registered;
        SetContextMenu.Click += ContextMenu_Click;

        if (registered && ContextMenuManager.NeedsRepair())
            ContextMenuStatus.Text =
                "Entry points to a different location (folder moved). Untick and tick again to repair.";
        else if (registered)
            ContextMenuStatus.Text = "Active for files and folders.";
        else
            ContextMenuStatus.Text = "";
    }

    /// <summary>
    /// Registers or removes the Windows context menu entry when the checkbox
    /// is toggled. Called from: XAML Click binding of SetContextMenu.
    /// </summary>
    private void ContextMenu_Click(object sender, RoutedEventArgs e)
    {
        string? error;
        if (SetContextMenu.IsChecked == true)
        {
            ContextMenuManager.Register(out error);
            SetSettingsStatus(error == null
                ? "Context menu entry added." : $"Failed: {error}",
                error == null ? "OkBrush" : "DangerBrush");
        }
        else
        {
            ContextMenuManager.Unregister(out error);
            SetSettingsStatus(error == null
                ? "Context menu entry removed." : $"Failed: {error}",
                error == null ? "OkBrush" : "DangerBrush");
        }
        RefreshContextMenuState();
    }

    /// <summary>
    /// (Re)loads both conf files and rebuilds the editor rows from the schema.
    /// Called from: InitializeSettingsTab and the Reload buttons.
    /// </summary>
    private void LoadConfEditors()
    {
        bool wasLoading = _settingsLoading;
        _settingsLoading = true;
        _clamdConf = ClamConfFile.Load(AppPaths.ClamdConf);
        _freshConf = ClamConfFile.Load(AppPaths.FreshClamConf);
        BuildConfRows(ClamdConfPanel, _clamdConf, ConfigSchema.ClamdParams, _clamdInputs);
        BuildConfRows(FreshConfPanel, _freshConf, ConfigSchema.FreshClamParams, _freshInputs);
        _settingsLoading = wasLoading;
    }

    /// <summary>
    /// Reads the documented default ("[yes]" or "[no]") embedded in a bool
    /// parameter's hint. Returns true for yes, false for no (or when absent).
    /// Called from: BuildConfRows.
    /// </summary>
    private static bool ParseDefaultBool(string hint)
    {
        int yes = hint.LastIndexOf("[yes]", StringComparison.OrdinalIgnoreCase);
        int no = hint.LastIndexOf("[no]", StringComparison.OrdinalIgnoreCase);
        return yes > no;
    }

    /// <summary>
    /// Builds one label+control row per schema parameter. Bool parameters get
    /// a (default)/yes/no dropdown, everything else a text box. "(default)" or
    /// an empty text box means: remove the key so ClamAV uses its built-in
    /// default. Called from: LoadConfEditors.
    /// </summary>
    private void BuildConfRows(StackPanel host, ClamConfFile conf,
        ConfigSchema.ConfParam[] schema, Dictionary<string, FrameworkElement> inputs)
    {
        host.Children.Clear();
        inputs.Clear();

        foreach (var param in schema)
        {
            // Section headers are not editable, they only group the rows below.
            if (param.Type == ConfigSchema.ParamType.Header)
            {
                host.Children.Add(new TextBlock
                {
                    Text = param.Key,
                    FontWeight = FontWeights.SemiBold,
                    Opacity = 0.7,
                    Margin = new Thickness(0, host.Children.Count == 0 ? 0 : 14, 0, 4)
                });
                continue;
            }

            // Right margin keeps inputs off the scrollbar.
            var row = new Grid { Margin = new Thickness(0, 5, 10, 5) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(110) });

            var label = new TextBlock
            {
                Text = param.Key,
                VerticalAlignment = VerticalAlignment.Center,
                ToolTip = param.Hint,
                Margin = new Thickness(0, 0, 8, 0)
            };
            Grid.SetColumn(label, 0);
            row.Children.Add(label);

            var current = conf.GetValue(param.Key);
            FrameworkElement input;

            // ExcludePath is multi-valued and managed by the exclusions dialog
            // (same list as the scan "Exclusions..." button), so offer a button
            // instead of a single text field. Not added to inputs: it is written
            // via ConfigManager.WriteClamdExclusions, not ApplyConfRows.
            if (param.Key == "ExcludePath")
            {
                var btn = new Button
                {
                    Content = "Manage list...",
                    Height = 28,
                    Padding = new Thickness(12, 0, 12, 0),
                    ToolTip = param.Hint
                };
                btn.Click += (_, _) => OpenExclusionsFromSettings();
                Grid.SetColumn(btn, 1);
                row.Children.Add(btn);
                host.Children.Add(row);
                continue;
            }

            if (param.Type == ConfigSchema.ParamType.Bool)
            {
                // yes/no only; the documented default is preselected when the
                // key is absent, instead of a separate "(default)" entry.
                var combo = new ComboBox { Height = 24, ToolTip = param.Hint };
                combo.Items.Add(new ComboBoxItem { Content = "yes" });
                combo.Items.Add(new ComboBoxItem { Content = "no" });
                bool def = ParseDefaultBool(param.Hint);
                combo.SelectedIndex = current?.ToLowerInvariant() switch
                {
                    "yes" or "true" or "1" => 0,
                    "no" or "false" or "0" => 1,
                    _ => def ? 0 : 1
                };
                // Attach after setting the value so the initial fill is not dirty.
                combo.SelectionChanged += (_, _) => MarkSettingsDirty();
                input = combo;
            }
            else
            {
                var box = new TextBox
                {
                    Height = 24,
                    Text = current ?? "",
                    VerticalContentAlignment = VerticalAlignment.Center,
                    ToolTip = param.Hint
                };
                box.TextChanged += (_, _) => MarkSettingsDirty();
                input = box;
            }

            Grid.SetColumn(input, 1);
            row.Children.Add(input);
            host.Children.Add(row);
            inputs[param.Key] = input;
        }
    }

    /// <summary>
    /// Writes all editor rows back into a conf model and saves it. Cleared
    /// fields remove the key (ClamAV default applies).
    /// Called from: SaveClamdConf_Click and SaveFreshConf_Click.
    /// </summary>
    private static void ApplyConfRows(ClamConfFile conf,
        Dictionary<string, FrameworkElement> inputs)
    {
        foreach (var (key, element) in inputs)
        {
            switch (element)
            {
                case ComboBox combo:
                    // yes/no dropdown is always written explicitly.
                    conf.SetValue(key, combo.SelectedIndex == 0 ? "yes" : "no");
                    break;

                case TextBox box:
                    var value = box.Text.Trim();
                    if (value.Length == 0) conf.Remove(key);
                    else conf.SetValue(key, value);
                    break;
            }
        }
        conf.Save();
    }

    /// <summary>
    /// Clears the stored VirusTotal API key immediately: empties the field,
    /// removes it from settings.json and disables the VirusTotal buttons.
    /// Called from: XAML Click binding of the red clear button.
    /// </summary>
    private void ClearVtKey_Click(object sender, RoutedEventArgs e)
    {
        _settingsLoading = true;
        SetVtKey.Text = "";
        _settingsLoading = false;

        SettingsManager.Current.VirusTotalApiKey = "";
        SettingsManager.Save();
        RefreshVirusTotalButtons();
        SetSettingsStatus("VirusTotal API key removed.", "OkBrush");
    }

    /// <summary>
    /// Reads the GUI settings column into settings.json and saves immediately.
    /// Used for auto save, so it is silent on success apart from a status line.
    /// Called from: the change handlers wired in InitializeSettingsTab and from
    /// SaveVtKeyOnBlur.
    /// </summary>
    private void AutoSaveGuiSettings()
    {
        if (_settingsLoading) return;
        try
        {
            var s = SettingsManager.Current;
            s.UseDaemon = SetUseDaemon.IsChecked == true;
            s.AutoStartDaemon = SetAutoStart.IsChecked == true;
            s.UpdateOnStart = SetUpdateOnStart.IsChecked == true;
            s.SoundOnDetection = SetSound.IsChecked == true;
            s.CountFilesOnDaemonScan = SetCountFiles.IsChecked == true;
            s.MultiScan = SetMultiScan.IsChecked == true;
            s.DefaultAction = (InfectedFileAction)SetDefaultAction.SelectedIndex;

            // Only overwrite the stored key when the user actually typed a new
            // one; the mask means "unchanged".
            var typedKey = SetVtKey.Text.Trim();
            if (typedKey != VtKeyMask)
                s.VirusTotalApiKey = typedKey;

            if (!SettingsManager.Save())
            {
                SetSettingsStatus("Settings could not be saved.", "DangerBrush");
                return;
            }

            RefreshVirusTotalButtons();
            SetSettingsStatus("Settings saved.", "OkBrush");
        }
        catch (Exception ex)
        {
            SetSettingsStatus($"Save failed: {ex.Message}", "DangerBrush");
        }
    }

    /// <summary>
    /// Saves a freshly entered VirusTotal API key when the field loses focus,
    /// then re-masks it so the stored key is never shown.
    /// Called from: the LostFocus wiring in InitializeSettingsTab.
    /// </summary>
    private void SaveVtKeyOnBlur()
    {
        if (_settingsLoading) return;
        AutoSaveGuiSettings();
        _settingsLoading = true;
        var key = SettingsManager.Current.VirusTotalApiKey;
        SetVtKey.Text = string.IsNullOrEmpty(key) ? "" : VtKeyMask;
        _settingsLoading = false;
    }

    /// <summary>
    /// Saves the clamd.conf editor. Syncs a changed TCPSocket port into the GUI
    /// settings (the daemon controller connects to that port) and reminds the
    /// user to restart a running daemon.
    /// Called from: XAML Click binding (clamd.conf Save).
    /// </summary>
    private async void SaveClamdConf_Click(object sender, RoutedEventArgs e)
    {
        if (_clamdConf == null) return;
        try
        {
            ApplyConfRows(_clamdConf, _clamdInputs);

            // Keep the GUI's connection port in sync with the daemon config.
            var portText = _clamdConf.GetValue("TCPSocket");
            if (int.TryParse(portText, out var port) && port != SettingsManager.Current.ClamdPort)
            {
                SettingsManager.Current.ClamdPort = port;
                SettingsManager.Save();
            }

            string note = await DaemonController.IsRunningAsync(1000)
                ? " Restart the daemon to apply."
                : "";
            SetSettingsStatus($"clamd.conf saved.{note}", "OkBrush");
        }
        catch (Exception ex)
        {
            SetSettingsStatus($"Save failed: {ex.Message}", "DangerBrush");
        }
    }

    /// <summary>
    /// Saves the freshclam.conf editor.
    /// Called from: XAML Click binding (freshclam.conf Save).
    /// </summary>
    private void SaveFreshConf_Click(object sender, RoutedEventArgs e)
    {
        if (_freshConf == null) return;
        try
        {
            ApplyConfRows(_freshConf, _freshInputs);
            SetSettingsStatus("freshclam.conf saved.", "OkBrush");
        }
        catch (Exception ex)
        {
            SetSettingsStatus($"Save failed: {ex.Message}", "DangerBrush");
        }
    }

    /// <summary>
    /// Discards unsaved editor changes and reloads both files from disk.
    /// Called from: XAML Click binding (both Reload buttons).
    /// </summary>
    private void ReloadConfEditors_Click(object sender, RoutedEventArgs e)
    {
        LoadConfEditors();
        SetSettingsStatus("Reloaded from disk.", null);
    }

    /// <summary>
    /// Opens the raw conf file in the default text editor for parameters the
    /// typed editor does not cover. Called from: XAML Click binding (Open file).
    /// </summary>
    private void OpenConfFile_Click(object sender, RoutedEventArgs e)
    {
        var path = (sender as Button)?.Tag as string == "clamd"
            ? AppPaths.ClamdConf
            : AppPaths.FreshClamConf;
        try
        {
            System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo { FileName = path, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            AppendLine($"Could not open {path}: {ex.Message}");
        }
    }

    /// <summary>
    /// Rebuilds the clamd.conf or freshclam.conf chosen via the button Tag, after
    /// asking whether to keep the current settings. The database and log paths are
    /// always reset to the correct folders. Called from: XAML Click binding of the
    /// per-file "Rebuild config" buttons.
    /// </summary>
    private void RebuildConfig_Click(object sender, RoutedEventArgs e)
    {
        var target = (sender as FrameworkElement)?.Tag as string == "freshclam"
            ? ConfigManager.ConfigTarget.FreshClam
            : ConfigManager.ConfigTarget.Clamd;
        string name = target == ConfigManager.ConfigTarget.FreshClam ? "freshclam.conf" : "clamd.conf";

        if (!AskRebuild(name, out bool transfer)) return;

        try
        {
            ConfigManager.RebuildConfig(target, transfer);
        }
        catch (Exception ex)
        {
            SetSettingsStatus($"Could not rebuild {name}: {ex.Message}", "DangerBrush");
            return;
        }

        LoadConfEditors();
        AppendSection("REBUILD CONFIG");
        AppendLine($"{name} rebuilt ({(transfer ? "settings kept" : "defaults")}). Restart the daemon to apply.");
        SetSettingsStatus($"{name} rebuilt. Restart the daemon to apply.", "OkBrush");
    }

    /// <summary>
    /// Rebuilds both config files at once with the same transfer choice.
    /// Called from: XAML Click binding of the "Rebuild all configs" button.
    /// </summary>
    private void RebuildAllConfigs_Click(object sender, RoutedEventArgs e)
    {
        if (!AskRebuild("clamd.conf and freshclam.conf", out bool transfer)) return;

        try
        {
            ConfigManager.RebuildAllConfigs(transfer);
        }
        catch (Exception ex)
        {
            SetSettingsStatus($"Could not rebuild configs: {ex.Message}", "DangerBrush");
            return;
        }

        LoadConfEditors();
        AppendSection("REBUILD CONFIG");
        AppendLine($"clamd.conf and freshclam.conf rebuilt ({(transfer ? "settings kept" : "defaults")}). Restart the daemon to apply.");
        SetSettingsStatus("Configs rebuilt. Restart the daemon to apply.", "OkBrush");
    }

    /// <summary>
    /// Asks (via the custom RebuildConfigDialog) whether to rebuild and whether
    /// to keep the current values. Returns false when cancelled; otherwise sets
    /// transfer (true = keep settings, false = first-run defaults). Called from:
    /// the rebuild handlers.
    /// </summary>
    private bool AskRebuild(string what, out bool transfer)
    {
        transfer = false;
        var dialog = new RebuildConfigDialog(what) { Owner = this };
        if (dialog.ShowDialog() != true) return false;
        transfer = dialog.Choice == RebuildConfigDialog.RebuildChoice.KeepSettings;
        return true;
    }
}
