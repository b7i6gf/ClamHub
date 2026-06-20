using System.Windows;
using System.Windows.Input;

namespace ClamHub;

/// <summary>
/// Small modal dialog (same dark style as the About box) that asks how to
/// rebuild a config file: keep the current settings, reset to defaults, or
/// cancel. Replaces the plain Windows message box.
/// Opened from: MainWindow.Settings.cs (AskRebuild).
/// </summary>
public partial class RebuildConfigDialog : Window
{
    /// <summary>The choice the user made; defaults to Cancel.</summary>
    public enum RebuildChoice { Cancel, KeepSettings, Defaults }

    /// <summary>Result read by the caller after ShowDialog returns.</summary>
    public RebuildChoice Choice { get; private set; } = RebuildChoice.Cancel;

    /// <summary>
    /// Builds the dialog and fills in which file(s) will be rebuilt.
    /// Called from: AskRebuild.
    /// </summary>
    public RebuildConfigDialog(string what)
    {
        InitializeComponent();
        MessageText.Text =
            $"This rewrites {what} so the database and log paths point at the correct " +
            "folders (useful after moving the app).\n\n" +
            "Keep settings: carry over your current values; only the paths are reset.\n" +
            "Reset to defaults: discard changes and write first-run defaults.";
    }

    /// <summary>Keep current values. Called from: the Keep settings button.</summary>
    private void Keep_Click(object sender, RoutedEventArgs e)
    {
        Choice = RebuildChoice.KeepSettings;
        DialogResult = true;
    }

    /// <summary>Reset to defaults. Called from: the Reset to defaults button.</summary>
    private void Defaults_Click(object sender, RoutedEventArgs e)
    {
        Choice = RebuildChoice.Defaults;
        DialogResult = true;
    }

    /// <summary>Abort without changes. Called from: the Cancel button.</summary>
    private void Cancel_Click(object sender, RoutedEventArgs e)
        => DialogResult = false;

    /// <summary>Allows dragging the borderless dialog. Called from: window MouseLeftButtonDown.</summary>
    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }
}
