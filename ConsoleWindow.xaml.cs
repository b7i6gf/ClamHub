using System;
using System.Windows;

namespace ClamHub;

/// <summary>
/// Separate output window used by the "Output in a separate window" view.
/// Mirrors the main console text. When the user closes it, the main window
/// switches the view back to the bottom dock (handled via the Closed event).
/// </summary>
public partial class ConsoleWindow : Window
{
    /// <summary>Raised when the user clicks Clear, so the main console clears too.</summary>
    public event Action? ClearRequested;

    /// <summary>Raised when the user clicks Open logs folder.</summary>
    public event Action? OpenLogsRequested;

    public ConsoleWindow()
    {
        InitializeComponent();
    }

    /// <summary>Replaces the whole text (used to seed existing output on open).</summary>
    public void SetText(string text)
    {
        ConsoleBox.Text = text;
        ConsoleBox.ScrollToEnd();
    }

    /// <summary>Appends one line and scrolls to the end. Called from: MainWindow.AppendLine.</summary>
    public void AppendLine(string line)
    {
        ConsoleBox.AppendText(line + Environment.NewLine);
        ConsoleBox.ScrollToEnd();
    }

    /// <summary>Clears the output. Called from: MainWindow when the console is cleared.</summary>
    public void Clear() => ConsoleBox.Clear();

    /// <summary>Clears both windows. Called from: the Clear button.</summary>
    private void Clear_Click(object sender, RoutedEventArgs e) => ClearRequested?.Invoke();

    /// <summary>Opens the logs folder via the main window. Called from: the Open logs button.</summary>
    private void OpenLogs_Click(object sender, RoutedEventArgs e) => OpenLogsRequested?.Invoke();

    /// <summary>Closes the window. Called from: the close button.</summary>
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
