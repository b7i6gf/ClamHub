using System;
using System.Collections.Generic;
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

    /// <summary>Seeds the window with the output collected so far (URLs clickable).
    /// Called from: MainWindow.OpenConsoleWindow.</summary>
    public void SetLines(IEnumerable<string> lines) => ConsoleFormatting.SetLines(ConsoleBox, lines);

    /// <summary>Appends one line (URLs become clickable). Called from: MainWindow.AppendLine.</summary>
    public void AppendLine(string line) => ConsoleFormatting.AppendLine(ConsoleBox, line);

    /// <summary>Clears the output. Called from: MainWindow when the console is cleared.</summary>
    public void Clear() => ConsoleFormatting.Clear(ConsoleBox);

    /// <summary>Clears both windows. Called from: the Clear button.</summary>
    private void Clear_Click(object sender, RoutedEventArgs e) => ClearRequested?.Invoke();

    /// <summary>Opens the logs folder via the main window. Called from: the Open logs button.</summary>
    private void OpenLogs_Click(object sender, RoutedEventArgs e) => OpenLogsRequested?.Invoke();

    /// <summary>Minimizes the window. Called from: the minimize button.</summary>
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    /// <summary>Closes the window. Called from: the close button.</summary>
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
