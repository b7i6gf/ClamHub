using System.Diagnostics;
using System.Windows;
using System.Windows.Input;
using System.Windows.Navigation;

namespace ClamAVGui;

/// <summary>
/// Small modal About dialog. Shows the product name, version and a clickable
/// link to the GitHub repository. Opened from the title bar About button.
/// </summary>
public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Opens the clicked hyperlink in the default browser.
    /// Called from: the GitHub Hyperlink RequestNavigate event.
    /// </summary>
    private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = e.Uri.AbsoluteUri,
                UseShellExecute = true
            });
        }
        catch
        {
            // Ignore: if no browser is available there is nothing useful to do.
        }
        e.Handled = true;
    }

    /// <summary>Allows dragging the borderless dialog. Called from: window MouseLeftButtonDown.</summary>
    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    /// <summary>Closes the dialog. Called from: Close button.</summary>
    private void Close_Click(object sender, RoutedEventArgs e)
        => Close();
}
