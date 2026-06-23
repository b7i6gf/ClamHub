using System.ComponentModel;
using System.Windows;

namespace ClamHub;

/// <summary>
/// Small dark wait window shown ONLY during the initial signature database
/// download (not routine updates). It has no close button and refuses manual
/// closing so the user waits; the caller closes it via CloseForced when the
/// download finishes. Created by: MainWindow.RunSignatureUpdateAsync.
/// </summary>
public partial class DbDownloadWindow : Window
{
    private bool _allowClose;

    /// <summary>Builds the wait window. Called from: MainWindow.RunSignatureUpdateAsync.</summary>
    public DbDownloadWindow()
    {
        InitializeComponent();
        Closing += BlockManualClose;
    }

    /// <summary>
    /// Cancels user-initiated closing so the wait gate stays up until the
    /// download ends. Called from: the Closing event.
    /// </summary>
    private void BlockManualClose(object? sender, CancelEventArgs e)
    {
        if (!_allowClose) e.Cancel = true;
    }

    /// <summary>
    /// Closes the window from code once the download is complete.
    /// Called from: MainWindow.RunSignatureUpdateAsync (finally block).
    /// </summary>
    public void CloseForced()
    {
        _allowClose = true;
        Close();
    }
}
