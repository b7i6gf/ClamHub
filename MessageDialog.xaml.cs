using System.Windows;
using System.Windows.Input;

namespace ClamHub;

/// <summary>
/// Reusable modal dialog in the same dark style as the About box. Used for
/// confirmations (confirm + cancel button) and information (single button).
/// Replaces the Windows MessageBox so the app has no standard system dialogs.
/// Opened from: MainWindow Confirm/Inform helpers.
/// </summary>
public partial class MessageDialog : Window
{
    /// <summary>
    /// Builds the dialog. A null cancelLabel hides the second button, turning it
    /// into a single-button info dialog. Called from: Confirm and Inform.
    /// </summary>
    public MessageDialog(string title, string message, string confirmLabel, string? cancelLabel)
    {
        InitializeComponent();
        TitleText.Text = title;
        MessageText.Text = message;
        ConfirmButton.Content = confirmLabel;

        if (cancelLabel == null)
            CancelButton.Visibility = Visibility.Collapsed;
        else
            CancelButton.Content = cancelLabel;
    }

    /// <summary>Confirms (or dismisses an info dialog). Called from: the confirm button.</summary>
    private void Confirm_Click(object sender, RoutedEventArgs e)
        => DialogResult = true;

    /// <summary>Cancels. Called from: the cancel button.</summary>
    private void Cancel_Click(object sender, RoutedEventArgs e)
        => DialogResult = false;

    /// <summary>Allows dragging the borderless dialog. Called from: window MouseLeftButtonDown.</summary>
    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }
}
