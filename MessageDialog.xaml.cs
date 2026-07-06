using System.Windows;
using System.Windows.Input;

namespace ClamHub;

/// <summary>
/// Reusable modal dialog in the same dark style as the About box. Used for
/// confirmations (confirm + cancel button) and information (single button).
/// Replaces the Windows message box so the app has no standard system dialogs.
/// Opened from: MainWindow Confirm/Inform helpers.
/// </summary>
public partial class MessageDialog : Window
{
    /// <summary>
    /// Builds the dialog. A null cancelLabel hides the second button (single-button
    /// info dialog). A non-null extraLabel shows an optional third button that closes
    /// with a null ShowDialog result (used as an abort/Cancel). Called from: Confirm,
    /// Inform and OfferClamAvSetupAsync.
    /// </summary>
    public MessageDialog(string title, string message, string confirmLabel, string? cancelLabel,
        string? extraLabel = null)
    {
        InitializeComponent();
        TitleText.Text = title;
        MessageText.Text = message;
        ConfirmButton.Content = confirmLabel;

        if (cancelLabel == null)
            CancelButton.Visibility = Visibility.Collapsed;
        else
            CancelButton.Content = cancelLabel;

        if (extraLabel != null)
        {
            ExtraButton.Content = extraLabel;
            ExtraButton.Visibility = Visibility.Visible;
        }
    }

    /// <summary>
    /// Which button closed the dialog ("confirm" / "cancel" / "extra", or null when
    /// closed otherwise). Lets a 3-button caller distinguish the extra button without
    /// relying on the ShowDialog() return. Read by OfferClamAvSetupAsync.
    /// </summary>
    public string? ClickedButton { get; private set; }

    /// <summary>Confirms (or dismisses an info dialog). Called from: the confirm button.</summary>
    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        ClickedButton = "confirm";
        DialogResult = true;
    }

    /// <summary>Cancels. Called from: the cancel button.</summary>
    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        ClickedButton = "cancel";
        DialogResult = false;
    }

    /// <summary>Third option (abort): records the choice and closes. Called from: the extra button.</summary>
    private void Extra_Click(object sender, RoutedEventArgs e)
    {
        ClickedButton = "extra";
        Close();
    }

    /// <summary>Allows dragging the borderless dialog. Called from: window MouseLeftButtonDown.</summary>
    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }
}
