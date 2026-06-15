namespace ClamAVGui.Core;

/// <summary>
/// App wide one way hook for non fatal background errors (for example a failed
/// save), so the Core layer can surface a message without knowing about windows
/// or dialogs. The MainWindow subscribes at startup and shows the message.
/// Called from: the JSON managers (report on save failure), MainWindow (subscribe).
/// </summary>
public static class AppNotifications
{
    /// <summary>Raised with a user facing message when a non fatal error occurs.</summary>
    public static event Action<string>? ErrorOccurred;

    /// <summary>
    /// Reports a non fatal error message to whoever is listening (no-op when
    /// nobody subscribed yet). Called from: the JSON managers' Save methods.
    /// </summary>
    public static void ReportError(string message) => ErrorOccurred?.Invoke(message);
}
