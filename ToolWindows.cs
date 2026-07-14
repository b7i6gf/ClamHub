using System;
using System.Windows;

namespace ClamHub;

/// <summary>
/// Opens the non-modal tool windows (Detections, Signature search, Manage lists,
/// Custom database URLs, detached Console) WITHOUT a WPF Owner. An owned window
/// always floats above its owner, which made it impossible to bring the main
/// window in front of an open tool window by clicking it (v1.0.3.6 user request).
/// Without an owner the normal click-to-front z-order applies. The centering that
/// WindowStartupLocation=CenterOwner used to provide is done manually here, and
/// MainWindow.Window_Closing closes every remaining window so none of them keeps
/// the app alive after the main window is gone. Real dialogs (MessageDialog,
/// Exclusions, About, UpdateCheck, ScanQueue, DbDownload, RebuildConfig) keep
/// their Owner on purpose: they are modal and should stay in front of their
/// caller. Called from: the window openers in MainWindow and DetectionsWindow.
/// </summary>
public static class ToolWindows
{
    /// <summary>
    /// Shows a tool window centered over the reference window (or the screen when
    /// the reference is maximized/minimized), without making it an owned window.
    /// Called from: MainWindow (Detections/Signature search/Manage lists/Custom
    /// URLs/Console openers) and DetectionsWindow (Compare signature).
    /// </summary>
    public static void Show(Window window, Window reference)
    {
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        if (reference.WindowState == WindowState.Normal
            && !double.IsNaN(reference.Left) && !double.IsNaN(reference.Top))
        {
            double width = double.IsNaN(window.Width) ? 0 : window.Width;
            double height = double.IsNaN(window.Height) ? 0 : window.Height;
            double left = reference.Left + (reference.ActualWidth - width) / 2;
            double top = reference.Top + (reference.ActualHeight - height) / 2;
            // Keep the window on the virtual desktop (multi-monitor safe).
            left = Math.Max(SystemParameters.VirtualScreenLeft,
                Math.Min(left, SystemParameters.VirtualScreenLeft + SystemParameters.VirtualScreenWidth - width));
            top = Math.Max(SystemParameters.VirtualScreenTop,
                Math.Min(top, SystemParameters.VirtualScreenTop + SystemParameters.VirtualScreenHeight - height));
            window.Left = left;
            window.Top = top;
        }
        else
        {
            window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }
        window.Show();
    }
}
