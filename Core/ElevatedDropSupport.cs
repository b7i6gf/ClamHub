using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace ClamHub.Core;

/// <summary>
/// Restores file drag and drop when the app runs elevated. Windows UIPI blocks
/// OLE drag and drop from the non-elevated Explorer into an elevated process,
/// which silently kills every WPF AllowDrop target. Workaround (the established
/// one for elevated apps): allow the legacy WM_DROPFILES path through the UIPI
/// message filter, unregister WPF's OLE drop target for the window (otherwise
/// WM_DROPFILES is never sent), accept legacy drops via DragAcceptFiles and
/// route them by cursor position to the same handlers the normal WPF drop
/// events use. Does NOTHING when the process is not elevated, so the regular
/// WPF drag and drop (with its per-element cursor feedback) stays untouched.
/// Called from: every window with drop targets (MainWindow, SignaturesWindow,
/// ExclusionsWindow, ScanQueueWindow, VerifierQueueWindow) after SourceInitialized.
/// </summary>
public static class ElevatedDropSupport
{
    private const uint WmDropFiles = 0x0233;
    private const uint WmCopyData = 0x004A;
    private const uint WmCopyGlobalData = 0x0049;
    private const uint MsgFltAllow = 1;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hwnd, uint message, uint action, IntPtr changeInfo);

    [DllImport("shell32.dll")]
    private static extern void DragAcceptFiles(IntPtr hwnd, bool accept);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern uint DragQueryFile(IntPtr hDrop, uint iFile, System.Text.StringBuilder? lpszFile, uint cch);

    [DllImport("shell32.dll")]
    private static extern bool DragQueryPoint(IntPtr hDrop, out System.Drawing.Point point);

    [DllImport("shell32.dll")]
    private static extern void DragFinish(IntPtr hDrop);

    [DllImport("ole32.dll")]
    private static extern int RevokeDragDrop(IntPtr hwnd);

    /// <summary>
    /// One drop target: an element and the path-based handler that also backs
    /// its normal WPF drop event.
    /// </summary>
    public sealed record Target(UIElement Element, Action<string[]> Handler);

    /// <summary>
    /// Enables the elevated drop path for a window. Call once the window has a
    /// handle (after SourceInitialized, e.g. from Loaded); safe no-op when the
    /// process is not elevated or the handle is missing. The targets are checked
    /// in order on each drop: the first one whose bounds contain the drop point
    /// (and that is currently visible, so hidden tabs never receive drops) gets
    /// the file paths. Called from: the drop-enabled windows.
    /// </summary>
    public static void Enable(Window window, params Target[] targets)
    {
        if (!ClamHub.App.IsElevated()) return;

        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) return;
        var source = HwndSource.FromHwnd(hwnd);
        if (source == null) return;

        // Let the elevated window receive the legacy drop messages at all. Per
        // MSDN, WM_COPYGLOBALDATA must accompany WM_DROPFILES/WM_COPYDATA for
        // the shell to hand over the file list across the integrity boundary.
        ChangeWindowMessageFilterEx(hwnd, WmDropFiles, MsgFltAllow, IntPtr.Zero);
        ChangeWindowMessageFilterEx(hwnd, WmCopyData, MsgFltAllow, IntPtr.Zero);
        ChangeWindowMessageFilterEx(hwnd, WmCopyGlobalData, MsgFltAllow, IntPtr.Zero);

        // WPF registered an OLE drop target for the whole window (AllowDrop).
        // While that registration exists the shell uses OLE (which UIPI blocks)
        // and never falls back to WM_DROPFILES, so revoke it. Trade-off: the
        // per-element DragOver cursor feedback is gone in admin mode; Explorer
        // still shows the generic copy cursor over the window.
        RevokeDragDrop(hwnd);
        DragAcceptFiles(hwnd, true);

        source.AddHook((IntPtr _, int msg, IntPtr wParam, IntPtr _, ref bool handled) =>
        {
            if (msg != (int)WmDropFiles) return IntPtr.Zero;
            handled = true;
            try
            {
                var files = ExtractFiles(wParam);
                DragQueryPoint(wParam, out var pt); // client coordinates of the drop
                Dispatch(window, targets, files, new Point(pt.X, pt.Y));
            }
            finally
            {
                DragFinish(wParam);
            }
            return IntPtr.Zero;
        });
    }

    /// <summary>Reads all file paths from an HDROP handle. Called from: the WM_DROPFILES hook.</summary>
    private static string[] ExtractFiles(IntPtr hDrop)
    {
        uint count = DragQueryFile(hDrop, 0xFFFFFFFF, null, 0);
        var files = new string[count];
        for (uint i = 0; i < count; i++)
        {
            uint len = DragQueryFile(hDrop, i, null, 0);
            var sb = new System.Text.StringBuilder((int)len + 1);
            DragQueryFile(hDrop, i, sb, (uint)sb.Capacity);
            files[i] = sb.ToString();
        }
        return files;
    }

    /// <summary>
    /// Finds the visible target whose bounds contain the drop point (device
    /// pixels are converted to DIPs first) and invokes its handler. Handler
    /// exceptions surface through AppNotifications instead of crashing the
    /// message pump. Called from: the WM_DROPFILES hook.
    /// </summary>
    private static void Dispatch(Window window, Target[] targets, string[] files, Point clientPoint)
    {
        if (files.Length == 0) return;

        // WM_DROPFILES reports physical pixels; WPF layout works in DIPs.
        var dip = clientPoint;
        if (PresentationSource.FromVisual(window)?.CompositionTarget is { } ct)
            dip = ct.TransformFromDevice.Transform(clientPoint);

        foreach (var target in targets)
        {
            if (target.Element is not FrameworkElement fe) continue;
            if (!fe.IsVisible) continue;
            var origin = fe.TranslatePoint(new Point(0, 0), window);
            var bounds = new Rect(origin, new Size(fe.ActualWidth, fe.ActualHeight));
            if (!bounds.Contains(dip)) continue;

            try { target.Handler(files); }
            catch (Exception ex) { AppNotifications.ReportError($"Drop failed: {ex.Message}"); }
            return;
        }
        // Drop outside every registered target: ignore, like WPF would.
    }
}
