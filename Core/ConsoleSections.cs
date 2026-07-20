namespace ClamHub.Core;

/// <summary>
/// Builds the multi-line banner that separates report/console sections. A boxed
/// header (rule, padded title with optional right-aligned info, rule) is far
/// easier to scan than a single "==== TITLE ====" line, which is what made the
/// File-Verifier's many sections blur together. Pure strings, no UI, so both
/// the Core writer (IntegrityReportWriter.RenderAll) and the UI consoles
/// (MainWindow.AppendSection, DetectionsWindow.LogSection) share one format.
/// </summary>
public static class ConsoleSections
{
    /// <summary>Fixed rule width; readable in the dock and the console window.</summary>
    public const int Width = 66;

    /// <summary>
    /// Returns the banner lines for a section: a top rule, the title (upper
    /// case) with optional right-aligned info such as a timestamp, and a bottom
    /// rule. The caller adds any leading blank line. Called from:
    /// MainWindow.AppendSection, DetectionsWindow.LogSection, RenderAll.
    /// </summary>
    public static List<string> Banner(string title, string? right = null)
    {
        string bar = new string('=', Width);
        string name = (title ?? "").ToUpperInvariant();
        string left = "  " + name;

        string middle;
        if (string.IsNullOrEmpty(right))
        {
            middle = left;
        }
        else
        {
            // Right-align the info; if the title is too long to fit both on one
            // line, fall back to a trailing space so nothing is lost.
            int pad = Width - left.Length - right.Length - 2;
            middle = pad >= 1 ? left + new string(' ', pad) + right + "  "
                              : left + " " + right;
        }

        return new List<string> { bar, middle, bar };
    }
}
