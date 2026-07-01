using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Navigation;

namespace ClamHub;

/// <summary>
/// Shared helpers for the read-only output consoles (the main window dock and the
/// separate ConsoleWindow). Renders plain log lines into a RichTextBox and turns
/// any http(s) URL into a clickable hyperlink, used so the VirusTotal GUI link
/// printed after a lookup can be opened in the browser.
/// Called from: MainWindow (AppendLine/Clear) and ConsoleWindow.
/// </summary>
public static class ConsoleFormatting
{
    private static readonly Regex UrlRegex =
        new(@"https?://[^\s]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Appends one line as its own console paragraph (any URL becomes a clickable
    /// hyperlink) and scrolls to the end. Called from: MainWindow.AppendLine and
    /// ConsoleWindow.AppendLine.
    /// </summary>
    public static void AppendLine(RichTextBox box, string line)
    {
        AppendLineNoScroll(box, line);
        box.ScrollToEnd();
    }

    /// <summary>
    /// Same as AppendLine but without the ScrollToEnd, so a whole batch of lines can
    /// be appended with a single scroll at the end (ScrollToEnd forces a full re-layout,
    /// which is the dominant cost when many lines arrive in a burst). Each line becomes
    /// its OWN paragraph (Margin 0): a FlowDocument with many small blocks measures and
    /// lays out far cheaper for large logs than one giant paragraph full of inlines,
    /// which is what made switching to a full console stutter. Called from:
    /// MainWindow.FlushConsole, ConsoleWindow.AppendLineNoScroll and SetLines.
    /// </summary>
    public static void AppendLineNoScroll(RichTextBox box, string line)
    {
        var para = new Paragraph { Margin = new Thickness(0) };
        AppendWithLinks(para, line);
        box.Document.Blocks.Add(para);
    }

    /// <summary>Removes all output. Called from: the Clear actions.</summary>
    public static void Clear(RichTextBox box) => box.Document.Blocks.Clear();

    /// <summary>
    /// Drops the oldest 'count' lines from the front of the document. Each line is its
    /// own paragraph, so this removes the first 'count' blocks. Called from:
    /// MainWindow.TrimConsole and ConsoleWindow.RemoveLeadingLines.
    /// </summary>
    public static void RemoveLeadingLines(RichTextBox box, int count)
    {
        if (count <= 0) return;
        var blocks = box.Document.Blocks;
        while (count-- > 0 && blocks.FirstBlock is { } first)
            blocks.Remove(first);
    }

    /// <summary>
    /// Rebuilds the document from a list of lines, used to seed the separate window
    /// with the output collected so far. Called from: ConsoleWindow.SetLines.
    /// </summary>
    public static void SetLines(RichTextBox box, IEnumerable<string> lines)
    {
        box.Document.Blocks.Clear();
        foreach (var l in lines) AppendLineNoScroll(box, l);
    }

    /// <summary>
    /// Splits one line into plain Runs and clickable Hyperlinks at every URL.
    /// Called from: AppendLine.
    /// </summary>
    private static void AppendWithLinks(Paragraph para, string line)
    {
        // Fast path: the vast majority of log lines contain no URL, so skip the regex
        // scan entirely and add the line as a single Run. Matters during output floods.
        if (line.IndexOf("http", StringComparison.OrdinalIgnoreCase) < 0)
        {
            para.Inlines.Add(new Run(line));
            return;
        }

        int pos = 0;
        foreach (Match m in UrlRegex.Matches(line))
        {
            if (m.Index > pos)
                para.Inlines.Add(new Run(line.Substring(pos, m.Index - pos)));

            // Trailing punctuation is usually sentence punctuation, not part of the URL.
            string url = m.Value.TrimEnd('.', ',', ';', ':', ')', ']', '}');
            string trailing = m.Value.Substring(url.Length);

            if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                var link = new Hyperlink(new Run(url)) { NavigateUri = uri };
                link.RequestNavigate += OnRequestNavigate;
                para.Inlines.Add(link);
            }
            else
            {
                para.Inlines.Add(new Run(url));
            }

            if (trailing.Length > 0)
                para.Inlines.Add(new Run(trailing));
            pos = m.Index + m.Value.Length;
        }
        if (pos < line.Length)
            para.Inlines.Add(new Run(line.Substring(pos)));
    }

    /// <summary>
    /// Opens a clicked link in the default browser. Called from: hyperlink RequestNavigate.
    /// </summary>
    private static void OnRequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = e.Uri.AbsoluteUri,
                UseShellExecute = true
            });
        }
        catch { /* no browser available or launch blocked: ignore */ }
        e.Handled = true;
    }
}
