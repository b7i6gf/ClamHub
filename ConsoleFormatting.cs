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
    /// Appends one line as a new console row. All lines share a single FlowDocument
    /// paragraph separated by line breaks (cheaper than one paragraph per line), and
    /// any URL becomes a hyperlink. Scrolls to the end. Called from:
    /// MainWindow.AppendLine and ConsoleWindow.AppendLine.
    /// </summary>
    public static void AppendLine(RichTextBox box, string line)
    {
        if (box.Document.Blocks.LastBlock is not Paragraph para)
        {
            para = new Paragraph { Margin = new Thickness(0) };
            box.Document.Blocks.Add(para);
        }
        if (para.Inlines.Count > 0)
            para.Inlines.Add(new LineBreak());
        AppendWithLinks(para, line);
        box.ScrollToEnd();
    }

    /// <summary>Removes all output. Called from: the Clear actions.</summary>
    public static void Clear(RichTextBox box) => box.Document.Blocks.Clear();

    /// <summary>
    /// Rebuilds the document from a list of lines, used to seed the separate window
    /// with the output collected so far. Called from: ConsoleWindow.SetLines.
    /// </summary>
    public static void SetLines(RichTextBox box, IEnumerable<string> lines)
    {
        box.Document.Blocks.Clear();
        foreach (var l in lines) AppendLine(box, l);
    }

    /// <summary>
    /// Splits one line into plain Runs and clickable Hyperlinks at every URL.
    /// Called from: AppendLine.
    /// </summary>
    private static void AppendWithLinks(Paragraph para, string line)
    {
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
