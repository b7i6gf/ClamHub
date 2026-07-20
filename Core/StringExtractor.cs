using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Extracts indicators of compromise (URLs, registry autostart keys,
/// shell/PowerShell command fragments) from a file's printable strings.
/// Reads BOTH 7-bit ASCII runs and UTF-16LE runs (common in Windows binaries).
/// Everything here is EXTRACTED, never validated: a URL in the strings does not
/// mean the program contacts it. Deliberately bounded (byte cap, per-category
/// result cap) so a 56 MB binary cannot flood the report or the memory.
/// Called from: IntegrityScanner (INDICATORS stage, after the PE stage).
/// </summary>
public static class StringExtractor
{
    // A partial read is enough for indicators and keeps huge files cheap; most
    // strings of interest sit in the first tens of MB (code + resources).
    private const long MaxBytesScanned = 48L * 1024 * 1024;
    private const int MinStringLength = 5;
    // Generous safety ceiling only (a pathological file could otherwise collect
    // hundreds of thousands of strings). The report itself lists everything
    // collected; this just bounds memory. Set high so normal files never hit it.
    private const int MaxPerCategory = 5000;
    private const int MaxValueLength = 300;

    // Compiled once. Case-insensitive where it helps; anchored loosely because
    // the input is already a single extracted string, not a whole document.
    private static readonly Regex UrlRx = new(
        @"\b(?:https?|ftp)://[^\s""'<>|]{4,}", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex RunKeyRx = new(
        @"(?:SOFTWARE\\)?(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run[A-Za-z]*",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex PsRx = new(
        @"powershell(?:\.exe)?\s+[^\r\n""]{0,200}|-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{16,}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex CmdRx = new(
        @"cmd(?:\.exe)?\s+/[ck]\s+[^\r\n""]{0,200}", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Scans the file and fills a grouped, de-duplicated, capped indicator list.
    /// The target defaults to report.Pe.Indicators (the PE case); document-only
    /// runs pass report.Document?.Items via the Extract overload so IOC
    /// extraction no longer needs a PE section. Honors cancellation between
    /// chunks. Called from: IntegrityScanner.RunAsync.
    /// </summary>
    public static void Extract(IntegrityReport report, CancellationToken cancel)
    {
        if (report.Pe == null) return;
        ExtractInto(report.FilePath, report.Pe.Indicators, cancel);
    }

    /// <summary>
    /// IOC extraction into an explicit string list, for callers without a PE
    /// section (documents/scripts/archives). Same matchers and caps as Extract.
    /// Called from: IntegrityScanner.RunAsync (document branch).
    /// </summary>
    public static void ExtractInto(string filePath, List<string> target, CancellationToken cancel)
    {
        var urls = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var runKeys = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var commands = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

        void Consume(string s)
        {
            foreach (Match m in UrlRx.Matches(s)) Add(urls, m.Value);
            foreach (Match m in RunKeyRx.Matches(s)) Add(runKeys, m.Value);
            foreach (Match m in PsRx.Matches(s)) Add(commands, m.Value);
            foreach (Match m in CmdRx.Matches(s)) Add(commands, m.Value);
        }

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            long budget = Math.Min(fs.Length, MaxBytesScanned);
            var buffer = new byte[1 << 20];
            var ascii = new StringBuilder(256);
            var wide = new StringBuilder(256);
            long done = 0;
            int read;
            while (done < budget && (read = fs.Read(buffer, 0, (int)Math.Min(buffer.Length, budget - done))) > 0)
            {
                cancel.ThrowIfCancellationRequested();
                for (int i = 0; i < read; i++)
                {
                    byte b = buffer[i];
                    // ASCII run.
                    if (b >= 0x20 && b < 0x7F)
                    {
                        ascii.Append((char)b);
                        if (ascii.Length > MaxValueLength) { Flush(ascii, Consume); }
                    }
                    else if (ascii.Length > 0) Flush(ascii, Consume);

                    // UTF-16LE run: printable byte followed by a zero high byte.
                    if (b >= 0x20 && b < 0x7F && i + 1 < read && buffer[i + 1] == 0)
                    {
                        wide.Append((char)b);
                        if (wide.Length > MaxValueLength) Flush(wide, Consume);
                    }
                    else if (b != 0 && wide.Length > 0) Flush(wide, Consume);
                }
                done += read;
            }
            Flush(ascii, Consume);
            Flush(wide, Consume);
        }
        catch (OperationCanceledException) { throw; }
        catch { return; } // unreadable/locked: indicators are best-effort

        Emit(target, "URLs", urls);
        Emit(target, "Registry autostart", runKeys);
        Emit(target, "Shell commands", commands);
    }

    /// <summary>Emits a completed string run to the matchers when long enough,
    /// then clears the builder. Called from: Extract.</summary>
    private static void Flush(StringBuilder sb, Action<string> consume)
    {
        if (sb.Length >= MinStringLength) consume(sb.ToString());
        sb.Clear();
    }

    private static void Add(SortedSet<string> set, string value)
    {
        // Concatenated .rdata strings and printf-style templates bleed neighbour
        // bytes into a URL match. Cut at the first format specifier, whitespace,
        // quote or control-ish separator so "https://host/path%s..." becomes
        // "https://host/path".
        int cut = value.Length;
        foreach (char c in "%\"'<> \t\r\n|{}")
        {
            int idx = value.IndexOf(c);
            if (idx >= 0 && idx < cut) cut = idx;
        }
        value = value[..cut].Trim().TrimEnd('.', ',', ')', '(', '\\', '/', ';', ':');
        if (value.Length is >= 4 and <= MaxValueLength && set.Count < MaxPerCategory)
            set.Add(value);
    }

    /// <summary>Appends one category block to the indicator list. The report
    /// must not abbreviate, so every collected value is listed.
    /// Called from: Extract.</summary>
    private static void Emit(List<string> target, string label, SortedSet<string> values)
    {
        if (values.Count == 0) return;
        target.Add($"{label} ({values.Count}):");
        foreach (var v in values) target.Add($"  {v}");
    }
}
