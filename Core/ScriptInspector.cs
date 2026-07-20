using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Structural inspector for script files (ps1/psm1, bat/cmd, vbs/vbe, js/jse,
/// wsf/wsh, hta). Scripts are plain text, so there is nothing to "parse" in the
/// PE sense; what matters is WHICH capabilities the text reaches for and HOW
/// hard it works to hide them. This reports both: capability hits grouped by
/// intent (download, execute, obfuscation, persistence, evasion, in-memory
/// loading) and objective obfuscation metrics (entropy, longest line, base64
/// blob size, escape density).
///
/// Explicitly NOT a verdict: administrators write scripts that download and
/// execute things legitimately. A single hit is Low/Medium; the High findings
/// come from COMBINATIONS (download + execute, or heavy obfuscation + execute)
/// which is where benign admin scripts and droppers actually differ.
/// Called from: DocumentAnalyzer.Analyze.
/// </summary>
public static class ScriptInspector
{
    private const long MaxScriptBytes = 32L * 1024 * 1024;
    private const int LongLineThreshold = 1000;
    private const int Base64BlobThreshold = 200;

    /// <summary>A capability pattern: regex, item kind and report wording.</summary>
    private sealed record Pattern(Regex Rx, string Kind, string Detail);

    private static readonly RegexOptions Opts =
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;

    // Grouped by INTENT so the report says what the script can do, not just
    // which words appear.
    private static readonly Pattern[] Patterns =
    {
        // --- download / network ---
        new(new Regex(@"\b(DownloadString|DownloadFile|DownloadData)\b", Opts),
            "script-download", "downloads content from a remote address (WebClient download method)"),
        new(new Regex(@"\bInvoke-WebRequest\b|\bInvoke-RestMethod\b|\biwr\b|\bcurl\b|\bwget\b", Opts),
            "script-download", "performs an HTTP request (Invoke-WebRequest/curl/wget)"),
        new(new Regex(@"New-Object\s+.*Net\.WebClient|System\.Net\.WebClient", Opts),
            "script-download", "creates a .NET WebClient"),
        new(new Regex(@"\b(bitsadmin|certutil)\b.*(\/transfer|-urlcache|\/urlcache|-f\b)", Opts),
            "script-download", "uses bitsadmin/certutil to fetch a file (a common download proxy)"),
        new(new Regex(@"\bMSXML2\.XMLHTTP\b|\bWinHttp\.WinHttpRequest\b|\bADODB\.Stream\b", Opts),
            "script-download", "uses COM HTTP/stream objects to fetch and write data"),

        // --- execution ---
        new(new Regex(@"\bInvoke-Expression\b|\bIEX\b", Opts),
            "script-execute", "executes a constructed string (Invoke-Expression/IEX)"),
        new(new Regex(@"\bStart-Process\b|\bWScript\.Shell\b|\bShell\.Application\b|\.Run\s*\(", Opts),
            "script-execute", "starts another process (Start-Process/WScript.Shell/Shell.Application)"),
        new(new Regex(@"\beval\s*\(|\bexecute\s*\(|\bExecuteGlobal\b|\bFunction\s*\(\s*\)\s*\{", Opts),
            "script-execute", "evaluates code at runtime (eval/Execute/ExecuteGlobal)"),
        new(new Regex(@"\bregsvr32\b|\bmshta\b|\brundll32\b|\bwmic\b|\bmsbuild\b|\bcmstp\b", Opts),
            "script-execute", "invokes a system binary commonly abused to run code (regsvr32/mshta/rundll32/wmic/msbuild)"),
        new(new Regex(@"\bscrobj\.dll\b|\bscriptlet\b|\bjavascript:|\bvbscript:", Opts),
            "script-execute", "references scriptlet/protocol execution (scrobj.dll, javascript:/vbscript:)"),

        // --- in-memory / injection ---
        new(new Regex(@"\[Reflection\.Assembly\]::Load|\bAssembly\.Load\b|\bAdd-Type\b", Opts),
            "script-inmemory", "loads .NET code in memory (Reflection.Assembly::Load / Add-Type)"),
        new(new Regex(@"\bVirtualAlloc\b|\bWriteProcessMemory\b|\bCreateRemoteThread\b|\bNtCreateThreadEx\b|\bmemset\b", Opts),
            "script-injection", "references memory/process injection APIs (VirtualAlloc/WriteProcessMemory/CreateRemoteThread)"),
        new(new Regex(@"\bDllImport\b|\bGetProcAddress\b|\bLoadLibrary\b|\bMarshal\b", Opts),
            "script-inmemory", "declares native API calls from the script (P/Invoke)"),

        // --- obfuscation / encoding ---
        new(new Regex(@"-enc(odedcommand)?\b", Opts),
            "script-encoded", "passes a base64-encoded command to PowerShell (-EncodedCommand)"),
        new(new Regex(@"FromBase64String|\bbase64\b|\[Convert\]::", Opts),
            "script-encoded", "decodes base64 data at runtime"),
        new(new Regex(@"String\.fromCharCode|\[char\]\s*\d|\bChrW?\s*\(", Opts),
            "script-charcode", "builds strings from character codes (a common way to hide keywords)"),
        new(new Regex(@"\bunescape\s*\(|\bdecodeURIComponent\s*\(", Opts),
            "script-encoded", "unescapes encoded text at runtime"),
        new(new Regex(@"-join\s*|\[array\]::reverse|\.Replace\s*\(.{0,20}\)\s*\.Replace", Opts),
            "script-stringbuild", "assembles or rewrites strings before use (join/reverse/chained replace)"),
        new(new Regex(@"#@~\^", Opts),
            "script-vbe", "contains a Microsoft encoded-script block (#@~^): the source is deliberately unreadable"),

        // --- evasion / privileges ---
        new(new Regex(@"-w(indowstyle)?\s+hidden|CreateNoWindow|vbHide|\bWindowStyle\s*=\s*0", Opts),
            "script-hidden", "runs without a visible window"),
        new(new Regex(@"-(exec(utionpolicy)?)\s+bypass|Set-ExecutionPolicy\s+Bypass|-nop\b|-noprofile\b", Opts),
            "script-bypass", "disables PowerShell execution policy or profile loading"),
        new(new Regex(@"Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|\bnetsh\s+advfirewall\b", Opts),
            "script-defense", "modifies Defender or firewall settings"),
        new(new Regex(@"\bvssadmin\b.*\bdelete\b|\bwbadmin\b.*\bdelete\b|\bbcdedit\b.*\brecoveryenabled\b", Opts),
            "script-destructive", "deletes shadow copies/backups or disables recovery (ransomware behavior)"),

        // --- persistence ---
        new(new Regex(@"CurrentVersion\\Run|\bschtasks\b|\bNew-ScheduledTask|\bRegister-ScheduledTask|\bsc\s+create\b|\bNew-Service\b", Opts),
            "script-persistence", "creates an autostart entry, scheduled task or service"),
        new(new Regex(@"\bStartup\\|\bshell:startup\b", Opts),
            "script-persistence", "writes to the Startup folder"),
    };

    private static readonly Regex UrlRx =
        new(@"(https?|ftp)://[^\s""'<>\)]{4,200}", Opts);
    private static readonly Regex IpRx =
        new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", Opts);
    private static readonly Regex Base64Rx =
        new(@"[A-Za-z0-9+/]{" + Base64BlobThreshold + @",}={0,2}", RegexOptions.Compiled);

    /// <summary>
    /// Reads the script (BOM-aware) and fills the section with capability hits
    /// and obfuscation metrics. Never throws. Called from: DocumentAnalyzer.Analyze.
    /// </summary>
    public static void Inspect(string path, string extension,
        IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        sec.Format = "Script";
        sec.Description = $".{extension} script";

        string text;
        long fileLen;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            fileLen = fs.Length;
            if (fileLen > MaxScriptBytes)
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "script-truncated-scan",
                    Detail = $"only the first {MaxScriptBytes / (1024 * 1024)} MB were analyzed; the file is larger."
                });
            // detectEncodingFromByteOrderMarks handles UTF-8/UTF-16 BOMs; without
            // a BOM UTF-8 is assumed, which is right for scripts in practice.
            using var reader = new StreamReader(fs, Encoding.UTF8, true);
            var buffer = new char[(int)Math.Min(fileLen + 1, MaxScriptBytes)];
            int total = 0;
            while (total < buffer.Length)
            {
                int n = reader.Read(buffer, total, buffer.Length - total);
                if (n <= 0) break;
                total += n;
            }
            text = new string(buffer, 0, total);
        }
        cancel.ThrowIfCancellationRequested();

        if (text.Length == 0)
        {
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "clean-structure",
                Detail = "the script file is empty."
            });
            return;
        }

        // --- capability hits, de-duplicated per kind+detail ---
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in Patterns)
        {
            cancel.ThrowIfCancellationRequested();
            if (!p.Rx.IsMatch(text)) continue;
            if (!seen.Add(p.Kind + "|" + p.Detail)) continue;
            sec.Items.Add(new IntegrityReport.DocumentItem { Kind = p.Kind, Detail = p.Detail });
        }

        // --- objective obfuscation metrics ---
        var lines = text.Split('\n');
        int longest = 0;
        foreach (var line in lines) if (line.Length > longest) longest = line.Length;

        if (longest >= LongLineThreshold)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "script-longline",
                Detail = $"longest line is {longest:N0} characters: typical for minified or obfuscated code."
            });

        var b64 = Base64Rx.Match(text);
        if (b64.Success)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "script-base64blob",
                Detail = $"contains a base64-looking block of {b64.Length:N0} characters: often an embedded payload."
            });

        double entropy = ShannonEntropy(text);
        // Threshold calibrated against real files (2026-07-19): benign source
        // code sits at 4.4-5.0 and real-world admin scripts reach 5.4, while a
        // pure base64 blob is ~6.0. The old 5.2 flagged ordinary .bat/.ps1 files.
        // Note that entropy is a WEAK obfuscation signal in general: char-code
        // concatenation (~3.9) and hex blobs (~4.0) are LOW entropy, and the one
        // high-entropy case (base64) is already caught precisely by
        // script-base64blob. It is therefore reported as a statistic only and
        // deliberately does NOT feed the "obfuscated" combination finding.
        if (entropy >= 5.8)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "script-entropy",
                Detail = FormattableString.Invariant(
                    $"character entropy {entropy:0.00} bits: very high for source code, which points to a large encoded or compressed block.")
            });

        // PowerShell backtick / caret escaping used purely to break up keywords.
        int escapes = text.Count(c => c == '`') + text.Count(c => c == '^');
        if (text.Length > 0 && escapes * 100.0 / text.Length > 2.0 && escapes > 40)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "script-escapes",
                Detail = $"{escapes:N0} escape characters (` or ^) for {text.Length:N0} characters: a density typical of keyword-splitting obfuscation."
            });

        // Batch variable-substring obfuscation: %VAR:~3,1%
        if (Regex.IsMatch(text, @"%\w+:~\d+,?\d*%"))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "script-batchsubstr",
                Detail = "uses batch variable-substring expansion (%VAR:~n,m%): a standard way to hide commands in .bat/.cmd."
            });

        // --- network indicators, listed as values ---
        var urls = UrlRx.Matches(text).Select(m => m.Value).Distinct(StringComparer.OrdinalIgnoreCase).Take(15).ToList();
        foreach (var url in urls)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "script-url",
                Detail = $"URL: {Trim(url, 200)}"
            });

        var ips = IpRx.Matches(text).Select(m => m.Value)
            .Where(IsPlausibleIp).Distinct().Take(10).ToList();
        foreach (var ip in ips)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "script-ip",
                Detail = $"IPv4 address: {ip}"
            });

        sec.Items.Add(new IntegrityReport.DocumentItem
        {
            Kind = "script-stats",
            Detail = FormattableString.Invariant(
                $"{lines.Length:N0} line(s), {fileLen:N0} bytes, entropy {entropy:0.00}, longest line {longest:N0}.")
        });

        if (!sec.Items.Any(i => i.Kind.StartsWith("script-") && i.Kind is not "script-stats" and not "script-truncated-scan"))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "clean-structure",
                Detail = "no download, execution, obfuscation or persistence patterns matched."
            });
    }

    /// <summary>Rejects version-number-looking matches (1.2.3.4) that the IPv4
    /// regex would otherwise report. Called from: Inspect.</summary>
    private static bool IsPlausibleIp(string s)
    {
        var parts = s.Split('.');
        if (parts.Length != 4) return false;
        foreach (var p in parts)
            if (!int.TryParse(p, out int v) || v > 255) return false;
        // Drop the obvious non-addresses: 0.x and 1.2.3.4-style version strings
        // are far more common in scripts than real routable addresses.
        return !(parts[0] == "0" || s == "1.2.3.4" || s == "0.0.0.0");
    }

    /// <summary>Shannon entropy over the character distribution. Readable source
    /// sits around 4.2-4.8 bits; encoded blobs push well past 5.
    /// Called from: Inspect.</summary>
    private static double ShannonEntropy(string text)
    {
        var freq = new Dictionary<char, int>();
        foreach (char c in text) freq[c] = freq.GetValueOrDefault(c) + 1;
        double entropy = 0, len = text.Length;
        foreach (var count in freq.Values)
        {
            double p = count / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static string Trim(string s, int max)
        => s.Length <= max ? s : s.Substring(0, max) + "...";
}
