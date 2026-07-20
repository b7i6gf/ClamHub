using System.IO;
using System.Text;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Structural inspector for Windows shortcuts (.lnk, MS-SHLLINK). Shortcuts are
/// a top attack vector because Explorer hides what they actually run: the
/// visible name and icon are free-form while the real target and its command
/// line live in the binary. This parser reads the header, the string data
/// (name, relative path, working dir, ARGUMENTS, icon) and reports them as
/// facts, plus the patterns that matter: a living-off-the-land target
/// (powershell/cmd/mshta/rundll32/...), encoded or download-style arguments, a
/// deliberately hidden window, and an implausibly large shortcut (payload
/// carried inside the .lnk itself).
///
/// Strict bounds checking everywhere: the file is attacker-controlled, so every
/// offset/length is validated against the actual size before use and a
/// malformed structure ends the parse instead of throwing.
/// Called from: DocumentAnalyzer.Analyze.
/// </summary>
public static class LnkInspector
{
    private const int HeaderSize = 0x4C;
    private const long MaxLnkBytes = 16L * 1024 * 1024;   // sane ceiling for a shortcut
    private const long SuspiciousLnkBytes = 100 * 1024;   // a normal .lnk is ~1-2 KB

    // LinkFlags (MS-SHLLINK 2.1.1).
    private const uint HasLinkTargetIdList = 0x00000001;
    private const uint HasLinkInfo = 0x00000002;
    private const uint HasName = 0x00000004;
    private const uint HasRelativePath = 0x00000008;
    private const uint HasWorkingDir = 0x00000010;
    private const uint HasArguments = 0x00000020;
    private const uint HasIconLocation = 0x00000040;
    private const uint IsUnicode = 0x00000080;
    private const uint RunAsUser = 0x00004000;

    // Interpreters and system binaries commonly abused to run downloaded code.
    private static readonly string[] LolBins =
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "wscript.exe", "cscript.exe", "msiexec.exe", "certutil.exe",
        "bitsadmin.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "forfiles.exe",
        "conhost.exe", "curl.exe", "wmic.exe", "msbuild.exe", "cmstp.exe", "control.exe"
    };

    // Argument fragments that indicate download/execute or hidden execution.
    private static readonly string[] SuspiciousArgs =
    {
        "-enc", "-encodedcommand", "-e ", "frombase64string", "downloadstring",
        "downloadfile", "invoke-expression", "iex ", "invoke-webrequest", "webclient",
        "-w hidden", "-windowstyle hidden", "-nop", "-noprofile", "-executionpolicy bypass",
        "-ep bypass", "bypass", "hidden", "start-process", "http://", "https://",
        "ftp://", "\\\\", "certutil", "bitsadmin", "curl ", "wget ", "regsvr32",
        "javascript:", "vbscript:", "scrobj.dll", "urlmon", "createobject"
    };

    /// <summary>
    /// Parses the shortcut and fills the section. Never throws: a malformed or
    /// truncated file yields whatever was decoded plus a note.
    /// Called from: DocumentAnalyzer.Analyze.
    /// </summary>
    public static void Inspect(string path, IntegrityReport.DocumentSection sec, CancellationToken cancel)
    {
        sec.Format = "LNK";
        sec.Description = "Windows shortcut";

        byte[] data;
        long fileLen;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            fileLen = fs.Length;
            if (fileLen < HeaderSize)
            {
                sec.Status = StageStatus.Failed;
                sec.Error = "file is too small to be a shortcut";
                return;
            }
            int take = (int)Math.Min(fileLen, MaxLnkBytes);
            data = new byte[take];
            int total = 0;
            while (total < take)
            {
                int n = fs.Read(data, total, take - total);
                if (n <= 0) break;
                total += n;
            }
            if (total < HeaderSize)
            {
                sec.Status = StageStatus.Failed;
                sec.Error = "shortcut could not be read";
                return;
            }
            if (total < take) data = data[..total];
        }
        cancel.ThrowIfCancellationRequested();

        uint headerSize = BitConverter.ToUInt32(data, 0);
        if (headerSize != HeaderSize)
        {
            sec.Status = StageStatus.Failed;
            sec.Error = "not a valid shortcut header";
            return;
        }

        uint flags = BitConverter.ToUInt32(data, 20);
        uint showCommand = BitConverter.ToUInt32(data, 60);
        bool unicode = (flags & IsUnicode) != 0;

        int pos = HeaderSize;

        // Optional LinkTargetIDList: a 2-byte size followed by that many bytes.
        if ((flags & HasLinkTargetIdList) != 0)
        {
            if (pos + 2 > data.Length) { Truncated(sec); return; }
            int idListSize = BitConverter.ToUInt16(data, pos);
            pos += 2 + idListSize;
            if (pos > data.Length) { Truncated(sec); return; }
        }

        // Optional LinkInfo: gives the resolved local/UNC target path.
        string? linkInfoTarget = null;
        if ((flags & HasLinkInfo) != 0)
        {
            if (pos + 4 > data.Length) { Truncated(sec); return; }
            int linkInfoSize = (int)BitConverter.ToUInt32(data, pos);
            if (linkInfoSize > 0 && pos + linkInfoSize <= data.Length)
                linkInfoTarget = ReadLinkInfoPath(data, pos, linkInfoSize);
            pos += linkInfoSize;
            if (pos > data.Length || linkInfoSize <= 0) { Truncated(sec); return; }
        }

        // StringData, always in this order when their flag is set.
        string? name = null, relativePath = null, workingDir = null, arguments = null, iconLocation = null;
        if ((flags & HasName) != 0) name = ReadStringData(data, ref pos, unicode);
        if ((flags & HasRelativePath) != 0) relativePath = ReadStringData(data, ref pos, unicode);
        if ((flags & HasWorkingDir) != 0) workingDir = ReadStringData(data, ref pos, unicode);
        if ((flags & HasArguments) != 0) arguments = ReadStringData(data, ref pos, unicode);
        if ((flags & HasIconLocation) != 0) iconLocation = ReadStringData(data, ref pos, unicode);

        string target = linkInfoTarget ?? relativePath ?? "(not stored; resolved via the target ID list)";
        sec.Items.Add(new IntegrityReport.DocumentItem
        {
            Kind = "lnk-target",
            Detail = $"target: {Trim(target, 240)}"
        });
        if (!string.IsNullOrWhiteSpace(relativePath) && linkInfoTarget != null)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "lnk-relative",
                Detail = $"relative path: {Trim(relativePath!, 240)}"
            });
        if (!string.IsNullOrWhiteSpace(workingDir))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "lnk-workdir",
                Detail = $"working directory: {Trim(workingDir!, 240)}"
            });
        if (!string.IsNullOrWhiteSpace(name))
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "lnk-description",
                Detail = $"description: {Trim(name!, 240)}"
            });

        // Arguments are where the payload usually lives.
        if (!string.IsNullOrWhiteSpace(arguments))
        {
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "lnk-args",
                Detail = $"command line arguments: {Trim(arguments!, 400)}"
            });

            string lower = arguments!.ToLowerInvariant();
            var hits = SuspiciousArgs.Where(s => lower.Contains(s)).Distinct().ToList();
            if (hits.Count > 0)
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "lnk-args-suspicious",
                    Detail = "argument patterns of interest: " + string.Join(", ", hits.Take(10))
                });
            if (arguments!.Length > 400)
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "lnk-args-long",
                    Detail = $"the argument string is unusually long ({arguments.Length} characters), a common way to inline a script."
                });
        }

        // Living-off-the-land target: an interpreter rather than an application.
        string targetLower = (linkInfoTarget ?? relativePath ?? "").ToLowerInvariant();
        var lolBin = LolBins.FirstOrDefault(b => targetLower.EndsWith(b) || targetLower.Contains("\\" + b));
        if (lolBin != null)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "lnk-lolbin",
                Detail = $"the shortcut runs {lolBin}, a system interpreter frequently abused to execute downloaded code."
            });

        // SW_SHOWMINNOACTIVE (7) hides the console window of whatever runs.
        if (showCommand == 7)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "lnk-hidden",
                Detail = "the shortcut starts its target minimized/without an active window (hides a console window)."
            });

        if ((flags & RunAsUser) != 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "lnk-runas",
                Detail = "the shortcut requests elevation (run as a different user/administrator)."
            });

        // Icon disguise: a document-looking icon on a shortcut that runs an interpreter.
        if (!string.IsNullOrWhiteSpace(iconLocation))
        {
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "lnk-icon",
                Detail = $"icon source: {Trim(iconLocation!, 240)}"
            });
            string iconLower = iconLocation!.ToLowerInvariant();
            bool docIcon = iconLower.Contains("shell32") || iconLower.Contains("imageres")
                           || iconLower.EndsWith(".ico") || iconLower.Contains("wordicon")
                           || iconLower.Contains("acrobat") || iconLower.Contains("excel");
            if (lolBin != null && docIcon)
                sec.Items.Add(new IntegrityReport.DocumentItem
                {
                    Kind = "lnk-icon-disguise",
                    Detail = "the shortcut runs an interpreter but borrows a document/system icon: the visible icon does not reflect what it starts."
                });
        }

        // A shortcut is metadata; hundreds of KB means something is stored inside.
        if (fileLen > SuspiciousLnkBytes)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "lnk-oversize",
                Detail = $"the shortcut is {fileLen:N0} bytes; normal shortcuts are a few KB, so it likely carries embedded data."
            });

        if (sec.Items.Count == 0)
            sec.Items.Add(new IntegrityReport.DocumentItem
            {
                Kind = "clean-structure",
                Detail = "no target, arguments or icon information could be decoded."
            });
    }

    /// <summary>Marks a truncated/malformed shortcut without discarding what was
    /// already decoded. Called from: Inspect.</summary>
    private static void Truncated(IntegrityReport.DocumentSection sec)
        => sec.Items.Add(new IntegrityReport.DocumentItem
        {
            Kind = "lnk-malformed",
            Detail = "the shortcut structure is truncated or malformed; parsing stopped early."
        });

    /// <summary>
    /// Reads one StringData entry: a 2-byte character count followed by the
    /// characters (UTF-16LE when the IsUnicode flag is set, otherwise ANSI).
    /// Advances pos and returns null when the data does not fit.
    /// Called from: Inspect.
    /// </summary>
    private static string? ReadStringData(byte[] data, ref int pos, bool unicode)
    {
        if (pos + 2 > data.Length) { pos = data.Length; return null; }
        int count = BitConverter.ToUInt16(data, pos);
        pos += 2;
        int bytes = unicode ? count * 2 : count;
        if (bytes < 0 || pos + bytes > data.Length) { pos = data.Length; return null; }
        string value = unicode
            ? Encoding.Unicode.GetString(data, pos, bytes)
            : Encoding.Default.GetString(data, pos, bytes);
        pos += bytes;
        return value;
    }

    /// <summary>
    /// Extracts the target path from the LinkInfo structure: the local base path
    /// (plus common path suffix) or, for network targets, whatever string the
    /// offsets point at. All offsets are validated against the LinkInfo block.
    /// Returns null when the layout is not usable. Called from: Inspect.
    /// </summary>
    private static string? ReadLinkInfoPath(byte[] data, int start, int size)
    {
        try
        {
            int end = start + size;
            if (end > data.Length || size < 24) return null;

            uint headerSize = BitConverter.ToUInt32(data, start + 4);
            uint linkInfoFlags = BitConverter.ToUInt32(data, start + 8);
            uint localBasePathOffset = BitConverter.ToUInt32(data, start + 16);
            uint commonPathSuffixOffset = BitConverter.ToUInt32(data, start + 20);

            // Unicode variants exist only in the extended header (>= 0x24).
            uint localBasePathOffsetUnicode = 0, commonPathSuffixOffsetUnicode = 0;
            if (headerSize >= 0x24 && start + 32 <= data.Length)
            {
                localBasePathOffsetUnicode = BitConverter.ToUInt32(data, start + 28);
                if (start + 36 <= data.Length)
                    commonPathSuffixOffsetUnicode = BitConverter.ToUInt32(data, start + 32);
            }

            bool hasLocalPath = (linkInfoFlags & 0x1) != 0;
            if (!hasLocalPath) return null;

            string basePath = localBasePathOffsetUnicode > 0
                ? ReadUnicodeZ(data, start + (int)localBasePathOffsetUnicode, end)
                : ReadAnsiZ(data, start + (int)localBasePathOffset, end);
            string suffix = commonPathSuffixOffsetUnicode > 0
                ? ReadUnicodeZ(data, start + (int)commonPathSuffixOffsetUnicode, end)
                : ReadAnsiZ(data, start + (int)commonPathSuffixOffset, end);

            string full = (basePath + suffix).Trim();
            return full.Length > 0 ? full : null;
        }
        catch { return null; }
    }

    /// <summary>Reads a NUL-terminated ANSI string inside [offset, limit).
    /// Called from: ReadLinkInfoPath.</summary>
    private static string ReadAnsiZ(byte[] data, int offset, int limit)
    {
        if (offset < 0 || offset >= limit || offset >= data.Length) return "";
        int i = offset;
        while (i < limit && i < data.Length && data[i] != 0) i++;
        return Encoding.Default.GetString(data, offset, i - offset);
    }

    /// <summary>Reads a NUL-terminated UTF-16LE string inside [offset, limit).
    /// Called from: ReadLinkInfoPath.</summary>
    private static string ReadUnicodeZ(byte[] data, int offset, int limit)
    {
        if (offset < 0 || offset + 1 >= limit || offset + 1 >= data.Length) return "";
        int i = offset;
        while (i + 1 < limit && i + 1 < data.Length && !(data[i] == 0 && data[i + 1] == 0)) i += 2;
        return Encoding.Unicode.GetString(data, offset, i - offset);
    }

    private static string Trim(string s, int max)
        => s.Length <= max ? s : s.Substring(0, max) + "...";
}
