using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Collects file system level integrity information for the File-Verifier:
/// basic metadata (size, timestamps, attributes, hard links, reparse target,
/// volume format), NTFS security (owner + DACL) and NTFS alternate data
/// streams including the parsed Zone.Identifier (Mark of the Web). Everything
/// uses the BCL where possible; stream enumeration and the hard link count use
/// kernel32 P/Invoke because no managed API exists. All methods are pure data
/// collectors without UI access, safe to run on a worker thread.
/// Called from: Core.IntegrityScanner.
/// </summary>
public static class FileSystemInspector
{
    // ---------------------------------------------------------------- metadata

    /// <summary>
    /// Collects the always-on metadata section: size, timestamps (local time),
    /// attributes, reparse/link info, hard link count and the hosting volume's
    /// file system format. Individual sub-values degrade to defaults on error;
    /// only a completely unreadable file yields Status=Failed.
    /// Called from: IntegrityScanner.RunAsync (stage 1).
    /// </summary>
    public static IntegrityReport.MetadataSection CollectMetadata(string path)
    {
        var section = new IntegrityReport.MetadataSection();
        try
        {
            var info = new FileInfo(path);
            section.SizeBytes = info.Length;
            section.Created = info.CreationTime;
            section.Modified = info.LastWriteTime;
            section.Accessed = info.LastAccessTime;
            section.Attributes = info.Attributes.ToString();
            section.IsReparsePoint = (info.Attributes & FileAttributes.ReparsePoint) != 0;
            try { section.LinkTarget = info.LinkTarget; } catch { /* broken link */ }
            section.HardLinkCount = GetHardLinkCount(path);
            (section.FileSystemFormat, section.DriveType) = GetVolumeInfo(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SystemException)
        {
            section.Status = StageStatus.Failed;
            section.Error = ex.Message;
        }
        return section;
    }

    /// <summary>
    /// File system format and drive type of the volume hosting the path.
    /// UNC paths have no DriveInfo and report "unknown (network share)".
    /// Called from: CollectMetadata and CollectFileSystemInfo (NTFS check).
    /// </summary>
    public static (string Format, string DriveType) GetVolumeInfo(string path)
    {
        try
        {
            string? root = Path.GetPathRoot(Path.GetFullPath(path));
            if (string.IsNullOrEmpty(root)) return ("unknown", "unknown");
            if (root.StartsWith(@"\\")) return ("unknown (network share)", "Network");
            var drive = new DriveInfo(root);
            return (drive.DriveFormat, drive.DriveType.ToString());
        }
        catch
        {
            return ("unknown", "unknown");
        }
    }

    /// <summary>
    /// NTFS hard link count of the file via GetFileInformationByHandle
    /// (1 = the file has no additional links). Returns 0 when the count cannot
    /// be determined (locked file, exotic volume). Called from: CollectMetadata.
    /// </summary>
    private static uint GetHardLinkCount(string path)
    {
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            return GetFileInformationByHandle(handle.DangerousGetHandle(), out var info)
                ? info.NumberOfLinks : 0u;
        }
        catch
        {
            return 0;
        }
    }

    // ------------------------------------------------------------- file system

    /// <summary>
    /// Collects the file system section: owner, DACL, alternate data streams and
    /// the Mark of the Web. On non-NTFS/ReFS volumes the section is Skipped
    /// (those concepts do not exist there). Security read failures degrade to a
    /// Failed section that still carries any stream data gathered before.
    /// Called from: IntegrityScanner.RunAsync (file system stage).
    /// </summary>
    public static IntegrityReport.FileSystemSection CollectFileSystemInfo(string path)
    {
        var section = new IntegrityReport.FileSystemSection();

        var (format, _) = GetVolumeInfo(path);
        bool supportsNtfsFeatures =
            format.Equals("NTFS", StringComparison.OrdinalIgnoreCase) ||
            format.Equals("ReFS", StringComparison.OrdinalIgnoreCase);
        if (!supportsNtfsFeatures)
        {
            section.Status = StageStatus.Skipped;
            section.Error = $"volume is {format}: no owner/ACL/ADS information available";
            return section;
        }

        try
        {
            var security = new FileInfo(path).GetAccessControl();
            section.Owner = TranslateSid(security.GetOwner(typeof(SecurityIdentifier)));
            foreach (FileSystemAccessRule rule in
                     security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                section.AccessRules.Add(new IntegrityReport.AclEntry
                {
                    Identity = TranslateSid(rule.IdentityReference),
                    Type = rule.AccessControlType.ToString(),
                    Rights = FormatRights(rule.FileSystemRights),
                    Inherited = rule.IsInherited
                });
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SystemException)
        {
            section.Status = StageStatus.Failed;
            section.Error = $"owner/ACL not readable: {ex.Message}";
        }

        // Streams are independent of the security read; collect them either way.
        try
        {
            section.AlternateStreams = EnumerateAlternateStreams(path);
            if (section.AlternateStreams.Any(s =>
                    s.Name.Equals("Zone.Identifier", StringComparison.OrdinalIgnoreCase)))
                ReadZoneIdentifier(path, section);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            if (section.Status == StageStatus.Ok)
            {
                section.Status = StageStatus.Failed;
                section.Error = $"stream enumeration failed: {ex.Message}";
            }
        }

        return section;
    }

    /// <summary>
    /// Maps a SID to DOMAIN\name for display, falling back to the raw SID string
    /// for orphaned/unmappable accounts (deleted users, foreign machines).
    /// Called from: CollectFileSystemInfo.
    /// </summary>
    private static string TranslateSid(IdentityReference? sid)
    {
        if (sid == null) return "unknown";
        try { return sid.Translate(typeof(NTAccount)).Value; }
        catch (IdentityNotMappedException) { return sid.Value; }
        catch (SystemException) { return sid.Value; }
    }

    /// <summary>
    /// Renders FileSystemRights readably: the ubiquitous Synchronize bit is
    /// stripped, and generic-rights combinations that have no enum name are
    /// shown as hex instead of a negative number. Called from: CollectFileSystemInfo.
    /// </summary>
    private static string FormatRights(FileSystemRights rights)
    {
        // Generic rights (GENERIC_READ etc.) land outside the named enum range.
        if ((int)rights < 0)
            return $"0x{(uint)rights:X8} (generic rights)";

        var trimmed = rights & ~FileSystemRights.Synchronize;
        if (trimmed == 0) trimmed = rights; // pure Synchronize: keep it visible
        return trimmed.ToString();
    }

    // -------------------------------------------------- alternate data streams

    /// <summary>
    /// Enumerates the file's NTFS streams via FindFirstStreamW/FindNextStreamW
    /// and returns every ALTERNATE stream (the unnamed main "::$DATA" stream is
    /// excluded). Names are cleaned for display (":Zone.Identifier:$DATA" ->
    /// "Zone.Identifier"). A file without ADS returns an empty list.
    /// Called from: CollectFileSystemInfo.
    /// </summary>
    public static List<IntegrityReport.StreamEntry> EnumerateAlternateStreams(string path)
    {
        var result = new List<IntegrityReport.StreamEntry>();

        IntPtr handle = FindFirstStreamW(path, FindStreamInfoStandard, out var data, 0);
        if (handle == InvalidHandleValue)
        {
            int err = Marshal.GetLastWin32Error();
            // 38 = ERROR_HANDLE_EOF: the file simply has no streams to report.
            if (err == 38 || err == 0) return result;
            throw new IOException($"FindFirstStreamW failed (Win32 error {err}).");
        }

        try
        {
            do
            {
                var entry = ToStreamEntry(data);
                if (entry != null) result.Add(entry);
            }
            while (FindNextStreamW(handle, out data));
        }
        finally
        {
            FindClose(handle);
        }
        return result;
    }

    /// <summary>
    /// Converts one WIN32_FIND_STREAM_DATA to a display entry, or null for the
    /// main data stream. Called from: EnumerateAlternateStreams.
    /// </summary>
    private static IntegrityReport.StreamEntry? ToStreamEntry(WIN32_FIND_STREAM_DATA data)
    {
        string raw = data.cStreamName ?? "";
        if (raw == "::$DATA") return null; // the file content itself

        string name = raw;
        if (name.StartsWith(':')) name = name[1..];
        if (name.EndsWith(":$DATA", StringComparison.OrdinalIgnoreCase))
            name = name[..^":$DATA".Length];

        return new IntegrityReport.StreamEntry { Name = name, SizeBytes = data.StreamSize };
    }

    /// <summary>
    /// Reads and parses the Zone.Identifier stream (Mark of the Web) into the
    /// section: ZoneId plus ReferrerUrl/HostUrl when present. A malformed stream
    /// is ignored silently (the raw ADS entry is still listed).
    /// Called from: CollectFileSystemInfo.
    /// </summary>
    private static void ReadZoneIdentifier(string path, IntegrityReport.FileSystemSection section)
    {
        try
        {
            // .NET (Core) opens NTFS streams via the "file:stream" path syntax.
            using var stream = new FileStream(path + ":Zone.Identifier",
                FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                string key = line[..eq].Trim();
                string value = line[(eq + 1)..].Trim();
                if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase)
                    && int.TryParse(value, out int zone))
                    section.MotwZoneId = zone;
                else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase))
                    section.MotwReferrer = value;
                else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase))
                    section.MotwHost = value;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Stream vanished or is locked: keep the plain ADS listing.
        }
    }

    /// <summary>
    /// Human name for a Zone.Identifier zone id (URLZONE values).
    /// Called from: IntegrityReportWriter (display) and IntegrityScanner (findings).
    /// </summary>
    public static string ZoneName(int zoneId) => zoneId switch
    {
        0 => "Local machine",
        1 => "Local intranet",
        2 => "Trusted sites",
        3 => "Internet",
        4 => "Restricted sites",
        _ => $"unknown zone {zoneId}"
    };

    // ----------------------------------------------------------------- P/Invoke

    private static readonly IntPtr InvalidHandleValue = new(-1);
    private const int FindStreamInfoStandard = 0;

    /// <summary>Native stream record returned by FindFirstStreamW/FindNextStreamW.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(string lpFileName, int infoLevel,
        out WIN32_FIND_STREAM_DATA lpFindStreamData, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextStreamW(IntPtr hFindStream,
        out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr hFindFile);

    /// <summary>Native file info record used for the hard link count.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(IntPtr hFile,
        out BY_HANDLE_FILE_INFORMATION lpFileInformation);
}
