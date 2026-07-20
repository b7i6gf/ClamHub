using System.IO;
using System.Text;

namespace ClamHub.Core;

/// <summary>
/// Reader for the Compound File Binary Format (CFBF/OLE2), the container behind
/// legacy Office files (.doc/.xls/.ppt), .msg mails and encrypted OOXML. It is
/// a small file system: a header, a FAT of sector chains, a directory of
/// storages (folders) and streams (files), plus a "mini" FAT for streams below
/// the cutoff (4096 bytes by default) that live packed inside the root stream.
///
/// This parser exposes exactly what the inspector needs: the directory entries
/// and the ability to read one named stream. It is bounds-checked throughout
/// (attacker-controlled input): every sector index is validated, chain walks
/// are capped so a FAT loop cannot hang the scan, and any structural problem
/// results in an empty/partial result instead of an exception.
/// Called from: OleInspector.
/// </summary>
public sealed class OleCompoundFile : IDisposable
{
    /// <summary>Directory entry: a storage (folder), stream (file) or the root.</summary>
    public sealed record DirEntry(string Name, byte Type, uint StartSector, long Size, int Index);

    private const uint FreeSector = 0xFFFFFFFF;
    private const uint EndOfChain = 0xFFFFFFFE;
    private const uint FatSector = 0xFFFFFFFD;
    private const uint DifSector = 0xFFFFFFFC;
    private const int MaxChainSectors = 1_000_000;   // loop/DoS guard
    private const int MaxDirEntries = 20_000;

    private readonly FileStream _stream;
    private readonly int _sectorSize;
    private readonly int _miniSectorSize;
    private readonly uint _miniCutoff;
    private readonly List<uint> _fat = new();
    private readonly List<uint> _miniFat = new();
    private readonly long _fileLength;

    /// <summary>All directory entries in directory order (index = entry id).</summary>
    public List<DirEntry> Entries { get; } = new();

    /// <summary>True when the header parsed and a directory was found.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// Opens and parses the container. Never throws on malformed input: IsValid
    /// stays false instead. Called from: OleInspector.Inspect.
    /// </summary>
    public OleCompoundFile(string path)
    {
        _stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        _fileLength = _stream.Length;
        try
        {
            var header = new byte[512];
            if (_fileLength < 512 || _stream.Read(header, 0, 512) != 512) return;
            if (BitConverter.ToUInt64(header, 0) != 0xE11AB1A1E011CFD0UL) return;

            int sectorShift = BitConverter.ToUInt16(header, 0x1E);
            int miniShift = BitConverter.ToUInt16(header, 0x20);
            if (sectorShift is < 7 or > 20 || miniShift is < 2 or > 12) return;
            _sectorSize = 1 << sectorShift;
            _miniSectorSize = 1 << miniShift;
            _miniCutoff = BitConverter.ToUInt32(header, 0x38);
            if (_miniCutoff == 0 || _miniCutoff > 1 << 24) _miniCutoff = 4096;

            uint fatSectorCount = BitConverter.ToUInt32(header, 0x2C);
            uint firstDirSector = BitConverter.ToUInt32(header, 0x30);
            uint firstMiniFatSector = BitConverter.ToUInt32(header, 0x3C);
            uint miniFatCount = BitConverter.ToUInt32(header, 0x40);
            uint firstDifatSector = BitConverter.ToUInt32(header, 0x44);
            uint difatCount = BitConverter.ToUInt32(header, 0x48);

            BuildFat(header, fatSectorCount, firstDifatSector, difatCount);
            BuildMiniFat(firstMiniFatSector, miniFatCount);
            ReadDirectory(firstDirSector);

            IsValid = Entries.Count > 0;
        }
        catch
        {
            // Malformed container: whatever was collected stays, IsValid is false.
        }
    }

    /// <summary>
    /// Collects the FAT: the DIFAT lists which sectors hold FAT data. The first
    /// 109 DIFAT entries live in the header, the rest in a chain of DIFAT
    /// sectors. Called from: the constructor.
    /// </summary>
    private void BuildFat(byte[] header, uint fatSectorCount, uint firstDifatSector, uint difatCount)
    {
        var fatSectors = new List<uint>();
        for (int i = 0; i < 109 && fatSectors.Count < fatSectorCount; i++)
        {
            uint s = BitConverter.ToUInt32(header, 0x4C + i * 4);
            if (s == FreeSector || s == EndOfChain) break;
            fatSectors.Add(s);
        }

        // Additional DIFAT sectors: each holds (sectorSize/4 - 1) FAT sector ids
        // plus a pointer to the next DIFAT sector in its last slot.
        uint next = firstDifatSector;
        int guard = 0;
        while (next != EndOfChain && next != FreeSector && guard++ < 10_000
               && fatSectors.Count < fatSectorCount)
        {
            var sector = ReadSector(next);
            if (sector == null) break;
            int perSector = _sectorSize / 4 - 1;
            for (int i = 0; i < perSector && fatSectors.Count < fatSectorCount; i++)
            {
                uint s = BitConverter.ToUInt32(sector, i * 4);
                if (s == FreeSector || s == EndOfChain) break;
                fatSectors.Add(s);
            }
            next = BitConverter.ToUInt32(sector, perSector * 4);
        }

        foreach (var fs in fatSectors)
        {
            var sector = ReadSector(fs);
            if (sector == null) continue;
            for (int i = 0; i < _sectorSize / 4; i++)
                _fat.Add(BitConverter.ToUInt32(sector, i * 4));
        }
    }

    /// <summary>Collects the mini FAT (chains for streams below the cutoff).
    /// Called from: the constructor.</summary>
    private void BuildMiniFat(uint firstMiniFatSector, uint miniFatCount)
    {
        uint sector = firstMiniFatSector;
        int guard = 0;
        while (sector != EndOfChain && sector != FreeSector
               && guard++ < miniFatCount + 16 && guard < 100_000)
        {
            var data = ReadSector(sector);
            if (data == null) break;
            for (int i = 0; i < _sectorSize / 4; i++)
                _miniFat.Add(BitConverter.ToUInt32(data, i * 4));
            sector = NextInFat(sector);
            if (sector == uint.MaxValue) break;
        }
    }

    /// <summary>Walks the directory sector chain and decodes every 128-byte
    /// entry. Called from: the constructor.</summary>
    private void ReadDirectory(uint firstDirSector)
    {
        uint sector = firstDirSector;
        int guard = 0, index = 0;
        while (sector != EndOfChain && sector != FreeSector && guard++ < MaxChainSectors)
        {
            var data = ReadSector(sector);
            if (data == null) break;
            for (int off = 0; off + 128 <= data.Length && Entries.Count < MaxDirEntries; off += 128)
            {
                int nameLen = BitConverter.ToUInt16(data, off + 0x40);
                byte type = data[off + 0x42];
                if (type == 0) { index++; continue; }           // unused slot
                if (nameLen is < 2 or > 64) { index++; continue; }

                string name = Encoding.Unicode.GetString(data, off, nameLen - 2)
                    .TrimEnd('\0');
                uint start = BitConverter.ToUInt32(data, off + 0x74);
                long size = (long)BitConverter.ToUInt64(data, off + 0x78);
                if (size < 0 || size > _fileLength * 64) size = 0;  // implausible

                Entries.Add(new DirEntry(name, type, start, size, index));
                index++;
            }
            sector = NextInFat(sector);
            if (sector == uint.MaxValue) break;
        }
    }

    /// <summary>
    /// Reads a named stream in full (capped). Streams below the mini cutoff are
    /// assembled from the mini FAT inside the root stream, larger ones from the
    /// regular FAT. Returns null when the stream is missing or unreadable.
    /// Called from: OleInspector.
    /// </summary>
    public byte[]? ReadStream(string name, int maxBytes = 8 * 1024 * 1024)
    {
        var entry = Entries.FirstOrDefault(e =>
            e.Type == 2 && string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));
        return entry == null ? null : ReadStream(entry, maxBytes);
    }

    /// <summary>Reads a directory entry's stream data. Called from: ReadStream(string)
    /// and OleInspector.</summary>
    public byte[]? ReadStream(DirEntry entry, int maxBytes = 8 * 1024 * 1024)
    {
        try
        {
            int want = (int)Math.Min(entry.Size, maxBytes);
            if (want <= 0) return Array.Empty<byte>();

            // Small streams live in the root entry's mini stream.
            if (entry.Size < _miniCutoff && entry.Type != 5)
                return ReadMiniStream(entry.StartSector, want);

            var output = new byte[want];
            int written = 0;
            uint sector = entry.StartSector;
            int guard = 0;
            while (written < want && sector != EndOfChain && sector != FreeSector
                   && guard++ < MaxChainSectors)
            {
                var data = ReadSector(sector);
                if (data == null) break;
                int copy = Math.Min(_sectorSize, want - written);
                Array.Copy(data, 0, output, written, copy);
                written += copy;
                sector = NextInFat(sector);
                if (sector == uint.MaxValue) break;
            }
            return written == want ? output : output[..written];
        }
        catch { return null; }
    }

    /// <summary>Assembles a mini-stream from the root storage's stream using the
    /// mini FAT. Called from: ReadStream.</summary>
    private byte[]? ReadMiniStream(uint startMiniSector, int want)
    {
        var root = Entries.FirstOrDefault(e => e.Type == 5);
        if (root == null) return null;

        // The root's own data is a normal FAT chain; read only as much as needed.
        int rootNeeded = (int)Math.Min(root.Size, 64L * 1024 * 1024);
        var rootData = ReadChain(root.StartSector, rootNeeded);
        if (rootData == null) return null;

        var output = new byte[want];
        int written = 0;
        uint mini = startMiniSector;
        int guard = 0;
        while (written < want && mini != EndOfChain && mini != FreeSector
               && guard++ < MaxChainSectors)
        {
            long offset = (long)mini * _miniSectorSize;
            if (offset < 0 || offset + _miniSectorSize > rootData.Length) break;
            int copy = Math.Min(_miniSectorSize, want - written);
            Array.Copy(rootData, offset, output, written, copy);
            written += copy;
            mini = mini < _miniFat.Count ? _miniFat[(int)mini] : EndOfChain;
        }
        return written == want ? output : output[..written];
    }

    /// <summary>Reads a FAT sector chain into a buffer of the given size.
    /// Called from: ReadMiniStream.</summary>
    private byte[]? ReadChain(uint startSector, int want)
    {
        if (want <= 0) return Array.Empty<byte>();
        var output = new byte[want];
        int written = 0;
        uint sector = startSector;
        int guard = 0;
        while (written < want && sector != EndOfChain && sector != FreeSector
               && guard++ < MaxChainSectors)
        {
            var data = ReadSector(sector);
            if (data == null) break;
            int copy = Math.Min(_sectorSize, want - written);
            Array.Copy(data, 0, output, written, copy);
            written += copy;
            sector = NextInFat(sector);
            if (sector == uint.MaxValue) break;
        }
        return written > 0 ? (written == want ? output : output[..written]) : null;
    }

    /// <summary>Next sector in a FAT chain, or uint.MaxValue when the index is
    /// out of range (malformed file). Called from: the chain walkers.</summary>
    private uint NextInFat(uint sector)
    {
        if (sector >= _fat.Count) return uint.MaxValue;
        uint next = _fat[(int)sector];
        return next is FatSector or DifSector ? EndOfChain : next;
    }

    /// <summary>Reads one sector by index; sector N starts at (N+1)*sectorSize.
    /// Returns null for out-of-file indices. Called from: everywhere.</summary>
    private byte[]? ReadSector(uint index)
    {
        try
        {
            long offset = ((long)index + 1) * _sectorSize;
            if (offset < 0 || offset + _sectorSize > _fileLength) return null;
            var buffer = new byte[_sectorSize];
            _stream.Position = offset;
            int total = 0;
            while (total < _sectorSize)
            {
                int n = _stream.Read(buffer, total, _sectorSize - total);
                if (n <= 0) break;
                total += n;
            }
            return total == _sectorSize ? buffer : null;
        }
        catch { return null; }
    }

    public void Dispose() => _stream.Dispose();
}
