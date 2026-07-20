using System.IO;
using System.Security.Cryptography;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Self-contained PE (EXE/DLL/SYS) parser for the File-Verifier: COFF/optional
/// header, security mitigation flags (ASLR/DEP/CFG/...), CLR header, imports
/// with the pefile/VirusTotal-compatible imphash (frozen ordinal tables in
/// PeImphashOrdinals), exports, TLS callbacks, Rich header, version resource,
/// per-section Shannon entropy, overlay detection and the PE checksum. The
/// checksum and all section entropies are computed in ONE sequential read pass
/// over the file (plus small header seeks), so even large files cost roughly
/// one full read. Defensive against malformed files: every RVA/offset is
/// bounds-checked, tables are capped, and a parse error yields Status=Failed
/// with whatever was collected. Non-PE input yields Status=Skipped. No UI
/// access; safe on a worker thread.
/// Called from: Core.IntegrityScanner (PE ANALYSIS stage).
/// </summary>
public static class PeAnalyzer
{
    private const int MaxSections = 96;
    private const int MaxImportDlls = 256;
    private const int MaxImportFunctions = 65536;
    private const int MaxTlsCallbacks = 64;

    /// <summary>
    /// Analyzes one file. progress reports 0..1 during the full-file read pass
    /// (checksum + entropy); cancel aborts with OperationCanceledException.
    /// Called from: IntegrityScanner.RunAsync.
    /// </summary>
    public static IntegrityReport.PeAnalysisSection Analyze(string path,
        IProgress<double>? progress = null, CancellationToken cancel = default)
    {
        var pe = new IntegrityReport.PeAnalysisSection();
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 1 << 16);
            using var reader = new BinaryReader(stream);
            Parse(pe, path, stream, reader, progress, cancel);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                   or EndOfStreamException or ArgumentException)
        {
            if (pe.Status == StageStatus.Ok)
            {
                pe.Status = StageStatus.Failed;
                pe.Error = ex.Message;
            }
        }
        return pe;
    }

    /// <summary>Header walk + all sub-parsers. Called from: Analyze.</summary>
    private static void Parse(IntegrityReport.PeAnalysisSection pe, string path,
        FileStream stream, BinaryReader r, IProgress<double>? progress, CancellationToken cancel)
    {
        long fileLen = stream.Length;

        // ---- DOS header + PE signature -------------------------------------
        if (fileLen < 0x40 || r.ReadUInt16() != 0x5A4D) // "MZ"
        {
            pe.Status = StageStatus.Skipped;
            pe.Error = "not a PE file (no MZ signature)";
            return;
        }
        stream.Position = 0x3C;
        uint peOffset = r.ReadUInt32();
        if (peOffset < 0x40 || peOffset > fileLen - 24)
        {
            pe.Status = StageStatus.Skipped;
            pe.Error = "not a PE file (invalid PE header offset)";
            return;
        }
        stream.Position = peOffset;
        if (r.ReadUInt32() != 0x00004550) // "PE\0\0"
        {
            pe.Status = StageStatus.Skipped;
            pe.Error = "not a PE file (no PE signature)";
            return;
        }

        // ---- COFF header ----------------------------------------------------
        ushort machine = r.ReadUInt16();
        ushort sectionCount = r.ReadUInt16();
        pe.TimestampRaw = r.ReadUInt32();
        stream.Position += 8; // symbol table pointer + count (deprecated)
        ushort optionalSize = r.ReadUInt16();
        ushort characteristics = r.ReadUInt16();

        pe.Machine = machine switch
        {
            0x014C => "x86",
            0x8664 => "x64",
            0xAA64 => "ARM64",
            0x01C4 => "ARM (Thumb-2)",
            0x0200 => "IA-64",
            _ => $"unknown (0x{machine:X4})"
        };
        if (pe.TimestampRaw != 0)
        {
            pe.TimestampUtc = DateTimeOffset.FromUnixTimeSeconds(pe.TimestampRaw).UtcDateTime;
            pe.TimestampPlausible = pe.TimestampUtc >= new DateTime(1993, 1, 1)
                                    && pe.TimestampUtc <= DateTime.UtcNow.AddDays(2);
        }

        // ---- Optional header ------------------------------------------------
        long opt = stream.Position;
        if (optionalSize < 96 || opt + optionalSize > fileLen)
            throw new EndOfStreamException("optional header truncated");
        ushort magic = r.ReadUInt16();
        bool pe32Plus = magic == 0x20B;
        if (!pe32Plus && magic != 0x10B)
            throw new ArgumentException($"unknown optional header magic 0x{magic:X4}");
        pe.IsPe32Plus = pe32Plus;
        pe.LinkerVersion = $"{r.ReadByte()}.{r.ReadByte()}";

        stream.Position = opt + 16;
        pe.EntryPointRva = r.ReadUInt32();
        stream.Position = pe32Plus ? opt + 24 : opt + 28;
        ulong imageBase = pe32Plus ? r.ReadUInt64() : r.ReadUInt32();

        stream.Position = opt + 64;
        pe.CheckSumStored = r.ReadUInt32();
        ushort subsystem = r.ReadUInt16();
        ushort dllChars = r.ReadUInt16();
        pe.Subsystem = subsystem switch
        {
            1 => "Native",
            2 => "Windows GUI",
            3 => "Windows console",
            _ => $"other ({subsystem})"
        };
        bool isDll = (characteristics & 0x2000) != 0;
        pe.FileType = isDll ? "DLL"
            : subsystem == 1 ? "Driver/native image"
            : subsystem == 3 ? "EXE (console)"
            : "EXE (GUI)";

        pe.HighEntropyVa = (dllChars & 0x0020) != 0;
        pe.Aslr = (dllChars & 0x0040) != 0;
        pe.ForceIntegrity = (dllChars & 0x0080) != 0;
        pe.Dep = (dllChars & 0x0100) != 0;
        pe.NoSeh = (dllChars & 0x0400) != 0;
        pe.AppContainer = (dllChars & 0x1000) != 0;
        pe.ControlFlowGuard = (dllChars & 0x4000) != 0;

        stream.Position = pe32Plus ? opt + 108 : opt + 92;
        uint dirCount = Math.Min(r.ReadUInt32(), 16);
        var dirs = new (uint Rva, uint Size)[16];
        for (int i = 0; i < dirCount; i++)
            dirs[i] = (r.ReadUInt32(), r.ReadUInt32());

        // ---- Section table --------------------------------------------------
        stream.Position = opt + optionalSize;
        int sections = Math.Min((int)sectionCount, MaxSections);
        var secs = new List<(string Name, uint VSize, uint VAddr, uint RawSize, uint RawPtr, uint Chars)>();
        for (int i = 0; i < sections; i++)
        {
            var nameBytes = r.ReadBytes(8);
            string name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
            uint vSize = r.ReadUInt32();
            uint vAddr = r.ReadUInt32();
            uint rawSize = r.ReadUInt32();
            uint rawPtr = r.ReadUInt32();
            stream.Position += 12; // reloc/linenumber pointers + counts
            uint chars = r.ReadUInt32();
            // Clamp raw ranges to the file so malformed sizes cannot run away.
            if (rawPtr >= fileLen) { rawPtr = 0; rawSize = 0; }
            else if (rawPtr + (long)rawSize > fileLen) rawSize = (uint)(fileLen - rawPtr);
            secs.Add((name, vSize, vAddr, rawSize, rawPtr, chars));
        }

        foreach (var s in secs)
            pe.Sections.Add(new IntegrityReport.PeSectionInfo
            {
                Name = SanitizeName(s.Name),
                VirtualAddress = s.VAddr,
                VirtualSize = s.VSize,
                RawSize = s.RawSize,
                Readable = (s.Chars & 0x40000000) != 0,
                Writable = (s.Chars & 0x80000000) != 0,
                Executable = (s.Chars & 0x20000000) != 0,
                ContainsCode = (s.Chars & 0x00000020) != 0
            });

        // RVA -> file offset (headers below the first section map 1:1).
        uint firstSectionVa = secs.Count > 0
            ? secs.Where(s => s.VAddr > 0).Select(s => s.VAddr).DefaultIfEmpty(uint.MaxValue).Min()
            : uint.MaxValue;
        long RvaToOffset(uint rva)
        {
            foreach (var s in secs)
            {
                uint span = Math.Max(s.VSize, s.RawSize);
                if (rva >= s.VAddr && rva < s.VAddr + span)
                {
                    long off = (long)rva - s.VAddr + s.RawPtr;
                    return off < fileLen ? off : -1;
                }
            }
            return rva < firstSectionVa && rva < fileLen ? rva : -1;
        }

        // ---- Entry point location -------------------------------------------
        if (pe.EntryPointRva != 0)
        {
            var epSec = secs.FirstOrDefault(s =>
                pe.EntryPointRva >= s.VAddr && pe.EntryPointRva < s.VAddr + Math.Max(s.VSize, s.RawSize));
            if (epSec.Name != null && (epSec.VAddr != 0 || epSec.RawSize != 0))
            {
                pe.EntryPointSection = SanitizeName(epSec.Name);
                pe.EntryPointExecutable = (epSec.Chars & 0x20000000) != 0;
            }
            else
            {
                pe.EntryPointSection = null;      // outside all sections
                pe.EntryPointExecutable = false;
            }
        }

        // ---- Data directory driven parts ------------------------------------
        pe.SignatureDataSize = dirs[4].Size; // dirs[4].Rva is a FILE OFFSET here

        ParseImports(pe, stream, r, fileLen, pe32Plus, dirs[1], RvaToOffset, cancel);
        ParseExports(pe, stream, r, fileLen, dirs[0], RvaToOffset);
        ParseClr(pe, stream, r, fileLen, dirs[14], RvaToOffset);
        ParseTls(pe, stream, r, fileLen, pe32Plus, imageBase, dirs[9], RvaToOffset);
        ParseRichHeader(pe, stream, r, peOffset);

        // Batch-E parsers are individually shielded: a malformed directory must
        // not sink the rest of the PE stage.
        try { ParseDebugDirectory(pe, stream, r, fileLen, dirs[6], RvaToOffset); } catch { }
        try { ParseManifest(pe, stream, r, fileLen, dirs[2], RvaToOffset); } catch { }
        try { ParseDelayImports(pe, stream, r, fileLen, dirs[13], RvaToOffset); } catch { }
        DetectSectionAnomalies(pe, secs);

        // ---- Version resource -------------------------------------------------
        // GetFileVersionInfoEx with FILE_VER_GET_NEUTRAL reads the resources of
        // THIS file. Plain FileVersionInfo follows the MUI redirection and, for
        // localized Windows system files, returns the companion .mui file's
        // resources instead (v1.0.3.8 reported OriginalFilename "davsvc.dll.mui"
        // for WebClnt.dll because of that). Falls back to FileVersionInfo when
        // the native path yields nothing (e.g. exotic resource layouts).
        ReadNeutralVersionInfo(path, pe);

        // ---- Overlay ----------------------------------------------------------
        pe.FileSizeBytes = fileLen;
        long lastEnd = 0;
        foreach (var s in secs)
            if (s.RawSize > 0) lastEnd = Math.Max(lastEnd, (long)s.RawPtr + s.RawSize);
        long overlay = Math.Max(0, fileLen - lastEnd);
        if (pe.SignatureDataSize > 0 && dirs[4].Rva >= lastEnd)
            overlay = Math.Max(0, overlay - pe.SignatureDataSize);
        pe.OverlayBytes = overlay;

        // ---- One sequential pass: PE checksum + per-section entropy ----------
        ComputeChecksumAndEntropy(pe, stream, fileLen, checksumFieldOffset: opt + 64,
            secs, overlayStart: lastEnd, overlayLen: overlay, progress, cancel);

        DetectPackers(pe); // needs the per-section entropy from the pass above
        DetectDotNetBundle(pe, stream, fileLen);
        pe.CompilerGuess = GuessCompiler(pe);
    }

    // ------------------------------------------------------------- sub-parsers

    /// <summary>
    /// Walks the import descriptor table: DLL names, function counts and the
    /// pefile-compatible imphash (lowercase MD5 over "lib.func" CSV; extensions
    /// ocx/sys/dll stripped from lib; ordinals resolved via the FROZEN tables).
    /// Called from: Parse.
    /// </summary>
    private static void ParseImports(IntegrityReport.PeAnalysisSection pe, FileStream stream,
        BinaryReader r, long fileLen, bool pe32Plus, (uint Rva, uint Size) dir,
        Func<uint, long> rvaToOffset, CancellationToken cancel)
    {
        if (dir.Rva == 0 || dir.Size == 0) return;
        long tableOff = rvaToOffset(dir.Rva);
        if (tableOff < 0) return;

        var impStrings = new List<string>();
        int totalFuncs = 0;
        ulong ordFlag = pe32Plus ? 0x8000000000000000 : 0x80000000;

        for (int i = 0; i < MaxImportDlls; i++)
        {
            cancel.ThrowIfCancellationRequested();
            long descOff = tableOff + i * 20L;
            if (descOff + 20 > fileLen) break;
            stream.Position = descOff;
            uint oft = r.ReadUInt32();     // OriginalFirstThunk (import name table)
            stream.Position += 8;          // timestamp + forwarder chain
            uint nameRva = r.ReadUInt32();
            uint ft = r.ReadUInt32();      // FirstThunk (IAT)
            if (oft == 0 && nameRva == 0 && ft == 0) break; // terminator

            string dllName = ReadAsciiString(stream, r, rvaToOffset(nameRva), 256);
            if (dllName.Length == 0) continue;
            string dllLower = dllName.ToLowerInvariant();
            string libName = dllLower;
            int dot = libName.LastIndexOf('.');
            if (dot > 0)
            {
                string ext = libName[(dot + 1)..];
                if (ext is "ocx" or "sys" or "dll") libName = libName[..dot];
            }

            uint thunkRva = oft != 0 ? oft : ft; // some linkers leave OFT empty
            long thunkOff = rvaToOffset(thunkRva);
            int funcs = 0;
            if (thunkOff >= 0)
            {
                int width = pe32Plus ? 8 : 4;
                for (int t = 0; t < MaxImportFunctions; t++)
                {
                    long pos = thunkOff + (long)t * width;
                    if (pos + width > fileLen) break;
                    stream.Position = pos;
                    ulong thunk = pe32Plus ? r.ReadUInt64() : r.ReadUInt32();
                    if (thunk == 0) break;

                    string funcName;
                    if ((thunk & ordFlag) != 0)
                    {
                        funcName = PeImphashOrdinals.Lookup(dllLower, (int)(thunk & 0xFFFF));
                    }
                    else
                    {
                        long nameOff = rvaToOffset((uint)(thunk & 0x7FFFFFFF));
                        funcName = nameOff < 0 ? ""
                            : ReadAsciiString(stream, r, nameOff + 2, 512); // skip hint
                    }
                    if (funcName.Length > 0)
                        impStrings.Add($"{libName}.{funcName.ToLowerInvariant()}");
                    funcs++;
                }
            }

            pe.Imports.Add(new IntegrityReport.PeImportDll
            {
                Name = SanitizeName(dllName),
                FunctionCount = funcs
            });
            totalFuncs += funcs;
        }

        pe.TotalImportedFunctions = totalFuncs;
        if (impStrings.Count > 0)
        {
            byte[] md5 = MD5.HashData(System.Text.Encoding.ASCII.GetBytes(string.Join(",", impStrings)));
            pe.Imphash = Convert.ToHexString(md5).ToLowerInvariant();
        }

        DetectNotableImports(pe, impStrings);
    }

    /// <summary>
    /// Lists imported APIs that are worth a human's attention, grouped by
    /// technical function and shown with their REAL names. Deliberately NOT a
    /// capability verdict: it says which APIs are present, not what the program
    /// "does". These APIs are common in legitimate updaters, installers and
    /// debuggers, so labelling them "Process injection" would false-positive.
    /// The reader sees the facts and judges. Called from: ParseImports.
    /// </summary>
    private static void DetectNotableImports(IntegrityReport.PeAnalysisSection pe,
        List<string> importStrings)
    {
        // Normalize the imported names (strip lib prefix + A/W/Ex suffixes) for
        // matching only; display comes from the curated table so the casing is
        // the real WinAPI casing.
        static string Norm(string libDotFunc)
        {
            int dot = libDotFunc.IndexOf('.');
            string fn = dot >= 0 ? libDotFunc[(dot + 1)..] : libDotFunc;
            if (fn.EndsWith("exw") || fn.EndsWith("exa")) fn = fn[..^3];
            else if (fn.EndsWith("ex")) fn = fn[..^2];
            else if (fn.EndsWith("w") || fn.EndsWith("a")) fn = fn[..^1];
            return fn;
        }
        var present = importStrings.Select(Norm).ToHashSet();

        // (group label, (normalized key, display name)[]). Neutral, functional
        // group names; no judgement. Display names carry canonical casing.
        var table = new (string Group, (string Key, string Show)[] Apis)[]
        {
            ("Memory/threads", new[]
            {
                ("writeprocessmemory","WriteProcessMemory"), ("readprocessmemory","ReadProcessMemory"),
                ("createremotethread","CreateRemoteThread"), ("virtualallocex","VirtualAllocEx"),
                ("virtualprotect","VirtualProtect"), ("queueuserapc","QueueUserAPC"),
                ("setthreadcontext","SetThreadContext"), ("ntmapviewofsection","NtMapViewOfSection"),
                ("ntunmapviewofsection","NtUnmapViewOfSection"), ("ntcreatethread","NtCreateThreadEx"),
                ("rtlcreateuserthread","RtlCreateUserThread"), ("mapviewoffile","MapViewOfFile"),
            }),
            ("Debugging", new[]
            {
                ("isdebuggerpresent","IsDebuggerPresent"), ("checkremotedebuggerpresent","CheckRemoteDebuggerPresent"),
                ("ntqueryinformationprocess","NtQueryInformationProcess"), ("outputdebugstring","OutputDebugString"),
                ("ntsetinformationthread","NtSetInformationThread"), ("debugactiveprocess","DebugActiveProcess"),
            }),
            ("Registry/services", new[]
            {
                ("regsetvalue","RegSetValueEx"), ("regcreatekey","RegCreateKeyEx"),
                ("regopenkey","RegOpenKeyEx"), ("regdeletevalue","RegDeleteValue"),
                ("createservice","CreateService"), ("openscmanager","OpenSCManager"),
                ("startservice","StartService"), ("movefile","MoveFileEx"),
            }),
            ("Networking", new[]
            {
                ("wsastartup","WSAStartup"), ("connect","connect"), ("send","send"), ("recv","recv"),
                ("socket","socket"), ("internetopen","InternetOpen"), ("internetconnect","InternetConnect"),
                ("httpsendrequest","HttpSendRequest"), ("winhttpopen","WinHttpOpen"),
                ("winhttpconnect","WinHttpConnect"), ("winhttpsendrequest","WinHttpSendRequest"),
                ("urldownloadtofile","URLDownloadToFile"), ("dnsquery","DnsQuery"),
            }),
            ("Dynamic loading", new[]
            {
                ("getprocaddress","GetProcAddress"), ("loadlibrary","LoadLibrary"),
                ("ldrgetprocedureaddress","LdrGetProcedureAddress"), ("ldrloaddll","LdrLoadDll"),
            }),
            ("Cryptography", new[]
            {
                ("cryptencrypt","CryptEncrypt"), ("cryptdecrypt","CryptDecrypt"),
                ("cryptacquirecontext","CryptAcquireContext"), ("cryptgenkey","CryptGenKey"),
                ("bcryptencrypt","BCryptEncrypt"), ("bcryptdecrypt","BCryptDecrypt"),
                ("cryptunprotectdata","CryptUnprotectData"), ("cryptprotectdata","CryptProtectData"),
            }),
            ("Credentials", new[]
            {
                ("credenumerate","CredEnumerate"), ("credread","CredRead"),
                ("lsaopenpolicy","LsaOpenPolicy"), ("lsaretrieveprivatedata","LsaRetrievePrivateData"),
                ("samconnect","SamConnect"),
            }),
            ("Input capture", new[]
            {
                ("setwindowshook","SetWindowsHookEx"), ("getasynckeystate","GetAsyncKeyState"),
                ("getkeystate","GetKeyState"), ("getrawinputdata","GetRawInputData"),
                ("getforegroundwindow","GetForegroundWindow"), ("bitblt","BitBlt"),
            }),
        };

        foreach (var (group, apis) in table)
        {
            var shown = apis.Where(a => present.Contains(a.Key))
                            .Select(a => a.Show).Distinct().ToList();
            if (shown.Count > 0)
                pe.NotableImports.Add($"{group,-16}: {string.Join(", ", shown)}");
        }
    }

    /// <summary>Export directory: internal DLL name + named export count. Called from: Parse.</summary>
    private static void ParseExports(IntegrityReport.PeAnalysisSection pe, FileStream stream,
        BinaryReader r, long fileLen, (uint Rva, uint Size) dir, Func<uint, long> rvaToOffset)
    {
        if (dir.Rva == 0 || dir.Size == 0) return;
        long off = rvaToOffset(dir.Rva);
        if (off < 0 || off + 40 > fileLen) return;
        stream.Position = off + 12;
        uint nameRva = r.ReadUInt32();            // Name (RVA of the DLL name)
        stream.Position = off + 24;
        uint numberOfNames = r.ReadUInt32();      // NumberOfNames
        pe.ExportCount = (int)Math.Min(numberOfNames, 1_000_000);
        stream.Position = off + 32;
        uint addrOfNames = r.ReadUInt32();        // AddressOfNames (RVA of name-pointer table)
        string name = ReadAsciiString(stream, r, rvaToOffset(nameRva), 256);
        pe.ExportDllName = name.Length > 0 ? SanitizeName(name) : null;

        // Read every named export (the report lists them all). The high ceiling
        // is only a guard against a corrupt NumberOfNames.
        const int MaxExportNames = 65536;
        int take = (int)Math.Min(numberOfNames, MaxExportNames);
        long namesOff = rvaToOffset(addrOfNames);
        if (namesOff < 0) return;
        for (int i = 0; i < take; i++)
        {
            long p = namesOff + i * 4L;
            if (p + 4 > fileLen) break;
            stream.Position = p;
            uint strRva = r.ReadUInt32();
            long strOff = rvaToOffset(strRva);
            if (strOff < 0) continue;
            string ex = ReadAsciiString(stream, r, strOff, 256);
            if (ex.Length > 0) pe.ExportNames.Add(SanitizeName(ex));
        }
    }

    /// <summary>COR20 header + metadata version string for .NET files. Called from: Parse.</summary>
    private static void ParseClr(IntegrityReport.PeAnalysisSection pe, FileStream stream,
        BinaryReader r, long fileLen, (uint Rva, uint Size) dir, Func<uint, long> rvaToOffset)
    {
        if (dir.Rva == 0 || dir.Size == 0) return;
        long off = rvaToOffset(dir.Rva);
        if (off < 0 || off + 24 > fileLen) return;

        pe.IsDotNet = true;
        stream.Position = off + 8;
        uint metaRva = r.ReadUInt32();
        stream.Position = off + 16;
        uint flags = r.ReadUInt32();
        pe.ClrIlOnly = (flags & 0x1) != 0;
        pe.Clr32BitRequired = (flags & 0x2) != 0;

        long metaOff = rvaToOffset(metaRva);
        if (metaOff < 0 || metaOff + 20 > fileLen) return;
        stream.Position = metaOff;
        if (r.ReadUInt32() != 0x424A5342) return; // "BSJB"
        stream.Position = metaOff + 12;
        int verLen = (int)Math.Min(r.ReadUInt32(), 64);
        var verBytes = r.ReadBytes(verLen);
        pe.ClrMetadataVersion = System.Text.Encoding.ASCII
            .GetString(verBytes).TrimEnd('\0');
    }

    /// <summary>Counts TLS callbacks (they run BEFORE the entry point). Called from: Parse.</summary>
    private static void ParseTls(IntegrityReport.PeAnalysisSection pe, FileStream stream,
        BinaryReader r, long fileLen, bool pe32Plus, ulong imageBase,
        (uint Rva, uint Size) dir, Func<uint, long> rvaToOffset)
    {
        if (dir.Rva == 0 || dir.Size == 0) return;
        long off = rvaToOffset(dir.Rva);
        int ptr = pe32Plus ? 8 : 4;
        if (off < 0 || off + ptr * 4 > fileLen) return;

        stream.Position = off + ptr * 3; // AddressOfCallBacks (a VA, not an RVA)
        ulong cbVa = pe32Plus ? r.ReadUInt64() : r.ReadUInt32();
        if (cbVa <= imageBase) return;
        long cbOff = rvaToOffset((uint)(cbVa - imageBase));
        if (cbOff < 0) return;

        int count = 0;
        for (int i = 0; i < MaxTlsCallbacks; i++)
        {
            long pos = cbOff + (long)i * ptr;
            if (pos + ptr > fileLen) break;
            stream.Position = pos;
            ulong cb = pe32Plus ? r.ReadUInt64() : r.ReadUInt32();
            if (cb == 0) break;
            count++;
        }
        pe.TlsCallbackCount = count;
    }

    /// <summary>
    /// Detects the MSVC Rich header between the DOS header and the PE header
    /// ("Rich" marker + XOR key, entries decoded back to the "DanS" start).
    /// Only presence and entry count are recorded; the toolchain mapping comes
    /// from the linker version (more reliable). Called from: Parse.
    /// </summary>
    private static void ParseRichHeader(IntegrityReport.PeAnalysisSection pe, FileStream stream,
        BinaryReader r, uint peOffset)
    {
        int span = (int)Math.Min(peOffset, 0x400);
        if (span <= 0x40) return;
        stream.Position = 0;
        var buf = r.ReadBytes(span);

        int rich = -1;
        for (int i = 0x40; i + 8 <= buf.Length; i += 4)
            if (buf[i] == 'R' && buf[i + 1] == 'i' && buf[i + 2] == 'c' && buf[i + 3] == 'h')
            { rich = i; break; }
        if (rich < 0) return;

        uint key = BitConverter.ToUInt32(buf, rich + 4);
        int entries = 0;
        int dans = -1;
        for (int i = rich - 8; i >= 0x40; i -= 8)
        {
            uint id = BitConverter.ToUInt32(buf, i) ^ key;
            if (id == 0x536E6144) // "DanS"
            {
                dans = i;
                pe.RichHeaderPresent = true;
                pe.RichHeaderEntries = entries;
                break;
            }
            entries++;
            if (entries > 64) return; // implausible, treat as absent
        }
        if (dans < 0) return;

        // Real (comp.id, count) pairs start 16 bytes after DanS (three padding
        // dwords follow the marker). Collect a capped raw summary per tool id.
        for (int i = dans + 16; i + 8 <= rich && pe.RichEntrySummaries.Count < 4096; i += 8)
        {
            uint compId = BitConverter.ToUInt32(buf, i) ^ key;
            uint count = BitConverter.ToUInt32(buf, i + 4) ^ key;
            if (compId == 0 && count == 0) continue;
            pe.RichEntrySummaries.Add(
                $"0x{compId >> 16:X4}.{compId & 0xFFFF} x{count}");
        }

        // Checksum: the XOR key doubles as a checksum over the DOS header/stub
        // (e_lfanew zeroed) plus every entry. A mismatch means the header was
        // edited or transplanted from another binary.
        static uint Rol(uint v, int n) { n &= 31; return (v << n) | (v >> (32 - n)); }
        uint sum = (uint)dans;
        for (int i = 0; i < dans; i++)
        {
            if (i is >= 0x3C and < 0x40) continue; // e_lfanew counts as zero
            sum += Rol(buf[i], i);
        }
        for (int i = dans + 16; i + 8 <= rich; i += 8)
        {
            uint compId = BitConverter.ToUInt32(buf, i) ^ key;
            uint count = BitConverter.ToUInt32(buf, i + 4) ^ key;
            sum += Rol(compId, (int)count);
        }
        pe.RichChecksumValid = sum == key;
    }

    /// <summary>
    /// ONE sequential read over the whole file computing the standard PE
    /// checksum (16-bit one's-complement sum skipping the CheckSum field, plus
    /// the file length) and tallying byte frequencies per section for the
    /// entropy values. Reports progress and honors cancellation per chunk.
    /// Called from: Parse.
    /// </summary>
    private static void ComputeChecksumAndEntropy(IntegrityReport.PeAnalysisSection pe,
        FileStream stream, long fileLen, long checksumFieldOffset,
        List<(string Name, uint VSize, uint VAddr, uint RawSize, uint RawPtr, uint Chars)> secs,
        long overlayStart, long overlayLen,
        IProgress<double>? progress, CancellationToken cancel)
    {
        var counts = new long[secs.Count][];
        for (int i = 0; i < secs.Count; i++)
            if (secs[i].RawSize > 0) counts[i] = new long[256];
        // Overlay entropy piggybacks on the same read pass (the pass covers the
        // whole file anyway, so this costs one extra tally per overlay byte).
        long[]? overlayCounts = overlayLen > 0 ? new long[256] : null;

        ulong sum = 0;
        int pendingByte = -1; // low byte of a word split across chunks
        var buffer = new byte[1 << 20];
        stream.Position = 0;
        long pos = 0;
        var lastReport = DateTime.MinValue;

        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancel.ThrowIfCancellationRequested();

            // Checksum: word-wise sum, the 4 CheckSum field bytes count as 0.
            for (int i = 0; i < read; i++)
            {
                long abs = pos + i;
                int b = (abs >= checksumFieldOffset && abs < checksumFieldOffset + 4)
                    ? 0 : buffer[i];
                if (pendingByte < 0)
                {
                    pendingByte = b;
                }
                else
                {
                    sum += (uint)(pendingByte | (b << 8));
                    sum = (sum & 0xFFFF) + (sum >> 16);
                    pendingByte = -1;
                }
            }

            // Entropy: tally the chunk's overlap with every section's raw range.
            for (int s = 0; s < secs.Count; s++)
            {
                if (counts[s] == null) continue;
                long start = Math.Max(pos, secs[s].RawPtr);
                long end = Math.Min(pos + read, (long)secs[s].RawPtr + secs[s].RawSize);
                for (long a = start; a < end; a++)
                    counts[s][buffer[a - pos]]++;
            }
            if (overlayCounts != null)
            {
                long start = Math.Max(pos, overlayStart);
                long end = Math.Min(pos + read, overlayStart + overlayLen);
                for (long a = start; a < end; a++)
                    overlayCounts[buffer[a - pos]]++;
            }

            pos += read;
            var now = DateTime.UtcNow;
            if (progress != null && (now - lastReport).TotalMilliseconds >= 50)
            {
                lastReport = now;
                progress.Report(fileLen > 0 ? (double)pos / fileLen : 1);
            }
        }
        progress?.Report(1);

        if (pendingByte >= 0) // odd file length: final byte padded with 0
        {
            sum += (uint)pendingByte;
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum = (sum & 0xFFFF) + (sum >> 16);
        pe.CheckSumComputed = (uint)(sum + (ulong)fileLen);

        for (int i = 0; i < secs.Count && i < pe.Sections.Count; i++)
            if (counts[i] != null)
                pe.Sections[i].Entropy = HashTool.ShannonEntropy(counts[i]);
        if (overlayCounts != null)
            pe.OverlayEntropy = HashTool.ShannonEntropy(overlayCounts);
    }

    // -------------------------------------------------------- batch E parsers

    /// <summary>
    /// Reads the debug directory (data dir 6): extracts the PDB path from a
    /// CodeView RSDS entry (build path, often revealing) and notes a REPRO entry
    /// that marks a reproducible build. Bounds-checked; a bad entry is skipped.
    /// Called from: Parse.
    /// </summary>
    private static void ParseDebugDirectory(IntegrityReport.PeAnalysisSection pe,
        FileStream stream, BinaryReader r, long fileLen,
        (uint Rva, uint Size) dir, Func<uint, long> rvaToOffset)
    {
        if (dir.Rva == 0 || dir.Size == 0) return;
        long off = rvaToOffset(dir.Rva);
        if (off < 0) return;
        int count = (int)Math.Min(dir.Size / 28, 64); // 28 bytes per entry
        for (int i = 0; i < count; i++)
        {
            long entry = off + i * 28;
            if (entry + 28 > fileLen) break;
            stream.Position = entry + 12; // skip chars/time/major/minor
            uint type = r.ReadUInt32();
            uint sizeOfData = r.ReadUInt32();
            r.ReadUInt32(); // AddressOfRawData
            uint ptrToRaw = r.ReadUInt32();

            if (type == 16) pe.DebugReproducible = true;      // IMAGE_DEBUG_TYPE_REPRO
            if (type == 2 && ptrToRaw > 0 && ptrToRaw < fileLen && sizeOfData is > 24 and < 4096)
            {
                stream.Position = ptrToRaw;
                uint sig = r.ReadUInt32();
                if (sig == 0x53445352) // "RSDS"
                    pe.PdbPath = ReadAsciiString(stream, r, ptrToRaw + 24,
                        (int)Math.Min(sizeOfData - 24, 512)); // after sig(4)+GUID(16)+Age(4)
            }
        }
    }

    /// <summary>
    /// Locates the RT_MANIFEST resource (type 24) in the resource directory and
    /// pulls the execution level, uiAccess, autoElevate and dpiAware values with
    /// light string scanning (no full XML parse; manifests are tiny and ASCII).
    /// Called from: Parse.
    /// </summary>
    private static void ParseManifest(IntegrityReport.PeAnalysisSection pe,
        FileStream stream, BinaryReader r, long fileLen,
        (uint Rva, uint Size) dir, Func<uint, long> rvaToOffset)
    {
        if (dir.Rva == 0) return;
        long rootOff = rvaToOffset(dir.Rva);
        if (rootOff < 0) return;

        (long dataRva, long size)? found =
            FindResourceData(stream, r, rootOff, fileLen, 24);
        if (found == null) return;
        long manOff = rvaToOffset((uint)found.Value.dataRva);
        if (manOff < 0) return;
        int len = (int)Math.Min(found.Value.size, 16384);
        if (manOff + len > fileLen) len = (int)(fileLen - manOff);
        if (len <= 0) return;

        stream.Position = manOff;
        string xml = System.Text.Encoding.UTF8.GetString(r.ReadBytes(len));
        pe.HasManifest = true;

        pe.ManifestExecutionLevel = ExtractAttr(xml, "level");
        string? ui = ExtractAttr(xml, "uiAccess");
        if (ui != null) pe.ManifestUiAccess = ui.Equals("true", StringComparison.OrdinalIgnoreCase);

        int ae = xml.IndexOf("autoElevate", StringComparison.OrdinalIgnoreCase);
        if (ae >= 0)
        {
            int gt = xml.IndexOf('>', ae);
            int lt = gt >= 0 ? xml.IndexOf('<', gt) : -1;
            if (gt >= 0 && lt > gt)
                pe.ManifestAutoElevate = xml[(gt + 1)..lt].Trim()
                    .Equals("true", StringComparison.OrdinalIgnoreCase);
        }
        int d = xml.IndexOf("<dpiAware", StringComparison.OrdinalIgnoreCase);
        if (d >= 0)
        {
            int gt = xml.IndexOf('>', d);
            int lt = gt >= 0 ? xml.IndexOf('<', gt) : -1;
            if (gt >= 0 && lt > gt) pe.ManifestDpiAware = xml[(gt + 1)..lt].Trim();
            pe.ManifestDpiAware ??= "declared";
        }
        int lp = xml.IndexOf("longPathAware", StringComparison.OrdinalIgnoreCase);
        if (lp >= 0)
        {
            int gt = xml.IndexOf('>', lp);
            int lt = gt >= 0 ? xml.IndexOf('<', gt) : -1;
            if (gt >= 0 && lt > gt)
                pe.ManifestLongPathAware = xml[(gt + 1)..lt].Trim()
                    .Equals("true", StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>Finds the first data leaf under a resource type id by walking
    /// the type/name/language levels. Returns (dataRva, size) or null.
    /// Called from: ParseManifest.</summary>
    private static (long dataRva, long size)? FindResourceData(FileStream stream,
        BinaryReader r, long rootOff, long fileLen, uint wantedType)
    {
        void ReadEntry(long dirOff, int index, out uint id, out bool isDir, out long nextOff)
        {
            id = 0; isDir = false; nextOff = 0;
            long entry = dirOff + 16 + index * 8;
            if (entry + 8 > fileLen) return;
            stream.Position = entry;
            id = r.ReadUInt32();
            uint offsetField = r.ReadUInt32();
            isDir = (offsetField & 0x80000000) != 0;
            nextOff = rootOff + (offsetField & 0x7FFFFFFF);
        }
        int Total(long dirOff)
        {
            if (dirOff + 16 > fileLen || dirOff < 0) return 0;
            stream.Position = dirOff + 12;
            ushort named = r.ReadUInt16();
            ushort idc = r.ReadUInt16();
            return named + idc;
        }

        int typeCount = Total(rootOff);
        for (int t = 0; t < typeCount && t < 256; t++)
        {
            ReadEntry(rootOff, t, out uint id, out bool isDir, out long nameOff);
            if (id != wantedType || !isDir) continue;
            int nameCount = Total(nameOff);
            for (int n = 0; n < nameCount && n < 256; n++)
            {
                ReadEntry(nameOff, n, out _, out bool nDir, out long langOff);
                if (!nDir) continue;
                int langCount = Total(langOff);
                for (int l = 0; l < langCount && l < 64; l++)
                {
                    ReadEntry(langOff, l, out _, out _, out long dataEntry);
                    if (dataEntry + 8 > fileLen || dataEntry < 0) continue;
                    stream.Position = dataEntry;
                    uint dataRva = r.ReadUInt32();
                    uint size = r.ReadUInt32();
                    return (dataRva, size);
                }
            }
        }
        return null;
    }

    /// <summary>
    /// Reads delay-import descriptors (data dir 13) and collects the DLL names.
    /// Called from: Parse.
    /// </summary>
    private static void ParseDelayImports(IntegrityReport.PeAnalysisSection pe,
        FileStream stream, BinaryReader r, long fileLen,
        (uint Rva, uint Size) dir, Func<uint, long> rvaToOffset)
    {
        if (dir.Rva == 0) return;
        long off = rvaToOffset(dir.Rva);
        if (off < 0) return;
        for (int i = 0; i < 256; i++) // each descriptor is 32 bytes
        {
            long d = off + i * 32;
            if (d + 32 > fileLen) break;
            stream.Position = d + 4; // skip Attributes
            uint nameRva = r.ReadUInt32();
            if (nameRva == 0) break; // null terminator descriptor
            long nameOff = rvaToOffset(nameRva);
            if (nameOff < 0) continue;
            string name = ReadAsciiString(stream, r, nameOff, 128);
            if (name.Length > 0) pe.DelayImports.Add(name);
            if (pe.DelayImports.Count >= 4096) break;
        }
    }

    /// <summary>
    /// Detects overlapping raw section ranges, non-printable section names and
    /// executable sections with zero raw data; all unusual for compiler output.
    /// Called from: Parse.
    /// </summary>
    private static void DetectSectionAnomalies(IntegrityReport.PeAnalysisSection pe,
        List<(string Name, uint VSize, uint VAddr, uint RawSize, uint RawPtr, uint Chars)> secs)
    {
        var raw = secs.Where(s => s.RawSize > 0).OrderBy(s => s.RawPtr).ToList();
        for (int i = 1; i < raw.Count; i++)
        {
            long prevEnd = (long)raw[i - 1].RawPtr + raw[i - 1].RawSize;
            if (raw[i].RawPtr < prevEnd)
                pe.SectionAnomalies.Add(
                    $"sections {SanitizeName(raw[i - 1].Name)} and {SanitizeName(raw[i].Name)} overlap on disk");
        }
        foreach (var s in secs)
        {
            bool clean = s.Name.All(c => c == '\0' || (c >= 0x20 && c < 0x7F));
            if (!clean)
                pe.SectionAnomalies.Add(
                    $"section name {SanitizeName(s.Name)} contains non-printable bytes");
            if (s.RawSize == 0 && (s.Chars & 0x20000000) != 0 && s.VSize > 0)
                pe.SectionAnomalies.Add(
                    $"section {SanitizeName(s.Name)} is executable but has zero raw data");
        }
    }

    /// <summary>
    /// Deterministic .NET single-file bundle detection: every apphost carries a
    /// fixed 32-byte bundle signature; in a real single-file build the 8 bytes
    /// IMMEDIATELY BEFORE it hold the non-zero file offset of the bundle
    /// header (a plain apphost has 0 there). Marker found + plausible offset =
    /// the overlay IS a .NET bundle (a fact, not a heuristic), which explains
    /// a large high-entropy overlay. The search covers the PE IMAGE only (file
    /// minus overlay, capped at 64 MB): the marker sits in the host's .data
    /// section, which for singlefilehost lies several MB into the file, while
    /// scanning the multi-GB overlay itself would be waste. Requires an
    /// overlay: without one there is nothing bundled. Called from: Parse.
    /// </summary>
    private static void DetectDotNetBundle(IntegrityReport.PeAnalysisSection pe,
        FileStream stream, long fileLen)
    {
        // The bundle signature bytes VERBATIM from dotnet/runtime
        // src/native/corehost/apphost/bundle_marker.cpp (its comment claims
        // "SHA-256 for '.net core bundle'", but the actual bytes differ from
        // that hash: treat them as an opaque constant, do NOT recompute).
        ReadOnlySpan<byte> marker = new byte[]
        {
            0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38,
            0x72, 0x7B, 0x93, 0x02, 0x14, 0xD7, 0xA0, 0x32,
            0x13, 0xF5, 0xB9, 0xE6, 0xEF, 0xAE, 0x33, 0x18,
            0xEE, 0x3B, 0x2D, 0xCE, 0x24, 0xB3, 0x6A, 0xAE
        };

        try
        {
            if (pe.OverlayBytes <= 0) return; // no overlay, nothing bundled
            long imageEnd = Math.Max(0, fileLen - pe.OverlayBytes);
            int searchLen = (int)Math.Min(imageEnd, 64L * 1024 * 1024);
            if (searchLen < marker.Length + 8) return;

            // Chunked scan (1 MB pieces, 39-byte overlap for marker + offset
            // field across a boundary) so a large PE image never forces a
            // large-object-heap allocation.
            const int chunkSize = 1024 * 1024;
            int overlap = marker.Length + 8 - 1;
            var buf = new byte[chunkSize + overlap];
            long pos = 0;
            int carried = 0;
            stream.Position = 0;
            while (pos < searchLen)
            {
                int want = (int)Math.Min(chunkSize, searchLen - pos);
                int total = 0;
                while (total < want)
                {
                    int n = stream.Read(buf, carried + total, want - total);
                    if (n <= 0) break;
                    total += n;
                }
                if (total == 0) break;
                int filled = carried + total;

                int idx = ((ReadOnlySpan<byte>)buf)[..filled].IndexOf(marker);
                if (idx >= 8)
                {
                    long headerOffset = BitConverter.ToInt64(buf, idx - 8);
                    if (headerOffset <= 0 || headerOffset >= fileLen) return; // plain apphost placeholder
                    pe.DotNetBundle = true;
                    pe.DotNetBundleHeaderOffset = headerOffset;
                    return;
                }

                // Keep the tail so a marker straddling the boundary is found.
                carried = Math.Min(overlap, filled);
                Array.Copy(buf, filled - carried, buf, 0, carried);
                pos += total;
            }
        }
        catch
        {
            // Best effort: a read problem here never fails the PE stage.
        }
    }

    /// <summary>
    /// Flags likely packers by known section names and by the entropy/import
    /// heuristic (very high code/.rsrc entropy plus a tiny import table). Always
    /// heuristic; the wording says so. Called from: Parse (after the entropy pass).
    /// </summary>
    private static void DetectPackers(IntegrityReport.PeAnalysisSection pe)
    {
        var byName = new (string Prefix, string Packer)[]
        {
            ("UPX", "UPX"), (".vmp", "VMProtect"), (".themida", "Themida"),
            (".enigma", "Enigma"), (".aspack", "ASPack"), (".adata", "ASPack"),
            (".MPRESS", "MPRESS"), (".petite", "Petite"), (".nsp", "NsPack"),
            (".pklstb", "PKLite"), (".WWP", "WWPack"), (".taz", "PESpin")
        };
        foreach (var s in pe.Sections)
            foreach (var (prefix, packer) in byName)
            {
                string tag = $"{packer} (section {s.Name})";
                if (s.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                    && !pe.PackerSigns.Contains(tag))
                    pe.PackerSigns.Add(tag);
            }

        double textEnt = pe.Sections
            .Where(s => s.ContainsCode || s.Name.Equals(".text", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.Entropy ?? 0).DefaultIfEmpty(0).Max();
        double rsrcEnt = pe.Sections
            .Where(s => s.Name.Equals(".rsrc", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.Entropy ?? 0).DefaultIfEmpty(0).Max();
        int impDlls = pe.Imports.Count;
        if ((textEnt > 7.2 || rsrcEnt > 7.2) && impDlls > 0 && impDlls < 20 && !pe.IsDotNet)
            pe.PackerSigns.Add(System.FormattableString.Invariant(
                $"entropy/import heuristic (code entropy {textEnt:0.00}, .rsrc {rsrcEnt:0.00}, only {impDlls} import DLLs)"));
    }

    /// <summary>Reads an attribute value (attr="..." or attr='...'),
    /// case-insensitive, from a manifest XML string. Called from: ParseManifest.</summary>
    private static string? ExtractAttr(string xml, string attr)
    {
        int a = xml.IndexOf(attr, StringComparison.OrdinalIgnoreCase);
        if (a < 0) return null;
        int eq = xml.IndexOf('=', a);
        if (eq < 0) return null;
        int q1 = xml.IndexOfAny(new[] { '"', '\'' }, eq);
        if (q1 < 0) return null;
        int q2 = xml.IndexOf(xml[q1], q1 + 1);
        if (q2 <= q1) return null;
        return xml[(q1 + 1)..q2].Trim();
    }

    // ---------------------------------------------------------------- helpers

    /// <summary>
    /// Toolchain guess from CLR presence, packer section names, Rich header and
    /// linker version. Best effort; the output always labels it heuristic.
    /// Called from: Parse.
    /// </summary>
    private static string GuessCompiler(IntegrityReport.PeAnalysisSection pe)
    {
        if (pe.IsDotNet)
            return $".NET (managed{(pe.ClrMetadataVersion != null ? $", metadata {pe.ClrMetadataVersion}" : "")})";

        var names = pe.Sections.Select(s => s.Name).ToList();
        if (names.Any(n => n.StartsWith("UPX", StringComparison.OrdinalIgnoreCase)))
            return "UPX-packed (original toolchain hidden)";
        if (names.Any(n => n is ".go.buildinfo" or ".symtab"))
            return "Go (gc toolchain)";
        if (names.Contains("CODE") && names.Contains("DATA") || names.Contains(".itext"))
            return "Borland/Embarcadero (Delphi or C++Builder)";
        if (names.Any(n => n.StartsWith(".debug_")) || names.Contains(".eh_fram"))
            return "GCC (MinGW-w64)";

        string vs = "";
        var parts = pe.LinkerVersion.Split('.');
        if (parts.Length == 2 && int.TryParse(parts[0], out int lMajor)
                              && int.TryParse(parts[1], out int lMinor))
            vs = lMajor switch
            {
                14 => lMinor >= 30 ? "Visual Studio 2022"
                    : lMinor >= 20 ? "Visual Studio 2019"
                    : lMinor >= 10 ? "Visual Studio 2017"
                    : "Visual Studio 2015",
                12 => "Visual Studio 2013",
                11 => "Visual Studio 2012",
                10 => "Visual Studio 2010",
                9 => "Visual Studio 2008",
                8 => "Visual Studio 2005",
                7 => "Visual Studio .NET 2002/2003",
                6 => "Visual C++ 6",
                _ => ""
            };
        if (pe.RichHeaderPresent && vs.Length > 0)
            return $"MSVC ({vs}, linker {pe.LinkerVersion})";
        if (vs.Length > 0)
            return $"MSVC-compatible linker {pe.LinkerVersion} ({vs} era; possibly Clang/LLD)";
        return "unknown";
    }

    /// <summary>Reads a NUL-terminated ASCII string at a file offset (-1 = none). Called from: import/export parsing.</summary>
    private static string ReadAsciiString(FileStream stream, BinaryReader r, long offset, int maxLen)
    {
        if (offset < 0 || offset >= stream.Length) return "";
        stream.Position = offset;
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < maxLen && stream.Position < stream.Length; i++)
        {
            int b = stream.ReadByte();
            if (b <= 0) break;
            sb.Append((char)b);
        }
        return sb.ToString();
    }

    /// <summary>Keeps names printable so malformed bytes cannot mangle the console. Called from: parsers.</summary>
    private static string SanitizeName(string name)
    {
        var chars = name.Where(c => c >= 0x20 && c < 0x7F).ToArray();
        return chars.Length > 0 ? new string(chars) : "(unprintable)";
    }

    // -------------------------------------------------------------------------
    // Neutral version resource (no MUI redirection)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Reads the version STRING values from the file's OWN resources via
    /// GetFileVersionInfoEx(FILE_VER_GET_NEUTRAL). FileVersionInfo would follow
    /// the MUI redirection and read the localized companion file instead, which
    /// falsified OriginalFilename for Windows system DLLs. Falls back to
    /// FileVersionInfo when the native path returns nothing.
    /// Called from: Analyze.
    /// </summary>
    private static void ReadNeutralVersionInfo(string path, IntegrityReport.PeAnalysisSection pe)
    {
        try
        {
            if (TryReadNeutralStrings(path, out var values))
            {
                pe.VersionCompany = values.GetValueOrDefault("CompanyName", "");
                pe.VersionProduct = values.GetValueOrDefault("ProductName", "");
                pe.VersionFileVersion = values.GetValueOrDefault("FileVersion", "");
                pe.VersionOriginalFilename = values.GetValueOrDefault("OriginalFilename", "");
                pe.VersionDescription = values.GetValueOrDefault("FileDescription", "");
                return;
            }
        }
        catch { /* fall through to the BCL */ }

        try
        {
            var vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
            pe.VersionCompany = vi.CompanyName ?? "";
            pe.VersionProduct = vi.ProductName ?? "";
            pe.VersionFileVersion = vi.FileVersion ?? "";
            pe.VersionOriginalFilename = vi.OriginalFilename ?? "";
            pe.VersionDescription = vi.FileDescription ?? "";
        }
        catch { /* resource-less or locked: leave empty */ }
    }

    private const uint FILE_VER_GET_NEUTRAL = 0x02;

    [System.Runtime.InteropServices.DllImport("version.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFileVersionInfoSizeExW(uint dwFlags, string filename, out uint handle);

    [System.Runtime.InteropServices.DllImport("version.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern bool GetFileVersionInfoExW(uint dwFlags, string filename, uint handle, uint len, byte[] data);

    [System.Runtime.InteropServices.DllImport("version.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern bool VerQueryValueW(byte[] block, string subBlock, out IntPtr buffer, out uint len);

    /// <summary>
    /// Loads the neutral version block and extracts the five string values ClamHub
    /// reports, trying every translation listed in \VarFileInfo\Translation plus
    /// the common en-US fallbacks. Returns false when no StringFileInfo exists.
    /// Called from: ReadNeutralVersionInfo.
    /// </summary>
    private static bool TryReadNeutralStrings(string path, out Dictionary<string, string> values)
    {
        values = new Dictionary<string, string>();
        uint size = GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, path, out _);
        if (size == 0 || size > 4 * 1024 * 1024) return false;
        var block = new byte[size];
        if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, path, 0, size, block)) return false;

        // Candidate lang+codepage pairs: the declared translations first, then
        // the usual suspects (some files declare none but still carry 040904B0).
        var candidates = new List<string>();
        if (VerQueryValueW(block, "\\VarFileInfo\\Translation", out var tPtr, out var tLen) && tLen >= 4)
        {
            for (uint i = 0; i + 4 <= tLen; i += 4)
            {
                ushort lang = (ushort)System.Runtime.InteropServices.Marshal.ReadInt16(tPtr, (int)i);
                ushort cp = (ushort)System.Runtime.InteropServices.Marshal.ReadInt16(tPtr, (int)i + 2);
                candidates.Add($"{lang:X4}{cp:X4}");
            }
        }
        foreach (var fb in new[] { "040904B0", "040904E4", "00000000", "000004B0" })
            if (!candidates.Contains(fb)) candidates.Add(fb);

        string[] keys = { "CompanyName", "ProductName", "FileVersion", "OriginalFilename", "FileDescription" };
        foreach (var trans in candidates)
        {
            foreach (var key in keys)
            {
                if (values.ContainsKey(key)) continue;
                if (VerQueryValueW(block, $"\\StringFileInfo\\{trans}\\{key}", out var vPtr, out var vLen)
                    && vPtr != IntPtr.Zero && vLen > 0)
                {
                    var s = System.Runtime.InteropServices.Marshal.PtrToStringUni(vPtr);
                    if (!string.IsNullOrEmpty(s)) values[key] = s.Trim();
                }
            }
            if (values.Count == keys.Length) break;
        }
        return values.Count > 0;
    }
}
