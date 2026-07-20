using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using ClamHub.Models;

namespace ClamHub.Core;

/// <summary>
/// Verifies a file's Authenticode signature the way Windows itself does, in two
/// steps: first the signature EMBEDDED in the file, and when there is none, the
/// CATALOG signature (the file's hash is looked up in the installed security
/// catalogs; this is how most Windows system files are signed, which is why an
/// embedded-only check would call them unsigned). Verification runs offline:
/// WTD_CACHE_ONLY_URL_RETRIEVAL forbids network fetches and revocation is not
/// checked online (WTD_REVOKE_NONE), fitting a portable offline-capable tool.
/// Everything here is blocking Win32; callers run it via Task.Run.
/// Called from: IntegrityScanner.RunAsync (SIGNATURE stage).
/// </summary>
public static class AuthenticodeInspector
{
    /// <summary>
    /// Runs the full check (embedded first, then catalog) and returns the filled
    /// section. Never throws; failures land in Status/Error.
    /// Called from: IntegrityScanner.RunAsync.
    /// </summary>
    public static IntegrityReport.SignatureSection Inspect(string path)
    {
        var sec = new IntegrityReport.SignatureSection();
        try
        {
            // 1) Embedded signature.
            int hr = VerifyEmbedded(path);
            // TRUST_E_NOSIGNATURE (no signature) and TRUST_E_SUBJECT_FORM_UNKNOWN
            // (Windows cannot Authenticode-verify this file FORMAT at all, e.g.
            // a PDF/ZIP/plain file) both mean "no verifiable embedded signature":
            // fall through to the catalog check, do NOT report a broken signature.
            if (hr != TRUST_E_NOSIGNATURE && hr != TRUST_E_SUBJECT_FORM_UNKNOWN)
            {
                sec.Location = "embedded";
                sec.Trusted = hr == 0;
                sec.TrustHResult = hr;
                sec.TrustText = TrustResultText(hr);
                ReadSignerFromSignedFile(path, sec);
                ReadSigningTime(path, sec);
                return sec;
            }

            // 2) Catalog signature (hash lookup in the installed catalogs).
            hr = VerifyCatalog(path, out var catalogFile);
            if (catalogFile != null)
            {
                sec.Location = "catalog";
                sec.CatalogFile = catalogFile;
                sec.Trusted = hr == 0;
                sec.TrustHResult = hr;
                sec.TrustText = TrustResultText(hr);
                // The signer of a catalog member is the signer OF THE CATALOG.
                ReadSignerFromSignedFile(catalogFile, sec);
                return sec;
            }

            // 3) Neither: unsigned.
            sec.Location = "none";
            sec.Trusted = null;
            sec.TrustHResult = TRUST_E_NOSIGNATURE;
            sec.TrustText = "not signed";
        }
        catch (Exception ex)
        {
            sec.Status = StageStatus.Failed;
            sec.Error = ex.Message;
        }
        return sec;
    }

    /// <summary>
    /// Extracts the SIGNING TIME from an embedded signature's timestamp: first
    /// the modern RFC 3161 token (unsigned attribute 1.3.6.1.4.1.311.3.3.1),
    /// then the legacy Authenticode countersignature (PKCS#9 signingTime,
    /// 1.2.840.113549.1.9.5). Reads the PKCS#7 blob straight from the PE
    /// security directory and decodes it managed (SignedCms /
    /// Rfc3161TimestampToken from System.Security.Cryptography.Pkcs). Best
    /// effort: any problem simply leaves SignedAt null - a missing timestamp is
    /// itself reported by the writer. Embedded signatures only; a catalog's
    /// timestamp would describe the catalog, not the file. Called from: Inspect.
    /// </summary>
    private static void ReadSigningTime(string signedFile, IntegrityReport.SignatureSection sec)
    {
        try
        {
            byte[]? pkcs7 = ReadSecurityDirectory(signedFile);
            if (pkcs7 == null) return;

            var cms = new SignedCms();
            cms.Decode(pkcs7);
            if (cms.SignerInfos.Count == 0) return;
            var signer = cms.SignerInfos[0];

            // RFC 3161 timestamp token (the standard since ~2016).
            foreach (var attr in signer.UnsignedAttributes)
            {
                if (attr.Oid?.Value != "1.3.6.1.4.1.311.3.3.1" || attr.Values.Count == 0) continue;
                if (Rfc3161TimestampToken.TryDecode(attr.Values[0].RawData, out var token, out _)
                    && token != null)
                {
                    sec.SignedAt = token.TokenInfo.Timestamp.UtcDateTime;
                    sec.TimestampSource = "RFC 3161";
                    return;
                }
            }

            // Legacy countersignature with PKCS#9 signingTime.
            foreach (SignerInfo counter in signer.CounterSignerInfos)
            {
                foreach (var attr in counter.SignedAttributes)
                {
                    if (attr.Oid?.Value != "1.2.840.113549.1.9.5" || attr.Values.Count == 0) continue;
                    // The framework usually materializes the known OID as
                    // Pkcs9SigningTime; decode the raw bytes as a fallback.
                    var st = attr.Values[0] as Pkcs9SigningTime
                             ?? new Pkcs9SigningTime(attr.Values[0].RawData);
                    sec.SignedAt = st.SigningTime.ToUniversalTime();
                    sec.TimestampSource = "countersignature";
                    return;
                }
            }
        }
        catch
        {
            // Unparseable or exotic signature layout: no timestamp, no failure.
        }
    }

    /// <summary>
    /// Reads the raw PKCS#7 blob from the PE security directory (data directory
    /// index 4): a minimal standalone header walk (MZ -> e_lfanew -> optional
    /// header magic -> directory), independent of the PE stage so the SIGNATURE
    /// stage works alone. Returns null for non-PE files, unsigned files or
    /// implausible directory values. The 8-byte WIN_CERTIFICATE header
    /// (dwLength, wRevision, wCertificateType) is stripped, the bCertificate
    /// payload returned. Called from: ReadSigningTime.
    /// </summary>
    private static byte[]? ReadSecurityDirectory(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var r = new BinaryReader(stream);
            long len = stream.Length;
            if (len < 0x40) return null;
            if (r.ReadUInt16() != 0x5A4D) return null;              // "MZ"
            stream.Position = 0x3C;
            int lfanew = r.ReadInt32();
            if (lfanew <= 0 || lfanew + 24 + 2 > len) return null;
            stream.Position = lfanew;
            if (r.ReadUInt32() != 0x00004550) return null;          // "PE\0\0"
            stream.Position += 20;                                  // COFF header
            ushort magic = r.ReadUInt16();
            bool pe32Plus = magic == 0x20B;
            if (!pe32Plus && magic != 0x10B) return null;
            // Security directory = data directory index 4; the directory array
            // starts 96 (PE32) / 112 (PE32+) bytes into the optional header.
            long dirOffset = lfanew + 24 + (pe32Plus ? 112 : 96) + 4 * 8;
            if (dirOffset + 8 > len) return null;
            stream.Position = dirOffset;
            uint secOffset = r.ReadUInt32();                        // FILE offset, not an RVA
            uint secSize = r.ReadUInt32();
            if (secOffset == 0 || secSize <= 8 || secSize > 32 * 1024 * 1024
                || (long)secOffset + secSize > len) return null;

            stream.Position = secOffset + 8;                        // skip WIN_CERTIFICATE header
            return r.ReadBytes((int)(secSize - 8));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Loads the leaf signing certificate of a signed file (or catalog file) and
    /// copies subject, issuer, thumbprint and validity into the section. Uses
    /// CryptQueryObject + the signer's issuer/serial to find the certificate in
    /// the message's own store, then materializes it via X509CertificateLoader
    /// (X509Certificate.CreateFromSignedFile is obsolete since .NET 9,
    /// SYSLIB0057). Best effort: an unreadable certificate leaves the fields
    /// empty, the trust verdict from WinVerifyTrust stands on its own.
    /// Called from: Inspect.
    /// </summary>
    private static void ReadSignerFromSignedFile(string signedFile,
        IntegrityReport.SignatureSection sec)
    {
        IntPtr hStore = IntPtr.Zero, hMsg = IntPtr.Zero, pCert = IntPtr.Zero;
        IntPtr pSigner = IntPtr.Zero;
        try
        {
            // Both PE files (embedded PKCS#7) and .cat files (plain PKCS#7).
            if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, signedFile,
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                    out _, out _, out _, out hStore, out hMsg, IntPtr.Zero))
                return;

            // Primary signer (index 0): issuer + serial identify the leaf cert.
            uint cb = 0;
            if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, IntPtr.Zero, ref cb) || cb == 0)
                return;
            pSigner = Marshal.AllocHGlobal((int)cb);
            if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSigner, ref cb))
                return;
            var signer = Marshal.PtrToStructure<CMSG_SIGNER_INFO_HEAD>(pSigner);

            var certInfo = new CERT_INFO
            {
                SerialNumber = signer.SerialNumber,
                Issuer = signer.Issuer
            };
            pCert = CertFindCertificateInStore(hStore,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, ref certInfo, IntPtr.Zero);
            if (pCert == IntPtr.Zero) return;

            // Copy the DER bytes out and load them with the supported loader.
            var ctx = Marshal.PtrToStructure<CERT_CONTEXT>(pCert);
            if (ctx.pbCertEncoded == IntPtr.Zero || ctx.cbCertEncoded == 0) return;
            var der = new byte[ctx.cbCertEncoded];
            Marshal.Copy(ctx.pbCertEncoded, der, 0, der.Length);

            using var cert = X509CertificateLoader.LoadCertificate(der);
            sec.SignerSubject = cert.GetNameInfo(X509NameType.SimpleName, false);
            sec.SignerIssuer = cert.GetNameInfo(X509NameType.SimpleName, true);
            sec.SignerThumbprint = cert.Thumbprint;
            sec.SignerNotBefore = cert.NotBefore;
            sec.SignerNotAfter = cert.NotAfter;
        }
        catch { /* verdict without signer details is still useful */ }
        finally
        {
            if (pSigner != IntPtr.Zero) Marshal.FreeHGlobal(pSigner);
            if (pCert != IntPtr.Zero) CertFreeCertificateContext(pCert);
            if (hMsg != IntPtr.Zero) CryptMsgClose(hMsg);
            if (hStore != IntPtr.Zero) CertCloseStore(hStore, 0);
        }
    }

    /// <summary>
    /// Maps the common WinVerifyTrust HRESULTs to short human wording; unknown
    /// codes fall back to the hex value. Called from: Inspect and
    /// IntegrityScanner (findings wording).
    /// </summary>
    public static string TrustResultText(int hr) => hr switch
    {
        0 => "valid and trusted",
        TRUST_E_NOSIGNATURE => "not signed",
        unchecked((int)0x800B0101) => "a required certificate is expired (CERT_E_EXPIRED)",
        unchecked((int)0x800B0109) => "the certificate chain ends in an untrusted root (CERT_E_UNTRUSTEDROOT)",
        unchecked((int)0x800B010A) => "the certificate chain could not be built (CERT_E_CHAINING)",
        unchecked((int)0x800B010C) => "a certificate in the chain was revoked (CERT_E_REVOKED)",
        unchecked((int)0x800B0111) => "the certificate is explicitly distrusted (TRUST_E_EXPLICIT_DISTRUST)",
        unchecked((int)0x80096010) => "the digest does not match: the file was MODIFIED after signing (TRUST_E_BAD_DIGEST)",
        unchecked((int)0x800B0004) => "the subject is not trusted for this action (TRUST_E_SUBJECT_NOT_TRUSTED)",
        unchecked((int)0x80092026) => "signing policy forbids this signature (CRYPT_E_SECURITY_SETTINGS)",
        unchecked((int)0x800B0110) => "the certificate is not valid for this usage (CERT_E_WRONG_USAGE)",
        _ => $"not trusted (0x{hr:X8})"
    };

    // -------------------------------------------------------------------------
    // Embedded signature via WinVerifyTrust
    // -------------------------------------------------------------------------

    /// <summary>
    /// WinVerifyTrust on the file itself (embedded signature). Returns the raw
    /// HRESULT; TRUST_E_NOSIGNATURE means "no embedded signature, try catalog".
    /// Called from: Inspect.
    /// </summary>
    private static int VerifyEmbedded(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path
        };
        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = NewTrustData(WTD_CHOICE_FILE, pFile);
            return InvokeWinVerifyTrust(ref data);
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    // -------------------------------------------------------------------------
    // Catalog signature via CryptCATAdmin + WinVerifyTrust
    // -------------------------------------------------------------------------

    /// <summary>
    /// Computes the file's catalog hash, searches the installed catalogs for it
    /// and, on a hit, verifies the membership with WinVerifyTrust. catalogFile
    /// is null when no catalog contains the hash (the file is simply unsigned).
    /// SHA256 (context v2) is tried first, SHA1 (v1) as legacy fallback.
    /// Called from: Inspect.
    /// </summary>
    private static int VerifyCatalog(string path, out string? catalogFile)
    {
        catalogFile = null;

        IntPtr hCatAdmin = IntPtr.Zero;
        bool v2 = CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, "SHA256",
                      IntPtr.Zero, 0);
        if (!v2 && !CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0))
            return Marshal.GetHRForLastWin32Error();

        IntPtr hCatInfo = IntPtr.Zero;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();

            // Hash the file with the algorithm the acquired context expects.
            uint cbHash = 0;
            if (v2)
                CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, null, 0);
            else
                CryptCATAdminCalcHashFromFileHandle(hFile, ref cbHash, null, 0);
            if (cbHash == 0 || cbHash > 128) return TRUST_E_NOSIGNATURE;

            var hash = new byte[cbHash];
            bool hashed = v2
                ? CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, hash, 0)
                : CryptCATAdminCalcHashFromFileHandle(hFile, ref cbHash, hash, 0);
            if (!hashed) return Marshal.GetHRForLastWin32Error();

            // First catalog containing this hash (one is enough for a verdict).
            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, cbHash, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero) return TRUST_E_NOSIGNATURE;

            var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0))
                return Marshal.GetHRForLastWin32Error();
            catalogFile = catInfo.wszCatalogFile;

            // Member tag: the hash as uppercase hex (Windows convention).
            string memberTag = Convert.ToHexString(hash);

            var wtCat = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = catalogFile,
                pcwszMemberTag = memberTag,
                pcwszMemberFilePath = path,
                hMemberFile = hFile,
                hCatAdmin = hCatAdmin
            };
            var pCat = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.StructureToPtr(wtCat, pCat, false);
                var data = NewTrustData(WTD_CHOICE_CATALOG, pCat);
                return InvokeWinVerifyTrust(ref data);
            }
            finally
            {
                Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(pCat);
                Marshal.FreeHGlobal(pCat);
            }
        }
        finally
        {
            if (hCatInfo != IntPtr.Zero)
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    // -------------------------------------------------------------------------
    // Shared WinVerifyTrust plumbing
    // -------------------------------------------------------------------------

    /// <summary>
    /// Builds the WINTRUST_DATA shared by both checks: no UI, no online
    /// revocation, cached URL retrieval only (offline-safe).
    /// Called from: VerifyEmbedded and VerifyCatalog.
    /// </summary>
    private static WINTRUST_DATA NewTrustData(uint unionChoice, IntPtr pInfo) => new()
    {
        cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
        dwUIChoice = WTD_UI_NONE,
        fdwRevocationChecks = WTD_REVOKE_NONE,
        dwUnionChoice = unionChoice,
        pInfoStruct = pInfo,
        dwStateAction = WTD_STATEACTION_IGNORE,
        dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext = 0
    };

    /// <summary>Runs the generic Authenticode policy provider. Called from:
    /// VerifyEmbedded and VerifyCatalog.</summary>
    private static int InvokeWinVerifyTrust(ref WINTRUST_DATA data)
    {
        var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        return WinVerifyTrust(INVALID_HANDLE_VALUE, ref action, ref data);
    }

    // -------------------------------------------------------------------------
    // Win32 declarations
    // -------------------------------------------------------------------------

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    // Returned by WinVerifyTrust for files whose format it cannot Authenticode-
    // verify (PDF, ZIP, images, ...). Treated as "not signed", never as a bad
    // signature: the alternative wrongly flags every downloaded PDF/ZIP.
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_IGNORE = 0;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfoStruct;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID,
        ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin,
        IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin,
        IntPtr pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin,
        IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile,
        ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin,
        byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo,
        ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin,
        IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    // ---- crypt32: extract the signer certificate from the PKCS#7 ------------

    private const uint CERT_QUERY_OBJECT_FILE = 1;
    private const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = 1 << 8;
    private const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10;
    private const uint CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1;
    private const uint CMSG_SIGNER_INFO_PARAM = 6;
    private const uint X509_ASN_ENCODING = 0x1;
    private const uint PKCS_7_ASN_ENCODING = 0x10000;
    private const uint CERT_FIND_SUBJECT_CERT = 0x000B0000;

    /// <summary>cbData + pbData pair used all over crypt32 (name/serial blobs).</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPT_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    /// <summary>Leading fields of CMSG_SIGNER_INFO; only issuer and serial are
    /// needed to find the leaf certificate, the buffer holds the full struct.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct CMSG_SIGNER_INFO_HEAD
    {
        public uint dwVersion;
        public CRYPT_BLOB Issuer;
        public CRYPT_BLOB SerialNumber;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPT_ALGORITHM_IDENTIFIER
    {
        public IntPtr pszObjId;
        public CRYPT_BLOB Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPT_BIT_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
        public uint cUnusedBits;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CERT_PUBLIC_KEY_INFO
    {
        public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
        public CRYPT_BIT_BLOB PublicKey;
    }

    /// <summary>Full CERT_INFO layout; CertFindCertificateInStore with
    /// CERT_FIND_SUBJECT_CERT only reads SerialNumber and Issuer.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct CERT_INFO
    {
        public uint dwVersion;
        public CRYPT_BLOB SerialNumber;
        public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
        public CRYPT_BLOB Issuer;
        public System.Runtime.InteropServices.ComTypes.FILETIME NotBefore;
        public System.Runtime.InteropServices.ComTypes.FILETIME NotAfter;
        public CRYPT_BLOB Subject;
        public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
        public CRYPT_BIT_BLOB IssuerUniqueId;
        public CRYPT_BIT_BLOB SubjectUniqueId;
        public uint cExtension;
        public IntPtr rgExtension;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CERT_CONTEXT
    {
        public uint dwCertEncodingType;
        public IntPtr pbCertEncoded;
        public uint cbCertEncoded;
        public IntPtr pCertInfo;
        public IntPtr hCertStore;
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptQueryObject(uint dwObjectType, string pvObject,
        uint dwExpectedContentTypeFlags, uint dwExpectedFormatTypeFlags, uint dwFlags,
        out uint pdwMsgAndCertEncodingType, out uint pdwContentType,
        out uint pdwFormatType, out IntPtr phCertStore, out IntPtr phMsg,
        IntPtr ppvContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptMsgGetParam(IntPtr hCryptMsg, uint dwParamType,
        uint dwIndex, IntPtr pvData, ref uint pcbData);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertFindCertificateInStore(IntPtr hCertStore,
        uint dwCertEncodingType, uint dwFindFlags, uint dwFindType,
        ref CERT_INFO pvFindPara, IntPtr pPrevCertContext);

    [DllImport("crypt32.dll")]
    private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

    [DllImport("crypt32.dll")]
    private static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

    [DllImport("crypt32.dll")]
    private static extern bool CryptMsgClose(IntPtr hCryptMsg);
}
