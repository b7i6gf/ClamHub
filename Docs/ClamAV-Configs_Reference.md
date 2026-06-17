# ClamAV Configuration Reference (clamd.conf and freshclam.conf)

This document explains every setting that the application's **Settings** tab exposes for `clamd.conf` (the ClamAV daemon) and `freshclam.conf` (the signature updater). Each parameter is listed with its type, built-in default, accepted values, and a short description.

The parameter set was audited against the official ClamAV man pages for **ClamAV 1.4.x**.

## Sources

- Configuration guide: https://docs.clamav.net/manual/Usage/Configuration.html
- Usage overview: https://docs.clamav.net/manual/Usage.html
- clamd.conf man page: https://www.mankier.com/5/clamd.conf
- freshclam.conf man page: https://www.mankier.com/5/freshclam.conf
- Sample config (clamd): https://github.com/Cisco-Talos/clamav/blob/main/etc/clamd.conf.sample
- Sample config (freshclam): https://github.com/Cisco-Talos/clamav/blob/main/etc/freshclam.conf.sample

## How to read this reference

- **Boolean** parameters are edited in the GUI through a `(default) / yes / no` dropdown.
- **Text** parameters are edited through a text box.
- Choosing `(default)` for a boolean, or leaving a text box empty, removes the key from the file so ClamAV falls back to its built-in default.
- Size values accept a number with an optional `M` or `m` (megabytes) or `K` or `k` (kilobytes) suffix, for example `400M`.
- Comments, blank lines, and any parameters not listed below are preserved untouched when the files are saved.

---

# clamd.conf (ClamAV Daemon)

## Daemon

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| TCPSocket | Port | disabled | 1-65535 | TCP port the daemon listens on. The GUI follows this port automatically. |
| TCPAddr | Address | all interfaces | IP address | Bind address. Keep `127.0.0.1` so the daemon is never exposed to the network. |
| MaxThreads | Integer | 10 | positive integer | Worker threads for parallel scans. Recommended: number of CPU cores. |
| MaxQueue | Integer | 100 | positive integer | Queued scan jobs including running ones. Keep at least 2x MaxThreads. |
| IdleTimeout | Seconds | 30 | positive integer | Seconds a worker waits for a new job. |
| SelfCheck | Seconds | 600 | positive integer | Database self check interval in seconds. |
| ConcurrentDatabaseReload | Boolean | yes | yes / no | Load the new database in parallel during reloads. `no` halves RAM usage but blocks scans briefly. |
| TemporaryDirectory | Path | system temp | absolute path | Override the temp directory. |

## Logging

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| LogTime | Boolean | no | yes / no | Prefix log entries with a timestamp. |
| LogVerbose | Boolean | no | yes / no | Verbose daemon logging. |
| LogClean | Boolean | no | yes / no | Also log clean files. Massively grows the log. |
| LogFileMaxSize | Size | 1M | size, `0` disables the limit | Max log size, for example `5M`. |
| LogRotate | Boolean | no | yes / no | Rotate the log when LogFileMaxSize is reached. |
| ExtendedDetectionInfo | Boolean | no | yes / no | Log size and hash of infected files next to the virus name. |

## Detection

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| DetectPUA | Boolean | no | yes / no | Also detect potentially unwanted applications like adware or cracks. |
| HeuristicAlerts | Boolean | yes | yes / no | Algorithmic detection for complex malware. |
| HeuristicScanPrecedence | Boolean | no | yes / no | Stop at the first heuristic match instead of scanning on. |
| Bytecode | Boolean | yes | yes / no | Load bytecode signatures, strongly recommended. |
| PhishingSignatures | Boolean | yes | yes / no | Signature based phishing detection in mails. |
| PhishingScanURLs | Boolean | yes | yes / no | URL based phishing detection in mails. |

## File types

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| ScanPE | Boolean | yes | yes / no | Deep analysis of Windows executables including UPX unpacking. |
| ScanELF | Boolean | yes | yes / no | Deep analysis of Linux/Unix executables. |
| ScanOLE2 | Boolean | yes | yes / no | Office documents, `.msi`, and OLE2 containers. |
| ScanPDF | Boolean | yes | yes / no | Scan inside PDF files. |
| ScanSWF | Boolean | yes | yes / no | Scan inside Flash files. |
| ScanHTML | Boolean | yes | yes / no | HTML and JavaScript normalisation and decryption. |
| ScanMail | Boolean | yes | yes / no | Parse mail files and their attachments. |
| ScanXMLDOCS | Boolean | yes | yes / no | XML based documents (docx, xlsx, and similar). |
| ScanOneNote | Boolean | yes | yes / no | OneNote files. |
| ScanImage | Boolean | yes | yes / no | Image files. |
| ScanImageFuzzyHash | Boolean | yes | yes / no | Detection via image fuzzy hashes. |
| ScanArchive | Boolean | yes | yes / no | Scan inside archives (zip, rar, 7z, and similar). |

## Extra alerts

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| AlertEncrypted | Boolean | no | yes / no | Alert on encrypted archives AND documents. |
| AlertEncryptedArchive | Boolean | no | yes / no | Alert on encrypted archives (zip, 7z, rar). |
| AlertEncryptedDoc | Boolean | no | yes / no | Alert on encrypted documents (pdf). |
| AlertOLE2Macros | Boolean | no | yes / no | Alert on Office files containing VBA macros. |
| AlertBrokenExecutables | Boolean | no | yes / no | Alert on broken PE/ELF executables. |
| AlertBrokenMedia | Boolean | no | yes / no | Alert on broken image files. |
| AlertExceedsMax | Boolean | no | yes / no | Alert on files skipped due to size limits. |

## Limits

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| MaxScanTime | Milliseconds | 120000 | integer, `0` disables (DoS risk) | Max milliseconds per file. |
| MaxScanSize | Size | 400M | size | Max data scanned per file including archive content, for example `400M`. |
| MaxFileSize | Size | 100M | size, hard limit `2G` | Skip files larger than this, for example `100M`. |
| MaxRecursion | Integer | 17 | positive integer | Max nesting depth of archives inside archives. |
| MaxFiles | Integer | 10000 | positive integer | Max files scanned per archive or container. |
| MaxDirectoryRecursion | Integer | 15 | positive integer | Max folder nesting depth. |
| MaxEmbeddedPE | Size | 40M | size | Max file size checked for embedded executables. |

## File system

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| ExcludePath | Regex | disabled | regex pattern | Regex of paths to skip. For multiple entries, edit via "Open file". |
| CrossFilesystems | Boolean | yes | yes / no | Scan across file system boundaries. |
| FollowDirectorySymlinks | Boolean | no | yes / no | Follow directory symlinks. |
| FollowFileSymlinks | Boolean | no | yes / no | Follow file symlinks. |

## Cache

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| DisableCache | Boolean | no | yes / no | Disable the clean file cache. Slows large scans. |
| CacheSize | Integer | 65536 | positive integer (entries) | Cache entries for known clean files. |

---

# freshclam.conf (Signature Updater)

## Update source

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| DatabaseMirror | Hostname | database.clamav.net | hostname | Signature mirror. |
| PrivateMirror | URL | disabled | URL | Private mirror URL, overrides DatabaseMirror. |
| DatabaseCustomURL | URL | disabled | URL | Additional database from a custom URL. For multiple entries, edit via "Open file". |
| ExtraDatabase | Name | disabled | database name | Additional 3rd party database via ClamAV mirrors. For multiple entries, edit via "Open file". |
| ExcludeDatabase | Name | disabled | database name | Skip a standard database. For multiple entries, edit via "Open file". |
| ScriptedUpdates | Boolean | yes | yes / no | Incremental updates instead of full downloads, keep enabled. |
| Bytecode | Boolean | yes | yes / no | Download bytecode signatures, recommended. |

## Connection

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| ConnectTimeout | Seconds | 10 | positive integer | Connect timeout in seconds. |
| ReceiveTimeout | Seconds | 0 | integer, `0` = no limit | Max seconds per download. Too low aborts the first full database download. |
| MaxAttempts | Integer | 3 | positive integer | Download attempts per mirror. |
| HTTPProxyServer | Hostname | disabled | hostname, optional scheme like `socks5://` | Proxy server. |
| HTTPProxyPort | Port | disabled | 1-65535 | Proxy port. |
| HTTPProxyUsername | String | disabled | string | Proxy user. |
| HTTPProxyPassword | String | disabled | string | Proxy password, stored in plain text in the conf. |

## Behaviour

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| TestDatabases | Boolean | yes | yes / no | Verify downloaded databases before activating them. |
| CompressLocalDatabase | Boolean | no | yes / no | Store local databases compressed. Saves disk, slows loading. |
| NotifyClamd | Path | disabled | path to clamd.conf | A running daemon reloads signatures after updates. |

## Logging

| Parameter | Type | Default | Accepted values | Description |
|---|---|---|---|---|
| LogTime | Boolean | no | yes / no | Prefix log entries with a timestamp. |
| LogVerbose | Boolean | no | yes / no | Verbose update logging. |
| LogFileMaxSize | Size | 1M | size | Max log size, for example `5M`. CAUTION: when exceeded without LogRotate, logging silently stops. |
| LogRotate | Boolean | no | yes / no | Rotate the log when LogFileMaxSize is reached. |

---

## Notes

- Leaving a text field empty or selecting `(default)` for a boolean removes the key, so ClamAV uses its built-in default for that parameter.
- The following parameter groups are deliberately not shown in the Settings tab and can only be changed through "Open file":
  - Unix-only options (`LocalSocket*`, `User`, `DatabaseOwner`, `LogSyslog`, `LogFacility`, `PidFile`, `Foreground`), which are meaningless on Windows.
  - On-access scanning options (`OnAccess*`), which rely on Linux fanotify and are not available on Windows.
  - Command-executing or unsigned-code options (`VirusEvent`, `OnUpdateExecute`, `OnErrorExecute`, `BytecodeUnsigned`).
  - Debugging-only options (`Debug`, `LeaveTemporaryFiles`, `GenerateMetadataJson`).
- After editing `clamd.conf`, restart a running daemon to apply the changes.
