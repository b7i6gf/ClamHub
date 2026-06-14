# ClamHub

![ClamHub](docs/ClamHub.png)

A portable Windows frontend for ClamAV. Just drop the EXE next to the ClamAV binaries and go - no installation, no system changes, everything in one folder.

---

## What is this?

ClamHub puts a clean, dark UI on top of ClamAV so you do not have to deal with the command line. Scans run fast thanks to the multi-threaded daemon, the interface stays out of the way, and nothing gets written outside the app folder. Works on any machine without touching the registry or requiring admin rights (unless you want to scan protected system paths).

---

## Highlights

- **Portable** - the entire setup lives in one folder, move it wherever you want
- **Fast** - daemon-backed scans use all CPU cores via `--multiscan`
- **Modern dark UI** - custom title bar, clean tab layout, no clutter
- **Smart console layout** - dock the output below, to the right, or pop it into a separate window. On the Settings tab the console hides automatically so the config editors get the full space
- **No surprises** - configs are generated once and never overwritten, so your edits stick

---

## Usage

### Scan tab

Pick a file, folder or entire drive and hit Scan. The app prefers the ClamAV daemon (`clamdscan`) for parallel multi-core scanning and falls back to `clamscan` automatically if the daemon is not running.

You can filter by file extension (e.g. `exe dll sys`) to skip irrelevant files, or run a **memory scan** to check running processes. Infected files can be reported only, moved to quarantine, or deleted - your choice per scan.

Paths can be dragged and dropped directly onto the input field. Scans can be cancelled at any point.

### Hash Checker tab

Drop or browse to any file and compute its hash. Supports SHA-1, SHA-256, SHA-384, SHA-512 and MD5 - individually or all at once. Paste an expected hash to get an instant match / mismatch result.

If you have a VirusTotal API key set up (in Settings), you can look up the file's SHA-256 directly from this tab. Only the hash is sent - the file never leaves your machine.

### Quarantine tab

Shows every file ClamHub has quarantined, with the original path, date and file name. From here you can:

- **Restore** a file back to exactly where it came from
- **Delete** it permanently
- **Check it on VirusTotal** using its stored hash

### History tab

Every completed scan is saved automatically. The history table shows when it ran, what was scanned, which scanner was used, how long it took and how many infected files were found. Click any entry to see the full list of detections for that scan. You can clear the history or open the raw JSON file directly.

### Settings tab

The Settings tab gets the full window - the output console hides here so the config editors have room to breathe. From Settings you can:

- Toggle daemon auto-start and auto-stop
- Set the default infected-file action
- Configure the ClamAV port and thread count
- Add or remove path and extension exclusions
- Enable the Windows Explorer context menu entry ("Scan with ClamHub")
- Enter your VirusTotal API key
- Edit `clamd.conf` and `freshclam.conf` directly in the built-in editor

---

## Folder layout

```
<AppFolder>
|- ClamHub.exe
|- settings.json
|- ClamAV\
|   |- clamd.exe, clamdscan.exe, clamscan.exe, freshclam.exe (+ DLLs)
|   |- clamd.conf
|   |- freshclam.conf
|   |- database\
|- Logs\
|   |- history.json
|   |- INFECTED_FILES.txt
|   |- clamd-scan.log, clamd.log, freshclam.log
|- Quarantine\
    |- quarantine.json
```

---

## Getting started

1. Place `ClamHub.exe` in any folder
2. Create a `ClamAV` subfolder and copy the portable ClamAV binaries into it
3. Launch the EXE - configs and folders are created automatically on first run
4. Click **Update signatures** to download the virus database
5. Select a target and scan

ClamAV portable builds can be downloaded from [clamav.net](https://www.clamav.net/downloads).

---

## Build

Requires .NET SDK 10.0.301 or newer.

```
dotnet build        # debug
publish.cmd         # portable single-file release into .\publish
```

---

## Notes

- The daemon listens on `127.0.0.1` only, it is never exposed to the network
- Moving the app folder invalidates the Explorer context menu entry - just toggle it off and back on in Settings
- `clamdscan` produces a shorter native summary than `clamscan`; ClamHub adds its own summary block with engine, target, duration and result after every daemon scan
