# ClamHub

A portable, modern Windows desktop frontend for ClamAV. No installation required.
The EXE, ClamAV binaries, configs, logs and quarantine all live inside one folder you can move or copy freely.

---

## Overview

ClamHub wraps the open-source [ClamAV](https://www.clamav.net/) antivirus engine in a clean WPF interface.
It targets power users and administrators who want full control over scan behaviour without
touching command-line tools. Everything is self-contained: drop the portable ClamAV binaries
next to the EXE and it works, with no registry writes and no system-wide installation.

---

## Features

### Daemon control
- Start and stop `clamd` directly from the GUI
- Readiness check via PING before every daemon scan
- Auto-start on launch and auto-stop on exit, both configurable
- Configurable TCP port (default 3310), localhost only
- Configurable worker thread count (defaults to all logical CPU cores)

### Scanning
- Targets: single file, folder or whole drive
- Prefers `clamdscan` with `--multiscan` and `--fdpass` for parallel, multi-core scanning
- Automatic fallback to `clamscan` when the daemon is not running
- Extension filter: restrict a scan to specific file types (e.g. `exe dll sys`)
- Memory scan via `clamscan --memory` with optional termination of infected processes
- Cancellable scans with a live indicator in the UI
- Drag-and-drop paths onto the scan target field

### Infected file actions
Three selectable actions applied when infections are found:
- **Report only** - log the result, leave the file in place
- **Quarantine** - GUI-managed move to the `Quarantine` folder, tracked in `quarantine.json` so every file can be restored to its exact original path
- **Remove** - permanently delete

### Quarantine manager
- View all quarantined files in a sortable table
- Restore a file to its original path with one click
- Permanently delete individual entries or clear the entire quarantine
- VirusTotal hash lookup directly from the quarantine list

### Scan history
- Every completed scan is saved to `history.json`
- History table shows timestamp, target, scanner used, duration and infected count
- Click any entry to see the full infected-file list for that scan
- Clear history with confirmation, or open the JSON file directly

### Signature updates
- Run `freshclam` from the GUI with live output
- Optional auto-update on startup to keep the database current
- After an update, `NotifyClamd` signals the running daemon to reload signatures without a restart

### Hash tool
- Compute SHA-1, SHA-256, SHA-384, SHA-512 or MD5 for any file
- Compute all algorithms at once
- Optional comparison against an expected hash with a clear match/mismatch result

### VirusTotal integration
- Look up any file by its SHA-256 hash against the VirusTotal API
- Only the hash is sent; the file never leaves the machine
- Verdict shown as `X / N engines` with a direct link to the full report
- API key stored locally in `settings.json`, never hard-coded

### Exclusions
- Exclude directories and file extensions from all scans
- Applied to `clamscan` immediately via `--exclude-dir` and `--exclude`
- Written into `clamd.conf` as `ExcludePath` blocks; GUI offers a daemon restart to activate them

### Scan profiles
- Save named scan configurations (target path, action, extension filter, multiscan toggle)
- Load a profile to pre-fill the scan tab in one click
- Profiles stored in `profiles.json`, fully portable

### Windows context menu
- Optional "Scan with ClamHub" entry for files and folders in Explorer
- Registered under `HKEY_CURRENT_USER`, no admin rights needed
- If the portable folder is moved, the Settings tab detects the stale path and shows a hint

### Settings and config editor
- Live `clamd.conf` and `freshclam.conf` editors inside the Settings tab
- Configs are auto-generated on first run and never overwritten on update
- All GUI preferences (daemon behaviour, default action, sound on detection, console position, VirusTotal key) saved to `settings.json`

### Elevated mode
- One-click restart as Administrator from inside the app
- Required for memory scans of system processes and protected folders
- Title bar and daemon button reflect the current privilege level

### Console output
- All scan, update and daemon output streams into a built-in console
- Dockable: bottom (default), right panel or detached window
- Section headers separate different operations for easy reading

---

## Folder layout

```
<AppFolder>
|- ClamHub.exe
|- ClamHub.ico
|- settings.json          auto-created on first run
|- profiles.json          auto-created when saving the first profile
|- ClamAV\
|   |- clamd.exe, clamdscan.exe, clamscan.exe, freshclam.exe (+ DLLs)
|   |- clamd.conf         auto-created when missing, never overwritten
|   |- freshclam.conf     auto-created when missing, never overwritten
|   |- database\          virus signature database (filled by freshclam)
|- Logs\
|   |- clamd-scan.log
|   |- clamd.log
|   |- freshclam.log
|   |- INFECTED_FILES.txt
|   |- history.json
|- Quarantine\
    |- quarantine.json
    |- <quarantined files by internal ID>
```

---

## Requirements

- Windows 10 or later (x64)
- [ClamAV portable binaries](https://www.clamav.net/downloads) placed in the `ClamAV` subfolder
- No .NET runtime installation required (self-contained build)

To build from source:

```
dotnet build              # debug build
publish.cmd               # portable single-file release into .\publish
```

Requires .NET SDK 10.0.301 or newer.

---

## Getting started

1. Download or build `ClamHub.exe`
2. Create a `ClamAV` folder next to the EXE and copy the portable ClamAV binaries into it
3. Launch `ClamHub.exe`
4. On first run, `clamd.conf` and `freshclam.conf` are generated automatically
5. Click **Update signatures** to download the virus database
6. Select a scan target and click **Scan**

---

## Notes

- `clamdscan` produces a shorter summary than `clamscan` by design. ClamHub appends its own summary block (engine used, target, duration, infected count) after every daemon scan.
- The context menu entry stores the absolute EXE path. Moving the portable folder requires toggling the entry off and on again in Settings.
- Log cleanup preserves `INFECTED_FILES.txt`. Clearing the infected report is a separate, confirmed action.
- The daemon listens on `127.0.0.1` only and is never exposed to the network.

---

## License

ClamAV is licensed under [GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
ClamHub itself is provided as-is. See the repository for details.
