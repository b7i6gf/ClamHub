<p align="center">
  <img src="Docs/ClamHub.png" alt="ClamHub" width="400"/>
</p>

An open-source application for using [ClamAV](https://www.clamav.net) with a GUI on Windows. Just run the EXE and go - free, portable, extensive features and always up-to-date.

---

## What is this?

I usually use ClamAV with a batch script on my personal computer. It's rudimentary, not easy to use and very restrictive. A GUI would be nice... I thought. Sure there are some similar applications on GitHub, like [ClamShield](https://github.com/orloxgr/ClamShield); [ClamAV Native Win32](https://oss.netfarm.it/clamav/) or [ClamUI](https://github.com/linx-systems/clamui) on Linux. I was missing a portable version you can carry around on a flash drive, something with a user friendly GUI and clear instructions and feedback...

So I sat down and worked on this project. I put a lot of effort into designing an all around experience with usability in mind. Of course I had some coding help from Claude Opus 4.8 and Fable 5 for this, just like our AI overlord insists! (Roko’s Basilisk is watching)

And here it is:

ClamHub puts a clean, dark UI on top of ClamAV so you do not have to deal with the command line. Scans run fast thanks to the multi-threaded daemon, the interface stays out of the way, and nothing gets written outside the app folder. Works on any (Windows) machine without installation or requiring admin rights (unless you want to scan protected system paths).

## Highlights

- **Portable** - the entire setup lives in one folder, move it wherever you want
- **Extensive** - Feature-rich application, with full control over scans, infected files and configs. Efficient scanning with Windows context menu actions.
- **Modern dark UI** - consistent design, clean layout, pleasant for the eye
- **Smart console layout** - dock the output below, to the right, or pop it into a separate window. On the Settings tab the console hides automatically so the config editors get the full space
- **No surprises** - configs are generated once on startup and are highly customizable within the settings tab
- **Profiles** - save your regular scans in profiles for repeatable workflows

---
---

## Usage

### Scan
<p align="center">
<img src="Docs/Scan.png" alt="ClamHub" width="700"/>
</p>

- Pick or Drag and Drop a file, folder or entire drive and hit 'Start Scan'. The app prefers the ClamAV daemon (`clamdscan`) for parallel multi-core scanning and falls back to `clamscan` automatically if the daemon is not running.
- You can filter by file extension (e.g. `exe dll sys`) or even exclude paths systemwide or for a particular scan to skip irrelevant files. You can also query multiple files and folders at once so scanning becomes more efficient!
- Run a **memory scan** to check running processes and kill them instantly.
Infected files can be reported only, moved to quarantine, or deleted - your choice per scan.
- Use VirusTotal as a secondary scan for single files. (sends only the hash of the file to VirusTotal for a report) 
- Create profiles for your custom scans. You can even save queues for reoccuring tasks
- Scans can be cancelled at any point.

---

### File-Verifier (Introduced in 1.0.4)
<p align="center">
<img src="Docs/File-Verifier.png" alt="ClamHub" width="700"/>
</p>

- Drag & Drop or select multiple files to inspect. Choose checks and scans you want to process before inspecting.
- With this tool you get all the importand information of a single file: File System; PE Analysis; Document Analysis; Digital Signature; Strings/IOCs
- Paste an expected hash to get an instant match / mismatch result
- If you have a VirusTotal API key set up (in Settings), you can look up the file's SHA-256 directly from this tab. Only the hash is sent - the file never leaves your machine
- Be efficient by using the context menu action `Create Integrity Report` to quickly inspect a file on your PC
- All reports can be found in `History` and be exported to a .txt file

---

### Quarantine
<p align="center">
<img src="Docs/Quarantine.png" alt="ClamHub" width="700"/>
</p>

Shows every file ClamHub has quarantined, with the original path, date and file name. From here you can:

- **Restore** a file back to exactly where it came from
- **Delete** it permanently
- **Check it on VirusTotal** using its stored hash

---

### Detections (Introduced in 1.0.3.6)
<p align="center">
<img src="Docs/Detections.png" alt="ClamHub" width="700"/>
</p>

- "Detections" is now available (button currently on the upper right corner besides "About", might change in the future)
- With this window you are now able to view all found files from previous scans to work through!
- The 'Actions' provide a wide palette of functions to handle potential infected files. 
- Once you managed a file the "Status" will show what was done. By selecting `Delete managed entries` you can clean up the list of all handled files and continue with the pending ones.

---

### Signatures (Introduced in 1.0.3)
<p align="center">
<img src="Docs/Signatures.png" alt="ClamHub" width="700"/>
</p>

- See all relevant information about the database you selected within the tab
- Easily add custom URLs from third-party database providers by pressing the button `Add from URL`
- Manage black- and whitelist entries; a new context menu entry got introduced to quickly add entries to the lists -> `Put on List`
- Search for signatures within all or selected databases; you can also compare the signature of quarantined files with the databases
- Select and disable databases to exclude those signatures for scans. Simply right-click on an entry and select `Disable database`. When databases get disabled, they will be moved in a separate folder to ensure freshclam will not delete it. Therefore all disabled databases will not be updated as well!
- Quickly remove databases by right-clicking an entry and select `Remove database`
- Added the ability to search for specific signatures or duplicates in different databases as well as comparing found signatures from quarantined files with available databases.


---

### History
<p align="center">
<img src="Docs/History.png" alt="ClamHub" width="700"/>
</p>

- Every completed scan is saved automatically. The history table shows when it ran, what was scanned, which scanner was used, how long it took and how many infected files were found.
- History will also show actions you made in Quarantine or Hash Verifier
- Click any entry to see the full report of the scan or action.
- You can clear the history or open the raw JSON file directly.
- Deletion of entries or the whole history is supported as well.
- Export selected entries to a .txt file by using the `Export` button

---

### Settings
<p align="center">
<img src="Docs/Settings.png" alt="ClamHub" width="700"/>
</p>

The Settings tab gets the full window - the output console hides here so the config editors have room to breathe. Use the widened window option to have even more space!
From Settings you can configure the default behaviour of the app, as well as the config files of the daemon (clamd.conf) and the updater (freshclam.conf)

You can also:
- Add or remove path and extension exclusions under Daemon > File system > Exclude Path
- Enable the Windows Explorer context menu entries you need for your convenience
- Enter your VirusTotal API key to enable the VirusTotal feature in Scan, Hash Verifier and Quarantine
- Run diagnostics with ClamAVs built-in clamconf.exe.
- Always start in administrator mode.
- Open the `clamd.conf` and `freshclam.conf` directly if you need to
- and many more...

---

### Update Checker

<p align="center">
<img src="Docs/Update.png" alt="ClamHub" width="500"/>
</p>

- Keeping the app up-to-date is simple. You can update the app via the `Check for updates` button in the Settings tab or by navigating to the `About` window in the top right corner of the app.
<p align="center">
<img src="Docs/About.png" alt="ClamHub" width="400"/>
</p>
- ClamHub will show you the newest updates there. Press the download button and wait.
- You can enable an automatic check on startup. You'll notice an indicator on the `About` lable that will tell you an update is available

---
---

## Getting started

1. Place `ClamHub.exe` in any folder
2. Run the .exe and select one of the following options.
<p align="center">
<img src="Docs/Startup.png" alt="ClamHub" width="450"/>
</p>

  - a) Download automatically: The official ClamAV build is automatically being downloaded and extracted next to the ClamHub.exe. Fully automatic and no further clicks needed.
  - b) Manually select existing ClamAV folder: It does what it says. Search for your own ClamAV installation and select the folder. It automatically detects all databases and executables within. ClamAV can be downloaded at [clamav.net](https://www.clamav.net/downloads)
3. Have fun hunting for viruses :)

## Building it yourself

Requires .NET SDK 10.0.301 or newer.

```
dotnet build        # debug
publish.cmd         # portable single-file release into .\publish
```

---

## Notes

- Moving the app folder invalidates the Explorer context menu entry - just toggle it off and back on in Settings
- `clamdscan` produces a shorter native summary than `clamscan`; ClamHub adds its own summary block with engine, target, duration and result after every daemon scan

## Future

- ClamHub is in active development.
