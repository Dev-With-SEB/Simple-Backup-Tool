# Backup Tool (Windows SMB)

A small, practical utility to back up files and folders from **local paths** or **UNC/SMB shares** into a central **SMB backup location**. It can run **once on demand**, **on a schedule** (cron-like), or as a **Windows service**, and also ships with a simple **Tk/Tkinter GUI** for configuration and quick runs.

> **Highlights**
>
> - Copy from local paths or remote UNC paths (with SMB fallback)
> - Zip the collected files per-run, upload to SMB share, and enforce retention
> - Config hot-reload: changes to the YAML are detected at runtime
> - DPAPI-based password protection for credentials stored in the config
> - Lightweight custom scheduler (cron-like) without external daemons
> - GUI for editing config, service control (install/start/stop), and one-click backup

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Config file location](#config-file-location)
  - [YAML schema](#yaml-schema)
  - [Excludes syntax](#excludes-syntax)
- [Usage](#usage)
  - [GUI mode](#gui-mode)
  - [Run once (console or GUI)](#run-once-console)
  - [Protect config (encrypt passwords)](#protect-config-encrypt-passwords)
  - [Service mode](#service-mode)
- [How it works](#how-it-works)
- [Logging](#logging)
- [Security Notes](#security-notes)
- [Requirements](#requirements)
- [Project Layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

---

## Overview

The tool aggregates one or more **sources** (local directories/files or UNC paths) per machine entry, copies them into a temporary working directory, compresses the result into a single zip (named by date), then uploads it to a central SMB share. The number of zip files kept per host path can be capped with **retention**.

Scheduling uses a simple in-process, cron-like scheduler and a file watcher that reloads the YAML configuration as soon as you save it—no restarts required.

It’s designed for straightforward operations teams use: centralizing workstation or tool backups onto a hardened fileserver on a predictable cadence.

---

## Architecture

Core modules (under `src/`):

- **`backupTool.py`** – entry point; launches GUI by default, or runs `--run`, `--protect`, or `--service` modes. Also initializes logging and wire-up between components.
- **`config_loader.py`** – watches and parses the YAML config, normalizes fields, and exposes a strongly-typed `Config` object.
- **`cron.py`** – minimal cron-like schedule parser supporting cron expressions and convenience presets (daily/weekly/monthly/interval).
- **`scheduler_thread.py`** – daemon thread that computes the next run and triggers backup jobs on time; responds to config reloads.
- **`backup.py`** – high-level backup orchestration: copies sources (local/UNC/SMB), zips them, uploads to SMB destination, and enforces retention.
- **`smb_ops.py`** – SMB session/operations using `pysmb` with connection caching, name resolution helpers, and robust path utilities.
- **`utils.py`** – helpers (hostname resolution, UNC path parsing/sanitization, zip/delete helpers, temp dir handling, etc.).
- **`passwords.py`** – DPAPI (Windows) based credential protection plus config sanitization (replaces plaintext `password` with `encryptedPassword`).
- **`simpleLogger.py`** – lightweight, colored console/file logger with rotation.
- **`GUI.py`** – Tk/Tkinter GUI for editing config, scheduling, ad‑hoc runs, Windows service install/start/stop, and downloading a prior backup.

> **Windows Service wrapper**: The GUI expects a `Wrapper/` folder to contain `BackupToolWrapper.exe` and `BackupToolWrapper.xml`. When you click **Install Service**, these are copied next to the config and registered as a service.
`BackupToolWrapper.exe` = WinSW.Net2 from (https://github.com/winsw/winsw) for Windows Xp compadibility

---

## Installation

### 1) Supported platform

- **Windows 10/11** or **Windows Server 2016+** (required for DPAPI + service control)
- **Python 3.8+** recommended (the code contains Python 2.7 compatibility shims for running on older OS but the target runtime should be modern Python and a newer version of WinSw)

### 2) Create and activate a virtual environment (recommended)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\activate
```

### 3) Install dependencies

> Versions below reflect those referenced/tested in the source. If your environment mandates newer libs, adjust accordingly.

```powershell
pip install pysmb==1.2.6 \
            pywin32==228 \
            PyYAML==5.4.1 \
            psutil \
            dnspython \
            colorama  # optional; improves console colors on legacy terminals
```

### 4) Source layout

Place the Python sources under a `src/` package (so imports like `from src.backup import BackupRunner` resolve), e.g.:

```
repo/
  src/
    backupTool.py
    backup.py
    config_loader.py
    cron.py
    GUI.py
    passwords.py
    scheduler_thread.py
    simpleLogger.py
    smb_ops.py
    utils.py
  backup_config.yaml        # your configuration (see below)
  Wrapper/                  # optional, for Windows service install from GUI
    BackupToolWrapper.exe
    BackupToolWrapper.xml
```

> If your files currently live at repo root, either move them under `src/` or adjust `PYTHONPATH` so `import src.*` works. The code assumes a `src` package.

---

## Configuration

### Config file location

By default the tool looks for `backup_config.yaml` **in the same directory** as the executable or script. During development it also falls back to `../config/backup_config.yaml`. You can keep a single YAML next to `backupTool.py` for simplicity.

### YAML schema

Below is a practical, commented example to get started:

```yaml
# Where backup zips are stored on the SMB server.  IMPORTANT: omit the server/host here.
# The server(s) are listed separately in backupServerIps.
# Format: "<share>/<optional_subpath>"
backupLocation: "backups/tools"   # becomes //{chosen_server}/backups/tools/<HOSTNAME>/YYYYMMDD.zip

# One or more SMB servers (IPs or DNS names) to try in order. First reachable wins.
backupServerIps:
  - 10.23.45.67
  - 10.23.45.68

# How many zip files to keep per host directory
retentionCount: 14

# Optional: where to stage files before zipping (defaults to %TEMP%\ToolBackups)
# tempRoot: "C:\\Temp\\ToolBackups"

# Logging verbosity (0=errors only, 1=warnings, 2=info, 3=debug, 4=verbose)
logLvl: 3

# Optional: display-only version stamp for splash/banner
Version: "5"

# Scheduler — pick ONE of: cron | weekly | monthly | daily | intervalMinutes
schedule:
  cron: "0 2 * * 1-5"     # At 02:00 on weekdays
  # weekly:
  #   runAt: "02:00"
  #   days: [mon, wed, fri]
  # daily: "02:00"
  # monthly:
  #   runAt: "03:30"
  #   days: [1, 15]
  # intervalMinutes: 120

# SMB auth. You can set a default and then override per host below.
auth:
  dpapiScope: "machine"  # or "user"; controls DPAPI encryption scope
  default:
    domain: "CORP"
    username: "backup_svc"
    password: "PlaintextOnlyOnFirstRun"  # will be encrypted on --protect or on first GUI save
  hosts:
    - host: "10.23.45.67"
      username: "special_user"
      domain: "CORP"
      password: "OnlyUntilProtected"

# Machines to back up.  Each map key is a friendly name shown in UI; values define paths.
computer2Backup:
  - WORKSTATION-42:
      Host: 10.23.77.42            # Optional but improves reachability checks
      Backups:
        - "C:/Projects"
        - "C:/Users/alice/Documents/Notes.txt"
        - "\\\\filesrv\\DeptShare\\Team"   # UNC; tool will try direct copy then SMB fallback
      Exclude:
        - "C:/Projects/.git"         # prefix match exclude
        - "regex .*\\\.tmp$"         # regex exclude (prefix with `regex `)
        - "*\\node_modules\\*"        # wildcard exclude
```

#### Notes

- **`backupLocation`** deliberately omits the server. The chosen server comes from `backupServerIps` (first healthy wins).
- Backups are uploaded to: `//<server>/<share>/<optional_subpath>/<HOSTNAME>/<YYYYMMDD>.zip`.
- If a zip with that date already exists, a timestamped variant like `YYYYMMDD_HHMM.zip` is used automatically.
- The tool derives `<HOSTNAME>` from local network info (reverse DNS/NetBIOS), with sensible fallbacks; name is sanitized for filesystem safety.

### Excludes syntax

For each computer entry:

- **Prefix match**: a literal path prefix prevents copying (`C:/Projects/.git`).
- **Wildcard**: `*` can stand in for any sequence (e.g., `*\node_modules\*`).
- **Regex**: start the pattern with `regex ` and provide a Python regular expression (`regex .*\.tmp$`).
- Excludes are applied to **canonicalized** local/remote paths; UNC paths are normalized to compare correctly.

---

## Usage

From the repository root (with venv activated):

### GUI mode

```powershell
python -m src.backupTool
```

- Opens the **Backup Config Manager** window.
- Edit **Backup Settings**, add/edit/remove **Computers**, set **Schedule**, and **Run Now**.
- **Install Service** uses the optional `Wrapper/` files to register a Windows service.

### Run once (console)

```powershell
python -m src.backupTool --run
```

Performs a single backup run from the current `backup_config.yaml` and exits. Useful for testing or ad‑hoc jobs.

### Protect config (encrypt passwords)

```powershell
python -m src.backupTool --protect
```

- Rewrites `backup_config.yaml` in-place, replacing any plaintext `password` fields with `encryptedPassword` (DPAPI).
- A timestamped `.bak-YYYYmmddHHMMSS` copy of the previous config is kept, with automatic cleanup of older backups.

### Service mode

```powershell
python -m src.backupTool --service
```

Runs the scheduler loop in the foreground (useful when wrapping with a service host). For **Windows Service** management, prefer the GUI’s **Install/Start/Stop** buttons which use pywin32 under the hood.

---

## How it works

1. **Config load & watch** — a background thread parses the YAML and normalizes fields. Changes are detected via file mtime and applied live.
2. **Scheduling** — a cron-like engine computes the next eligible run. On a due tick, a `RUN` signal is queued to the worker.
3. **Copy phase** — for each configured computer entry:
   - If the source is **local** or a **UNC path**, we attempt a direct filesystem copy; otherwise we fall back to **SMB** file-by-file copy.
   - Excludes are checked against canonicalized paths (literal prefix, wildcard, or regex).
4. **Zip phase** — the day’s working folder is zipped into `%TEMP%/ToolBackups/<YYYYMMDD>.zip` (or your `tempRoot`).
5. **Upload & retention** — zip is uploaded to the selected server/share/subpath/`<HOSTNAME>/`. Old zips are deleted to enforce `retentionCount`.

---

## Logging

- Logs are written near the executable/script (e.g., `backupTool.log`) and rotated into a `<name>_logs/` folder when they grow to ~5MB; up to several generations are retained.
- Log levels: `0=ERROR, 1=WARNING, 2=INFO, 3=DEBUG, 4=VERBOSE`.
- Console output shows colored level tags when run in a TTY terminal.

---

## Security Notes

- **Passwords**: run `--protect` (or save via GUI) to encrypt plain `password` values into `encryptedPassword` using Windows **DPAPI**. Choose `dpapiScope: machine` for service accounts, or `user` if running as an interactive user.
- **File cleanups**: when sanitizing the config, the tool creates timestamped `.bak-...` snapshots and automatically prunes older ones.
- **Permissions**: ensure the account used to connect to the SMB share has read/write permissions on the target share and subpaths.

---

## Requirements

- Windows 10/11 or Server 2016+
- Python 3.8+
- Packages: `pysmb`, `pywin32`, `PyYAML`, `psutil`, `dnspython`, `colorama (optional)`

> Non‑Windows environments are **not supported** for DPAPI and Windows Service features. Core SMB backup operations may work, but this project is intended for Windows.

---

## Project Layout

```
src/
  backupTool.py         # entry point / CLI / GUI bootstrap
  backup.py             # run_backup(): copy -> zip -> upload -> retention
  config_loader.py      # Config + file watcher thread
  cron.py               # CronSchedule (cron, daily/weekly/monthly/interval)
  scheduler_thread.py   # Scheduler thread (computes and queues RUN events)
  smb_ops.py            # SMB session cache & file operations
  passwords.py          # DPAPI protect/decrypt and config sanitization
  simpleLogger.py       # lightweight logger with rotation and color
  GUI.py                # Tk/Tkinter GUI (config editor, service control, run now)
backup_config.yaml      # your configuration
Wrapper/                # (optional) Windows service wrapper files
```

---

## Troubleshooting

- **`pysmb is not installed` or SMB connect errors** — ensure `pip install pysmb==1.2.6` and that ports 445/139 are reachable; verify credentials/domain.
- **`DPAPI not available: install pywin32`** — install `pywin32==228` and run on Windows.
- **`STATUS_ACCESS_DENIED` when listing share** — some servers disallow share enumeration; the tool falls back to probing the share root. Verify permissions.
- **Zips not showing up** — check `backupLocation`/`backupServerIps`, that the `<HOSTNAME>` directory is created remotely, and local logs for errors.
- **Regex/wildcard excludes not working** — ensure `regex ` prefix is present for regex; wildcards use `*` and are matched case‑insensitively.

---

## Development

- The codebase includes a number of Python 2.7 compatibility shims but targets Python 3 for production.
- Contributions are welcome: please open issues or PRs describing your environment and steps to reproduce.

### Quick dev loop

```powershell
# 1) Start the GUI to configure a test backup
python -m src.backupTool

# 2) Run a one-off from the console while tailing logs
python -m src.backupTool --run
```

---

## License

Choose an open-source license (e.g., MIT, Apache-2.0) and add a `LICENSE` file.

