# Winlock

[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0.0-blue.svg)](https://polyformproject.org/licenses/noncommercial/1.0.0)
![C++](https://img.shields.io/badge/C%2B%2B-17%2B-00599C?logo=c%2B%2B&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)

# Timed File Lock & Wipe System

Winlock is a cross-platform C++ proof-of-concept that demonstrates timed file locking, automatic persistence across restarts, watchdog-based resilience, and a recovery utility for restoring encrypted files. It is designed for isolated test environments and is not intended for production workloads or real-world data protection.

This repository contains two main components:

- `winlock.exe` / `winlock.cpp`: encrypts a target directory, starts a countdown, and can be restored by entering the correct password before expiration.
- `recovery.exe` / `recovery.cpp`: scans for `.locked` files and restores them without requiring the primary lock process or registry state.

The setup scripts automatically detect and install a compiler when needed, so the project can be built with minimal manual setup.

---

## ⚠️ Safety notice

> This project intentionally modifies system state, writes startup entries, changes registry settings on Windows, encrypts local files, and destroys original plaintext data after expiration or successful unlock. It is meant only for controlled testing, research, and isolated lab environments.
>
> Do not run this on personal machines, shared workstations, or production environments. Always use a disposable VM, sandbox, or dedicated test folder with backups.

---

## 📌 Repository contents

```text
.
├── winlock.cpp              # Main timed lock utility
├── winlock_setup.ps1        # Builds and runs winlock.exe automatically
├── recovery.cpp            # Standalone recovery utility
├── recovery_setup.ps1      # Builds and runs recovery.exe automatically
├── recovery_run.bat        # Helper to launch recovery_setup.ps1 with execution policy handling
├── session_elevate.bat     # Windows helper to launch the lock script by bypassing policy
├── CHANGELOG.md            # Version history
├── LICENSE                 # PolyForm Noncommercial License
├── README.md               # Project documentation
└── .gitignore              # Repo metadata (if present in your checkout)
```

---

## 🧩 What the project does

### Lock mode (`winlock.exe`)

- Recursively encrypts files in a target directory.
- Appends a `.locked` extension to encrypted files.
- Starts a countdown timer and persists the session state.
- On Windows, stores persistence data in the registry.
- On Linux, stores session metadata in a config file and autostart entry.
- Launches a watchdog process to monitor and restart the main app if it terminates.
- Prompts for a password in the terminal and unlocks the files before expiration.
- If the timer expires, files are destroyed and the registry/autostart state is cleaned up.

### Recovery mode (`recovery.exe`)

- Scans a target folder for `.locked` files.
- Decrypts each file without requiring the main lock utility.
- Reports per-file status such as `[OK]`, `[SKIP]`, and `[FAIL]`.
- Removes the `.locked` source after successful restore.
- Performs secure cleanup of original lock files.

---

## 🛠️ Build and run

### Windows

Option 1: run the PowerShell script directly:

```powershell
powershell -ExecutionPolicy Bypass -File .\winlock_setup.ps1
```

Option 2: use the helper batch file:

```bat
session_elevate.bat
```

For recovery:

```bat
recovery_run.bat
```

### Linux

The project is designed for a Linux build as well, but the lock mechanism still depends on the target directory, config file, and session cleanup logic.

```bash
g++ winlock.cpp -o winlock -std=c++17 -pthread
./winlock
```

For recovery:

```bash
g++ recovery.cpp -o recovery -std=c++17 -pthread
./recovery
```

---

## ⚙️ Key configuration values

The setup scripts embed constants for the target path, lock duration, password, and crypto key. They are located near the top of each PowerShell source file and should be reviewed before execution.

### `winlock_setup.ps1`

| Parameter | Typical value | Purpose |
| :--- | :--- | :--- |
| `ADMIN_PASSWORD` | `"admin123"` | Unlock password before the timer expires |
| `TARGET_PATH` (Windows) | `"C:\Users\Public\pupy"` | Folder to encrypt |
| `TARGET_PATH` (Linux) | `"/home/yigit/pupy"` | Folder to encrypt |
| `LOCK_DURATION_SECONDS` | `300` | Session duration in seconds |
| `CRYPTO_KEY` | `"Fast_XOR_Key_2026"` | Shared encryption key |

### `recovery_setup.ps1`

| Parameter | Typical value | Purpose |
| :--- | :--- | :--- |
| `TARGET_PATH` (Windows) | `"C:\Users\Public\pupy"` | Folder to scan for `.locked` files |
| `TARGET_PATH` (Linux) | `"/home/yigit/pupy"` | Folder to scan for `.locked` files |
| `CRYPTO_KEY` | `"Fast_XOR_Key_2026"` | Must match the lock utility |

> Do not set `TARGET_PATH` to `./`, the current repository directory, or any folder that contains the executable itself. Use a dedicated testing folder only.

---

## 🔐 Notes on security

This code is a demonstration project and not a hardened production encryption system. The implementation is intentionally designed to show mechanism and behavior rather than to provide strong enterprise-grade cryptographic guarantees.

In particular:

- encryption is demonstration-oriented
- key handling is intentionally simple
- persistence and watchdog behavior are designed for test automation and local research
- secure deletion is best-effort and depends on filesystem behavior and platform-level APIs

Use it only in isolated, disposable, and fully controlled environments.

---

## 📂 Platform behavior

| Subsystem | Windows | Linux |
| :--- | :--- | :--- |
| Persistence | Registry (`HKCU\Software\TimedFileLock`) | Config file under `~/.config` |
| Autostart | Run key in `CurrentVersion\Run` | XDG autostart entry |
| Signals | WinAPI console handlers | POSIX signals |
| Input | `_kbhit()` / `_getch()` | `termios` + `select()` |
| Watchdog | `CreateProcess()` | `fork()` + `setsid()` + `exec` |
| Recovery | Registry not required | Registry not required |

---

## 🚨 Emergency reset

If the lock utility is stuck or persistence is stale, you can remove the state manually.

### Built-in reset

```powershell
.\winlock.exe --reset
```

### Manual cleanup on Windows

```powershell
Get-Process | Where-Object { $_.Path -like "*winlock*" } | Stop-Process -Force
reg delete "HKCU\Software\TimedFileLock" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TimedFileLockProgram /f
```

---

## 🔄 High-level flow

### Lock flow

```text
winlock_setup.ps1
  ├─ Detect compiler (g++, cl.exe, or portable MinGW)
  ├─ Compile winlock.cpp
  └─ Run winlock.exe
      ├─ Encrypt files under TARGET_PATH
      ├─ Persist session metadata
      ├─ Start watchdog
      ├─ Countdown begins
      ├─ Correct password unlocks files
      ├─ Timer expiry destroys files
      └─ --reset clears entries and exits
```

### Recovery flow

```text
recovery_run.bat
  ├─ Set execution policy if possible
  └─ Run recovery_setup.ps1
      ├─ Detect compiler
      ├─ Compile recovery.cpp
      └─ Run recovery.exe
          ├─ Scan TARGET_PATH for .locked files
          ├─ Decrypt each file in parallel
          ├─ Report status per file
          └─ Remove source lock files after success
```

---

## 🧪 Recommended usage model

Use this project only in:

- a dedicated VM or disposable environment
- an isolated test directory with no important files
- a controlled local experiment where data loss is acceptable

Never run it on:

- personal work drives
- shared computers
- production infrastructure
- folders containing source code, documents, or backups you care about

---

## License

Copyright © 2026 Yiğit Erim Özdamar

This project is licensed under the PolyForm Noncommercial License 1.0.0.

You may inspect, study, modify, and use this software for personal, educational, research, testing, and other non-commercial purposes, subject to the terms of the license.

Commercial use is not permitted without explicit permission from the copyright holder.

For commercial licensing, contact the copyright holder.

License:
https://polyformproject.org/licenses/noncommercial/1.0.0
