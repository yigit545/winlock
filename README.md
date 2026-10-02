[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![C++](https://img.shields.io/badge/C%2B%2B-17%2B-00599C?logo=c%2B%2B&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)
# Timed File Lock & Wipe System

A cross-platform C++ proof-of-concept demonstrating timed file encryption, Windows Registry persistence, watchdog-based process resilience, parallel file processing, and interactive countdown unlocking — compiled and deployed automatically via a self-contained PowerShell setup script.

---

## ⚠️ Disclaimer

> **Educational & Testing Purpose Only:** This repository contains software that modifies the Windows Registry and encrypts local files. It is intended solely for educational, security research, and personal administrative demonstration purposes. Do not run this software on systems without authorization or on files that have not been backed up.

---

## 📌 Overview

The project compiles and runs a single C++ binary (`winwipe.exe`) from a self-contained PowerShell setup script. The binary handles timed file encryption, Registry-based session persistence, a watchdog subprocess for process resilience, parallel file processing, and secure file destruction upon timer expiry.

`winwipe.exe` and `winlock.cpp` are generated at runtime by the setup script and are not stored in the repository.

---

## 🛠️ Features

- **Cross-Platform:** Supports Windows (Registry + WinAPI) and Linux (config file + XDG autostart).
- **XOR Encryption:** Encrypts target files recursively using a symmetric XOR key, appending a `.locked` extension. Decryption uses the same key in reverse.
- **Parallel Processing:** File encryption and decryption run concurrently across CPU cores via `std::async`, automatically scaled to `hardware_concurrency × 2` threads.
- **Chunked I/O:** RAM usage is fixed at 4 MB regardless of individual file size.
- **Secure Deletion:** Original plaintext files are overwritten with zeroes before removal, leaving no recoverable trace on disk.
- **Registry Persistence (Windows):** Writes a startup entry under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and stores the session end time in `HKCU\Software\TimedFileLock`.
- **Session Continuity:** If the process is killed and restarted, the countdown resumes from the stored end time. Stale registry entries (registry record present but no `.locked` files found) are automatically cleaned up on startup.
- **Watchdog Subprocess:** A background process monitors the main process and relaunches it upon termination, preventing easy interruption.
- **Interactive Terminal:** Displays a real-time countdown with masked password input.
- **Reset Mode:** `winwipe.exe --reset` decrypts all files, kills the watchdog, and removes all Registry and autostart entries — for use when a session needs to be manually cleared.
- **Ordered Cleanup:** On unlock or timer expiry, the watchdog is always terminated before Registry entries are removed, preventing the watchdog from spawning a new instance during cleanup.
- **Execution Policy Handling:** The `.bat` launcher automatically attempts to set a permanent execution policy and falls back to a per-session bypass if that fails, requiring no manual configuration.

---

## 🌐 Platform Support

The codebase is fully guarded with `#ifdef _WIN32` / `#else` blocks. Every platform-specific subsystem has a separate implementation with no shared state between them.

| Subsystem | Windows | Linux |
| :--- | :--- | :--- |
| **Persistence** | Registry (`HKCU\Software\TimedFileLock`) | Config file (`~/.config/timedfilelock/endtime`) |
| **Autostart** | `HKCU\...\CurrentVersion\Run` registry key | XDG `.desktop` entry (`~/.config/autostart/`) |
| **Signal handling** | `SetConsoleCtrlHandler` (WinAPI) | `signal()` with POSIX signals (`SIGINT`, `SIGTERM`, `SIGHUP`) |
| **Terminal input** | `_kbhit()` / `_getch()` via `<conio.h>` | `termios` raw mode with `select()` |
| **Watchdog spawn** | `CreateProcess()` with `CREATE_NO_WINDOW` | `fork()` + `setsid()` + `execl()` |
| **Watchdog monitor** | `WaitForSingleObject(hParent, INFINITE)` | Polling `kill(parentPID, 0)` every 500 ms |
| **Watchdog relaunch** | `CreateProcessA()` (new console window) | `relaunchInTerminal()` — tries gnome-terminal, xfce4-terminal, konsole, xterm |
| **Exe path resolution** | `GetModuleFileNameA()` | `readlink("/proc/self/exe", ...)` |
| **ANSI escape codes** | Enabled via `SetConsoleMode` + `ENABLE_VIRTUAL_TERMINAL_PROCESSING` | Supported natively |

### Building on Linux

```bash
g++ winlock.cpp -o winwipe -std=c++17 -pthread
```

No additional link flags needed — `advapi32` is Windows-only. The `_WIN32` guards prevent any WinAPI code from being compiled on Linux.

---

## 📂 Repository Structure

```text
.
├── winwipev6_run.bat     # Launcher: handles execution policy and triggers the setup script
├── winwipev6_setup.ps1   # Self-contained setup: embeds, compiles, and runs winwipe.exe
└── README.md             # Documentation
```

---

## ⚙️ Configuration

All configuration is embedded in `winwipev6_setup.ps1`. Edit the constants block in the C++ source section before running the script:

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `ADMIN_PASSWORD` | `"admin123"` | Password to unlock files before the timer expires. |
| `TARGET_PATH` (Windows) | `"./"` | Directory to recursively encrypt. |
| `TARGET_PATH` (Linux) | `"./"` | Directory to recursively encrypt. |
| `LOCK_DURATION_SECONDS` | `300` | Lock timer duration in seconds (default: 5 minutes). |
| `CRYPTO_KEY` | `"Fast_XOR_Key_2026"` | Symmetric XOR key used for both encryption and decryption. Must match in any recovery scenario. |

> **Note:** `TARGET_PATH` must be an explicit, dedicated directory. Do not set it to `"./"` or any path containing the binary itself.

---

## 🔨 Building

The setup script handles compilation automatically. To build manually:

### MinGW (g++)
```bash
g++ winlock.cpp -o winwipe.exe -std=c++17 -pthread -ladvapi32
```

### MSVC (Developer Command Prompt)
```cmd
cl winlock.cpp /std:c++17 /EHsc /Fe:winwipe.exe /link advapi32.lib
```

**Requirements:** C++17-compliant compiler (MinGW-w64 or MSVC). `advapi32` must be explicitly linked for Registry API access — omitting it causes silent runtime failures on some MinGW configurations.

For Linux build instructions, see [Platform Support](#-platform-support).

---

## 🚀 Usage

### Normal run
Double-click `winwipev6_run.bat`. It will:
1. Attempt to permanently set `RemoteSigned` execution policy for the current user.
2. Fall back to a per-session `Bypass` if that fails.
3. Launch `winwipev6_setup.ps1`, which compiles and starts `winwipe.exe`.

### Unlock before timer expires
Type your password in the console and press `Enter`.

### Emergency reset

If the session is stuck or needs to be cleared manually, kill all instances first, then use one of the following:

**Option A — built-in reset flag:**
```powershell
.\winwipe.exe --reset
```

**Option B — manual cleanup:**
```powershell
# Kill all running instances
Get-Process | Where-Object {$_.Path -like "*winwipe*"} | Stop-Process -Force

# Remove Registry entries
reg delete "HKCU\Software\TimedFileLock" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TimedFileLockProgram /f
```

---

## 🔄 Session Flow

```
winwipev6_run.bat
│
└─ winwipev6_setup.ps1
   │
   └─ winwipe.exe
      │
      ├─ Spawn watchdog subprocess
      ├─ Check registry for existing session
      │   ├─ Session found + .locked files exist  → resume countdown
      │   └─ Session found + no .locked files     → stale record, clean up, start fresh
      │
      ├─ [New session] Encrypt files → write registry → start countdown
      │
      ├─ Countdown loop (password input)
      │   ├─ Correct password → decrypt → kill watchdog → clean registry
      │   └─ Timer expires   → destroy → kill watchdog → clean registry
      │
      └─ [--reset flag] Decrypt → kill watchdog → clean registry → exit
```
