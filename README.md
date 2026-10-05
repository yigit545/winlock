# Winlock

[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0.0-blue.svg)](https://polyformproject.org/licenses/noncommercial/1.0.0)
![C++](https://img.shields.io/badge/C%2B%2B-17%2B-00599C?logo=c%2B%2B&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)
# Timed File Lock & Wipe System

A cross-platform C++ proof-of-concept demonstrating timed file encryption, Windows Registry persistence, watchdog-based process resilience, parallel file processing, and interactive countdown unlocking — compiled and deployed automatically via self-contained PowerShell setup scripts with zero prerequisite installation.

---

## ⚠️ Disclaimer

> **Educational & Testing Purpose Only:** This repository contains software that modifies the Windows Registry and encrypts local files. It is intended solely for educational, security research, and personal administrative demonstration purposes. Do not run this software on systems without authorization or on files that have not been backed up.

---

## 📌 Overview

The project consists of two independent C++ utilities, each embedded in its own self-contained PowerShell setup script. No compiler or toolchain needs to be pre-installed — the setup scripts detect, install, or download one automatically.

| Binary | Script | Purpose |
| :--- | :--- | :--- |
| `winwipe.exe` | `winwipev6_setup.ps1` | Timed file lock with Registry persistence, watchdog, and countdown |
| `recovery.exe` | `recovery_setup.ps1` | Standalone decryption — no registry or timer required |

Both binaries are generated at runtime and are not stored in the repository.

---

## 🛠️ Features

### Lock (`winwipe.exe`)
- **Cross-Platform:** Supports Windows (Registry + WinAPI) and Linux (config file + XDG autostart).
- **XOR Encryption:** Encrypts target files recursively using a symmetric XOR key, appending a `.locked` extension. Decryption uses the same key in reverse.
- **Parallel Processing:** File encryption and decryption run concurrently across CPU cores via `std::async`, automatically scaled to `hardware_concurrency × 2` threads.
- **Chunked I/O:** RAM usage is fixed at 4 MB regardless of individual file size.
- **Secure Deletion:** Original plaintext files are overwritten with zeroes before removal, leaving no recoverable trace on disk.
- **Registry Persistence (Windows):** Writes a startup entry under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and stores the session end time in `HKCU\Software\TimedFileLock`.
- **Session Continuity:** If the process is killed and restarted, the countdown resumes from the stored end time. Stale registry entries (registry record present but no `.locked` files found) are automatically cleaned up on startup.
- **Watchdog Subprocess:** A background process monitors the main process and relaunches it upon termination, preventing easy interruption.
- **Interactive Terminal:** Displays a real-time countdown with masked password input.
- **Reset Mode:** `winwipe.exe --reset` decrypts all files, kills the watchdog, and removes all Registry and autostart entries.
- **Ordered Cleanup:** On unlock or timer expiry, the watchdog is always terminated before Registry entries are removed, preventing the watchdog from spawning a new instance during cleanup.

### Recovery (`recovery.exe`)
- **Independent Operation:** Decrypts files without requiring Registry keys, timers, or the main lock process.
- **Parallel Recovery:** Same `std::async` multi-threaded engine as the lock tool.
- **Thread-Safe Output:** Per-file status lines (`[OK]`, `[SKIP]`, `[FAIL]`) are printed safely across threads via `std::mutex`.
- **Secure Cleanup:** After successful decryption, the `.locked` source file is securely wiped with zeroes before removal.
- **Partial Failure Handling:** If an I/O error occurs mid-decryption, the incomplete output file is removed and the error is reported without affecting other files.

### Setup Scripts (both)
- **Hybrid Compiler Detection:** No pre-installed toolchain required. Each setup script finds or installs a compiler automatically using a four-stage fallback:
  1. System `g++` (MinGW/GCC on PATH)
  2. System `cl.exe` (MSVC)
  3. Portable MinGW placed next to the script (`mingw-portable\mingw64\bin\g++.exe`)
  4. Automatic installation: `winget` → Chocolatey → direct zip download (~80 MB from winlibs)
- **Execution Policy Handling:** The `.bat` launcher sets `RemoteSigned` policy permanently for the current user, falling back to a per-session `Bypass` if that fails.

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

> `recovery.exe` is Windows-only by design — its ANSI block is the only platform-guarded section. It requires no WinAPI beyond console setup.

---

## 📂 Repository Structure

```text
.
├── winwipev6_run.bat     # Launcher for winwipe: handles execution policy, triggers setup
├── winwipev6_setup.ps1   # Embeds, compiles, and runs winwipe.exe
├── recovery_run.bat      # Launcher for recovery: same policy handling as winwipe launcher
├── recovery_setup.ps1    # Embeds, compiles, and runs recovery.exe
└── README.md             # Documentation
```

> If `mingw-portable\mingw64\` is placed next to the `.ps1` files, the compiler download step is skipped entirely — enabling fully offline operation.

---

## ⚙️ Configuration

Constants are embedded in the C++ source block inside each setup script. Edit them before running:

### `winwipev6_setup.ps1`

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `ADMIN_PASSWORD` | `"admin123"` | Password to unlock files before the timer expires. |
| `TARGET_PATH` (Windows) | `"C:\\Users\\Public\\pupy"` | Directory to recursively encrypt. |
| `TARGET_PATH` (Linux) | `"/home/yigit/pupy"` | Directory to recursively encrypt. |
| `LOCK_DURATION_SECONDS` | `300` | Lock timer duration in seconds (default: 5 minutes). |
| `CRYPTO_KEY` | `"Fast_XOR_Key_2026"` | Symmetric XOR key. Must match `recovery_setup.ps1`. |

### `recovery_setup.ps1`

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `TARGET_PATH` (Windows) | `"C:\\Users\\Public\\pupy"` | Directory to scan for `.locked` files. |
| `TARGET_PATH` (Linux) | `"/home/yigit/pupy"` | Directory to scan for `.locked` files. |
| `CRYPTO_KEY` | `"Fast_XOR_Key_2026"` | Must match the value used during encryption. |

> **Note:** `TARGET_PATH` must be an explicit, dedicated directory. Do not set it to `"./"` or any path containing the binary itself.

---

## 🔨 Building

The setup scripts handle compilation automatically through the hybrid detection pipeline. To build manually:

### `winwipe` — MinGW (g++)
```bash
g++ winlock.cpp -o winwipe.exe -std=c++17 -pthread -ladvapi32
```

### `winwipe` — MSVC
```cmd
cl winlock.cpp /std:c++17 /EHsc /Fe:winwipe.exe /link advapi32.lib
```

### `recovery` — MinGW (g++)
```bash
g++ recovery.cpp -o recovery.exe -std=c++17 -pthread
```

### `recovery` — MSVC
```cmd
cl recovery.cpp /std:c++17 /EHsc /Fe:recovery.exe
```

### Linux (`winwipe` only)
```bash
g++ winlock.cpp -o winwipe -std=c++17 -pthread
```

> `advapi32` is Windows-only and must be explicitly linked for Registry API access — omitting it causes silent runtime failures on some MinGW configurations. `recovery` does not use the Registry and requires no extra link flags.

---

## 🚀 Usage

### Lock (winwipe)
Double-click `winwipev6_run.bat`. The script will find or install a compiler, build `winwipe.exe`, and launch it. Once running:
- Files in `TARGET_PATH` are encrypted and the countdown begins.
- Type the password and press `Enter` to unlock before the timer expires.
- On expiry, locked files are permanently destroyed.

### Recovery
Double-click `recovery_run.bat`. The script will build and run `recovery.exe`, which:
- Scans `TARGET_PATH` recursively for `.locked` files.
- Decrypts each file in parallel and reports per-file status.
- Securely wipes the `.locked` source after successful restoration.

### Emergency reset (winwipe stuck)

**Option A — built-in flag:**
```powershell
.\winwipe.exe --reset
```

**Option B — manual cleanup:**
```powershell
Get-Process | Where-Object {$_.Path -like "*winwipe*"} | Stop-Process -Force
reg delete "HKCU\Software\TimedFileLock" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TimedFileLockProgram /f
```

---

## 🔄 Flow Diagrams

### Lock flow
```
winwipev6_run.bat
│
├─ Set RemoteSigned policy (permanent) → success
└─ Fallback: Bypass (this session only)
   │
   └─ winwipev6_setup.ps1
      │
      ├─ [1/4] Write winlock.cpp to disk
      ├─ [2/4] Find compiler:
      │         system g++ → system cl → portable g++ → install (winget/choco/download)
      ├─ [3/4] Compile → winwipe.exe
      └─ [4/4] Launch winwipe.exe
               │
               ├─ Spawn watchdog subprocess
               ├─ Check registry:
               │   ├─ Session + .locked files  → resume countdown
               │   └─ Session + no .locked     → stale record, reset
               │
               ├─ [New] Encrypt → write registry → countdown
               │
               ├─ Password correct → decrypt → kill watchdog → clean registry
               ├─ Timer expires   → destroy  → kill watchdog → clean registry
               └─ --reset flag    → decrypt  → kill watchdog → clean registry → exit
```

### Recovery flow
```
recovery_run.bat
│
├─ Set RemoteSigned policy (permanent) → success
└─ Fallback: Bypass (this session only)
   │
   └─ recovery_setup.ps1
      │
      ├─ [1/4] Write recovery.cpp to disk
      ├─ [2/4] Find compiler:
      │         system g++ → system cl → portable g++ → install (winget/choco/download)
      ├─ [3/4] Compile → recovery.exe
      └─ [4/4] Launch recovery.exe
               │
               ├─ Scan TARGET_PATH for .locked files
               ├─ Decrypt each file in parallel (std::async)
               │   ├─ [OK]   → secureDelete .locked source
               │   ├─ [SKIP] → cannot open / write
               │   └─ [FAIL] → I/O error, partial output removed
               └─ Report complete
```
## License

Copyright © 2026 Yiğit Erim Özdamar

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

You may inspect, study, modify, and use this software for **personal, educational, research, testing, and other non-commercial purposes**, subject to the terms of the license.

**Commercial use is not permitted without explicit permission from the copyright holder.**

For commercial licensing or permission, please contact the copyright holder.

License:
https://polyformproject.org/licenses/noncommercial/1.0.0
