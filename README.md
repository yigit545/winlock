# Winlock

[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0.0-blue.svg)](https://polyformproject.org/licenses/noncommercial/1.0.0)
![C++](https://img.shields.io/badge/C%2B%2B-17%2B-00599C?logo=c%2B%2B&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)

# Timed File Lock & Wipe System

A cross-platform C++ security research tool implementing timed file encryption with **AES-256-GCM** (per-file random IV, authenticated), filesystem-aware secure deletion, Windows Registry persistence, watchdog-based process resilience, and parallel file processing — compiled and deployed automatically via self-contained PowerShell setup scripts with zero prerequisite installation.

The system has been tested and validated on isolated folder environments, virtual machines, and physical test devices.

---

## 🎯 Research Motivation

Recent ransomware incidents targeting academic and institutional infrastructure — including attacks on university networks — have exposed a critical gap in applied cybersecurity research: the lack of controlled, transparent, and auditable implementations of timed encryption and data lifecycle management systems for research and educational purposes.

Existing industry tools operate as closed-source black boxes. This project addresses that gap by providing an open, inspectable implementation of the core mechanisms used in timed file lock and secure wipe scenarios, enabling researchers and students to study, analyze, and build upon these techniques in a controlled environment.

This work contributes to applied cybersecurity R&D by:
- Providing a fully auditable AES-256-GCM implementation with per-file random nonces and authenticated decryption
- Demonstrating filesystem-aware secure deletion across SSD/NVMe, HDD, CoW (btrfs/ZFS/ReFS), and journaled filesystems
- Establishing a reproducible test baseline for studying ransomware-class behavior in isolated environments

---

## ⚠️ Disclaimer

> **Research & Educational Use Only:** This repository contains software that modifies the Windows Registry and encrypts local files. It is intended solely for cybersecurity research, security education, and authorized system administration demonstration purposes. Only run this software on systems and files for which you have explicit authorization. Always maintain backups before testing.

---

## 📌 Overview

The project consists of two independent C++ utilities, each embedded in its own self-contained PowerShell setup script. No compiler or toolchain needs to be pre-installed — the setup scripts detect, install, or download one automatically.

| Binary | Script | Purpose |
| :--- | :--- | :--- |
| `winwipe.exe` | `winwipev6_setup.ps1` | Timed file lock with AES-256-GCM, Registry persistence, watchdog, and countdown |
| `recovery.exe` | `recovery_setup.ps1` | Standalone decryption — no registry or timer required |

Both binaries are generated at runtime and are not stored in the repository.

---

## 🛠️ Features

### Lock (`winwipe.exe`)

- **Cross-Platform:** Supports Windows (Registry + WinAPI) and Linux (config file + XDG autostart).
- **AES-256-GCM Encryption:** Encrypts target files recursively using AES-256-GCM with a per-file randomly generated 96-bit IV/nonce and a 128-bit authentication tag. Each encrypted file is stored as `[12-byte IV][ciphertext][16-byte GCM tag]`. The GCM authentication tag ensures both confidentiality and integrity — tampered or corrupted files are rejected at decryption.
  - **Windows:** Delegates to `BCrypt` (Windows CNG) for hardware-accelerated AES-NI.
  - **Linux:** Pure C++ implementation with zero external dependencies — FIPS 197 compliant AES core, NIST SP 800-38D compliant GCM, constant-time tag verification.
- **Key Derivation:** The AES key is derived from the SHA-256 hash of the administrator password, providing a fixed 256-bit key tied to credentials. *(For production hardening, replace with Argon2id or PBKDF2 with a random salt.)*
- **Parallel Processing:** File encryption and decryption run concurrently across CPU cores via `std::async`, automatically scaled to `hardware_concurrency × 2` threads.
- **Chunked I/O:** RAM usage is fixed at 4 MB regardless of individual file size.
- **Filesystem-Aware Secure Deletion:** Overwrite strategy is selected per storage type and filesystem class detected at runtime. See the [Secure Deletion Matrix](#-secure-deletion-matrix) below.
- **Registry Persistence (Windows):** Writes a startup entry under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and stores the session end time in `HKCU\Software\TimedFileLock`.
- **Session Continuity:** If the process is killed and restarted, the countdown resumes from the stored end time. Stale registry entries (registry record present but no `.locked` files found) are automatically cleaned up on startup.
- **Watchdog Subprocess:** A background process monitors the main process and relaunches it upon termination, preventing easy interruption.
- **Interactive Terminal:** Displays a real-time countdown with masked password input.
- **Reset Mode:** `winwipe.exe --reset` decrypts all files, kills the watchdog, and removes all Registry and autostart entries.
- **Ordered Cleanup:** On unlock or timer expiry, the watchdog is always terminated before Registry entries are removed, preventing the watchdog from spawning a new instance during cleanup.
- **Shell Injection Prevention:** Process relaunch uses `execvp()` (Linux) / `CreateProcessA()` (Windows) directly — no `system()` call.

### Recovery (`recovery.exe`)

- **Independent Operation:** Decrypts files without requiring Registry keys, timers, or the main lock process.
- **Authenticated Decryption:** GCM tag is verified before any plaintext is written — authentication failures are reported per-file without corrupting other files.
- **Parallel Recovery:** Same `std::async` multi-threaded engine as the lock tool.
- **Thread-Safe Output:** Per-file status lines (`[OK]`, `[SKIP]`, `[FAIL]`) are printed safely across threads via `std::mutex`.
- **Secure Cleanup:** After successful decryption, the `.locked` source file is securely wiped according to the same filesystem-aware deletion matrix.
- **Partial Failure Handling:** If an I/O error occurs mid-decryption, the incomplete output file is removed and the error is reported without affecting other files.

### Setup Scripts (both)

- **Hybrid Compiler Detection:** No pre-installed toolchain required. Each setup script finds or installs a compiler automatically using a four-stage fallback:
  1. System `g++` (MinGW/GCC on PATH)
  2. System `cl.exe` (MSVC)
  3. Portable MinGW placed next to the script (`mingw-portable\mingw64\bin\g++.exe`)
  4. Automatic installation: `winget` → Chocolatey → direct zip download (~80 MB from winlibs)
- **Execution Policy Handling:** The `.bat` launcher sets `RemoteSigned` policy permanently for the current user, falling back to a per-session `Bypass` if that fails.

---

## 🔐 Secure Deletion Matrix

Overwrite strategy is selected automatically based on detected storage type and filesystem class.

### Linux

| Storage | Filesystem | Strategy |
| :--- | :--- | :--- |
| NVMe / SSD | btrfs / ZFS (CoW) | FITRIM only — CoW always writes new blocks; TRIM instructs the controller to erase freed cells |
| NVMe / SSD | ext4 / XFS / exFAT / FAT | 1-pass zero-fill + fsync → FITRIM |
| HDD | btrfs (CoW) | 3-pass DoD (0x00 / 0xFF / 0xA5) on current extent *(CoW caveat: prior snapshots not covered)* |
| HDD | ext4 / XFS / exFAT / FAT | 3-pass DoD (0x00 / 0xFF / 0xA5) |
| RAM (tmpfs / ramfs) | — | Unlink only — memory-backed, no persistent media |
| Network (NFS / CIFS) | — | Unlink only — remote storage is out of scope |

Storage type detected via `/sys/block/<dev>/queue/rotational`. Filesystem type detected via `/proc/mounts`.

### Windows

| Filesystem | Drive Type | Strategy |
| :--- | :--- | :--- |
| ReFS (CoW) | Any | TRIM IOCTL only |
| NTFS | SSD (no seek penalty) | 1-pass zero + TRIM IOCTL |
| NTFS | HDD | 3-pass DoD + TRIM IOCTL |
| exFAT / FAT32 | Any | 3-pass DoD |

Drive type detected via `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageDeviceSeekPenaltyProperty`). Filesystem detected via `GetVolumeInformation`.

---

## 🌐 Platform Support

The codebase is fully guarded with `#ifdef _WIN32` / `#else` blocks. Every platform-specific subsystem has a separate implementation with no shared state between them.

| Subsystem | Windows | Linux |
| :--- | :--- | :--- |
| **Encryption** | BCrypt AES-256-GCM (AES-NI) | Pure C++ AES-256-GCM (zero deps) |
| **Persistence** | Registry (`HKCU\Software\TimedFileLock`) | Config file (`~/.config/timedfilelock/endtime`) |
| **Autostart** | `HKCU\...\CurrentVersion\Run` registry key | XDG `.desktop` entry (`~/.config/autostart/`) |
| **Signal handling** | `SetConsoleCtrlHandler` (WinAPI) | `signal()` with POSIX signals (`SIGINT`, `SIGTERM`, `SIGHUP`) |
| **Terminal input** | `_kbhit()` / `_getch()` via `<conio.h>` | `termios` raw mode with `select()` |
| **Watchdog spawn** | `CreateProcess()` with `CREATE_NO_WINDOW` | `fork()` + `setsid()` + `execl()` |
| **Watchdog monitor** | `WaitForSingleObject(hParent, INFINITE)` | Polling `kill(parentPID, 0)` every 500 ms |
| **Watchdog relaunch** | `CreateProcessA()` (new console window) | `relaunchInTerminal()` via `execvp()` — tries gnome-terminal, xfce4-terminal, konsole, xterm |
| **Exe path resolution** | `GetModuleFileNameA()` | `readlink("/proc/self/exe", ...)` |
| **ANSI escape codes** | Enabled via `SetConsoleMode` + `ENABLE_VIRTUAL_TERMINAL_PROCESSING` | Supported natively |
| **CSPRNG** | `BCryptGenRandom()` | `/dev/urandom` |
| **TRIM** | `IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES` | `FITRIM` via `ioctl()` |

> `recovery.exe` is Windows-only by design — its ANSI block is the only platform-guarded section.

---

## 📂 Repository Structure

```text
.
├── winlock_setup.ps1       # Embeds, compiles, and runs winlock.exe
├── winlock.cpp             # Source code of winlock
├── recovery_run.bat        # Launcher for recovery: same policy handling as winwipe launcher
├── recovery.cpp            # Source code of recovery
├── recovery_setup.ps1      # Embeds, compiles, and runs recovery.exe
├── session_elevate.bat     # Elevates PowerShell session permissions for authorized execution
└── README.md               # Documentation
```

> If `mingw-portable\mingw64\` is placed next to the `.ps1` files, the compiler download step is skipped entirely — enabling fully offline operation.

---

## ⚙️ Configuration

Constants are embedded in the C++ source block inside each setup script. Edit them before running:

### `winwipev6_setup.ps1`

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `ADMIN_PASSWORD_HASH` | *(SHA-256 of your chosen password)* | SHA-256 hex digest of the unlock password. Used to derive the 256-bit AES key. |
| `TARGET_PATH` (Windows) | `resolveHome() + "\\Path_example"` | Directory to recursively encrypt. |
| `TARGET_PATH` (Linux) | `resolveHome() + "/pupy"` | Directory to recursively encrypt. |
| `LOCK_DURATION_SECONDS` | `300` | Lock timer duration in seconds (default: 5 minutes). |

### `recovery_setup.ps1`

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `ADMIN_PASSWORD_HASH` | *(must match `winwipev6_setup.ps1`)* | SHA-256 hex digest — must match the value used during encryption. |
| `TARGET_PATH` (Windows) | *(same as above)* | Directory to scan for `.locked` files. |
| `TARGET_PATH` (Linux) | *(same as above)* | Directory to scan for `.locked` files. |

> **Note:** `TARGET_PATH` must be an explicit, dedicated directory. Do not set it to `"./"` or any path containing the binary itself. The AES key is derived from `ADMIN_PASSWORD_HASH` — changing this value makes previously encrypted files unrecoverable.

---

## 🔨 Building

The setup scripts handle compilation automatically through the hybrid detection pipeline. To build manually:

### `winwipe` — MinGW (g++)
```bash
g++ winlock.cpp -o winwipe.exe -std=c++17 -pthread -ladvapi32 -lbcrypt
```

### `winwipe` — MSVC
```cmd
cl winlock.cpp /std:c++17 /EHsc /Fe:winwipe.exe /link advapi32.lib bcrypt.lib
```

### `recovery` — MinGW (g++)
```bash
g++ recovery.cpp -o recovery.exe -std=c++17 -pthread -lbcrypt
```

### `recovery` — MSVC
```cmd
cl recovery.cpp /std:c++17 /EHsc /Fe:recovery.exe /link bcrypt.lib
```

### Linux (`winwipe` only)
```bash
g++ winlock.cpp -o winwipe -std=c++17 -pthread
```

> `bcrypt.lib` / `-lbcrypt` is required on Windows for the CNG AES-256-GCM implementation. The Linux build uses a pure C++ AES-256-GCM implementation with no external cryptography library dependency. `advapi32` is required for Registry API access.

---

## 🚀 Usage

### Lock (winwipe)
Double-click `winwipev6_run.bat`. The script will find or install a compiler, build `winwipe.exe`, and launch it. Once running:
- Files in `TARGET_PATH` are encrypted with AES-256-GCM and the countdown begins.
- Type the password and press `Enter` to unlock before the timer expires.
- On expiry, locked files are permanently destroyed using the filesystem-aware secure deletion strategy.

### Recovery
Double-click `recovery_run.bat`. The script will build and run `recovery.exe`, which:
- Scans `TARGET_PATH` recursively for `.locked` files.
- Verifies the GCM authentication tag before writing any plaintext.
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
               ├─ Check registry / config:
               │   ├─ Session + .locked files  → resume countdown
               │   └─ Session + no .locked     → stale record, reset
               │
               ├─ [New] AES-256-GCM encrypt (per-file IV) → write registry → countdown
               │
               ├─ Password correct → GCM decrypt → kill watchdog → clean registry
               ├─ Timer expires   → secure wipe  → kill watchdog → clean registry
               └─ --reset flag    → GCM decrypt  → kill watchdog → clean registry → exit
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
               ├─ For each file (parallel, std::async):
               │   ├─ Read IV (12 bytes) + ciphertext + GCM tag (16 bytes)
               │   ├─ Verify GCM tag (constant-time comparison)
               │   ├─ [OK]   → decrypt → secureDelete .locked source
               │   ├─ [SKIP] → cannot open / write
               │   └─ [FAIL] → auth failure or I/O error; partial output removed
               └─ Report complete
```

---

## 🧪 Test Results

The system has been validated across the following environments:

| Environment | OS | Result |
| :--- | :--- | :--- |
| Isolated folder (host) | Windows 11 | ✅ Pass |
| Virtual Machine | Windows 10 (VMware) | ✅ Pass |
| Virtual Machine | Ubuntu/Debian Linux 23 (Host) | ✅ Pass |
| Physical test device | Windows 11 | ✅ Pass |

All lock, countdown, AES-256-GCM encryption/decryption, recovery, watchdog resilience, and secure deletion behaviors performed as specified.

---

## Changelog

| Version | Changes |
| :--- | :--- |
| v3.0 | XOR → AES-256-GCM (per-file random IV, authenticated). BCrypt on Windows, pure C++ on Linux. Filesystem-aware secure deletion matrix. `system()` → `execvp()` shell injection fix. Thread pool for parallel processing. Cross-platform `resolveHome()`. |
| v2.x | Watchdog subprocess, Registry persistence, session continuity, parallel file processing, interactive countdown. |

---

## License

Copyright © 2026 Yiğit Erim Özdamar

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

You may inspect, study, modify, and use this software for **personal, educational, research, testing, and other non-commercial purposes**, subject to the terms of the license.

**Commercial use is not permitted without explicit permission from the copyright holder.**

For commercial licensing or permission, please contact the copyright holder.

License: https://polyformproject.org/licenses/noncommercial/1.0.0
