# Timed File Lock & Emergency Recovery System

A lightweight C++ proof-of-concept demonstrating timed file encryption, system persistence via the Windows Registry, interactive countdown unlocking, and an independent emergency file recovery tool.

---

## ⚠️ Disclaimer

> **Educational & Testing Purpose Only:** This repository contains software that modifies the Windows Registry and encrypts local files. It is intended solely for educational, security research, and personal administrative demonstration purposes. Do not run this software on systems without authorization or on unbacked-up critical files.

---

## 📌 Overview

This project consists of two core C++ utilities:

1. **`winlock.cpp`**: A timed lock mechanism that encrypts files recursively in a target directory, registers itself in the Windows autostart sequence, and provides an interactive terminal interface with a countdown timer and password authentication.
2. **`recovery.cpp`**: An emergency standalone decryption utility designed to manually scan for and restore `.locked` files independently of registry keys or timers.

---

## 🛠️ Features

### `winlock.cpp` (Lock & Persistence Service)
* **XOR Encryption:** Encrypts files recursively using a symmetric XOR key (`Hizli_XOR_Anahtari_2026`) and appends a `.locked` extension.
* **Registry Persistence:** Adds a startup entry under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` to re-launch upon system reboot.
* **Session Tracking:** Persists the timer state in `HKCU\Software\TimedFileLock` so the countdown resumes across restarts.
* **Interactive Terminal:** Displays a real-time countdown with masked password input.
* **Auto-Cleanup:** Automatically decrypts files and removes registry persistence upon successful password entry or countdown expiration.

### `recovery.cpp` (Emergency Recovery Tool)
* **Independent Recovery:** Decrypts files without requiring registry keys or running the main timer thread.
* **Recursive Recovery:** Traverses a specified target directory for `.locked` files.
* **Clean Restoration:** Restores original file names by stripping `.locked` extensions and removes encrypted temporary files.

---

## 📂 Repository Structure

```text
.
├── winlock.cpp     # Main timed locking software with registry persistence
├── recovery.cpp    # Independent emergency file restoration utility
└── README.md       # Documentation
```

---

## ⚙️ Configuration Parameters

Before compiling, configuration constants can be modified inside the source files:

| File | Parameter | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `winlock.cpp` | `ADMIN_PASSWORD` | `"admin123"` | Password required to unlock files immediately. |
| `winlock.cpp` | `TARGET_PATH` | `"./"` | Directory to recursively lock. |
| `winlock.cpp` | `LOCK_DURATION_SECONDS` | `300` (5 minutes) | Lock timer duration in seconds. |
| `winlock.cpp` / `recovery.cpp` | `CRYPTO_KEY` | `"Hizli_XOR_Anahtari_2026"` | Symmetric XOR key used for encryption/decryption. |
| `recovery.cpp` | `TARGET_PATH` | `R"(C:\Users\EXCALIBUR\Downloads)"` | Target path for emergency decryption. |

---

## 🔨 Building the Project

### Requirements
* **Operating System:** Windows (requires Windows API headers `<windows.h>` and `<conio.h>`).
* **Compiler:** C++17 compliant compiler (GCC/MinGW, MSVC, or Clang).

### Building with MinGW (g++)
```bash
# Compile the main locking application
g++ -std=c++17 winlock.cpp -o winlock.exe -lstdc++fs

# Compile the emergency recovery tool
g++ -std=c++17 recovery.cpp -o recovery.exe -lstdc++fs
```

### Building with MSVC (Developer Command Prompt)
```cmd
cl /EHsc /std:c++17 winlock.cpp
cl /EHsc /std:c++17 recovery.cpp
```

---

## 🚀 Usage Instructions

### 1. Running `winlock.exe`
1. Place `winlock.exe` in or near the target directory.
2. Run `winlock.exe`.
3. The program will encrypt files in `TARGET_PATH` with `.locked` extensions, create registry persistence entries, and initiate a countdown timer.
4. To unlock before the timer expires, enter `admin123` (or your configured password) in the console.

### 2. Emergency Recovery with `recovery.exe`
If `winlock.exe` crashes or registry keys are lost:
1. Open `recovery.cpp` and ensure `TARGET_PATH` points to your locked folder.
2. Compile and execute `recovery.exe`.
3. The utility will recursively locate all `.locked` files, decrypt them using `CRYPTO_KEY`, and delete the `.locked` binaries.
