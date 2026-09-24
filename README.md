# Timed File Lock System (WinLock)

A Windows-based, time-driven file locking utility written in C++. This program temporarily encrypts files in a specified directory for a set duration, integrates with the Windows startup registry to ensure persistence across reboots, and features an administrative override password to decrypt files before the timer expires.

⚠️ **WARNING / DISCLAIMER:** This software modifies the Windows Registry, adds itself to startup, and encrypts files using XOR encryption. It is intended for **educational purposes only**. Do not run this executable in system-critical directories or without understanding the source code. The developer assumes no liability for accidental data loss.

## Features

* **XOR File Encryption:** Encrypts all regular files in the target directory recursively and appends a `.locked` extension.
* **Persistent Countdown Timer:** Saves the unlock time in the Windows Registry. If the system is rebooted or the program is closed forcefully, it will resume the countdown from where it left off.
* **Startup Integration:** Automatically adds itself to the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` registry key so it launches on system boot until the timer expires.
* **Live Console UI:** Displays a real-time countdown timer alongside a hidden password input prompt.
* **Admin Override:** Allows early decryption and cleanup by entering a predefined password.
* **Auto-Cleanup:** Once the timer expires (or the admin password is provided), the program decrypts all files, removes the `.locked` extensions, and cleanly removes its registry keys and startup entries.

## Prerequisites

* **OS:** Windows (Uses `windows.h` and Windows Registry APIs).
* **Compiler:** A C++ compiler that supports the **C++17** standard (required for `<filesystem>`). MinGW (g++) or MSVC are recommended.

## Building / Compiling

You can compile the `winlock.cpp` file using a terminal or command prompt.

**Using g++ (MinGW):**
```bash
g++ winlock.cpp -o winlock.exe -std=c++17
```

**Using MSVC (Developer Command Prompt):**
```cmd
cl /EHsc /std:c++17 winlock.cpp
```

## Configuration

Before compiling, you can customize the program's behavior by modifying the embedded constants at the top of the `winlock.cpp` file:

```cpp
const std::string ADMIN_PASSWORD = "admin123";      // Password to unlock files instantly
const std::string TARGET_PATH = "./";               // Target directory ("./" is the current directory)
const int LOCK_DURATION_SECONDS = 300;              // Lock duration in seconds (Default: 5 mins)
const std::string CRYPTO_KEY = "Hizli_XOR_Anahtari_2026"; // The XOR encryption key
```

## Usage

1. **Place the compiled executable** in the directory you wish to lock (if `TARGET_PATH` is left as `"./"`).
2. **Run the executable.** It will immediately lock the files and start the countdown.
3. **To unlock early:** Type the `ADMIN_PASSWORD` (default is `admin123`) into the console and press `Enter`.
4. **To unlock normally:** Wait for the timer to reach `00:00`. The program will automatically decrypt the files and clean up the registry.

## How It Works

1. **Initialization:** On launch, the program checks `HKCU\Software\TimedFileLock` for an existing end time. If none exists, it calculates the end time based on `LOCK_DURATION_SECONDS`, writes it to the registry, and adds the executable path to the Windows Run key.
2. **Encryption:** It iterates through the `TARGET_PATH`, applying a symmetric XOR cipher to the binary data of each file, renaming them with a `.locked` suffix.
3. **Wait Loop:** It loops, calculating the time difference between the system clock and the saved registry target time, handling keystrokes for the admin password asynchronously.
4. **Decryption & Cleanup:** When the timer hits 0 or the password is correct, the XOR process is reversed, `.locked` extensions are removed, and all associated registry keys (including the startup entry) are deleted.
