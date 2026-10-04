# recovery_setup.ps1
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
        # recovery does not use registry API — no -ladvapi32 needed
        & $script:CompilerPath $Source -o $Output -std=c++17 -pthread
    } elseif ($script:CompilerType -eq "msvc") {
        cl $Source /std:c++17 /EHsc /Fe:$Output
    }
    return $LASTEXITCODE -eq 0
}
# ──────────────────────────────────────────────────────────────────────────

$source = @'
// recovery.cpp — standalone .locked file decryption tool
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <future>
#include <mutex>
#include <thread>
#include <algorithm>
#ifdef _WIN32
    #include <windows.h>
#endif

namespace fs = std::filesystem;

// ==========================================
// Constants — must match winwipe settings
// ==========================================
#ifdef _WIN32
const std::string TARGET_PATH = "C:\\Users\\Public\\pupy";
#else
const std::string TARGET_PATH = "/home/yigit/pupy";
#endif
const std::string CRYPTO_KEY = "Fast_XOR_Key_2026";
// ==========================================

static std::mutex g_consoleMtx;

// ── Secure deletion ───────────────────────────────────────────────────────
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

// ── Decrypt a single .locked file ────────────────────────────────────────
void recoverSingleFile(const fs::path& lockedPath) {
    fs::path restoredPath = lockedPath;
    restoredPath.replace_extension("");

    std::ifstream inFile(lockedPath, std::ios::binary);
    if (!inFile) {
        std::lock_guard<std::mutex> lock(g_consoleMtx);
        std::cerr << "[SKIP] Cannot open   : " << lockedPath.filename() << "\n";
        return;
    }
    std::ofstream outFile(restoredPath, std::ios::binary);
    if (!outFile) {
        std::lock_guard<std::mutex> lock(g_consoleMtx);
        std::cerr << "[SKIP] Cannot write  : " << restoredPath.filename() << "\n";
        return;
    }

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
            inFile.close(); outFile.close(); fs::remove(restoredPath);
            std::lock_guard<std::mutex> lock(g_consoleMtx);
            std::cerr << "[FAIL] I/O error     : " << restoredPath.filename() << "\n";
            return;
        }
    }
    inFile.close(); outFile.close();

    secureDelete(lockedPath);

    std::lock_guard<std::mutex> lock(g_consoleMtx);
    std::cout << "[OK]   " << restoredPath.filename() << "\n";
}

// ── Parallel recovery ─────────────────────────────────────────────────────
void recoverAll(const fs::path& targetPath) {
    std::error_code ec;
    if (!fs::exists(targetPath, ec)) {
        std::cerr << "[ERROR] Target path not found: " << targetPath << "\n";
        return;
    }

    std::vector<fs::path> targets;
    auto options = fs::directory_options::skip_permission_denied;
    for (const auto& entry : fs::recursive_directory_iterator(targetPath, options, ec)) {
        if (ec) { ec.clear(); continue; }
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() == ".locked") targets.push_back(entry.path());
    }

    if (targets.empty()) {
        std::cout << "No .locked files found in: " << targetPath << "\n";
        return;
    }

    std::cout << "Found " << targets.size() << " locked file(s). Recovering...\n\n";

    const unsigned int maxConcurrency = std::thread::hardware_concurrency() > 0
                                       ? std::thread::hardware_concurrency() : 4;
    std::vector<std::future<void>> futures;

    for (const auto& path : targets) {
        if (futures.size() >= maxConcurrency * 2) {
            for (auto& f : futures)
                if (f.valid()) { try { f.get(); } catch (...) {} }
            futures.clear();
        }
        futures.push_back(std::async(std::launch::async, recoverSingleFile, path));
    }
    for (auto& f : futures)
        if (f.valid()) { try { f.get(); } catch (...) {} }
}

// ── Main ──────────────────────────────────────────────────────────────────
int main() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0; GetConsoleMode(hOut, &mode);
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif
    std::cout << "--- Recovery Tool ---\n";
    std::cout << "Target : " << TARGET_PATH << "\n";
    std::cout << "Key    : " << std::string(CRYPTO_KEY.size(), '*') << "\n\n";

    recoverAll(TARGET_PATH);

    std::cout << "\nRecovery complete.\n";
    std::cout << "Press Enter to exit...";
    std::cin.get();
    return 0;
}
'@

Set-Content -Path "recovery.cpp" -Value $source -Encoding UTF8
Write-Host "[1/4] recovery.cpp created." -ForegroundColor Green

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
if (-not (Invoke-Compile "recovery.cpp" "recovery.exe")) {
    Write-Host "ERROR: Compilation failed." -ForegroundColor Red
    exit 1
}
Write-Host "      Compilation successful -> recovery.exe" -ForegroundColor Green

Write-Host "[4/4] Running recovery..." -ForegroundColor Cyan
Write-Host ""
.\recovery.exe
Remove-Item recovery.cpp -ErrorAction SilentlyContinue
