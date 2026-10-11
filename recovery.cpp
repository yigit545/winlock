// recovery.cpp — standalone .locked file decryption tool (Updated)
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
// Constants — must match winlock settings
// ==========================================
#ifdef _WIN32
const std::string TARGET_PATH = fs::current_path().string();   // ./ works for current directory it is working on";
#else
static std::string resolveHome() {
    const char* h = getenv("HOME");
    return h ? std::string(h) : std::string("/tmp");
}
const std::string TARGET_PATH = resolveHome() + "./";
#endif

const std::string CRYPTO_KEY = "Fast_XOR_Key_2026";
// ==========================================

static std::mutex g_consoleMtx;


// ── Secure deletion — 3-pass (winlockv2 compatible) ───────────────────────
bool secureDelete(const fs::path& filePath) {
    std::error_code ec;
    uintmax_t fileSize = fs::file_size(filePath, ec);
    if (!ec && fileSize > 0) {
        const unsigned char patterns[3] = {0x00, 0xFF, 0xA5};
        for (int pass = 0; pass < 3; ++pass) {
            std::ofstream file(filePath, std::ios::binary | std::ios::in | std::ios::out);
            if (!file.is_open()) break;
            constexpr size_t BLOCK_SIZE = 4096;
            std::vector<char> buf(BLOCK_SIZE, (char)patterns[pass]);
            uintmax_t written = 0;
            while (written < fileSize) {
                uintmax_t toWrite = std::min((uintmax_t)buf.size(), fileSize - written);
                file.write(buf.data(), (std::streamsize)toWrite);
                written += toWrite;
            }
            file.flush();
            file.close();
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
            inFile.close();
            outFile.close();
            fs::remove(restoredPath);
            std::lock_guard<std::mutex> lock(g_consoleMtx);
            std::cerr << "[FAIL] I/O error     : " << restoredPath.filename() << "\n";
            return;
        }
    }

    outFile.flush();
    inFile.close();
    outFile.close();

    // Securely wipe the .locked file using 3-pass deletion
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
        if (entry.path().extension() == ".locked")
            targets.push_back(entry.path());
    }

    if (targets.empty()) {
        std::cout << "No .locked files found in: " << targetPath << "\n";
        return;
    }

    std::cout << "Found " << targets.size() << " locked file(s). Recovering...\n\n";

    const unsigned int maxConcurrency = std::thread::hardware_concurrency() > 0
                                       ? std::thread::hardware_concurrency()
                                       : 4;

    std::vector<std::future<void>> futures;

    for (const auto& path : targets) {
        if (futures.size() >= maxConcurrency * 2) {
            for (auto& f : futures) {
                if (f.valid()) { try { f.get(); } catch (...) {} }
            }
            futures.clear();
        }
        futures.push_back(
            std::async(std::launch::async, recoverSingleFile, path)
        );
    }

    for (auto& f : futures) {
        if (f.valid()) { try { f.get(); } catch (...) {} }
    }
}


// ── Main ──────────────────────────────────────────────────────────────────
int main() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        GetConsoleMode(hOut, &mode);
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
