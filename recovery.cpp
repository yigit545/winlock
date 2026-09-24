#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

// Kilitli dosyalarınızın bulunduğu Windows klasör yolunu buraya yazın
const std::string TARGET_PATH = R"(C:\Users\EXCALIBUR\Downloads)";
const std::string CRYPTO_KEY = "Hizli_XOR_Anahtari_2026";

void decryptSingleFile(const fs::path& filePath) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) return;

    std::string data((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    // XOR ile şifre çözme işlemi
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= CRYPTO_KEY[i % CRYPTO_KEY.size()];
    }

    // .locked uzantısını kaldırarak orijinal yolu oluştur
    std::string pathStr = filePath.string();
    std::string originalPath = pathStr.substr(0, pathStr.length() - 7);

    std::ofstream outFile(originalPath, std::ios::binary);
    if (outFile) {
        outFile.write(data.data(), data.size());
        outFile.close();
        
        // Şifreli .locked dosyasını sil
        fs::remove(filePath);
        std::cout << "[+] Kurtarildi: " << originalPath << std::endl;
    }
}

int main() {
    std::cout << "--- WINDOWS DOSYA KURTARMA ARACI ---\n";

    if (!fs::exists(TARGET_PATH)) {
        std::cerr << "[-] Hata: Hedef klasor bulunamadi: " << TARGET_PATH << std::endl;
        return 1;
    }

    for (const auto& entry : fs::recursive_directory_iterator(TARGET_PATH)) {
        if (entry.is_regular_file()) {
            std::string pathStr = entry.path().string();
            if (pathStr.length() >= 7 && pathStr.substr(pathStr.length() - 7) == ".locked") {
                decryptSingleFile(entry.path());
            }
        }
    }

    std::cout << "\nIslem tamamlandi!\n";
    return 0;
}