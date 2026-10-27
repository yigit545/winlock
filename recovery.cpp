// recovery.cpp — standalone .locked file decryption tool
// Compatible with winlock_ex7.cpp (AES-256-GCM, disk-aware secureDelete, ThreadPool)
//
// Changelog (recovery v2.0):
// [SECURITY] XOR -> AES-256-GCM: deriveKeyFromHash + aesGcmDecrypt (winlock_ex7 uyumlu)
// [SECURITY] secureDelete: full storage×filesystem matrix (winlock_ex7 ile birebir)
//    Linux:
//      NVMe/SSD + CoW (btrfs/ZFS)    -> FITRIM only
//      NVMe/SSD + ext4/XFS/exFAT/FAT  -> 1-pass zero + fsync + FITRIM
//      HDD      + any                 -> 3-pass DoD (0x00/0xFF/0xA5)
//      RAM (tmpfs) / Network (NFS)    -> unlink only
//    Windows:
//      ReFS (CoW)                     -> TRIM IOCTL only
//      NTFS + SSD                     -> 1-pass zero + TRIM IOCTL
//      NTFS + HDD                     -> 3-pass + TRIM IOCTL
//      exFAT / FAT32                  -> 3-pass
// [PERF]      ThreadPool (min(hw_concurrency,8)) — winlock_ex7 ile aynı
// [FIX]       resolveHome(): cross-platform — USERPROFILE (Win) / HOME (Linux)

#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <future>
#include <mutex>
#include <thread>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <sstream>

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
    #include <winioctl.h>
    #pragma comment(lib, "advapi32.lib")
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <sys/sysmacros.h>
    #include <sys/ioctl.h>
    #include <linux/fs.h>
#endif

namespace fs = std::filesystem;

// ==========================================
// Constants — must match winlock_ex7 settings
// ==========================================
const std::string ADMIN_PASSWORD_HASH =
    "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9";

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
const std::string TARGET_PATH = resolveHome() + "\\Path_example";
#else
const std::string TARGET_PATH = resolveHome() + "/pupy";
#endif

// AES-256-GCM parameters (winlock_ex7 ile aynı)
constexpr size_t AES_KEY_SIZE = 32;
constexpr size_t GCM_IV_SIZE  = 12;
constexpr size_t GCM_TAG_SIZE = 16;

static std::mutex g_consoleMtx;

// ==========================================
// SECTION 1: Key derivation
// ==========================================
static std::array<uint8_t, AES_KEY_SIZE> deriveKeyFromHash(const std::string& hexHash) {
    std::array<uint8_t, AES_KEY_SIZE> key{};
    for (size_t i = 0; i < AES_KEY_SIZE && (i * 2 + 1) < hexHash.size(); ++i)
        key[i] = (uint8_t)std::stoul(hexHash.substr(i * 2, 2), nullptr, 16);
    return key;
}

// ==========================================
// SECTION 2: CSPRNG
// ==========================================
[[maybe_unused]] static bool fillRandom(uint8_t* buf, size_t len) {
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
#ifdef _WIN32
struct WinAesGcm {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
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

    bool decrypt(const uint8_t* iv, const uint8_t* cipherWithTag, size_t totalLen,
                 std::vector<uint8_t>& out) {
        if (totalLen < GCM_TAG_SIZE) return false;
        size_t cipherLen    = totalLen - GCM_TAG_SIZE;
        const uint8_t* tag  = cipherWithTag + cipherLen;

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
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    }
};

static std::vector<uint8_t> aesGcmDecrypt(
        const std::array<uint8_t, AES_KEY_SIZE>& key,
        const std::vector<uint8_t>& blob) {
    if (blob.size() < GCM_IV_SIZE + GCM_TAG_SIZE) return {};
    const uint8_t* iv           = blob.data();
    const uint8_t* cipherAndTag = blob.data() + GCM_IV_SIZE;
    size_t cipherAndTagLen      = blob.size() - GCM_IV_SIZE;

    WinAesGcm ctx;
    if (!ctx.init(key.data())) return {};

    std::vector<uint8_t> plain;
    if (!ctx.decrypt(iv, cipherAndTag, cipherAndTagLen, plain)) return {};
    return plain;
}

#else

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
    uint8_t r = 0, aa = a;
    for (int i = 0; i < 8; i++) { if (b & 1) r ^= aa; aa = xtime(aa); b >>= 1; }
    return r;
}

struct AES256 {
    static constexpr int NK = 8, NR = 14, NB = 4;
    uint32_t rk[60];

    void setKey(const uint8_t* key) {
        for (int i = 0; i < NK; i++)
            rk[i] = ((uint32_t)key[4*i]<<24)|((uint32_t)key[4*i+1]<<16)|
                    ((uint32_t)key[4*i+2]<<8)|key[4*i+3];
        for (int i = NK; i < NB*(NR+1); i++) {
            uint32_t t = rk[i-1];
            if (i % NK == 0) {
                t = (t << 8)|(t >> 24);
                t = ((uint32_t)SBOX[(t>>24)&0xff]<<24)|
                    ((uint32_t)SBOX[(t>>16)&0xff]<<16)|
                    ((uint32_t)SBOX[(t>> 8)&0xff]<< 8)|
                    (uint32_t)SBOX[t&0xff];
                t ^= ((uint32_t)RCON[i/NK]<<24);
            } else if (i % NK == 4) {
                t = ((uint32_t)SBOX[(t>>24)&0xff]<<24)|
                    ((uint32_t)SBOX[(t>>16)&0xff]<<16)|
                    ((uint32_t)SBOX[(t>> 8)&0xff]<< 8)|
                    (uint32_t)SBOX[t&0xff];
            }
            rk[i] = rk[i-NK] ^ t;
        }
    }

    void encryptBlock(uint8_t* blk) const {
        uint8_t s[4][4];
        for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) s[r][c] = blk[r+4*c];
        for (int c = 0; c < 4; c++) {
            uint32_t w = rk[c];
            s[0][c]^=(w>>24)&0xff; s[1][c]^=(w>>16)&0xff;
            s[2][c]^=(w>> 8)&0xff; s[3][c]^=w&0xff;
        }
        for (int round = 1; round <= NR; round++) {
            for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) s[r][c] = SBOX[s[r][c]];
            uint8_t t;
            t=s[1][0]; s[1][0]=s[1][1]; s[1][1]=s[1][2]; s[1][2]=s[1][3]; s[1][3]=t;
            t=s[2][0]; s[2][0]=s[2][2]; s[2][2]=t; t=s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
            t=s[3][3]; s[3][3]=s[3][2]; s[3][2]=s[3][1]; s[3][1]=s[3][0]; s[3][0]=t;
            if (round < NR) {
                for (int c = 0; c < 4; c++) {
                    uint8_t a0=s[0][c],a1=s[1][c],a2=s[2][c],a3=s[3][c];
                    s[0][c]=mul(0x02,a0)^mul(0x03,a1)^a2^a3;
                    s[1][c]=a0^mul(0x02,a1)^mul(0x03,a2)^a3;
                    s[2][c]=a0^a1^mul(0x02,a2)^mul(0x03,a3);
                    s[3][c]=mul(0x03,a0)^a1^a2^mul(0x02,a3);
                }
            }
            for (int c = 0; c < 4; c++) {
                uint32_t w = rk[round*4+c];
                s[0][c]^=(w>>24)&0xff; s[1][c]^=(w>>16)&0xff;
                s[2][c]^=(w>> 8)&0xff; s[3][c]^=w&0xff;
            }
        }
        for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) blk[r+4*c] = s[r][c];
    }
};

struct GHash {
    uint8_t H[16];
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
        for (int i = 0; i < 128; i++) {
            if ((x[i/8] >> (7-(i%8))) & 1)
                for (int j = 0; j < 16; j++) r[j] ^= v[j];
            uint8_t lsb = v[15] & 1;
            for (int j = 15; j > 0; j--) v[j] = (uint8_t)((v[j]>>1)|(v[j-1]<<7));
            v[0] >>= 1;
            if (lsb) v[0] ^= 0xe1;
        }
        memcpy(z, r, 16);
    }

    void update(const uint8_t* data, size_t len) {
        size_t blocks = len / 16;
        for (size_t i = 0; i < blocks; i++) {
            uint8_t tmp[16];
            for (int j = 0; j < 16; j++) tmp[j] = state[j] ^ data[i*16+j];
            mulGF(tmp, H, state);
        }
        size_t rem = len % 16;
        if (rem > 0) {
            uint8_t tmp[16] = {};
            memcpy(tmp, data + blocks*16, rem);
            for (int j = 0; j < 16; j++) tmp[j] ^= state[j];
            mulGF(tmp, H, state);
        }
    }
};

static void ctrKeystream(const AES256& aes, const uint8_t* iv,
                       size_t blockOffset, uint8_t* out, size_t numBlocks) {
    for (size_t i = 0; i < numBlocks; i++) {
        uint8_t ctr[16];
        memcpy(ctr, iv, 12);
        uint32_t cnt = (uint32_t)(blockOffset + i + 1);
        ctr[12] = (uint8_t)(cnt >> 24);
        ctr[13] = (uint8_t)(cnt >> 16);
        ctr[14] = (uint8_t)(cnt >>  8);
        ctr[15] = (uint8_t)(cnt);
        memcpy(out + i*16, ctr, 16);
        aes.encryptBlock(out + i*16);
    }
}
} // namespace aes_impl

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

    aes_impl::GHash gh;
    gh.init(aes);
    gh.update(cipher, cipherLen);
    uint8_t lenBlock[16] = {};
    uint64_t cBits = (uint64_t)cipherLen * 8;
    for (int i = 0; i < 8; i++) lenBlock[8+i] = (uint8_t)(cBits >> (56 - i*8));
    gh.update(lenBlock, 16);

    uint8_t e0[16];
    memcpy(e0, iv, 12);
    e0[12]=e0[13]=e0[14]=e0[15]=0;
    aes.encryptBlock(e0);
    uint8_t computedTag[GCM_TAG_SIZE];
    for (int i = 0; i < 16; i++) computedTag[i] = gh.state[i] ^ e0[i];

    volatile int diff = 0;
    for (size_t i = 0; i < GCM_TAG_SIZE; i++)
        diff |= computedTag[i] ^ storedTag[i];
    if (diff != 0) return {};

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
#endif

// ==========================================
// SECTION 4: Disk-type-aware secure delete
// ==========================================
#ifndef _WIN32
enum class StorageKind { SSD_NVME, HDD, RAM, NETWORK, UNKNOWN };
enum class FsClass { COW, JOURNALED, FLAT, PSEUDO, NETWORK, UNKNOWN };

static StorageKind detectStorage(const fs::path& filePath) {
    struct stat st{};
    if (lstat(filePath.c_str(), &st) != 0) return StorageKind::UNKNOWN;
    unsigned int fileMaj = (unsigned int)major(st.st_dev);
    if (fileMaj == 0) return StorageKind::RAM;

    std::error_code ec;
    for (const auto& blkEntry : fs::directory_iterator("/sys/block", ec)) {
        if (ec) { ec.clear(); continue; }
        std::string devName = blkEntry.path().filename().string();
        std::string devPath = "/dev/" + devName;
        struct stat devSt{};
        if (stat(devPath.c_str(), &devSt) != 0) continue;
        if ((unsigned int)major(devSt.st_rdev) != fileMaj) continue;
        int rotVal = 1;
        std::ifstream rot(blkEntry.path() / "queue" / "rotational");
        if (rot) rot >> rotVal;
        return (rotVal == 0) ? StorageKind::SSD_NVME : StorageKind::HDD;
    }
    return StorageKind::UNKNOWN;
}

static FsClass detectFsClass(const fs::path& filePath) {
    struct stat st{};
    if (lstat(filePath.c_str(), &st) != 0) return FsClass::UNKNOWN;
    dev_t dev = st.st_dev;

    std::ifstream mounts("/proc/mounts");
    std::string line, bestFsType;
    size_t bestLen = 0;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string device, mountpoint, fstype;
        iss >> device >> mountpoint >> fstype;
        struct stat ms{};
        if (lstat(mountpoint.c_str(), &ms) == 0 && ms.st_dev == dev) {
            if (mountpoint.size() > bestLen) {
                bestLen   = mountpoint.size();
                bestFsType = fstype;
            }
        }
    }
    if (bestFsType.empty()) return FsClass::UNKNOWN;

    if (bestFsType=="btrfs"||bestFsType=="zfs"||bestFsType=="bcachefs"||bestFsType=="apfs")
        return FsClass::COW;
    if (bestFsType=="ext4"||bestFsType=="ext3"||bestFsType=="xfs"||bestFsType=="jfs"||
        bestFsType=="ntfs"||bestFsType=="ntfs-3g"||bestFsType=="f2fs"||bestFsType=="nilfs2")
        return FsClass::JOURNALED;
    if (bestFsType=="exfat"||bestFsType=="vfat"||bestFsType=="fat"||
        bestFsType=="msdos"||bestFsType=="hfs"||bestFsType=="hfsplus")
        return FsClass::FLAT;
    if (bestFsType=="tmpfs"||bestFsType=="ramfs"||bestFsType=="sysfs"||
        bestFsType=="proc"||bestFsType=="devtmpfs"||bestFsType=="hugetlbfs")
        return FsClass::PSEUDO;
    if (bestFsType=="nfs"||bestFsType=="nfs4"||bestFsType=="cifs"||bestFsType=="smbfs"||
        bestFsType=="fuse"||bestFsType.rfind("fuse.",0)==0||
        bestFsType=="davfs"||bestFsType=="sshfs")
        return FsClass::NETWORK;

    return FsClass::UNKNOWN;
}

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
    ioctl(mountFd, FITRIM, &range);
    close(mountFd);
}

static void zeroFillFile(const fs::path& filePath, uintmax_t fileSize) {
    int fd = open(filePath.c_str(), O_WRONLY);
    if (fd < 0) return;
    const size_t BLOCK = 4096;
    std::vector<char> zeros(BLOCK, 0);
    uintmax_t written = 0;
    while (written < fileSize) {
        size_t toWrite = (size_t)std::min((uintmax_t)BLOCK, fileSize - written);
        ssize_t r = write(fd, zeros.data(), toWrite);
        if (r <= 0) break;
        written += (uintmax_t)r;
    }
    fsync(fd);
    close(fd);
}

static void threePassOverwrite(const fs::path& filePath, uintmax_t fileSize) {
    const unsigned char patterns[3] = {0x00, 0xFF, 0xA5};
    for (int pass = 0; pass < 3; ++pass) {
        int fd = open(filePath.c_str(), O_WRONLY);
        if (fd < 0) break;
        const size_t BLOCK = 4096;
        std::vector<char> buf(BLOCK, (char)patterns[pass]);
        uintmax_t written = 0;
        while (written < fileSize) {
            size_t toWrite = (size_t)std::min((uintmax_t)BLOCK, fileSize - written);
            ssize_t r = write(fd, buf.data(), toWrite);
            if (r <= 0) break;
            written += (uintmax_t)r;
        }
        fsync(fd);
        close(fd);
    }
}
#endif

bool secureDelete(const fs::path& filePath) {
    std::error_code ec;
    uintmax_t fileSize = fs::file_size(filePath, ec);
    bool deleted = false;

#ifndef _WIN32
    StorageKind storage = detectStorage(filePath);
    FsClass     fsClass = detectFsClass(filePath);
    bool needFitrim = false;

    if (fileSize > 0 && !ec) {
        if (storage == StorageKind::RAM || fsClass == FsClass::PSEUDO) {
        } else if (fsClass == FsClass::NETWORK) {
        } else if (storage == StorageKind::SSD_NVME) {
            if (fsClass == FsClass::COW) {
                needFitrim = true;
            } else {
                zeroFillFile(filePath, fileSize);
                needFitrim = true;
            }
        } else {
            threePassOverwrite(filePath, fileSize);
        }
    }

    fs::remove(filePath, ec);
    deleted = !ec;
    if (needFitrim && deleted) issueFitrim(filePath);

#else
    bool isCoWFs    = false;
    bool isFlatFs   = false;
    bool isSSDDrive = false;
    bool trimIssued = false;

    std::wstring wpath(filePath.wstring());
    wchar_t volPath[MAX_PATH];
    if (GetVolumePathNameW(wpath.c_str(), volPath, MAX_PATH)) {
        wchar_t fsName[MAX_PATH] = {};
        GetVolumeInformationW(volPath, NULL, 0, NULL, NULL, NULL, fsName, MAX_PATH);
        std::wstring fsNameStr(fsName);
        if (fsNameStr == L"ReFS") isCoWFs = true;
        if (fsNameStr==L"FAT32"||fsNameStr==L"FAT"||fsNameStr==L"exFAT") isFlatFs = true;

        std::wstring volName = std::wstring(L"\\\\.\\") + std::wstring(volPath, wcslen(volPath)-1);
        HANDLE hVol = CreateFileW(volName.c_str(),
            GENERIC_READ|GENERIC_WRITE,
            FILE_SHARE_READ|FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);

        if (hVol != INVALID_HANDLE_VALUE) {
            STORAGE_PROPERTY_QUERY spq{};
            spq.PropertyId = (STORAGE_PROPERTY_ID)7;
            spq.QueryType  = PropertyStandardQuery;
            DEVICE_SEEK_PENALTY_DESCRIPTOR dspd{};
            DWORD bytesRet = 0;
            if (DeviceIoControl(hVol, IOCTL_STORAGE_QUERY_PROPERTY,
                    &spq, sizeof(spq), &dspd, sizeof(dspd), &bytesRet, NULL))
                isSSDDrive = !dspd.IncursSeekPenalty;

            if (fileSize > 0 && !ec) {
                if (!isCoWFs) {
                    if (isSSDDrive && !isFlatFs) {
                        HANDLE hFile = CreateFileW(wpath.c_str(),
                            GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                            FILE_FLAG_WRITE_THROUGH|FILE_FLAG_NO_BUFFERING, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            std::vector<char> zeros(4096, 0);
                            DWORD wr2 = 0; ULONGLONG pos = 0;
                            while (pos < fileSize) {
                                DWORD toWrite = (DWORD)std::min((ULONGLONG)zeros.size(), fileSize-pos);
                                WriteFile(hFile, zeros.data(), toWrite, &wr2, NULL);
                                pos += wr2; if (wr2 == 0) break;
                            }
                            FlushFileBuffers(hFile);
                            CloseHandle(hFile);
                        }
                    } else {
                        const unsigned char patterns[3] = {0x00,0xFF,0xA5};
                        for (int pass = 0; pass < 3; ++pass) {
                            std::ofstream ofile(filePath, std::ios::binary|std::ios::in|std::ios::out);
                            if (!ofile.is_open()) break;
                            const size_t BLOCK = 4096;
                            std::vector<char> buf(BLOCK,(char)patterns[pass]);
                            uintmax_t written = 0;
                            while (written < fileSize) {
                                uintmax_t toWrite = std::min((uintmax_t)buf.size(), fileSize-written);
                                ofile.write(buf.data(),(std::streamsize)toWrite);
                                written += toWrite;
                            }
                            ofile.flush(); ofile.close();
                        }
                    }
                }
                if ((isSSDDrive||isCoWFs) && !isFlatFs) {
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

    if (!trimIssued && isFlatFs && !ec && fileSize > 0) {
        const unsigned char patterns[3] = {0x00,0xFF,0xA5};
        for (int pass = 0; pass < 3; ++pass) {
            std::ofstream ofile(filePath, std::ios::binary|std::ios::in|std::ios::out);
            if (!ofile.is_open()) break;
            const size_t BLOCK = 4096;
            std::vector<char> buf(BLOCK,(char)patterns[pass]);
            uintmax_t written = 0;
            while (written < fileSize) {
                uintmax_t toWrite = std::min((uintmax_t)buf.size(), fileSize-written);
                ofile.write(buf.data(),(std::streamsize)toWrite);
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
        for (auto& f : futures) f.get();
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
// SECTION 6: Single file recovery
// ==========================================
void recoverSingleFile(const fs::path& lockedPath,
                       const std::array<uint8_t, AES_KEY_SIZE>& key) {
    std::ifstream inFile(lockedPath, std::ios::binary);
    if (!inFile) {
        std::lock_guard<std::mutex> lock(g_consoleMtx);
        std::cerr << "[SKIP] Cannot open   : " << lockedPath.filename() << "\n";
        return;
    }
    std::vector<uint8_t> blob(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    std::vector<uint8_t> plaintext = aesGcmDecrypt(key, blob);
    if (plaintext.empty()) {
        std::lock_guard<std::mutex> lock(g_consoleMtx);
        std::cerr << "[FAIL] Auth/decrypt  : " << lockedPath.filename()
                  << " (wrong key or corrupt)\n";
        return;
    }

    fs::path restoredPath = lockedPath;
    restoredPath.replace_extension("");

    std::ofstream outFile(restoredPath, std::ios::binary);
    if (!outFile) {
        std::lock_guard<std::mutex> lock(g_consoleMtx);
        std::cerr << "[SKIP] Cannot write  : " << restoredPath.filename() << "\n";
        return;
    }
    outFile.write(reinterpret_cast<const char*>(plaintext.data()),
                  (std::streamsize)plaintext.size());
    if (!outFile) {
        outFile.close();
        std::error_code ec;
        fs::remove(restoredPath, ec);
        std::lock_guard<std::mutex> lock(g_consoleMtx);
        std::cerr << "[FAIL] I/O error     : " << restoredPath.filename() << "\n";
        return;
    }
    outFile.flush();
    outFile.close();

    secureDelete(lockedPath);

    std::lock_guard<std::mutex> lock(g_consoleMtx);
    std::cout << "[OK]   " << restoredPath.filename() << "\n";
}

// ==========================================
// SECTION 7: Parallel recovery
// ==========================================
void recoverAll(const fs::path& targetPath,
                const std::array<uint8_t, AES_KEY_SIZE>& key) {
    std::error_code ec;
    if (!fs::exists(targetPath, ec)) {
        std::cerr << "[ERROR] Target path not found: " << targetPath << "\n";
        return;
    }

    std::vector<fs::path> targets;
    auto options = fs::directory_options::skip_permission_denied;
    auto it  = fs::recursive_directory_iterator(targetPath, options, ec);
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

    if (targets.empty()) {
        std::cout << "No .locked files found in: " << targetPath << "\n";
        return;
    }

    std::cout << "Found " << targets.size() << " locked file(s). Recovering...\n\n";

    size_t numThreads = std::min<size_t>(
        std::max<size_t>(1, std::thread::hardware_concurrency()), 8);
    ThreadPool pool(numThreads);

    std::vector<std::future<void>> futures;
    futures.reserve(targets.size());
    for (const auto& p : targets) {
        futures.push_back(pool.enqueue([p, &key]() {
            recoverSingleFile(p, key);
        }));
    }
    pool.waitAll(futures);
}

// ==========================================
// SECTION 8: main()
// ==========================================
int main() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        GetConsoleMode(hOut, &mode);
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif

    auto key = deriveKeyFromHash(ADMIN_PASSWORD_HASH);

    std::cout << "--- Recovery Tool v2.0 (AES-256-GCM) ---\n";
    std::cout << "Target : " << TARGET_PATH << "\n";
    std::cout << "Key    : " << std::string(AES_KEY_SIZE * 2, '*') << "\n\n";

    recoverAll(TARGET_PATH, key);

    std::cout << "\n[INFO] Recovery process finished.\n";
#ifdef _WIN32
    std::cout << "Press Enter to exit...";
    std::cin.get();
#endif
    return 0;
}
