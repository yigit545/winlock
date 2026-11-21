# Winlock

[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0.0-blue.svg)](https://polyformproject.org/licenses/noncommercial/1.0.0)
![C++](https://img.shields.io/badge/C%2B%2B-17%2B-00599C?logo=c%2B%2B&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)

# Ransomware Davranış Analizi ve Tespit Araştırması

A cross-platform C++ security research project studying ransomware-class behavior through controlled implementation and behavioral analysis. The project implements **AES-256-GCM** authenticated encryption, filesystem-aware secure deletion, and parallel file processing — and uses these as a controlled baseline for behavioral signature extraction, sandbox comparison, and YARA/Sigma detection rule development.

> **Branch structure:** `main` contains detection research artifacts and the recovery module. The controlled implementation used as a research subject is isolated in the `experimental` branch.

---

## 🎯 Research Motivation

Recent ransomware incidents targeting academic and institutional infrastructure have exposed a critical gap in applied cybersecurity research: the absence of **transparent, auditable, and behaviorally documented** implementations that can serve as a controlled baseline for detection research.

This project addresses that gap by:

- Providing a fully auditable AES-256-GCM implementation as a **controlled research subject**
- Extracting behavioral signatures (file velocity, entropy delta, syscall profile, secure deletion pattern) from the controlled implementation in isolated environments
- Comparing extracted signatures against known ransomware families (WannaCry, NotPetya, Petya) using public sandbox reports (Any.run, Hybrid Analysis, CISA advisories)
- Developing **YARA and Sigma detection rules** that capture behaviors invisible to signature-based AV engines — validated against the controlled implementation and public malware samples

The long-term goal is to contribute a reproducible detection methodology applicable to ransomware-class threats targeting institutional infrastructure, with a TÜBİTAK 2204-A research submission as a target milestone.

---

## ⚠️ Disclaimer

> **Research & Educational Use Only:** This repository contains software that encrypts local files and performs low-level storage operations. It is intended solely for cybersecurity research, security education, and authorized system administration demonstration purposes in isolated environments. Only run this software on systems and files for which you have explicit authorization. Always maintain backups before testing. The `experimental` branch is restricted to authorized researchers.

---

## 📌 Repository Structure (main branch)

```text
.
├── recovery.cpp            # AES-256-GCM authenticated decryption tool
├── recovery_setup.ps1      # Self-contained build and run script for recovery
├── CHANGELOG.md
├── LICENSE
└── README.md
```

> The controlled implementation (`winlock.cpp`, setup scripts, session tools) is maintained in the `experimental` branch for authorized research access.

---

## 🔬 Detection Research Methodology

### 1. Behavioral Signature Extraction

The controlled implementation is executed in an isolated VM environment (network-disabled, snapshot-based) while behavioral telemetry is collected:

**Linux:** `inotifywait` (file access patterns), `strace` (syscall profile), `auditd`

**Windows:** Sysmon (Event IDs 1, 11, 23, 3), ProcMon, ETW

Key metrics extracted per execution:

| Metric | Description |
| :--- | :--- |
| File velocity | Peak and mean file operations per second |
| Entropy delta | Pre/post encryption Shannon entropy (target: 7.9–8.0 bit/byte) |
| Target extension profile | Extensions accessed during encryption pass |
| Syscall signature | `fallocate`, `BLKDISCARD`, `BLKSECDISCARD`, `fsync` patterns |
| Shadow copy / MFT behavior | VSS deletion, MFT encryption attempts |

### 2. Comparative Analysis

Extracted signatures are compared against public behavioral reports for known ransomware families:

| Sample | Source |
| :--- | :--- |
| WannaCry | Any.run sandbox report, CISA advisory |
| NotPetya | Hybrid Analysis behavioral report, US-CERT advisory |
| Petya | Any.run interactive sandbox |

Comparison dimensions: file velocity, encryption entropy, target extension count, shadow copy deletion, lateral movement vector, C2 connectivity, MFT encryption.

### 3. Detection Rule Development

Behavioral signatures inform YARA rules (static + behavioral indicators) and Sigma rules (SIEM-compatible log-based detection), targeting behaviors that evade signature-based AV engines — validated on the controlled implementation and cross-checked against public malware hashes.

---

## 🔐 Recovery Module

The `recovery` tool is an independent AES-256-GCM decryption utility compatible with the controlled implementation. It operates without registry keys, timers, or the lock process.

### Features

- **Authenticated Decryption:** GCM tag verified before any plaintext is written — authentication failures reported per-file without affecting others
- **Parallel Processing:** Thread pool scaled to `min(hardware_concurrency, 8)`
- **Filesystem-Aware Secure Deletion:** After successful decryption, the `.locked` source is securely wiped per the deletion matrix below
- **Partial Failure Handling:** Incomplete output files are removed on I/O error

### Building

**Windows — MinGW:**
```bash
g++ recovery.cpp -o recovery.exe -std=c++17 -pthread -lbcrypt
```

**Windows — MSVC:**
```cmd
cl recovery.cpp /std:c++17 /EHsc /Fe:recovery.exe /link bcrypt.lib
```

**Linux:**
```bash
g++ recovery.cpp -o recovery -std=c++17 -pthread
```

### Usage

**Windows:** Double-click `recovery_run.bat`. The script builds and launches `recovery.exe`, which:
- Scans `TARGET_PATH` recursively for `.locked` files
- Verifies the GCM authentication tag before writing any plaintext
- Decrypts each file in parallel and reports per-file status
- Securely wipes the `.locked` source after successful restoration

**Linux (manual build):**
```bash
g++ recovery.cpp -o recovery -std=c++17 -pthread
./recovery
```

---

## 🔐 Secure Deletion Matrix

Overwrite strategy selected automatically based on detected storage type and filesystem class.

### Linux

| Storage | Filesystem | Strategy |
| :--- | :--- | :--- |
| NVMe / SSD | btrfs / ZFS (CoW) | FITRIM only |
| NVMe / SSD | ext4 / XFS / exFAT / FAT | 1-pass zero-fill + fsync → FITRIM |
| HDD | btrfs (CoW) | 3-pass DoD (0x00 / 0xFF / 0xA5) |
| HDD | ext4 / XFS / exFAT / FAT | 3-pass DoD (0x00 / 0xFF / 0xA5) |
| RAM (tmpfs / ramfs) | — | Unlink only |
| Network (NFS / CIFS) | — | Unlink only |

Storage type detected via `/sys/block/<dev>/queue/rotational`. Filesystem type detected via `/proc/mounts`.

### Windows

| Filesystem | Drive Type | Strategy |
| :--- | :--- | :--- |
| ReFS (CoW) | Any | TRIM IOCTL only |
| NTFS | SSD | 1-pass zero + TRIM IOCTL |
| NTFS | HDD | 3-pass DoD + TRIM IOCTL |
| exFAT / FAT32 | Any | 3-pass DoD |

Drive type detected via `IOCTL_STORAGE_QUERY_PROPERTY`. Filesystem detected via `GetVolumeInformation`.

---

## 🌐 Platform Support

| Subsystem | Windows | Linux |
| :--- | :--- | :--- |
| **Encryption** | BCrypt AES-256-GCM (AES-NI) | Pure C++ AES-256-GCM (zero deps) |
| **CSPRNG** | `BCryptGenRandom()` | `/dev/urandom` |
| **TRIM** | `IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES` | `FITRIM` via `ioctl()` |

---

## 🧪 Test Environments

| Environment | OS | Result |
| :--- | :--- | :--- |
| Isolated folder (host) | Windows 11 | ✅ Pass |
| Virtual Machine | Windows 10 (VMware) | ✅ Pass |
| Virtual Machine | Ubuntu/Debian Linux 23 | ✅ Pass |
| Physical test device | Windows 11 | ✅ Pass |

---

## Changelog

| Version | Changes |
| :--- | :--- |
| v3.0 | XOR → AES-256-GCM (per-file random IV, authenticated). BCrypt on Windows, pure C++ on Linux. Filesystem-aware secure deletion matrix. Thread pool for parallel processing. |
| v2.x | Watchdog subprocess, Registry persistence, session continuity, parallel file processing, interactive countdown. |

---

## License

Copyright © 2026 Yiğit Erim Özdamar

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

You may inspect, study, modify, and use this software for **personal, educational, research, testing, and other non-commercial purposes**, subject to the terms of the license.

**Commercial use is not permitted without explicit permission from the copyright holder.**

License: https://polyformproject.org/licenses/noncommercial/1.0.0
