# Changelog

All notable changes, architectural improvements, and security enhancements for the Timed File Lock & Wipe System project are documented below.

---

## [v3.0] - 2026-10
### Added & Merged
* **Filesystem & Storage-Aware Secure Delete Matrix:** Refined the `secureDelete` mechanism to automatically adapt its overwrite and wipe strategies based on storage medium and file system structure:
  * **Linux:** Differentiates between NVMe/SSD, HDD, RAM (`tmpfs`), and network storage (`NFS`/`CIFS`). Uses `FITRIM` for CoW filesystems (`btrfs`, `ZFS`), single-pass zero-fill + `FITRIM` for SSDs, and 3-pass DoD standard overwrites (0x00 / 0xFF / 0xA5) for traditional HDDs.
  * **Windows:** Inspects drive type via `DeviceIoControl` seek penalty queries and volume file system type (`ReFS`, `NTFS`, `exFAT`/`FAT32`). Applies TRIM IOCTLs for SSD/ReFS and 3-pass overwrites for HDDs and legacy FAT structures.
* **Unified Cross-Platform Home Resolver:** Integrated a robust `resolveHome()` function handling both Windows (`USERPROFILE`) and Linux (`HOME`) environment variables.

---

## [v2.1] - 2026-09
### Changed & Fixed
* **XDG Compliance:** Standardized configuration storage and lock file paths across Linux environments (`~/.config/timedfilelock`, `/tmp/timedfilelock.pid`).
* **Path Resolution Fixes:** Fixed cross-platform directory resolution issues across GCC and MinGW compilation environments.

---

## [v2.0] - 2026-08
### Security Enhancements
* **AES-256-GCM Migration:** Replaced simple XOR encryption with authenticated, per-file random IV/nonce-based **AES-256-GCM**:
  * *Windows:* Utilizes native `BCrypt` API with hardware AES-NI acceleration.
  * *Linux:* Implemented a zero-dependency C++ AES-256-GCM engine.
* **Storage Type Detection:** Enriched disk wiping logic by querying `/sys/block/<dev>/queue/rotational` (Linux) and storage seek penalties (Windows) to distinguish SSDs from HDDs.
* **Shell Injection Prevention:** Replaced `system()` calls in terminal relaunch routines with `execvp()` using structured argument arrays.

### Performance & Architecture
* **Thread Pool Integration:** Transitioned file processing operations from serial execution to a concurrent thread pool bound by hardware concurrency limits (`min(hw_concurrency, 8)`).
* **Codebase Cleanup:** Pruned unused headers (`winternl.h`), redundant library dependencies (`ntdll.lib`), obsolete hash reset logic, and duplicated console event handlers.

---

## [v1.0] - 2026-04
### Initial Prototype
* **Basic Functionality:** Initial implementation of the timed locking mechanism, countdown loop, and password verification framework.
* **Legacy Cryptography & Wipe:** Multi-pass file overwriting and XOR stream transformation.
* **Platform Support:** Basic POSIX and Windows process initialization routines.
