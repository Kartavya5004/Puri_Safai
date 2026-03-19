# SecureWipe (C++ Edition)

Secure, verifiable data wiping system — C++20 port for Windows.

## Project layout

```
securewipe_cpp/
├── CMakeLists.txt          Build system (CMake 3.20+)
├── include/
│   ├── common.h            Shared types, logging, Win32 helpers
│   ├── db.h                SQLite metadata store interface
│   ├── wipe_engine.h       NIST SP 800-88 wipe engine interface
│   ├── scanner.h           Privacy-preserving metadata scanner
│   ├── usn_tracker.h       USN Journal file-change tracker
│   ├── idle_profiler.h     CPU + user idle state profiler
│   ├── optimizer.h         ROT analyzer + NTFS compression
│   ├── certificate.h       RSA-PSS signed wipe certificate
│   ├── dashboard.h         CO2 sustainability dashboard
│   └── detection.h         HPA/DCO hidden storage detector
└── src/
    ├── main.cpp            CLI entry point + command handlers
    ├── db.cpp              SQLite implementation (SQLiteCpp)
    ├── wipe_engine.cpp     Secure overwrite + volume wipe
    ├── scanner.cpp         GetFileAttributesEx metadata scan
    ├── usn_tracker.cpp     FSCTL_READ_USN_JOURNAL implementation
    ├── idle_profiler.cpp   GetSystemTimes + GetLastInputInfo
    ├── optimizer.cpp       ROT analysis + FSCTL_SET_COMPRESSION
    ├── certificate.cpp     OpenSSL RSA-PSS sign/verify
    ├── dashboard.cpp       CO2 model + console output
    └── detection.cpp       IOCTL_ATA_PASS_THROUGH HPA detection
```

## Dependencies

Fetched automatically by CMake FetchContent:
- **nlohmann/json 3.11.3** — JSON serialization
- **SQLiteCpp 3.3.1** — SQLite C++ wrapper

System-provided (install via vcpkg):
- **OpenSSL 3.x** — RSA-PSS certificate signing

```powershell
# Install vcpkg then:
vcpkg install openssl:x64-windows
```

## Build

```powershell
# Prerequisites: Visual Studio 2022, CMake 3.20+, vcpkg with OpenSSL

git clone https://github.com/yourorg/securewipe_cpp
cd securewipe_cpp

cmake -B build -DCMAKE_BUILD_TYPE=Release ^
      -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release

# Binary: build\Release\securewipe.exe
```

## Usage

```powershell
# Wipe a file or folder
securewipe wipe C:\OldProject --method nist-purge --cert-out cert.json

# Wipe entire drive (requires admin, DESTRUCTIVE)
securewipe wipe-volume \\.\PhysicalDrive1 --method nist-clear --cert-out vol_cert.json

# Scan filesystem metadata (privacy-preserving — no file content accessed)
securewipe scan C:\ --db mydata.db

# Analyze for ROT files (suggestions only, never auto-deletes)
securewipe analyze --db mydata.db --stale-days 180 --output rot.json

# Detect HPA/DCO hidden storage (read-only, never modifies drive)
securewipe detect-hidden \\.\PhysicalDrive0

# Verify a certificate offline
securewipe verify-cert cert.json

# View sustainability dashboard
securewipe dashboard cert.json

# Background USN Journal monitor
securewipe monitor C: --db activity.db
```

## Wipe methods

| Flag | Passes | Standard |
|------|--------|----------|
| `nist-clear`  | 1 (zeros)             | NIST SP 800-88 Clear |
| `nist-purge`  | 3 (zeros/ones/random) | NIST SP 800-88 Purge |
| `dod-3pass`   | 3 (zeros/ones/random) | DoD 5220.22-M |
| `single-pass` | 1 (random)            | — |
| `gutmann`     | 35                    | Gutmann 1996 (legacy) |

## Key implementation notes

### Wipe engine (`wipe_engine.cpp`)
- Uses `FILE_FLAG_WRITE_THROUGH` on file handles to bypass OS write cache
- Volume wipe uses `VirtualAlloc` for sector-aligned buffers (required by `FILE_FLAG_NO_BUFFERING`)
- `mt19937_64` seeded from `std::random_device` for the random pass

### USN tracker (`usn_tracker.cpp`)
- Manually parses `USN_RECORD_V2` binary layout from `DeviceIoControl` output
- Decodes UTF-16LE filenames inline using `WideCharToMultiByte`
- Advances `next_usn` cursor so each `PollRecords()` only returns new entries

### Certificate (`certificate.cpp`)
- OpenSSL EVP API with `RSA_PKCS1_PSS_PADDING` and `RSA_PSS_SALTLEN_DIGEST`
- SHA-256 hashes a deterministic JSON canonical form before signing
- `VerifySelf()` uses the embedded `public_key_pem` field for fully offline verification

### SSD limitation
Software overwrite on SSDs is NOT certified due to wear levelling. The engine:
1. Performs overwrite passes on all OS-accessible sectors
2. Logs `ssd_warning = true` in the certificate
3. Phase 3 will add ATA Secure Erase support

## Roadmap

- **Phase 2** — PDF certificates, org key management
- **Phase 3** — Bootable offline environment, ATA Secure Erase for SSDs
- **Phase 4** — Linux/Android, hardware-level sanitization
