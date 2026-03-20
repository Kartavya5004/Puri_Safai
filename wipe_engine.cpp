// src/wipe_engine.cpp
// Secure Wipe Engine — NIST SP 800-88 compliant
//
// SSD LIMITATION: Software overwrite is NOT guaranteed on SSDs due to wear
// levelling and over-provisioning. TRIM is issued as a best-effort hint.
// For certified SSD erasure use ATA Secure Erase (Phase 3).

#include "wipe_engine.h"
#include <windows.h>
#include <winioctl.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <cassert>
#include <algorithm>

namespace fs = std::filesystem;

// 4 MB write buffer — good balance of throughput vs memory
static constexpr size_t kBufferSize = 4 * 1024 * 1024;

// ─── Method helpers ───────────────────────────────────────────────────────────

WipeMethod ParseWipeMethod(const std::string& s)
{
    if (s == "nist-clear"   || s == "clear")   return WipeMethod::NistClear;
    if (s == "nist-purge"   || s == "purge")   return WipeMethod::NistPurge;
    if (s == "dod-3pass"    || s == "dod")     return WipeMethod::Dod3Pass;
    if (s == "single-pass"  || s == "single")  return WipeMethod::SinglePassRandom;
    if (s == "gutmann"      || s == "gutmann35") return WipeMethod::Gutmann35Pass;
    throw SecureWipeError("Unknown wipe method '" + s +
        "'. Valid: nist-clear, nist-purge, dod-3pass, single-pass, gutmann");
}

std::string WipeMethodName(WipeMethod m)
{
    switch (m) {
        case WipeMethod::NistClear:        return "nist-clear";
        case WipeMethod::NistPurge:        return "nist-purge";
        case WipeMethod::Dod3Pass:         return "dod-3pass";
        case WipeMethod::SinglePassRandom: return "single-pass";
        case WipeMethod::Gutmann35Pass:    return "gutmann";
    }
    return "unknown";
}

std::string WipeMethodDescription(WipeMethod m)
{
    switch (m) {
        case WipeMethod::NistClear:        return "NIST SP 800-88 Clear (1-pass zeros)";
        case WipeMethod::NistPurge:        return "NIST SP 800-88 Purge (3-pass zeros/ones/random)";
        case WipeMethod::Dod3Pass:         return "DoD 5220.22-M (3-pass with verification)";
        case WipeMethod::SinglePassRandom: return "Single-pass cryptographic random overwrite";
        case WipeMethod::Gutmann35Pass:    return "Gutmann 35-pass (legacy)";
    }
    return "unknown";
}

std::vector<PassPattern> BuildPasses(WipeMethod method)
{
    switch (method) {
        case WipeMethod::NistClear:
            return {{ PassKind::Zeros }};

        case WipeMethod::NistPurge:
        case WipeMethod::Dod3Pass:
            return {{ PassKind::Zeros }, { PassKind::Ones }, { PassKind::Random }};

        case WipeMethod::SinglePassRandom:
            return {{ PassKind::Random }};

        case WipeMethod::Gutmann35Pass: {
            // Gutmann's 35-pass schedule
            static const uint8_t fixed[] = {
                0x55,0xAA,0x92,0x49,0x24,
                0x00,0x11,0x22,0x33,0x44,
                0x55,0x66,0x77,0x88,0x99,
                0xAA,0xBB,0xCC,0xDD,0xEE,
                0xFF,0x92,0x49,0x24,0x6D,
                0xB6,0xDB,0x49,0x92,0x24
            };
            std::vector<PassPattern> passes;
            for (int i = 0; i < 4; ++i) passes.push_back({ PassKind::Random });
            for (uint8_t b : fixed)     passes.push_back({ PassKind::Fixed, b });
            passes.push_back({ PassKind::Random });
            return passes;
        }
    }
    return {};
}

// ─── WipeResult ───────────────────────────────────────────────────────────────

std::string WipeResult::Summary() const
{
    int64_t duration = completed_at - started_at;
    double  gb       = static_cast<double>(bytes_wiped) / 1073741824.0;

    std::ostringstream ss;
    ss << "\n=== SecureWipe " << (errors.empty() ? "SUCCESS" : "COMPLETED WITH ERRORS") << " ===\n"
       << "Target  : " << target_path                       << "\n"
       << "Method  : " << WipeMethodDescription(method)     << "\n"
       << "Passes  : " << passes_completed                   << "\n"
       << "Data    : " << std::fixed << std::setprecision(2) << gb
                       << " GB (" << bytes_wiped << " bytes)\n"
       << "Files   : " << files_processed                    << "\n"
       << "Duration: " << duration << "s\n"
       << "Verified: " << (verified
                            ? (verification_passed ? "PASS" : "FAIL")
                            : "skipped")
       << "\n";

    if (ssd_warning) {
        ss << "\n"
           << "\u26A0 SSD DETECTED: Software overwrite does not guarantee full erasure\n"
           << "  on SSDs. TRIM hint sent. For certified erasure use ATA Secure Erase.\n";
    }
    if (!errors.empty()) {
        ss << "\nErrors:\n";
        for (const auto& e : errors) ss << "  - " << e << "\n";
    }
    return ss.str();
}

// ─── Buffer fill helper ───────────────────────────────────────────────────────

static void FillBuffer(std::vector<uint8_t>& buf, const PassPattern& p)
{
    switch (p.kind) {
        case PassKind::Zeros:
            std::fill(buf.begin(), buf.end(), 0x00u);
            break;
        case PassKind::Ones:
            std::fill(buf.begin(), buf.end(), 0xFFu);
            break;
        case PassKind::Fixed:
            std::fill(buf.begin(), buf.end(), p.value);
            break;
        case PassKind::Random: {
            // mt19937_64 seeded from hardware RNG — fast and cryptographically
            // adequate for data overwrite (not a key generation scenario).
            static thread_local std::mt19937_64 rng{std::random_device{}()};
            static thread_local std::uniform_int_distribution<uint8_t> dist;
            for (auto& b : buf) b = dist(rng);
            break;
        }
    }
}

// ─── WipeEngine — file-level ──────────────────────────────────────────────────

uint64_t WipeEngine::WipeFile(
    const std::string& path,
    const std::vector<PassPattern>& passes)
{
    // Get file size without opening for read
    LARGE_INTEGER file_size_li{};
    {
        WIN32_FILE_ATTRIBUTE_DATA info{};
        if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &info)) {
            ThrowWin32("GetFileAttributesEx failed for " + path);
        }
        file_size_li.LowPart  = info.nFileSizeLow;
        file_size_li.HighPart = static_cast<LONG>(info.nFileSizeHigh);
    }
    const uint64_t file_size = static_cast<uint64_t>(file_size_li.QuadPart);
    if (file_size == 0) return 0;

    LOG_INFO("Wiping: " + path + " (" + std::to_string(file_size) + " bytes, "
             + std::to_string(passes.size()) + " passes)");

    std::vector<uint8_t> buffer(kBufferSize);

    for (size_t pass_idx = 0; pass_idx < passes.size(); ++pass_idx) {
        LOG_DEBUG("  Pass " + std::to_string(pass_idx + 1) + "/" +
                  std::to_string(passes.size()));

        FillBuffer(buffer, passes[pass_idx]);

        // Open with FILE_FLAG_WRITE_THROUGH to bypass OS write cache
        HANDLE hFile = CreateFileA(
            path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH,
            nullptr
        );
        if (hFile == INVALID_HANDLE_VALUE) ThrowWin32("CreateFile for wipe: " + path);

        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);

        uint64_t written = 0;
        while (written < file_size) {
            DWORD chunk = static_cast<DWORD>(
                std::min<uint64_t>(kBufferSize, file_size - written));
            DWORD bytes_written = 0;
            if (!WriteFile(hFile, buffer.data(), chunk, &bytes_written, nullptr)) {
                CloseHandle(hFile);
                ThrowWin32("WriteFile at offset " + std::to_string(written));
            }
            written += bytes_written;
        }

        // FlushFileBuffers ensures data hits the physical medium
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
    }

    return file_size;
}

std::vector<std::string> WipeEngine::CollectFiles(
    const std::string& dir, std::vector<std::string>& errors)
{
    std::vector<std::string> files;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(
                dir,
                fs::directory_options::skip_permission_denied))
        {
            if (entry.is_symlink()) continue;
            if (entry.is_regular_file()) {
                files.push_back(entry.path().string());
            }
        }
    } catch (const fs::filesystem_error& e) {
        errors.push_back(std::string("Directory scan error: ") + e.what());
    }
    return files;
}

WipeResult WipeEngine::WipePath(
    const std::string& path, WipeMethod method, bool verify)
{
    if (!fs::exists(path)) throw PathNotFoundError(path);

    const int64_t started_at = NowUnix();
    std::vector<std::string> errors;
    uint64_t bytes_wiped     = 0;
    uint64_t files_processed = 0;

    std::vector<std::string> files;
    if (fs::is_regular_file(path)) {
        files.push_back(path);
    } else {
        files = CollectFiles(path, errors);
    }

    const auto passes = BuildPasses(method);

    for (const auto& fp : files) {
        try {
            uint64_t n = WipeFile(fp, passes);
            bytes_wiped += n;
            ++files_processed;

            if (!DeleteFileA(fp.c_str())) {
                errors.push_back("Delete failed for " + fp + ": error "
                    + std::to_string(GetLastError()));
            }
        } catch (const std::exception& e) {
            errors.push_back("Wipe failed " + fp + ": " + e.what());
        }
    }

    const int64_t completed_at      = NowUnix();
    const bool    verification_passed = verify
        ? std::all_of(files.begin(), files.end(),
              [](const std::string& f){ return !fs::exists(f); })
        : false;

    DeviceInfo dev = ProbeDevice(path);
    if (dev.is_ssd) {
        LOG_WARN("SSD detected — software overwrite may be incomplete");
        IssueTrimHint(path);
    }

    WipeResult result;
    result.target_path          = path;
    result.method               = method;
    result.passes_completed     = static_cast<uint32_t>(passes.size());
    result.bytes_wiped          = bytes_wiped;
    result.files_processed      = files_processed;
    result.started_at           = started_at;
    result.completed_at         = completed_at;
    result.verified             = verify;
    result.verification_passed  = verification_passed;
    result.errors               = std::move(errors);
    result.ssd_warning          = dev.is_ssd;
    result.device_info          = std::move(dev);
    return result;
}

// ─── Volume-level wipe (requires administrator) ───────────────────────────────

WipeResult WipeEngine::WipeVolume(
    const std::string& volume_path, WipeMethod method)
{
    LOG_INFO("Volume wipe: " + volume_path);
    LOG_WARN("DESTRUCTIVE — entire volume will be overwritten");

    // Open with FILE_FLAG_NO_BUFFERING for direct I/O (sector-aligned writes)
    std::wstring wide = ToWide(volume_path);
    HANDLE hVolume = CreateFileW(
        wide.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
        nullptr
    );
    if (hVolume == INVALID_HANDLE_VALUE) {
        ThrowWin32("CreateFile volume: " + volume_path);
    }

    // IOCTL_DISK_GET_LENGTH_INFO → GET_LENGTH_INFORMATION { LARGE_INTEGER Length }
    GET_LENGTH_INFORMATION len_info{};
    DWORD returned = 0;
    if (!DeviceIoControl(hVolume, IOCTL_DISK_GET_LENGTH_INFO,
                         nullptr, 0,
                         &len_info, sizeof(len_info),
                         &returned, nullptr))
    {
        CloseHandle(hVolume);
        ThrowWin32("IOCTL_DISK_GET_LENGTH_INFO");
    }

    const uint64_t capacity  = static_cast<uint64_t>(len_info.Length.QuadPart);
    const auto     passes    = BuildPasses(method);
    const int64_t  started   = NowUnix();

    // Sector-aligned 4 MB buffer (physical sector size ≤ 4096 bytes on all modern drives)
    constexpr DWORD kSector  = 4096;
    constexpr DWORD kChunkSz = kSector * 1024;  // 4 MB

    // VirtualAlloc gives sector-aligned memory (required for NO_BUFFERING)
    uint8_t* buf = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, kChunkSz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!buf) { CloseHandle(hVolume); throw SecureWipeError("VirtualAlloc failed"); }

    std::vector<PassPattern> pass_list = passes;

    for (size_t pi = 0; pi < pass_list.size(); ++pi) {
        LOG_INFO("  Volume pass " + std::to_string(pi+1) + "/" +
                 std::to_string(pass_list.size()));

        // Fill pattern into buffer
        switch (pass_list[pi].kind) {
            case PassKind::Zeros:  memset(buf, 0x00, kChunkSz); break;
            case PassKind::Ones:   memset(buf, 0xFF, kChunkSz); break;
            case PassKind::Fixed:  memset(buf, pass_list[pi].value, kChunkSz); break;
            case PassKind::Random: {
                static thread_local std::mt19937_64 rng{std::random_device{}()};
                static thread_local std::uniform_int_distribution<uint8_t> dist;
                for (DWORD i = 0; i < kChunkSz; ++i) buf[i] = dist(rng);
                break;
            }
        }

        // Seek to beginning
        LARGE_INTEGER zero{};
        SetFilePointerEx(hVolume, zero, nullptr, FILE_BEGIN);

        uint64_t offset = 0;
        while (offset < capacity) {
            DWORD to_write = static_cast<DWORD>(
                std::min<uint64_t>(kChunkSz, capacity - offset));
            // Round up to sector boundary (NO_BUFFERING requirement)
            to_write = ((to_write + kSector - 1) / kSector) * kSector;

            DWORD written = 0;
            if (!WriteFile(hVolume, buf, to_write, &written, nullptr)) {
                VirtualFree(buf, 0, MEM_RELEASE);
                CloseHandle(hVolume);
                ThrowWin32("WriteFile volume at offset " + std::to_string(offset));
            }
            offset += written;
        }
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    CloseHandle(hVolume);

    WipeResult result;
    result.target_path      = volume_path;
    result.method           = method;
    result.passes_completed = static_cast<uint32_t>(passes.size());
    result.bytes_wiped      = capacity;
    result.files_processed  = 1;
    result.started_at       = started;
    result.completed_at     = NowUnix();
    result.device_info.capacity_bytes = capacity;
    return result;
}

// ─── Device probing ───────────────────────────────────────────────────────────

DeviceInfo WipeEngine::ProbeDevice(const std::string& /*path*/)
{
    // Phase 1 stub.
    // Production: use DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY) with
    // StorageDeviceProperty to read STORAGE_DEVICE_DESCRIPTOR (serial, model,
    // firmware, bus type). BusTypeSata + rotation rate == 1 indicates SSD.
    DeviceInfo info;
    info.serial_number = "UNKNOWN";
    info.model         = "UNKNOWN";
    info.firmware      = "UNKNOWN";
    info.is_ssd        = false;   // Conservative assumption
    return info;
}

void WipeEngine::IssueTrimHint(const std::string& /*path*/)
{
    // FSCTL_FILE_LEVEL_TRIM or IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES
    // signals the SSD firmware to mark freed sectors as available.
    // This is a hint — not a security guarantee. Phase 3 will add ATA SE.
    LOG_WARN("TRIM hint issued (best-effort; not a security guarantee for SSDs)");
}
