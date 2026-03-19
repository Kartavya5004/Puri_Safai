// src/optimizer.cpp
#include "optimizer.h"
#include <windows.h>
#include <winioctl.h>
#include <filesystem>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

// ─── RotAnalyzer ─────────────────────────────────────────────────────────────

RotAnalyzer::RotAnalyzer(MetadataStore& store) : store_(store) {}

RotType RotAnalyzer::ClassifyRot(const FileRecord& r)
{
    if (r.size_bytes == 0) return RotType::Empty;

    // Lower-case extension and filename for pattern matching
    fs::path p(r.path);
    std::string ext  = p.extension().string();
    std::string name = p.filename().string();
    auto lower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        return s;
    };
    ext  = lower(ext);
    name = lower(name);

    // Temporary file patterns
    if (ext == ".tmp" || ext == ".temp" ||
        name.substr(0, 2) == "~$" ||
        name.rfind("_tmp") != std::string::npos)
    {
        return RotType::Temporary;
    }

    // Likely backup / duplicate
    if (ext == ".bak" || ext == ".old" || ext == ".orig" ||
        name.find(" - copy") != std::string::npos ||
        name.find(" copy")   != std::string::npos)
    {
        return RotType::LikelyDuplicate;
    }

    // Large log files (>100 MB)
    if ((ext == ".log" || ext == ".log1" || ext == ".log2") &&
        r.size_bytes > 100ULL * 1024 * 1024)
    {
        return RotType::LargeLog;
    }

    return RotType::Stale;
}

static RotCategory BuildCategory(
    const std::string& name,
    const std::string& desc,
    std::vector<RotFileSuggestion> files)
{
    std::sort(files.begin(), files.end(),
        [](const RotFileSuggestion& a, const RotFileSuggestion& b){
            return a.size_bytes > b.size_bytes;
        });
    uint64_t total = 0;
    for (const auto& f : files) total += f.size_bytes;
    return { name, desc, std::move(files), total };
}

RotReport RotAnalyzer::Analyze(uint64_t stale_days) const
{
    LOG_INFO("ROT analysis (stale threshold: " + std::to_string(stale_days) + " days)");

    auto stale = store_.StaleFiles(stale_days);

    std::vector<RotFileSuggestion> sv, ev, tv, dv, lv;

    for (const auto& rec : stale) {
        RotType rt = ClassifyRot(rec);
        std::string suggestion;
        switch (rt) {
            case RotType::Empty:           suggestion = "Review: zero-byte, safe to delete if not needed"; break;
            case RotType::Temporary:       suggestion = "Review: temp file pattern, likely safe to delete"; break;
            case RotType::LikelyDuplicate: suggestion = "Review: backup suffix, verify before deleting"; break;
            case RotType::LargeLog:        suggestion = "Review: large log file, consider archiving"; break;
            case RotType::Stale:           suggestion = "Review: not accessed recently, consider archiving"; break;
        }
        RotFileSuggestion s;
        s.path          = rec.path;
        s.size_bytes    = rec.size_bytes;
        s.last_accessed = rec.last_accessed;
        s.last_modified = rec.last_modified;
        s.rot_type      = rt;
        s.suggestion    = std::move(suggestion);

        switch (rt) {
            case RotType::Stale:           sv.push_back(std::move(s)); break;
            case RotType::Empty:           ev.push_back(std::move(s)); break;
            case RotType::Temporary:       tv.push_back(std::move(s)); break;
            case RotType::LikelyDuplicate: dv.push_back(std::move(s)); break;
            case RotType::LargeLog:        lv.push_back(std::move(s)); break;
        }
    }

    std::vector<RotCategory> cats;
    cats.push_back(BuildCategory("Stale files",        "Not accessed in threshold period",          std::move(sv)));
    cats.push_back(BuildCategory("Temporary files",    "Likely temp files by extension/prefix",     std::move(tv)));
    cats.push_back(BuildCategory("Likely duplicates",  "Backup/duplicate suffixes",                 std::move(dv)));
    cats.push_back(BuildCategory("Large log files",    "Log files over 100 MB",                     std::move(lv)));
    cats.push_back(BuildCategory("Empty files",        "Zero-byte files",                           std::move(ev)));

    std::sort(cats.begin(), cats.end(),
        [](const RotCategory& a, const RotCategory& b){ return a.total_bytes > b.total_bytes; });

    uint64_t total_bytes = 0, total_files = 0;
    for (const auto& c : cats) { total_bytes += c.total_bytes; total_files += c.files.size(); }

    RotReport report;
    report.generated_at         = NowUnix();
    report.stale_days_threshold = stale_days;
    report.total_rot_bytes      = total_bytes;
    report.total_rot_files      = total_files;
    report.potential_savings_gb = static_cast<double>(total_bytes) / 1073741824.0;
    report.categories           = std::move(cats);

    LOG_INFO("ROT: " + std::to_string(total_files) + " files, "
             + std::to_string((int)report.potential_savings_gb) + " GB potential savings");
    return report;
}

// ─── NtfsOptimizer ───────────────────────────────────────────────────────────

CompressionResult NtfsOptimizer::CompressFile(const std::string& path)
{
    WIN32_FILE_ATTRIBUTE_DATA info{};
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &info)) {
        ThrowWin32("GetFileAttributesEx: " + path);
    }

    LARGE_INTEGER sz;
    sz.LowPart  = info.nFileSizeLow;
    sz.HighPart = static_cast<LONG>(info.nFileSizeHigh);
    const uint64_t original = static_cast<uint64_t>(sz.QuadPart);

    // Already compressed?
    if (info.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED) {
        return { path, original, original, 0, true };
    }

    // Open with GENERIC_WRITE | FILE_FLAG_BACKUP_SEMANTICS
    std::wstring wide = ToWide(path);
    HANDLE h = CreateFileW(
        wide.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );
    if (h == INVALID_HANDLE_VALUE) ThrowWin32("Open for compression: " + path);

    // FSCTL_SET_COMPRESSION — COMPRESSION_FORMAT_DEFAULT = 1
    USHORT format = COMPRESSION_FORMAT_DEFAULT;
    DWORD returned = 0;
    if (!DeviceIoControl(h, FSCTL_SET_COMPRESSION,
                         &format, sizeof(format),
                         nullptr, 0, &returned, nullptr))
    {
        CloseHandle(h);
        ThrowWin32("FSCTL_SET_COMPRESSION: " + path);
    }
    CloseHandle(h);

    // GetCompressedFileSizeW — actual on-disk size after compression
    DWORD high = 0;
    std::wstring wpath = ToWide(path);
    DWORD low = GetCompressedFileSizeW(wpath.c_str(), &high);
    uint64_t compressed = (low == INVALID_FILE_SIZE)
        ? original
        : ((static_cast<uint64_t>(high) << 32) | low);

    int64_t savings = static_cast<int64_t>(original) - static_cast<int64_t>(compressed);
    LOG_INFO("Compressed " + path + ": "
             + std::to_string(original/1024) + " KB → "
             + std::to_string(compressed/1024) + " KB");

    return { path, original, compressed, savings, false };
}

void NtfsOptimizer::DecompressFile(const std::string& path)
{
    std::wstring wide = ToWide(path);
    HANDLE h = CreateFileW(
        wide.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );
    if (h == INVALID_HANDLE_VALUE) ThrowWin32("Open for decompression: " + path);

    USHORT format = COMPRESSION_FORMAT_NONE;
    DWORD returned = 0;
    DeviceIoControl(h, FSCTL_SET_COMPRESSION,
                    &format, sizeof(format),
                    nullptr, 0, &returned, nullptr);
    CloseHandle(h);
}
