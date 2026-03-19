// src/scanner.cpp
// Privacy-Preserving Metadata Scanner
//
// PRIVACY GUARANTEE: File content is NEVER opened, read, or stored.
// Only path, size, and timestamps are collected via GetFileAttributesEx.

#include "scanner.h"
#include <windows.h>
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

MetadataScanner::MetadataScanner(MetadataStore& store) : store_(store) {}

ScanStats MetadataScanner::Scan(const std::string& root)
{
    if (!fs::exists(root)) throw PathNotFoundError(root);

    LOG_INFO("Starting metadata scan: " + root);
    auto t0 = std::chrono::steady_clock::now();

    ScanStats stats{};
    ScanDir(root, 0, stats);

    auto t1 = std::chrono::steady_clock::now();
    stats.elapsed_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    LOG_INFO("Scan complete: " + std::to_string(stats.file_count) + " files, "
        + std::to_string(stats.dir_count) + " dirs, "
        + std::to_string(stats.total_bytes / 1073741824) + " GB in "
        + std::to_string(stats.elapsed_ms) + "ms");

    return stats;
}

void MetadataScanner::ScanDir(
    const std::string& dir, size_t depth, ScanStats& stats)
{
    if (max_depth > 0 && depth > max_depth) return;

    fs::directory_iterator it;
    try {
        it = fs::directory_iterator(dir,
            fs::directory_options::skip_permission_denied);
    } catch (...) {
        ++stats.skipped;
        return;
    }

    for (const auto& entry : it) {
        const auto& path = entry.path();

        // Skip symlinks — avoid loops and unintended cross-volume traversal
        if (fs::is_symlink(path)) { ++stats.skipped; continue; }

        // Skip hidden files/dirs (Windows: FILE_ATTRIBUTE_HIDDEN)
        if (skip_hidden) {
            DWORD attr = GetFileAttributesW(path.wstring().c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_HIDDEN)) {
                ++stats.skipped; continue;
            }
        }

        if (fs::is_directory(path)) {
            ++stats.dir_count;
            ScanDir(path.string(), depth + 1, stats);
        } else if (fs::is_regular_file(path)) {
            auto rec = CollectMetadata(path.string());
            if (!rec) { ++stats.skipped; continue; }
            stats.total_bytes += rec->size_bytes;
            ++stats.file_count;
            try {
                store_.UpsertFile(*rec);
            } catch (const std::exception& e) {
                LOG_WARN("DB insert failed for " + path.string() + ": " + e.what());
            }
        }
    }
}

std::optional<FileRecord> MetadataScanner::CollectMetadata(const std::string& path)
{
    // GetFileAttributesEx — stat-equivalent, never opens the file for reading
    WIN32_FILE_ATTRIBUTE_DATA info{};
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &info)) {
        return std::nullopt;
    }

    LARGE_INTEGER sz;
    sz.LowPart  = info.nFileSizeLow;
    sz.HighPart = static_cast<LONG>(info.nFileSizeHigh);
    const uint64_t size = static_cast<uint64_t>(sz.QuadPart);

    if (size < min_size_bytes) return std::nullopt;

    FileRecord rec;
    rec.path          = path;
    rec.size_bytes    = size;
    rec.last_accessed = FiletimeToUnix(info.ftLastAccessTime);
    rec.last_modified = FiletimeToUnix(info.ftLastWriteTime);
    rec.created_at    = FiletimeToUnix(info.ftCreationTime);
    rec.scanned_at    = NowUnix();
    rec.is_compressed = (info.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED) != 0;
    return rec;
}
