#pragma once
// include/scanner.h

#include "common.h"
#include "db.h"
#include <string>

struct ScanStats {
    uint64_t file_count   = 0;
    uint64_t dir_count    = 0;
    uint64_t total_bytes  = 0;
    uint64_t skipped      = 0;
    uint64_t elapsed_ms   = 0;
};

class MetadataScanner {
public:
    explicit MetadataScanner(MetadataStore& store);

    ScanStats Scan(const std::string& root);

    size_t   max_depth       = 0;      // 0 = unlimited
    bool     skip_hidden     = false;
    uint64_t min_size_bytes  = 0;

private:
    void ScanDir(const std::string& dir, size_t depth, ScanStats& stats);
    std::optional<FileRecord> CollectMetadata(const std::string& path);

    MetadataStore& store_;
};
