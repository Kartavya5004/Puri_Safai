#pragma once
// include/optimizer.h  —  ROT analyzer + NTFS compression

#include "common.h"
#include "db.h"
#include <string>
#include <vector>

enum class RotType {
    Stale,
    Empty,
    Temporary,
    LikelyDuplicate,
    LargeLog,
};

struct RotFileSuggestion {
    std::string path;
    uint64_t    size_bytes    = 0;
    int64_t     last_accessed = 0;
    int64_t     last_modified = 0;
    RotType     rot_type      = RotType::Stale;
    std::string suggestion;
};

struct RotCategory {
    std::string name;
    std::string description;
    std::vector<RotFileSuggestion> files;
    uint64_t    total_bytes = 0;
};

struct RotReport {
    int64_t  generated_at          = 0;
    uint64_t stale_days_threshold  = 0;
    uint64_t total_rot_bytes       = 0;
    uint64_t total_rot_files       = 0;
    double   potential_savings_gb  = 0.0;
    std::vector<RotCategory> categories;
};

class RotAnalyzer {
public:
    explicit RotAnalyzer(MetadataStore& store);
    RotReport Analyze(uint64_t stale_days) const;

private:
    MetadataStore& store_;
    static RotType ClassifyRot(const FileRecord& record);
};

struct CompressionResult {
    std::string path;
    uint64_t    original_bytes    = 0;
    uint64_t    compressed_bytes  = 0;
    int64_t     savings_bytes     = 0;
    bool        already_compressed = false;
};

class NtfsOptimizer {
public:
    NtfsOptimizer() = default;
    CompressionResult CompressFile(const std::string& path);
    void              DecompressFile(const std::string& path);
};
