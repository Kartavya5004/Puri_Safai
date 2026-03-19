#pragma once
// include/db.h  —  SQLite metadata store (metadata only, never file contents)

#include "common.h"
#include <string>
#include <vector>
#include <optional>
#include <memory>

// Forward-declare SQLiteCpp types to keep include minimal in header
namespace SQLite { class Database; }

struct FileRecord {
    std::string path;
    uint64_t    size_bytes   = 0;
    int64_t     last_accessed = 0;   // Unix timestamp, 0 = unknown
    int64_t     last_modified = 0;
    int64_t     created_at    = 0;
    int64_t     scanned_at    = 0;
    bool        is_compressed = false;
    uint32_t    usn_reason    = 0;
};

class MetadataStore {
public:
    explicit MetadataStore(const std::string& db_path);
    ~MetadataStore();

    // Prevent copy — owns the database connection
    MetadataStore(const MetadataStore&)            = delete;
    MetadataStore& operator=(const MetadataStore&) = delete;
    MetadataStore(MetadataStore&&)                 = default;

    void        UpsertFile(const FileRecord& record);
    std::vector<FileRecord> StaleFiles(uint64_t older_than_days) const;
    uint64_t    TotalSize()  const;
    uint64_t    FileCount()  const;

    void LogWipe(
        const std::string& path,
        const std::string& method,
        uint32_t passes,
        uint64_t bytes_wiped,
        int64_t  started_at,
        int64_t  completed_at,
        bool     verified,
        const std::string& cert_id
    );

    void InsertUsnEvent(
        int64_t     usn,
        const std::string& file_name,
        uint32_t    reason_mask,
        int64_t     timestamp,
        int64_t     file_ref
    );

private:
    void InitSchema();
    std::unique_ptr<SQLite::Database> db_;
};
