// src/db.cpp
#include "db.h"
#include <SQLiteCpp/SQLiteCpp.h>
#include <stdexcept>

// ─── Construction / schema ────────────────────────────────────────────────────

MetadataStore::MetadataStore(const std::string& db_path)
    : db_(std::make_unique<SQLite::Database>(
          db_path,
          SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE))
{
    InitSchema();
}

MetadataStore::~MetadataStore() = default;

void MetadataStore::InitSchema()
{
    db_->exec("PRAGMA journal_mode=WAL");
    db_->exec("PRAGMA synchronous=NORMAL");

    db_->exec(R"sql(
        CREATE TABLE IF NOT EXISTS file_metadata (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            path          TEXT    NOT NULL UNIQUE,
            size_bytes    INTEGER NOT NULL DEFAULT 0,
            last_accessed INTEGER,
            last_modified INTEGER,
            created_at    INTEGER,
            scanned_at    INTEGER NOT NULL,
            is_compressed INTEGER NOT NULL DEFAULT 0,
            usn_reason    INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_last_accessed ON file_metadata(last_accessed);
        CREATE INDEX IF NOT EXISTS idx_size_bytes    ON file_metadata(size_bytes);
    )sql");

    db_->exec(R"sql(
        CREATE TABLE IF NOT EXISTS wipe_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            path          TEXT    NOT NULL,
            method        TEXT    NOT NULL,
            passes        INTEGER NOT NULL,
            bytes_wiped   INTEGER NOT NULL,
            started_at    INTEGER NOT NULL,
            completed_at  INTEGER NOT NULL,
            verified      INTEGER NOT NULL DEFAULT 0,
            cert_id       TEXT
        );
    )sql");

    db_->exec(R"sql(
        CREATE TABLE IF NOT EXISTS usn_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            usn         INTEGER NOT NULL,
            file_name   TEXT    NOT NULL,
            reason_mask INTEGER NOT NULL,
            timestamp   INTEGER NOT NULL,
            file_ref    INTEGER
        );
    )sql");
}

// ─── File metadata ────────────────────────────────────────────────────────────

void MetadataStore::UpsertFile(const FileRecord& r)
{
    SQLite::Statement q(*db_,
        "INSERT INTO file_metadata"
        " (path,size_bytes,last_accessed,last_modified,created_at,scanned_at,is_compressed,usn_reason)"
        " VALUES (?,?,?,?,?,?,?,?)"
        " ON CONFLICT(path) DO UPDATE SET"
        "   size_bytes=excluded.size_bytes,"
        "   last_accessed=excluded.last_accessed,"
        "   last_modified=excluded.last_modified,"
        "   scanned_at=excluded.scanned_at,"
        "   is_compressed=excluded.is_compressed,"
        "   usn_reason=excluded.usn_reason"
    );

    q.bind(1, r.path);
    q.bind(2, static_cast<int64_t>(r.size_bytes));
    if (r.last_accessed) q.bind(3, r.last_accessed); else q.bindNULL(3);
    if (r.last_modified) q.bind(4, r.last_modified); else q.bindNULL(4);
    if (r.created_at)    q.bind(5, r.created_at);    else q.bindNULL(5);
    q.bind(6, r.scanned_at);
    q.bind(7, static_cast<int>(r.is_compressed));
    if (r.usn_reason) q.bind(8, static_cast<int64_t>(r.usn_reason));
    else              q.bindNULL(8);

    q.exec();
}

std::vector<FileRecord> MetadataStore::StaleFiles(uint64_t older_than_days) const
{
    int64_t cutoff = NowUnix() - static_cast<int64_t>(older_than_days) * 86400LL;

    SQLite::Statement q(*db_,
        "SELECT path,size_bytes,last_accessed,last_modified,created_at,"
        "       scanned_at,is_compressed,usn_reason"
        " FROM file_metadata"
        " WHERE last_accessed < ? OR last_accessed IS NULL"
        " ORDER BY size_bytes DESC"
    );
    q.bind(1, cutoff);

    std::vector<FileRecord> out;
    while (q.executeStep()) {
        FileRecord r;
        r.path          = q.getColumn(0).getString();
        r.size_bytes    = static_cast<uint64_t>(q.getColumn(1).getInt64());
        r.last_accessed = q.getColumn(2).isNull() ? 0 : q.getColumn(2).getInt64();
        r.last_modified = q.getColumn(3).isNull() ? 0 : q.getColumn(3).getInt64();
        r.created_at    = q.getColumn(4).isNull() ? 0 : q.getColumn(4).getInt64();
        r.scanned_at    = q.getColumn(5).getInt64();
        r.is_compressed = q.getColumn(6).getInt() != 0;
        r.usn_reason    = q.getColumn(7).isNull() ? 0u :
                          static_cast<uint32_t>(q.getColumn(7).getInt64());
        out.push_back(std::move(r));
    }
    return out;
}

uint64_t MetadataStore::TotalSize() const
{
    SQLite::Statement q(*db_, "SELECT COALESCE(SUM(size_bytes),0) FROM file_metadata");
    q.executeStep();
    return static_cast<uint64_t>(q.getColumn(0).getInt64());
}

uint64_t MetadataStore::FileCount() const
{
    SQLite::Statement q(*db_, "SELECT COUNT(*) FROM file_metadata");
    q.executeStep();
    return static_cast<uint64_t>(q.getColumn(0).getInt64());
}

// ─── Wipe log ─────────────────────────────────────────────────────────────────

void MetadataStore::LogWipe(
    const std::string& path, const std::string& method,
    uint32_t passes, uint64_t bytes_wiped,
    int64_t started_at, int64_t completed_at,
    bool verified, const std::string& cert_id)
{
    SQLite::Statement q(*db_,
        "INSERT INTO wipe_log"
        " (path,method,passes,bytes_wiped,started_at,completed_at,verified,cert_id)"
        " VALUES (?,?,?,?,?,?,?,?)"
    );
    q.bind(1, path);
    q.bind(2, method);
    q.bind(3, static_cast<int>(passes));
    q.bind(4, static_cast<int64_t>(bytes_wiped));
    q.bind(5, started_at);
    q.bind(6, completed_at);
    q.bind(7, static_cast<int>(verified));
    if (!cert_id.empty()) q.bind(8, cert_id); else q.bindNULL(8);
    q.exec();
}

// ─── USN events ───────────────────────────────────────────────────────────────

void MetadataStore::InsertUsnEvent(
    int64_t usn, const std::string& file_name,
    uint32_t reason_mask, int64_t timestamp, int64_t file_ref)
{
    SQLite::Statement q(*db_,
        "INSERT INTO usn_events (usn,file_name,reason_mask,timestamp,file_ref)"
        " VALUES (?,?,?,?,?)"
    );
    q.bind(1, usn);
    q.bind(2, file_name);
    q.bind(3, static_cast<int64_t>(reason_mask));
    q.bind(4, timestamp);
    q.bind(5, file_ref);
    q.exec();
}
