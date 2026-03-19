#pragma once
// include/usn_tracker.h  —  Windows USN Journal file-change tracker

#include "common.h"
#include "db.h"
#include <string>
#include <vector>

// USN reason flag constants (from winioctl.h)
namespace UsnReason {
    constexpr uint32_t DATA_OVERWRITE       = 0x00000001;
    constexpr uint32_t DATA_EXTEND          = 0x00000002;
    constexpr uint32_t DATA_TRUNCATION      = 0x00000004;
    constexpr uint32_t FILE_CREATE_FLAG     = 0x00000100;
    constexpr uint32_t FILE_DELETE          = 0x00000200;
    constexpr uint32_t RENAME_OLD_NAME      = 0x00001000;
    constexpr uint32_t RENAME_NEW_NAME      = 0x00002000;
    constexpr uint32_t COMPRESSION_CHANGE   = 0x00020000;
    constexpr uint32_t CLOSE                = 0x80000000;
}

struct UsnRecord {
    int64_t     usn         = 0;
    std::string file_name;
    uint32_t    reason_mask = 0;
    int64_t     timestamp   = 0;
    uint64_t    file_ref    = 0;
    uint64_t    parent_ref  = 0;

    std::string ReasonDescription() const;
};

class UsnJournalTracker {
public:
    /// drive: e.g. "C:" or "C:\"
    UsnJournalTracker(const std::string& drive, MetadataStore& store);
    ~UsnJournalTracker();

    /// Blocking monitor loop — exits on Ctrl-C.
    void RunLoop();

    /// Poll once; returns new records and advances internal cursor.
    std::vector<UsnRecord> PollRecords();

private:
    void OpenVolume();
    void QueryJournal();

    std::string    drive_;
    MetadataStore& store_;
    HANDLE         volume_handle_ = INVALID_HANDLE_VALUE;
    uint64_t       journal_id_    = 0;
    int64_t        next_usn_      = 0;
};
