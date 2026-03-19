// src/usn_tracker.cpp
// Windows USN Journal Tracker
//
// IOCTLs used:
//   FSCTL_QUERY_USN_JOURNAL  (0x000900F4) — get journal ID and current USN
//   FSCTL_READ_USN_JOURNAL   (0x000900BB) — read records from a start USN
//
// USN_RECORD_V2 layout (variable length):
//   DWORD  RecordLength        offset 0
//   WORD   MajorVersion        offset 4
//   WORD   MinorVersion        offset 6
//   DWORDLONG FileReferenceNumber   offset 8
//   DWORDLONG ParentFileRefNumber   offset 16
//   USN    Usn                 offset 24  (LONGLONG)
//   LARGE_INTEGER TimeStamp    offset 32  (FILETIME)
//   DWORD  Reason              offset 40
//   DWORD  SourceInfo          offset 44
//   DWORD  SecurityId          offset 48
//   DWORD  FileAttributes      offset 52
//   WORD   FileNameLength      offset 56
//   WORD   FileNameOffset      offset 58  (= 60 for V2)
//   WCHAR  FileName[]          offset 60

#include "usn_tracker.h"
#include <windows.h>
#include <winioctl.h>
#include <sstream>
#include <csignal>

// ─── UsnRecord ────────────────────────────────────────────────────────────────

std::string UsnRecord::ReasonDescription() const
{
    std::string out;
    auto add = [&](const char* s){ if (!out.empty()) out += '|'; out += s; };
    if (reason_mask & UsnReason::FILE_CREATE)        add("Created");
    if (reason_mask & UsnReason::FILE_DELETE)        add("Deleted");
    if (reason_mask & UsnReason::DATA_OVERWRITE)     add("Overwritten");
    if (reason_mask & UsnReason::DATA_EXTEND)        add("Extended");
    if (reason_mask & UsnReason::DATA_TRUNCATION)    add("Truncated");
    if (reason_mask & UsnReason::RENAME_NEW_NAME)    add("Renamed");
    if (reason_mask & UsnReason::COMPRESSION_CHANGE) add("CompressionChanged");
    if (reason_mask & UsnReason::CLOSE)              add("Closed");
    if (out.empty()) out = "Unknown";
    return out;
}

// ─── UsnJournalTracker ────────────────────────────────────────────────────────

UsnJournalTracker::UsnJournalTracker(
    const std::string& drive, MetadataStore& store)
    : drive_(drive), store_(store)
{
    OpenVolume();
    QueryJournal();
    LOG_INFO("USN Journal opened on " + drive_
             + ": journal_id=" + std::to_string(journal_id_)
             + ", next_usn=" + std::to_string(next_usn_));
}

UsnJournalTracker::~UsnJournalTracker()
{
    if (volume_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(volume_handle_);
    }
}

void UsnJournalTracker::OpenVolume()
{
    std::string vol = "\\\\.\\" + drive_;
    // Remove trailing backslash if present
    while (!vol.empty() && (vol.back() == '\\' || vol.back() == '/')) vol.pop_back();

    std::wstring wide = ToWide(vol);
    volume_handle_ = CreateFileW(
        wide.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );
    if (volume_handle_ == INVALID_HANDLE_VALUE) {
        ThrowWin32("Cannot open volume " + drive_ + " for USN Journal");
    }
}

void UsnJournalTracker::QueryJournal()
{
    // USN_JOURNAL_DATA_V0 (64 bytes):
    //   UsnJournalID   u64  offset 0
    //   FirstUsn       i64  offset 8
    //   NextUsn        i64  offset 16
    //   LowestValidUsn i64  offset 24
    //   MaxUsn         i64  offset 32
    //   MaximumSize    u64  offset 40
    //   AllocationDelta u64 offset 48
    uint8_t data[64]{};
    DWORD returned = 0;

    if (!DeviceIoControl(volume_handle_,
                         FSCTL_QUERY_USN_JOURNAL,
                         nullptr, 0,
                         data, sizeof(data),
                         &returned, nullptr))
    {
        ThrowWin32("FSCTL_QUERY_USN_JOURNAL");
    }

    memcpy(&journal_id_, data + 0, 8);
    memcpy(&next_usn_,   data + 16, 8);
}

// ─── Poll ─────────────────────────────────────────────────────────────────────

static volatile bool g_stop = false;
static void SigHandler(int) { g_stop = true; }

void UsnJournalTracker::RunLoop()
{
    signal(SIGINT,  SigHandler);
    signal(SIGTERM, SigHandler);

    while (!g_stop) {
        auto records = PollRecords();
        if (records.empty()) {
            Sleep(2000);
            continue;
        }

        for (const auto& r : records) {
            LOG_DEBUG(std::to_string(r.timestamp) + " " + r.file_name
                      + " (" + r.ReasonDescription() + ")");
            store_.InsertUsnEvent(
                r.usn, r.file_name, r.reason_mask,
                r.timestamp, static_cast<int64_t>(r.file_ref));
        }

        LOG_INFO("Processed " + std::to_string(records.size())
                 + " USN records (next=" + std::to_string(next_usn_) + ")");
    }

    LOG_INFO("USN monitor stopped.");
}

std::vector<UsnRecord> UsnJournalTracker::PollRecords()
{
    // READ_USN_JOURNAL_DATA_V0 (40 bytes):
    //   StartUsn          i64  offset 0
    //   ReasonMask        u32  offset 8
    //   ReturnOnlyOnClose u32  offset 12
    //   Timeout           u64  offset 16
    //   BytesToWaitFor    u64  offset 24
    //   UsnJournalID      u64  offset 32
    uint8_t query[40]{};
    memcpy(query + 0,  &next_usn_,   8);
    uint32_t all_reasons = 0xFFFFFFFF;
    memcpy(query + 8,  &all_reasons, 4);
    memcpy(query + 32, &journal_id_, 8);

    constexpr DWORD kOutBuf = 65536;
    std::vector<uint8_t> output(kOutBuf);
    DWORD returned = 0;

    BOOL ok = DeviceIoControl(
        volume_handle_,
        FSCTL_READ_USN_JOURNAL,
        query, sizeof(query),
        output.data(), kOutBuf,
        &returned, nullptr
    );

    if (!ok || returned < 8) return {};

    // First 8 bytes = NextUsn
    memcpy(&next_usn_, output.data(), 8);

    std::vector<UsnRecord> records;
    DWORD offset = 8;

    while (offset + 60 <= returned) {
        uint32_t rec_len = 0;
        memcpy(&rec_len, output.data() + offset, 4);
        if (rec_len == 0 || offset + rec_len > returned) break;

        UsnRecord r;
        uint64_t file_ref = 0, parent_ref = 0;
        LONGLONG usn = 0, ft = 0;
        uint32_t reason = 0;
        uint16_t name_len = 0, name_off = 0;

        memcpy(&file_ref,   output.data() + offset + 8,  8);
        memcpy(&parent_ref, output.data() + offset + 16, 8);
        memcpy(&usn,        output.data() + offset + 24, 8);
        memcpy(&ft,         output.data() + offset + 32, 8);
        memcpy(&reason,     output.data() + offset + 40, 4);
        memcpy(&name_len,   output.data() + offset + 56, 2);
        memcpy(&name_off,   output.data() + offset + 58, 2);

        // Decode wide filename
        DWORD name_start = offset + name_off;
        if (name_start + name_len <= returned) {
            std::wstring wname(name_len / 2, L'\0');
            memcpy(wname.data(), output.data() + name_start, name_len);
            r.file_name = ToUtf8(wname);
        } else {
            r.file_name = "<unknown>";
        }

        // Convert FILETIME → Unix
        r.timestamp = ft / 10'000'000LL - 11'644'473'600LL;

        r.usn         = static_cast<int64_t>(usn);
        r.reason_mask = reason;
        r.file_ref    = file_ref;
        r.parent_ref  = parent_ref;

        records.push_back(std::move(r));
        offset += rec_len;
    }

    return records;
}
