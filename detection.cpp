// src/detection.cpp
// Hidden Storage Region Detector — READ-ONLY
//
// SAFETY: This module NEVER modifies HPA or DCO.
// Incorrect HPA/DCO manipulation can permanently damage drives.
//
// Detection approach:
//   1. IOCTL_DISK_GET_LENGTH_INFO  → OS-visible capacity
//   2. IOCTL_ATA_PASS_THROUGH with READ_NATIVE_MAX_ADDRESS (0xF8)
//      → true native capacity; compare against (1)

#include "detection.h"
#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>   // ATA_PASS_THROUGH_EX
#include <sstream>
#include <iomanip>
#include <algorithm>

// ─── HiddenStorageReport::Report ─────────────────────────────────────────────

std::string HiddenStorageReport::Report() const
{
    std::ostringstream ss;
    ss << "=== Hidden Storage Detection Report ===\n"
       << "Drive    : " << drive << "\n"
       << "Scanned  : " << UnixToIso8601(scanned_at) << "\n\n"
       << "OS-visible sectors : " << os_visible_sectors << "\n";

    if (native_max_sectors > 0) {
        ss << "Native max sectors : " << native_max_sectors << "\n";
    } else {
        ss << "Native max sectors : (could not read — may need admin rights)\n";
    }

    ss << "\n";

    if (hpa_detected) {
        double hidden_mb = static_cast<double>(hpa_hidden_bytes) / 1048576.0;
        ss << "WARNING: HPA DETECTED\n"
           << "  Hidden sectors : " << hpa_hidden_sectors
           << " (" << std::fixed << std::setprecision(1) << hidden_mb << " MB)\n"
           << "  The Host Protected Area may contain data invisible to the OS.\n"
           << "  DO NOT attempt to remove HPA without proper ATA Secure Erase procedure.\n";
    } else {
        ss << "HPA: Not detected\n";
    }

    ss << "\n";

    if (dco_detected) {
        ss << "WARNING: DCO DETECTED\n";
        for (const auto& f : dco_features_hidden) {
            ss << "  Hidden feature: " << f << "\n";
        }
    } else {
        ss << "DCO: Not detected\n";
    }

    if (!warnings.empty()) {
        ss << "\nWarnings:\n";
        for (const auto& w : warnings) ss << "  ! " << w << "\n";
    }

    ss << "\nRecommendation: " << recommendation << "\n";
    return ss.str();
}

// ─── HiddenStorageDetector::Detect ───────────────────────────────────────────

HiddenStorageReport HiddenStorageDetector::Detect(const std::string& drive) const
{
    LOG_INFO("Scanning for hidden storage regions on: " + drive);
    LOG_WARN("HPA/DCO detection: read-only scan — no modifications will be made.");

    HiddenStorageReport report;
    report.drive      = drive;
    report.scanned_at = NowUnix();

    // Normalise drive path → \\.\PhysicalDriveN  or  \\.\C:
    std::string vol = drive;
    if (vol.substr(0, 4) != "\\\\.\\") vol = "\\\\.\\" + vol;
    // Strip trailing backslash
    while (!vol.empty() && (vol.back() == '\\' || vol.back() == '/')) vol.pop_back();

    std::wstring wide = ToWide(vol);
    HANDLE hDrive = CreateFileW(
        wide.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        nullptr
    );

    if (hDrive == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            report.warnings.push_back(
                "Access denied for '" + drive + "' — run as administrator.");
        } else {
            report.warnings.push_back(
                "Cannot open drive '" + drive + "': error " + std::to_string(err));
        }
        report.recommendation =
            "Re-run as administrator for full HPA/DCO detection.";
        return report;
    }

    // ── Step 1: OS-visible capacity ──────────────────────────────────────────
    {
        GET_LENGTH_INFORMATION len_info{};
        DWORD returned = 0;
        if (DeviceIoControl(hDrive, IOCTL_DISK_GET_LENGTH_INFO,
                            nullptr, 0,
                            &len_info, sizeof(len_info),
                            &returned, nullptr))
        {
            report.os_visible_sectors =
                static_cast<uint64_t>(len_info.Length.QuadPart) / 512ULL;
        } else {
            report.warnings.push_back(
                "IOCTL_DISK_GET_LENGTH_INFO failed: error "
                + std::to_string(GetLastError()));
        }
    }

    // ── Step 2: ATA READ_NATIVE_MAX_ADDRESS ──────────────────────────────────
    report.native_max_sectors = AtaReadNativeMax(hDrive);

    CloseHandle(hDrive);

    // ── Step 3: Compute HPA discrepancy ──────────────────────────────────────
    if (report.native_max_sectors > 0 &&
        report.native_max_sectors > report.os_visible_sectors)
    {
        report.hpa_hidden_sectors =
            report.native_max_sectors - report.os_visible_sectors;
        report.hpa_hidden_bytes   = report.hpa_hidden_sectors * 512ULL;
        report.hpa_detected       = true;

        double hidden_mb = static_cast<double>(report.hpa_hidden_bytes) / 1048576.0;
        report.recommendation =
            "HPA detected: " + std::to_string(report.hpa_hidden_sectors)
            + " hidden sectors (" + std::to_string(static_cast<int>(hidden_mb)) + " MB). "
            "Data in the HPA may not be wiped by standard software tools. "
            "For certified erasure, use a hardware-level ATA Secure Erase tool "
            "(Phase 3 feature). Do NOT attempt manual HPA removal without "
            "proper tooling and a full backup.";
    } else if (report.warnings.empty()) {
        report.recommendation =
            "No hidden storage regions detected. "
            "Standard wipe procedures are sufficient.";
    } else {
        report.recommendation =
            "Scan was incomplete. Re-run with administrator privileges.";
    }

    // DCO detection requires DEVICE CONFIGURATION IDENTIFY (ATA command 0xB1/0xC2)
    // — deferred to Phase 3. Mark as not detected for now.
    report.dco_detected = false;

    return report;
}

// ─── ATA PASS-THROUGH: READ_NATIVE_MAX_ADDRESS (command 0xF8) ────────────────
//
// Uses IOCTL_ATA_PASS_THROUGH (via ntddscsi.h) to send an ATA non-data command.
// ATA_PASS_THROUGH_EX structure (from ntddscsi.h):
//   USHORT  Length             = sizeof(ATA_PASS_THROUGH_EX)
//   USHORT  AtaFlags           = ATA_FLAGS_DRDY_REQUIRED (0x0001)
//   UCHAR   PathId, TargetId, Lun = 0
//   UCHAR   ReservedAsUchar    = 0
//   ULONG   DataTransferLength = 0  (non-data command)
//   ULONG   TimeOutValue       = 5  (seconds)
//   ULONG   ReservedAsUlong    = 0
//   ULONG_PTR DataBufferOffset = sizeof(ATA_PASS_THROUGH_EX)
//   UCHAR   PreviousTaskFile[8] — returned register values
//   UCHAR   CurrentTaskFile[8] — command registers
//     [0] Features, [1] SectorCount, [2] SectorNum (LBA_Low),
//     [3] CylLow (LBA_Mid), [4] CylHigh (LBA_High), [5] DevHead, [6] Command

uint64_t HiddenStorageDetector::AtaReadNativeMax(HANDLE hDrive) const
{
    // Build ATA_PASS_THROUGH_EX manually (avoids ntddscsi dependency issues)
    // Total struct size = 40 bytes on 32-bit, 48 bytes on 64-bit (pointer field)
    // We use a fixed 48-byte layout which works on both.

    struct AtaPassThroughEx48 {
        USHORT  Length            = 0;
        USHORT  AtaFlags          = 0;
        UCHAR   PathId            = 0;
        UCHAR   TargetId          = 0;
        UCHAR   Lun               = 0;
        UCHAR   ReservedAsUchar   = 0;
        ULONG   DataTransferLength = 0;
        ULONG   TimeOutValue      = 0;
        ULONG   ReservedAsUlong   = 0;
        ULONG64 DataBufferOffset  = 0;
        UCHAR   PreviousTaskFile[8]{};
        UCHAR   CurrentTaskFile[8]{};
    };

    AtaPassThroughEx48 cmd{};
    cmd.Length             = sizeof(AtaPassThroughEx48);
    cmd.AtaFlags           = 0x0001;            // ATA_FLAGS_DRDY_REQUIRED
    cmd.DataTransferLength = 0;                 // non-data command
    cmd.TimeOutValue       = 5;
    cmd.DataBufferOffset   = sizeof(AtaPassThroughEx48);
    cmd.CurrentTaskFile[6] = 0xF8;              // READ_NATIVE_MAX_ADDRESS

    AtaPassThroughEx48 out{};
    DWORD returned = 0;

    BOOL ok = DeviceIoControl(
        hDrive,
        0x0004D028,     // IOCTL_ATA_PASS_THROUGH
        &cmd, sizeof(cmd),
        &out, sizeof(out),
        &returned,
        nullptr
    );

    if (!ok || returned < sizeof(out)) {
        LOG_WARN("IOCTL_ATA_PASS_THROUGH failed (may not be an ATA drive): error "
                 + std::to_string(GetLastError()));
        return 0;
    }

    // PreviousTaskFile contains the returned LBA registers:
    //   [2] LBA_Low, [3] LBA_Mid, [4] LBA_High  → 24-bit sector count (LBA28)
    uint64_t lba = (static_cast<uint64_t>(out.PreviousTaskFile[4]) << 16)
                 | (static_cast<uint64_t>(out.PreviousTaskFile[3]) <<  8)
                 |  static_cast<uint64_t>(out.PreviousTaskFile[2]);

    return (lba == 0) ? 0 : lba + 1;   // +1: command returns last addressable sector
}
