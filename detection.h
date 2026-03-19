#pragma once
// include/detection.h  —  HPA/DCO hidden storage detector (read-only)

#include "common.h"
#include <string>
#include <vector>

struct HiddenStorageReport {
    std::string drive;
    int64_t     scanned_at           = 0;
    uint64_t    os_visible_sectors   = 0;
    uint64_t    native_max_sectors   = 0;   // 0 = could not read
    bool        hpa_detected         = false;
    uint64_t    hpa_hidden_sectors   = 0;
    uint64_t    hpa_hidden_bytes     = 0;
    bool        dco_detected         = false;
    std::vector<std::string> dco_features_hidden;
    std::vector<std::string> warnings;
    std::string recommendation;

    std::string Report() const;
};

class HiddenStorageDetector {
public:
    HiddenStorageDetector() = default;

    /// Scan the drive for hidden storage regions.
    /// READ-ONLY — does not modify HPA or DCO under any circumstances.
    HiddenStorageReport Detect(const std::string& drive) const;

private:
    uint64_t AtaReadNativeMax(HANDLE hDrive) const;
};
