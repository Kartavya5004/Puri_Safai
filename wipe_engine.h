#pragma once
// include/wipe_engine.h  —  NIST SP 800-88 compliant secure wipe engine

#include "common.h"
#include <string>
#include <vector>

// ─── Wipe methods ─────────────────────────────────────────────────────────────

enum class WipeMethod {
    NistClear,        // 1-pass zeros          (NIST SP 800-88 §2.3)
    NistPurge,        // 3-pass zeros/ones/rnd  (NIST SP 800-88)
    Dod3Pass,         // 3-pass zeros/ones/rnd  (DoD 5220.22-M)
    SinglePassRandom, // 1-pass CSPRNG random
    Gutmann35Pass,    // 35-pass (legacy)
};

WipeMethod      ParseWipeMethod(const std::string& s);
std::string     WipeMethodName(WipeMethod m);
std::string     WipeMethodDescription(WipeMethod m);

// ─── Pass patterns ────────────────────────────────────────────────────────────

enum class PassKind { Zeros, Ones, Random, Fixed };

struct PassPattern {
    PassKind kind  = PassKind::Zeros;
    uint8_t  value = 0x00;  // used only when kind == Fixed
};

std::vector<PassPattern> BuildPasses(WipeMethod method);

// ─── Device info ──────────────────────────────────────────────────────────────

struct DeviceInfo {
    std::string serial_number;
    std::string model;
    std::string firmware;
    bool        is_ssd        = false;
    uint64_t    capacity_bytes = 0;
    std::string interface_type;
};

// ─── Wipe result ──────────────────────────────────────────────────────────────

struct WipeResult {
    std::string target_path;
    WipeMethod  method               = WipeMethod::NistClear;
    uint32_t    passes_completed     = 0;
    uint64_t    bytes_wiped          = 0;
    uint64_t    files_processed      = 0;
    int64_t     started_at           = 0;
    int64_t     completed_at         = 0;
    bool        verified             = false;
    bool        verification_passed  = false;
    std::vector<std::string> errors;
    bool        ssd_warning          = false;
    DeviceInfo  device_info;

    std::string Summary() const;
};

// ─── Engine ───────────────────────────────────────────────────────────────────

class WipeEngine {
public:
    WipeEngine() = default;

    /// Wipe a single file or all files under a directory.
    WipeResult WipePath(const std::string& path, WipeMethod method, bool verify);

    /// Overwrite an entire volume (requires administrator).
    WipeResult WipeVolume(const std::string& volume_path, WipeMethod method);

private:
    /// Overwrite a single file with all passes; returns bytes written.
    uint64_t WipeFile(const std::string& path, const std::vector<PassPattern>& passes);

    /// Collect all files under a directory recursively.
    std::vector<std::string> CollectFiles(
        const std::string& dir, std::vector<std::string>& errors);

    DeviceInfo ProbeDevice(const std::string& path);
    void       IssueTrimHint(const std::string& path);
};
