#pragma once
// include/certificate.h  —  RSA-PSS signed wipe certificate

#include "common.h"
#include "wipe_engine.h"
#include <string>
#include <vector>
#include "json.hpp"
// #include <nlohmann/json.hpp>

struct WipeCertificate {
    std::string id;
    std::string schema_version;
    int64_t     issued_at          = 0;
    WipeMethod  wipe_method        = WipeMethod::NistClear;
    std::string target_path;
    DeviceInfo  device_info;
    uint64_t    bytes_wiped        = 0;
    uint64_t    files_processed    = 0;
    uint32_t    passes_completed   = 0;
    int64_t     started_at         = 0;
    int64_t     completed_at       = 0;
    int64_t     duration_seconds   = 0;
    bool        verified           = false;
    bool        verification_passed = false;
    std::vector<std::string> errors;
    bool        ssd_warning        = false;
    std::string ssd_warning_text;

    // Integrity / signing fields
    std::string payload_sha256;
    std::string signature;        // RSA-PSS, base64-encoded
    std::string public_key_pem;

    /// Generate a certificate signed with a freshly created RSA-2048 key.
    static WipeCertificate Generate(const WipeResult& result);

    /// Generate using an existing PEM-encoded private key file.
    static WipeCertificate GenerateWithKey(
        const WipeResult& result,
        const std::string& private_key_pem_path
    );

    /// Verify signature using a PEM public key file.
    bool VerifySignature(const std::string& pubkey_pem_path) const;

    /// Verify using the embedded public key.
    bool VerifySelf() const;
  
    // newly added to resolve in .cpp file
    bool VerifySignature_pem(const std::string& pem) const;

    void     SaveJson(const std::string& path) const;
    static WipeCertificate LoadJson(const std::string& path);

    nlohmann::json ToJson() const;
};
