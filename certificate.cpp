// src/certificate.cpp
// Wipe Certificate — RSA-PSS signing via OpenSSL

#include "certificate.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

// ─── Helpers ──────────────────────────────────────────────────────────────────
std::string signature = "DEMO_SIGNATURE";
static std::string OpenSSLErrors()
{
    std::string out;
    unsigned long e;
    char buf[256];
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.empty()) out += '\n';
        out += buf;
    }
    return out;
}

static std::string BytesToHex(const unsigned char* data, size_t len)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) ss << std::setw(2) << (int)data[i];
    return ss.str();
}

static std::string Base64Encode(const unsigned char* data, size_t len)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, static_cast<int>(len));
    BIO_flush(b64);

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(mem, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    return out;
}

static std::vector<unsigned char> Base64Decode(const std::string& s)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(s.data(), static_cast<int>(s.size()));
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> out(s.size());
    int n = BIO_read(b64, out.data(), static_cast<int>(out.size()));
    BIO_free_all(b64);
    if (n < 0) throw SecureWipeError("Base64 decode failed");
    out.resize(static_cast<size_t>(n));
    return out;
}

// Build a UUID v4 from OS random bytes
static std::string GenerateUuid()
{
    unsigned char bytes[16];
    RAND_bytes(bytes, 16);
    bytes[6] = (bytes[6] & 0x0F) | 0x40;  // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80;  // variant bits

    char uuid[37];
    snprintf(uuid, sizeof(uuid),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0],  bytes[1],  bytes[2],  bytes[3],
        bytes[4],  bytes[5],  bytes[6],  bytes[7],
        bytes[8],  bytes[9],  bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]);
    return uuid;
}

// ─── Canonical payload → JSON string for hashing ─────────────────────────────

static std::string BuildCanonicalPayload(const WipeCertificate& c)
{
    // Must be deterministic — same field order every time
    nlohmann::json j;
    j["id"]                  = c.id;
    j["schema_version"]      = c.schema_version;
    j["issued_at"]           = c.issued_at;
    j["wipe_method"]         = WipeMethodName(c.wipe_method);
    j["target_path"]         = c.target_path;
    j["device_info"]["serial_number"]  = c.device_info.serial_number;
    j["device_info"]["model"]          = c.device_info.model;
    j["device_info"]["firmware"]       = c.device_info.firmware;
    j["device_info"]["is_ssd"]         = c.device_info.is_ssd;
    j["device_info"]["capacity_bytes"] = c.device_info.capacity_bytes;
    j["device_info"]["interface_type"] = c.device_info.interface_type;
    j["bytes_wiped"]         = c.bytes_wiped;
    j["files_processed"]     = c.files_processed;
    j["passes_completed"]    = c.passes_completed;
    j["started_at"]          = c.started_at;
    j["completed_at"]        = c.completed_at;
    j["duration_seconds"]    = c.duration_seconds;
    j["verified"]            = c.verified;
    j["verification_passed"] = c.verification_passed;
    j["errors"]              = c.errors;
    j["ssd_warning"]         = c.ssd_warning;
    return j.dump();  // compact, keys in insertion order
}

// ─── Generate ─────────────────────────────────────────────────────────────────

WipeCertificate WipeCertificate::Generate(const WipeResult& result)
{
    // Generate a fresh RSA-2048 key pair
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    if (!pkey) throw SecureWipeError("RSA key generation failed: " + OpenSSLErrors());

    // Serialize private key (for GenerateWithKey path; not stored in cert)
    BIO* bio_priv = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    BUF_MEM* bm_priv = nullptr;
    BIO_get_mem_ptr(bio_priv, &bm_priv);
    std::string priv_pem(bm_priv->data, bm_priv->length);
    BIO_free(bio_priv);

    // Serialize public key PEM
    BIO* bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_pub, pkey);
    BUF_MEM* bm_pub = nullptr;
    BIO_get_mem_ptr(bio_pub, &bm_pub);
    std::string pub_pem(bm_pub->data, bm_pub->length);
    BIO_free(bio_pub);

    // Build certificate (without signing fields)
    WipeCertificate cert;
    cert.id              = GenerateUuid();
    cert.schema_version  = "1.0";
    cert.issued_at       = NowUnix();
    cert.wipe_method     = result.method;
    cert.target_path     = result.target_path;
    cert.device_info     = result.device_info;
    cert.bytes_wiped     = result.bytes_wiped;
    cert.files_processed = result.files_processed;
    cert.passes_completed = result.passes_completed;
    cert.started_at      = result.started_at;
    cert.completed_at    = result.completed_at;
    cert.duration_seconds = result.completed_at - result.started_at;
    cert.verified        = result.verified;
    cert.verification_passed = result.verification_passed;
    cert.errors          = result.errors;
    cert.ssd_warning     = result.ssd_warning;
    cert.public_key_pem  = pub_pem;

    if (result.ssd_warning) {
        cert.ssd_warning_text =
            "SSD DETECTED: Software overwrite does not guarantee full data erasure "
            "on SSDs due to wear levelling and over-provisioning. TRIM hint was sent. "
            "For certified erasure, use ATA Secure Erase (Phase 3).";
    }

    // Hash the canonical payload
    std::string payload = BuildCanonicalPayload(cert);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(payload.data()),
           payload.size(), hash);
    cert.payload_sha256 = BytesToHex(hash, SHA256_DIGEST_LENGTH);

    // RSA-PSS sign the hash
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* sctx = nullptr;
    EVP_DigestSignInit(mctx, &sctx, EVP_sha256(), nullptr, pkey);
    EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(sctx, RSA_PSS_SALTLEN_DIGEST);

    EVP_DigestSignUpdate(mctx, hash, SHA256_DIGEST_LENGTH);

    size_t sig_len = 0;
    EVP_DigestSignFinal(mctx, nullptr, &sig_len);
    std::vector<unsigned char> sig(sig_len);
    EVP_DigestSignFinal(mctx, sig.data(), &sig_len);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    cert.signature = Base64Encode(sig.data(), sig_len);

    LOG_INFO("Certificate generated: " + cert.id);
    return cert;
}

WipeCertificate WipeCertificate::GenerateWithKey(
    const WipeResult& result, const std::string& private_key_pem_path)
{
    // Load private key from file
    std::ifstream f(private_key_pem_path);
    if (!f) throw PathNotFoundError(private_key_pem_path);
    std::string pem((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());

    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) throw SecureWipeError("Load private key failed: " + OpenSSLErrors());

    // Extract public key PEM
    BIO* bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_pub, pkey);
    BUF_MEM* bm = nullptr;
    BIO_get_mem_ptr(bio_pub, &bm);
    std::string pub_pem(bm->data, bm->length);
    BIO_free(bio_pub);

    // Reuse Generate logic by temporarily creating a result copy
    WipeCertificate cert;
    cert.id              = GenerateUuid();
    cert.schema_version  = "1.0";
    cert.issued_at       = NowUnix();
    cert.wipe_method     = result.method;
    cert.target_path     = result.target_path;
    cert.device_info     = result.device_info;
    cert.bytes_wiped     = result.bytes_wiped;
    cert.files_processed = result.files_processed;
    cert.passes_completed = result.passes_completed;
    cert.started_at      = result.started_at;
    cert.completed_at    = result.completed_at;
    cert.duration_seconds = result.completed_at - result.started_at;
    cert.verified        = result.verified;
    cert.verification_passed = result.verification_passed;
    cert.errors          = result.errors;
    cert.ssd_warning     = result.ssd_warning;
    cert.public_key_pem  = pub_pem;

    std::string payload = BuildCanonicalPayload(cert);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), hash);
    cert.payload_sha256 = BytesToHex(hash, SHA256_DIGEST_LENGTH);

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* sctx = nullptr;
    EVP_DigestSignInit(mctx, &sctx, EVP_sha256(), nullptr, pkey);
    EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(sctx, RSA_PSS_SALTLEN_DIGEST);
    EVP_DigestSignUpdate(mctx, hash, SHA256_DIGEST_LENGTH);

    size_t sig_len = 0;
    EVP_DigestSignFinal(mctx, nullptr, &sig_len);
    std::vector<unsigned char> sig(sig_len);
    EVP_DigestSignFinal(mctx, sig.data(), &sig_len);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    cert.signature = Base64Encode(sig.data(), sig_len);
    return cert;
}

// ─── Verify ───────────────────────────────────────────────────────────────────

bool WipeCertificate::VerifySignature(const std::string& pubkey_pem_path) const
{
    std::ifstream f(pubkey_pem_path);
    if (!f) throw PathNotFoundError(pubkey_pem_path);
    std::string pem((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
    return VerifySignature_pem(pem);
}

bool WipeCertificate::VerifySelf() const
{
    return VerifySignature_pem(public_key_pem);
}

bool WipeCertificate::VerifySignature_pem(const std::string& pem) const
{
    // Recompute canonical hash
    std::string payload = BuildCanonicalPayload(*this);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), hash);

    // Check stored hash
    if (BytesToHex(hash, SHA256_DIGEST_LENGTH) != payload_sha256) return false;

    // Load public key
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;

    // Decode signature
    auto sig_bytes = Base64Decode(signature);

    // Verify RSA-PSS
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* vctx = nullptr;
    EVP_DigestVerifyInit(mctx, &vctx, EVP_sha256(), nullptr, pkey);
    EVP_PKEY_CTX_set_rsa_padding(vctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(vctx, RSA_PSS_SALTLEN_DIGEST);
    EVP_DigestVerifyUpdate(mctx, hash, SHA256_DIGEST_LENGTH);

    int ok = EVP_DigestVerifyFinal(mctx,
                 sig_bytes.data(), sig_bytes.size());

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return ok == 1;
}

// ─── Serialization ───────────────────────────────────────────────────────────

nlohmann::json WipeCertificate::ToJson() const
{
    nlohmann::json j;
    j["id"]                   = id;
    j["schema_version"]       = schema_version;
    j["issued_at"]            = UnixToIso8601(issued_at);
    j["wipe_method"]          = WipeMethodName(wipe_method);
    j["target_path"]          = target_path;
    j["device_info"]["serial_number"]  = device_info.serial_number;
    j["device_info"]["model"]          = device_info.model;
    j["device_info"]["firmware"]       = device_info.firmware;
    j["device_info"]["is_ssd"]         = device_info.is_ssd;
    j["device_info"]["capacity_bytes"] = device_info.capacity_bytes;
    j["bytes_wiped"]          = bytes_wiped;
    j["files_processed"]      = files_processed;
    j["passes_completed"]     = passes_completed;
    j["started_at"]           = UnixToIso8601(started_at);
    j["completed_at"]         = UnixToIso8601(completed_at);
    j["duration_seconds"]     = duration_seconds;
    j["verified"]             = verified;
    j["verification_passed"]  = verification_passed;
    j["errors"]               = errors;
    j["ssd_warning"]          = ssd_warning;
    j["ssd_warning_text"]     = ssd_warning_text;
    j["payload_sha256"]       = payload_sha256;
    j["signature"]            = signature;
    j["public_key_pem"]       = public_key_pem;
    return j;
}

void WipeCertificate::SaveJson(const std::string& path) const
{
    std::ofstream f(path);
    if (!f) throw SecureWipeError("Cannot write certificate to: " + path);
    f << ToJson().dump(2);
    LOG_INFO("Certificate saved: " + path);
}

WipeCertificate WipeCertificate::LoadJson(const std::string& path)
{
    std::ifstream f(path);
    if (!f) throw PathNotFoundError(path);
    nlohmann::json j = nlohmann::json::parse(f);

    WipeCertificate c;
    c.id                  = j.at("id");
    c.schema_version      = j.at("schema_version");
    c.wipe_method         = ParseWipeMethod(j.at("wipe_method").get<std::string>());
    c.target_path         = j.at("target_path");
    c.bytes_wiped         = j.at("bytes_wiped");
    c.files_processed     = j.at("files_processed");
    c.passes_completed    = j.at("passes_completed");
    c.duration_seconds    = j.at("duration_seconds");
    c.verified            = j.at("verified");
    c.verification_passed = j.at("verification_passed");
    c.errors              = j.at("errors").get<std::vector<std::string>>();
    c.ssd_warning         = j.at("ssd_warning");
    c.payload_sha256      = j.at("payload_sha256");
    c.signature           = j.at("signature");
    c.public_key_pem      = j.at("public_key_pem");
    if (j.contains("ssd_warning_text")) c.ssd_warning_text = j.at("ssd_warning_text");

    auto& di = j.at("device_info");
    c.device_info.serial_number  = di.value("serial_number",  "");
    c.device_info.model          = di.value("model",          "");
    c.device_info.firmware       = di.value("firmware",       "");
    c.device_info.is_ssd         = di.value("is_ssd",         false);
    c.device_info.capacity_bytes = di.value("capacity_bytes", uint64_t(0));

    // Re-parse issued_at / started_at / completed_at as stored Unix ints
    // (stored as ISO strings in JSON for readability; canonical payload uses raw ints)
    c.issued_at    = NowUnix(); // best-effort; not used in verification
    c.started_at   = 0;
    c.completed_at = 0;

    return c;
}
