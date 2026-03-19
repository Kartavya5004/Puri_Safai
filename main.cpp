// src/main.cpp
// SecureWipe — Secure, Verifiable Data Wiping System
// C++20 implementation for Windows (Phase 1 MVP)
//
// Build:  cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
// Usage:  securewipe.exe --help

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "json.hpp"
#include "common.h"
#include "db.h"
#include "wipe_engine.h"
#include "scanner.h"
#include "usn_tracker.h"
#include "idle_profiler.h"
#include "optimizer.h"
#include "certificate.h"
#include "dashboard.h"
#include "detection.h"

// #include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>

// ─── Minimal CLI parser ───────────────────────────────────────────────────────
// No external dep needed — subcommand + named flags only.

struct Args {
    std::string              command;
    std::vector<std::string> positional;

    std::string get(const std::string& flag, const std::string& def = "") const {
        for (size_t i = 0; i < flags.size(); ++i)
            if (flags[i] == flag && i + 1 < flags.size()) return flags[i + 1];
        return def;
    }
    bool has(const std::string& flag) const {
        for (const auto& f : flags) if (f == flag) return true;
        return false;
    }

    std::vector<std::string> flags;
};

static Args ParseArgs(int argc, char* argv[])
{
    Args a;
    if (argc < 2) return a;
    a.command = argv[1];
    for (int i = 2; i < argc; ++i) {
        if (argv[i][0] == '-') {
            a.flags.push_back(argv[i]);
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                ++i;
                a.flags.push_back(argv[i]);
            }
        } else {
            a.positional.push_back(argv[i]);
        }
    }
    return a;
}

static void PrintHelp()
{
    puts(R"(
SecureWipe v0.1.0 — Secure, verifiable data wiping system

USAGE:
  securewipe <command> [options]

COMMANDS:
  wipe         <path>         Securely wipe a file or directory
  wipe-volume  <volume>       Overwrite an entire volume (requires admin)
  scan         <path>         Collect metadata (privacy-preserving)
  analyze                     Analyze scanned data for ROT files
  detect-hidden <drive>       Detect HPA/DCO hidden storage (read-only)
  verify-cert  <cert.json>    Verify a wipe certificate
  dashboard    <cert.json>    Show sustainability dashboard
  monitor      <drive>        Start USN Journal background monitor

OPTIONS (wipe):
  --method     nist-clear | nist-purge | dod-3pass | single-pass | gutmann
  --cert-out   <path>         Write JSON certificate to this path
  --verify     true | false   Verify after wipe (default: true)
  --verbose                   Enable debug logging

OPTIONS (scan / analyze):
  --db         <path>         SQLite database path (default: securewipe.db)
  --stale-days <n>            Stale threshold in days (default: 180)
  --output     <path>         Save ROT report JSON to this path

OPTIONS (verify-cert):
  --pubkey     <path>         Path to PEM public key (optional; uses embedded key)

EXAMPLES:
  securewipe wipe C:\OldProject --method nist-purge --cert-out cert.json
  securewipe wipe-volume \\.\PhysicalDrive1 --method nist-clear
  securewipe scan C:\ --db mydata.db
  securewipe analyze --db mydata.db --stale-days 180 --output rot.json
  securewipe detect-hidden \\.\PhysicalDrive0
  securewipe verify-cert cert.json
  securewipe dashboard cert.json
  securewipe monitor C: --db activity.db
)");
}

// ─── Command handlers ─────────────────────────────────────────────────────────

static int CmdWipe(const Args& a)
{
    if (a.positional.empty()) {
        fprintf(stderr, "Usage: securewipe wipe <path> [--method ...] [--cert-out ...]\n");
        return 1;
    }
    std::string path   = a.positional[0];
    std::string method = a.get("--method", "nist-clear");
    std::string cert_out = a.get("--cert-out");
    bool verify = (a.get("--verify", "true") != "false");

    WipeEngine engine;
    WipeResult result = engine.WipePath(path, ParseWipeMethod(method), verify);
    std::cout << result.Summary();

    if (!cert_out.empty()) {
        auto cert = WipeCertificate::Generate(result);
        cert.SaveJson(cert_out);
        std::cout << "Certificate saved : " << cert_out << "\n";
        std::cout << "Certificate ID    : " << cert.id << "\n";
    }
    return 0;
}

static int CmdWipeVolume(const Args& a)
{
    if (a.positional.empty()) {
        fprintf(stderr, "Usage: securewipe wipe-volume <volume> [--method ...]\n");
        return 1;
    }
    std::string volume = a.positional[0];
    std::string method = a.get("--method", "nist-clear");
    std::string cert_out = a.get("--cert-out");

    printf("WARNING: This will DESTROY ALL DATA on %s.\n", volume.c_str());
    printf("Type 'YES' to confirm: ");
    std::string confirm;
    std::getline(std::cin, confirm);
    if (confirm != "YES") { puts("Aborted."); return 1; }

    WipeEngine engine;
    WipeResult result = engine.WipeVolume(volume, ParseWipeMethod(method));
    std::cout << result.Summary();

    if (!cert_out.empty()) {
        auto cert = WipeCertificate::Generate(result);
        cert.SaveJson(cert_out);
        std::cout << "Certificate saved: " << cert_out << "\n";
    }
    return 0;
}

static int CmdScan(const Args& a)
{
    if (a.positional.empty()) {
        fprintf(stderr, "Usage: securewipe scan <path> [--db securewipe.db]\n");
        return 1;
    }
    std::string root = a.positional[0];
    std::string db   = a.get("--db", "securewipe.db");

    MetadataStore store(db);
    MetadataScanner scanner(store);
    ScanStats stats = scanner.Scan(root);

    printf("\nScan complete:\n"
           "  Files   : %llu\n"
           "  Dirs    : %llu\n"
           "  Total   : %.2f GB\n"
           "  Skipped : %llu\n"
           "  Time    : %llums\n",
           (unsigned long long)stats.file_count,
           (unsigned long long)stats.dir_count,
           stats.total_bytes / 1073741824.0,
           (unsigned long long)stats.skipped,
           (unsigned long long)stats.elapsed_ms);
    return 0;
}

static int CmdAnalyze(const Args& a)
{
    std::string db         = a.get("--db", "securewipe.db");
    uint64_t stale_days    = static_cast<uint64_t>(
        std::stoul(a.get("--stale-days", "180")));
    std::string output     = a.get("--output");

    MetadataStore store(db);
    RotAnalyzer   analyzer(store);
    RotReport     report  = analyzer.Analyze(stale_days);

    // Serialize report to JSON
    nlohmann::json j;
    j["generated_at"]         = UnixToIso8601(report.generated_at);
    j["stale_days_threshold"]  = report.stale_days_threshold;
    j["total_rot_bytes"]       = report.total_rot_bytes;
    j["total_rot_files"]       = report.total_rot_files;
    j["potential_savings_gb"]  = report.potential_savings_gb;

    nlohmann::json cats = nlohmann::json::array();
    for (const auto& cat : report.categories) {
        nlohmann::json c;
        c["name"]        = cat.name;
        c["description"] = cat.description;
        c["total_bytes"] = cat.total_bytes;
        nlohmann::json files = nlohmann::json::array();
        for (const auto& f : cat.files) {
            files.push_back({
                {"path",          f.path},
                {"size_bytes",    f.size_bytes},
                {"last_accessed", f.last_accessed ? UnixToIso8601(f.last_accessed) : ""},
                {"suggestion",    f.suggestion},
            });
        }
        c["files"] = files;
        cats.push_back(c);
    }
    j["categories"] = cats;

    std::string json_str = j.dump(2);

    if (!output.empty()) {
        FILE* f = fopen(output.c_str(), "w");
        if (!f) throw SecureWipeError("Cannot write: " + output);
        fputs(json_str.c_str(), f);
        fclose(f);
        printf("ROT report saved: %s\n", output.c_str());
    } else {
        puts(json_str.c_str());
    }

    printf("\nSummary: %llu ROT files, %.2f GB potential savings\n",
           (unsigned long long)report.total_rot_files,
           report.potential_savings_gb);
    return 0;
}

static int CmdDetectHidden(const Args& a)
{
    if (a.positional.empty()) {
        fprintf(stderr, "Usage: securewipe detect-hidden <drive>\n"
                        "  e.g. securewipe detect-hidden \\\\.\\PhysicalDrive0\n");
        return 1;
    }
    HiddenStorageDetector detector;
    auto report = detector.Detect(a.positional[0]);
    std::cout << report.Report();
    return report.hpa_detected ? 2 : 0;  // exit 2 if HPA found (machine-readable)
}

static int CmdVerifyCert(const Args& a)
{
    if (a.positional.empty()) {
        fprintf(stderr, "Usage: securewipe verify-cert <cert.json> [--pubkey key.pem]\n");
        return 1;
    }
    auto cert = WipeCertificate::LoadJson(a.positional[0]);
    std::string pubkey_path = a.get("--pubkey");

    bool valid = pubkey_path.empty()
        ? cert.VerifySelf()
        : cert.VerifySignature(pubkey_path);

    if (valid) {
        printf("\n\u2713 Certificate is VALID and unmodified\n"
               "  ID      : %s\n"
               "  Method  : %s\n"
               "  Target  : %s\n"
               "  Wiped   : %.2f GB\n"
               "  SSD warn: %s\n",
               cert.id.c_str(),
               WipeMethodDescription(cert.wipe_method).c_str(),
               cert.target_path.c_str(),
               cert.bytes_wiped / 1073741824.0,
               cert.ssd_warning ? "YES" : "No");
        return 0;
    } else {
        printf("\n\u2717 Certificate signature INVALID — document may be tampered\n");
        return 1;
    }
}

static int CmdDashboard(const Args& a)
{
    if (a.positional.empty()) {
        fprintf(stderr, "Usage: securewipe dashboard <cert.json>\n");
        return 1;
    }
    auto cert = WipeCertificate::LoadJson(a.positional[0]);
    auto dash = SustainabilityDashboard::FromCertificate(cert);
    dash.Print();
    return 0;
}

static int CmdMonitor(const Args& a)
{
    if (a.positional.empty()) {
        fprintf(stderr, "Usage: securewipe monitor <drive> [--db securewipe.db]\n"
                        "  e.g. securewipe monitor C: --db activity.db\n");
        return 1;
    }
    std::string drive = a.positional[0];
    std::string db    = a.get("--db", "securewipe.db");

    MetadataStore store(db);
    UsnJournalTracker tracker(drive, store);

    printf("Monitoring %s for file changes (Ctrl-C to stop)...\n", drive.c_str());
    tracker.RunLoop();
    return 0;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

int main(int argc, char* argv[])
{
    // UTF-8 output on Windows
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) { PrintHelp(); return 0; }

    Args a = ParseArgs(argc, argv);

    if (a.has("--verbose")) g_log_level = LogLevel::DEBUG;

    if (a.command == "--help" || a.command == "-h" || a.command == "help") {
        PrintHelp();
        return 0;
    }

    try {
        if      (a.command == "wipe")           return CmdWipe(a);
        else if (a.command == "wipe-volume")    return CmdWipeVolume(a);
        else if (a.command == "scan")           return CmdScan(a);
        else if (a.command == "analyze")        return CmdAnalyze(a);
        else if (a.command == "detect-hidden")  return CmdDetectHidden(a);
        else if (a.command == "verify-cert")    return CmdVerifyCert(a);
        else if (a.command == "dashboard")      return CmdDashboard(a);
        else if (a.command == "monitor")        return CmdMonitor(a);
        else {
            fprintf(stderr, "Unknown command: %s\n", a.command.c_str());
            PrintHelp();
            return 1;
        }
    } catch (const AccessDeniedError& e) {
        fprintf(stderr, "ERROR (access denied): %s\n", e.what());
        fprintf(stderr, "Tip: Run as administrator.\n");
        return 1;
    } catch (const PathNotFoundError& e) {
        fprintf(stderr, "ERROR (not found): %s\n", e.what());
        return 1;
    } catch (const SecureWipeError& e) {
        fprintf(stderr, "ERROR: %s\n", e.what());
        return 1;
    } catch (const std::exception& e) {
        fprintf(stderr, "FATAL: %s\n", e.what());
        return 2;
    }
}
