#pragma once
// include/common.h  —  Shared types, enums, and error handling

#include <windows.h>
#undef ERROR
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>
#include <cstdint>
#include <chrono>

// ─── Timestamp helpers ────────────────────────────────────────────────────────

/// Convert a Windows FILETIME to a Unix timestamp (seconds since 1970-01-01)
inline int64_t FiletimeToUnix(const FILETIME& ft)
{
    // FILETIME: 100-nanosecond intervals since 1601-01-01
    // Subtract epoch difference: 11644473600 seconds
    ULARGE_INTEGER uli;
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return static_cast<int64_t>(uli.QuadPart / 10'000'000ULL) - 11'644'473'600LL;
}

/// Format a Unix timestamp as an ISO 8601 string (UTC)
inline std::string UnixToIso8601(int64_t unix_ts)
{
    time_t t = static_cast<time_t>(unix_ts);
    struct tm tm_utc{};
#ifdef _WIN32
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    return buf;
}

inline int64_t NowUnix()
{
    return static_cast<int64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())
    );
}

/// Convert UTF-8 std::string to wide string (Windows API needs LPCWSTR)
inline std::wstring ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(sz, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), sz);
    // Remove null terminator added by MultiByteToWideChar
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

inline std::string ToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), sz, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

// ─── Error handling ──────────────────────────────────────────────────────────

class SecureWipeError : public std::runtime_error {
public:
    explicit SecureWipeError(const std::string& msg) : std::runtime_error(msg) {}
};

class AccessDeniedError : public SecureWipeError {
public:
    explicit AccessDeniedError(const std::string& path)
        : SecureWipeError("Access denied — run as administrator for: " + path) {}
};

class PathNotFoundError : public SecureWipeError {
public:
    explicit PathNotFoundError(const std::string& path)
        : SecureWipeError("Path not found: " + path) {}
};

/// Throw a SecureWipeError with the last Win32 error message appended
[[noreturn]] inline void ThrowWin32(const std::string& context)
{
    DWORD err = GetLastError();
    char buf[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, err, 0, buf, sizeof(buf), nullptr);
    throw SecureWipeError(context + ": " + buf + " (error " + std::to_string(err) + ")");
}

// ─── Logging (simple, no external dep) ───────────────────────────────────────

enum class LogLevel { DEBUG, INFO, WARN, ERROR };

inline LogLevel g_log_level = LogLevel::INFO;

inline void Log(LogLevel level, const std::string& msg)
{
    if (level < g_log_level) return;
    const char* prefix = "";
    switch (level) {
        case LogLevel::DEBUG: prefix = "[DEBUG] "; break;
        case LogLevel::INFO:  prefix = "[INFO]  "; break;
        case LogLevel::WARN:  prefix = "[WARN]  "; break;
        case LogLevel::ERROR: prefix = "[ERROR] "; break;
    }
    // Timestamp
    char ts[24];
    time_t t = time(nullptr);
    struct tm tm_local{};
    localtime_s(&tm_local, &t);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm_local);

    fprintf(stderr, "%s %s%s\n", ts, prefix, msg.c_str());
}

#define LOG_DEBUG(msg) Log(LogLevel::DEBUG, msg)
#define LOG_INFO(msg)  Log(LogLevel::INFO,  msg)
#define LOG_WARN(msg)  Log(LogLevel::WARN,  msg)
#define LOG_ERROR(msg) Log(LogLevel::ERROR, msg)
