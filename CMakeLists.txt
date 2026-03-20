cmake_minimum_required(VERSION 3.20)
project(securewipe VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Dependencies (fetched automatically via FetchContent) ──────────────────
include(FetchContent)

# nlohmann/json  — JSON serialization
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

# SQLiteCpp      — SQLite wrapper
FetchContent_Declare(sqlitecpp
    GIT_REPOSITORY https://github.com/SRombauts/SQLiteCpp.git
    GIT_TAG        3.3.1
)
FetchContent_MakeAvailable(sqlitecpp)

# OpenSSL        — RSA signing (system-provided on Windows via vcpkg or bundled)
find_package(OpenSSL REQUIRED)

# ── Source files ───────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/db.cpp
    src/wipe_engine.cpp
    src/scanner.cpp
    src/usn_tracker.cpp
    src/idle_profiler.cpp
    src/optimizer.cpp
    src/certificate.cpp
    src/dashboard.cpp
    src/detection.cpp
)

add_executable(securewipe ${SOURCES})

target_include_directories(securewipe PRIVATE include)

target_link_libraries(securewipe PRIVATE
    nlohmann_json::nlohmann_json
    SQLiteCpp
    sqlite3
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(securewipe PRIVATE
        kernel32
        advapi32
        ntdll
    )
    target_compile_definitions(securewipe PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        UNICODE
        _UNICODE
    )
endif()

# Compiler warnings
if(MSVC)
    target_compile_options(securewipe PRIVATE /W4 /WX- /utf-8)
else()
    target_compile_options(securewipe PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS securewipe RUNTIME DESTINATION bin)
