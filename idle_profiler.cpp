// src/idle_profiler.cpp
#include "idle_profiler.h"
#include <windows.h>
#include <thread>
#include <chrono>

IdleProfiler::IdleProfiler(double cpu_idle_threshold, uint64_t user_idle_seconds)
    : cpu_idle_threshold_(cpu_idle_threshold)
    , user_idle_threshold_seconds_(user_idle_seconds)
{}

SystemIdleState IdleProfiler::Sample() const
{
    SystemIdleState state;
    state.cpu_idle_fraction  = MeasureCpuIdle();
    state.user_idle_seconds  = MeasureUserIdle();
    state.is_idle =
        state.cpu_idle_fraction  >= cpu_idle_threshold_         &&
        state.user_idle_seconds  >= user_idle_threshold_seconds_;

    LOG_DEBUG("Idle: cpu=" + std::to_string((int)(state.cpu_idle_fraction*100))
              + "% user=" + std::to_string(state.user_idle_seconds) + "s");
    return state;
}

SystemIdleState IdleProfiler::WaitUntilIdle(uint32_t poll_ms) const
{
    for (;;) {
        auto s = Sample();
        if (s.is_idle) return s;
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
    }
}

// ─── GetSystemTimes — two-sample CPU idle measurement ────────────────────────

double IdleProfiler::MeasureCpuIdle() const
{
    auto sample = [](uint64_t& idle, uint64_t& kernel, uint64_t& user) {
        FILETIME fi{}, fk{}, fu{};
        if (!GetSystemTimes(&fi, &fk, &fu)) return false;
        auto to64 = [](const FILETIME& f) -> uint64_t {
            return (static_cast<uint64_t>(f.dwHighDateTime) << 32) | f.dwLowDateTime;
        };
        idle   = to64(fi);
        kernel = to64(fk);
        user   = to64(fu);
        return true;
    };

    uint64_t i0,k0,u0, i1,k1,u1;
    if (!sample(i0,k0,u0)) return 0.5;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    if (!sample(i1,k1,u1)) return 0.5;

    double d_idle   = static_cast<double>(i1 - i0);
    double d_kernel = static_cast<double>(k1 - k0);  // includes idle time on Windows
    double d_user   = static_cast<double>(u1 - u0);
    double d_total  = d_kernel + d_user;

    if (d_total <= 0.0) return 1.0;   // No change → fully idle
    return d_idle / d_total;
}

// ─── GetLastInputInfo — user inactivity duration ─────────────────────────────

uint64_t IdleProfiler::MeasureUserIdle() const
{
    LASTINPUTINFO lii{ sizeof(LASTINPUTINFO), 0 };
    if (!GetLastInputInfo(&lii)) return 0;
    DWORD tick_now = GetTickCount();
    DWORD elapsed  = tick_now - lii.dwTime;
    return static_cast<uint64_t>(elapsed) / 1000ULL;
}
