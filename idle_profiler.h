#pragma once
// include/idle_profiler.h

#include "common.h"

struct SystemIdleState {
    double   cpu_idle_fraction = 0.0;  // 0.0 = busy, 1.0 = fully idle
    uint64_t user_idle_seconds = 0;
    bool     is_idle           = false;
};

class IdleProfiler {
public:
    /// cpu_idle_threshold: fraction of idle time required (default 0.90 = CPU < 10% busy)
    explicit IdleProfiler(double cpu_idle_threshold = 0.90,
                          uint64_t user_idle_seconds = 30);

    SystemIdleState Sample() const;

    /// Block until system is idle, polling every poll_ms milliseconds.
    SystemIdleState WaitUntilIdle(uint32_t poll_ms = 5000) const;

    /// Run fn() only when idle; returns false if system was busy and block=false.
    template<typename Fn>
    bool RunWhenIdle(Fn fn, bool block = false, uint32_t poll_ms = 5000) const
    {
        if (block) { WaitUntilIdle(poll_ms); fn(); return true; }
        auto state = Sample();
        if (state.is_idle) { fn(); return true; }
        return false;
    }

private:
    double   cpu_idle_threshold_;
    uint64_t user_idle_threshold_seconds_;

    double   MeasureCpuIdle()   const;
    uint64_t MeasureUserIdle()  const;
};
