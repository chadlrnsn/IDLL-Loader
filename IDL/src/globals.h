#pragma once
#include <atomic>
#include <logger/logger.h>

namespace globals {
    inline std::atomic<bool> g_break{ false };
}

namespace g_functions {}