#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/fmt/fmt.h>
#include <epn/core/types.hpp>
#include <string>
#include <memory>

namespace epn::observability {

// ─── Logger initialisation ────────────────────────────────────────────────────
inline void init_logger(
    const std::string& component,
    bool               debug = false,
    const std::string& log_file = "")
{
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    if (!log_file.empty()) {
        sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file, 10 * 1024 * 1024 /* 10 MiB */, 5));
    }

    auto logger = std::make_shared<spdlog::logger>(component, sinks.begin(), sinks.end());
    logger->set_level(debug ? spdlog::level::debug : spdlog::level::info);
    logger->set_pattern("[%Y-%m-%dT%H:%M:%S.%e] [%n] [%^%l%$] %v");
    spdlog::set_default_logger(logger);
    spdlog::flush_every(std::chrono::seconds(1));
}

// ─── Session-correlated logging ───────────────────────────────────────────────
// Formats: [sid:hex_prefix] message
inline std::string session_tag(const core::SessionId& sid) {
    return "[sid:" + core::to_hex({sid.data.data(), 4}) + "] ";
}

} // namespace epn::observability

// ─── Convenience macros ───────────────────────────────────────────────────────
#define LOG_TRACE(...) spdlog::trace(__VA_ARGS__)
#define LOG_DEBUG(...) spdlog::debug(__VA_ARGS__)
#define LOG_INFO(...)  spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)  spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...) spdlog::error(__VA_ARGS__)
#define LOG_CRITICAL(...) spdlog::critical(__VA_ARGS__)

#define LOG_SESSION(sid, level, ...) \
    spdlog::level(epn::observability::session_tag(sid) + fmt::format(__VA_ARGS__))
