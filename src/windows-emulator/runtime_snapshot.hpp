#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace sogen
{
    class windows_emulator;

    struct runtime_snapshot_metrics
    {
        uint64_t mapped_bytes{};
        uint64_t captured_bytes{};
        uint64_t file_bytes{};
        uint64_t memory_hash{14695981039346656037ULL};
        uint32_t modules{};
        uint32_t registers{};
        uint32_t regions{};
        double capture_ms{};
        std::vector<std::string> unavailable_registers{};
    };

    runtime_snapshot_metrics write_runtime_snapshot(windows_emulator& win, uint64_t start, const std::filesystem::path& path);
}
