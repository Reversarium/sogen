#pragma once

#include <windows_emulator.hpp>
#include <emulator/scoped_hook.hpp>
#include <filesystem>
#include <fstream>
#include "entry_handoff_tracker.hpp"

namespace sogen
{
    class oep_detector
    {
      public:
        oep_detector(windows_emulator& win, const std::filesystem::path& path, std::function<void(uint64_t)> on_candidate = {});
        oep_detector(const oep_detector&) = delete;
        oep_detector& operator=(const oep_detector&) = delete;
        void finish(bool completed);

      private:
        std::optional<entry_context> read_context() const;
        void observe_block(uint64_t address);
        void emit_context(const entry_context& context);
        void emit_address(uint64_t address);

        windows_emulator& win_;
        std::ofstream out_;
        entry_handoff_tracker tracker_{};
        uint64_t previous_block_{};
        uint64_t observed_blocks_{};
        uint64_t restored_stack_blocks_{};
        std::function<void(uint64_t)> on_candidate_{};
        scoped_hook entry_hook_{};
        scoped_hook block_hook_{};
    };
}
