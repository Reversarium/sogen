#pragma once

#include <windows_emulator.hpp>
#include <emulator/scoped_hook.hpp>
#include <filesystem>
#include <fstream>
#include "disassembler.hpp"

namespace sogen
{
    class import_trace
    {
      public:
        import_trace(windows_emulator& win, std::filesystem::path directory, bool from_entry);
        void request_start(uint64_t address);
        bool resume_pending();
        void finish(bool completed);

      private:
        void observe_instruction(uint64_t address);
        void emit_context();
        void emit_header(std::string_view event);
        void emit_bytes(std::span<const uint8_t> bytes);
        void write_image();

        windows_emulator& win_;
        std::filesystem::path directory_;
        std::ofstream out_;
        disassembler disassembler_{};
        std::optional<uint64_t> pending_{};
        uint64_t start_address_{};
        uint64_t candidate_count_{};
        uint64_t instructions_{};
        uint64_t image_instructions_{};
        uint64_t previous_address_{};
        uint32_t previous_thread_{};
        size_t write_width_{};
        bool active_{};
        scoped_hook entry_hook_{};
        scoped_hook execute_hook_{};
        scoped_hook write_hook_{};
    };
}
