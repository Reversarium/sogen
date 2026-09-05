#include "std_include.hpp"
#include "oep_detector.hpp"

namespace sogen
{
    namespace
    {
        constexpr std::array nonvolatile_registers{x86_register::rbx, x86_register::rbp, x86_register::rsi, x86_register::rdi,
                                                   x86_register::r12, x86_register::r13, x86_register::r14, x86_register::r15};
        constexpr std::array xmm_registers{x86_register::xmm6,  x86_register::xmm7,  x86_register::xmm8,  x86_register::xmm9,
                                           x86_register::xmm10, x86_register::xmm11, x86_register::xmm12, x86_register::xmm13,
                                           x86_register::xmm14, x86_register::xmm15};
    }

    oep_detector::oep_detector(windows_emulator& win, const std::filesystem::path& path, std::function<void(uint64_t)> on_candidate)
        : win_(win),
          out_(path),
          on_candidate_(std::move(on_candidate))
    {
        if (!out_)
        {
            throw std::runtime_error("Cannot open OEP report: " + path.string());
        }
        if (win_.mod_manager.get_execution_mode() != execution_mode::native_64bit)
        {
            throw std::runtime_error("OEP detection currently requires an x64 executable");
        }
        const auto ep = win_.mod_manager.executable->entry_point;
        entry_hook_ = scoped_hook(win_.emu(), win_.emu().hook_memory_execution(ep, [this](cpu_interface& cpu, uint64_t address) {
            win_.dispatch_on_cpu(cpu, [&] {
                if (tracker_.entry())
                {
                    return;
                }
                const auto context = read_context();
                if (!context)
                {
                    throw std::runtime_error("Cannot read entry stack");
                }
                tracker_.capture(win_.current_thread().id, address, *context);
                previous_block_ = address;
                out_ << R"({"event":"entry","thread":)" << std::dec << tracker_.thread() << ',';
                emit_address(address);
                out_ << ',';
                emit_context(*context);
                out_ << "}\n" << std::flush;
            });
        }));
        block_hook_ = scoped_hook(win_.emu(), win_.emu().hook_basic_block([this](cpu_interface& cpu, const basic_block& block) {
            win_.dispatch_on_cpu(cpu, [&] { observe_block(block.address); });
        }));
    }

    std::optional<entry_context> oep_detector::read_context() const
    {
        auto& cpu = win_.active_cpu();
        entry_context context{.rsp = cpu.reg<uint64_t>(x86_register::rsp)};
        if (!cpu.try_read_memory(context.rsp, &context.return_address, sizeof(context.return_address)))
        {
            return std::nullopt;
        }
        for (size_t i = 0; i < nonvolatile_registers.size(); ++i)
        {
            context.nonvolatile.at(i) = cpu.reg<uint64_t>(nonvolatile_registers.at(i));
        }
        for (size_t i = 0; i < xmm_registers.size(); ++i)
        {
            context.xmm.at(i) = cpu.reg<std::array<uint64_t, 2>>(xmm_registers.at(i));
        }
        return context;
    }

    void oep_detector::observe_block(uint64_t address)
    {
        if (!tracker_.entry() || win_.current_thread().id != tracker_.thread())
        {
            return;
        }
        ++observed_blocks_;
        const auto rsp = win_.active_cpu().reg<uint64_t>(x86_register::rsp);
        if (rsp != tracker_.entry()->rsp)
        {
            tracker_.observe(tracker_.thread(), address, entry_context{.rsp = rsp});
        }
        else
        {
            ++restored_stack_blocks_;
            const auto context = read_context();
            if (context && tracker_.observe(tracker_.thread(), address, *context))
            {
                out_ << R"({"event":"candidate",)";
                emit_address(address);
                out_ << R"(,"previous_block":"0x)" << std::hex << previous_block_ << R"(","block_index":)" << std::dec << observed_blocks_
                     << ',';
                emit_context(*context);
                std::array<uint8_t, 64> bytes{};
                const bool readable = win_.active_cpu().try_read_memory(address, bytes.data(), bytes.size());
                out_ << R"(,"bytes":)";
                if (readable)
                {
                    constexpr std::string_view hex = "0123456789abcdef";
                    out_ << '"';
                    for (auto byte : bytes)
                    {
                        out_ << hex.at(byte >> 4) << hex.at(byte & 15);
                    }
                    out_ << '"';
                }
                else
                {
                    out_ << "null";
                }
                out_ << "}\n" << std::flush;
                if (on_candidate_)
                {
                    on_candidate_(address);
                }
            }
        }
        previous_block_ = address;
    }

    void oep_detector::emit_address(uint64_t address)
    {
        const auto& exe = *win_.mod_manager.executable;
        out_ << R"("address":"0x)" << std::hex << address << R"(","image_base":"0x)" << exe.image_base << R"(","rva":)";
        if (exe.contains(address))
        {
            out_ << R"("0x)" << address - exe.image_base << '"';
        }
        else
        {
            out_ << "null";
        }
    }

    void oep_detector::emit_context(const entry_context& context)
    {
        out_ << R"("rsp":"0x)" << std::hex << context.rsp << R"(","return_address":"0x)" << context.return_address
             << R"(","nonvolatile":[)";
        for (size_t i = 0; i < context.nonvolatile.size(); ++i)
        {
            if (i)
            {
                out_ << ',';
            }
            out_ << R"("0x)" << context.nonvolatile.at(i) << '"';
        }
        out_ << R"(],"xmm6_to_xmm15":[)";
        for (size_t i = 0; i < context.xmm.size(); ++i)
        {
            if (i)
            {
                out_ << ',';
            }
            out_ << R"(["0x)" << context.xmm.at(i).at(0) << R"(","0x)" << context.xmm.at(i).at(1) << R"("])";
        }
        out_ << ']';
    }

    void oep_detector::finish(bool completed)
    {
        const auto count = tracker_.candidates().size();
        std::string_view status = "ambiguous";
        if (!completed)
        {
            status = "incomplete";
        }
        else if (!tracker_.entry())
        {
            status = "entry_not_reached";
        }
        else if (count == 0)
        {
            status = "no_candidate";
        }
        else if (count == 1)
        {
            status = "unique_candidate";
        }
        out_ << R"({"event":"result","status":")" << status << R"(","candidate_count":)" << std::dec << count << R"(,"observed_blocks":)"
             << observed_blocks_ << R"(,"restored_stack_blocks":)" << restored_stack_blocks_ << "}\n";
        out_.flush();
        if (!out_)
        {
            throw std::runtime_error("Cannot write OEP report");
        }
    }
}
