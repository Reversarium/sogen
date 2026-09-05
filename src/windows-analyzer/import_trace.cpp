#include "std_include.hpp"
#include "import_trace.hpp"

#include <iomanip>
#include <limits>
#include <utils/io.hpp>

namespace sogen
{
    namespace
    {
        constexpr std::array registers{x86_register::rax, x86_register::rcx, x86_register::rdx, x86_register::rbx,
                                       x86_register::rsp, x86_register::rbp, x86_register::rsi, x86_register::rdi,
                                       x86_register::r8,  x86_register::r9,  x86_register::r10, x86_register::r11,
                                       x86_register::r12, x86_register::r13, x86_register::r14, x86_register::r15};
        constexpr std::array xmm_registers{x86_register::xmm0,  x86_register::xmm1,  x86_register::xmm2,  x86_register::xmm3,
                                           x86_register::xmm4,  x86_register::xmm5,  x86_register::xmm6,  x86_register::xmm7,
                                           x86_register::xmm8,  x86_register::xmm9,  x86_register::xmm10, x86_register::xmm11,
                                           x86_register::xmm12, x86_register::xmm13, x86_register::xmm14, x86_register::xmm15};

        std::string json_string(std::string_view value)
        {
            std::ostringstream result{};
            result << '"';
            for (const auto character : value)
            {
                const auto byte = static_cast<unsigned char>(character);
                if (byte == '"' || byte == '\\')
                {
                    result << '\\' << character;
                }
                else if (byte < 32)
                {
                    result << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
                }
                else
                {
                    result << character;
                }
            }
            result << '"';
            return result.str();
        }
    }

    import_trace::import_trace(windows_emulator& win, std::filesystem::path directory, bool from_entry)
        : win_(win),
          directory_(std::move(directory))
    {
        if (win_.mod_manager.get_execution_mode() != execution_mode::native_64bit || win_.emu().get_name() != "Unicorn Engine")
        {
            throw std::runtime_error("Import tracing currently requires x64 and the Unicorn backend");
        }
        std::filesystem::create_directories(directory_);
        out_.open(directory_ / "trace.jsonl");
        if (!out_)
        {
            throw std::runtime_error("Cannot open import trace");
        }
        if (from_entry)
        {
            entry_hook_ =
                scoped_hook(win_.emu(), win_.emu().hook_memory_execution(win_.mod_manager.executable->entry_point,
                                                                         [this](cpu_interface& cpu, uint64_t address) {
                                                                             win_.dispatch_on_cpu(cpu, [&] { request_start(address); });
                                                                         }));
        }
    }

    void import_trace::request_start(uint64_t address)
    {
        ++candidate_count_;
        if (!active_ && !pending_)
        {
            pending_ = address;
            win_.stop();
        }
    }

    void import_trace::emit_header(std::string_view event)
    {
        out_ << "{\"event\":" << json_string(event) << ",\"sequence\":" << instructions_ << ",\"thread\":" << win_.current_thread().id;
    }

    void import_trace::emit_bytes(std::span<const uint8_t> bytes)
    {
        constexpr std::string_view digits = "0123456789abcdef";
        out_ << '"';
        for (auto byte : bytes)
        {
            out_ << digits.at(byte >> 4) << digits.at(byte & 15);
        }
        out_ << '"';
    }

    void import_trace::emit_context()
    {
        auto& cpu = win_.active_cpu();
        out_ << ",\"gpr\":[";
        for (size_t i = 0; i < registers.size(); ++i)
        {
            if (i)
            {
                out_ << ',';
            }
            out_ << cpu.reg<uint64_t>(registers.at(i));
        }
        out_ << "],\"xmm\":[";
        for (size_t i = 0; i < xmm_registers.size(); ++i)
        {
            if (i)
            {
                out_ << ',';
            }
            const auto value = cpu.reg<std::array<uint64_t, 2>>(xmm_registers.at(i));
            out_ << '[' << value.at(0) << ',' << value.at(1) << ']';
        }
        const auto& thread = win_.current_thread();
        const auto rsp = cpu.reg<uint64_t>(x86_register::rsp);
        const auto end = thread.stack_base + thread.stack_size;
        const auto count = rsp >= thread.stack_base && rsp < end ? std::min<uint64_t>(end - rsp, 264) : 0;
        std::vector<uint8_t> stack(static_cast<size_t>(count));
        if (!count || !cpu.try_read_memory(rsp, stack.data(), stack.size()))
        {
            stack.clear();
        }
        out_ << "],\"stack\":";
        emit_bytes(stack);
        out_ << ",\"stack_base\":" << thread.stack_base << ",\"stack_end\":" << end;
    }

    void import_trace::write_image()
    {
        const auto& exe = *win_.mod_manager.executable;
        std::vector<uint8_t> bytes(static_cast<size_t>(exe.size_of_image));
        for (size_t offset = 0; offset < bytes.size(); offset += 0x1000)
        {
            const auto length = std::min<size_t>(0x1000, bytes.size() - offset);
            if (!win_.active_cpu().try_read_memory(exe.image_base + offset, bytes.data() + offset, length))
            {
                throw std::runtime_error("Cannot read complete image at import trace start");
            }
        }
        if (!utils::io::write_file(directory_ / "image.bin", std::as_bytes(std::span(bytes))))
        {
            throw std::runtime_error("Cannot write import trace image");
        }
    }

    bool import_trace::resume_pending()
    {
        if (!pending_)
        {
            return false;
        }
        start_address_ = *pending_;
        if (win_.active_cpu().read_instruction_pointer() != start_address_)
        {
            throw std::runtime_error("Import trace did not stop at the requested instruction");
        }
        pending_.reset();
        entry_hook_.remove();
        active_ = true;
        const auto& exe = *win_.mod_manager.executable;
        write_image();
        emit_header("start");
        out_ << ",\"address\":" << start_address_ << ",\"image_base\":" << exe.image_base << ",\"preferred_base\":" << exe.image_base_file
             << ",\"image_size\":" << exe.size_of_image;
        emit_context();
        out_ << "}\n";
        for (const auto& [base, mod] : win_.mod_manager.modules())
        {
            for (const auto& symbol : mod.exports)
            {
                out_ << R"({"event":"export","module":)" << json_string(mod.name) << ",\"name\":" << json_string(symbol.name)
                     << ",\"ordinal\":" << symbol.ordinal << ",\"address\":" << symbol.address << "}\n";
            }
        }
        execute_hook_ = scoped_hook(win_.emu(), win_.emu().hook_memory_execution([this](cpu_interface& cpu, uint64_t address) {
            win_.dispatch_on_cpu(cpu, [&] { observe_instruction(address); });
        }));
        write_hook_ =
            scoped_hook(win_.emu(), win_.emu().hook_memory_write(0, std::numeric_limits<uint64_t>::max(),
                                                                 [this](cpu_interface& cpu, uint64_t address, const void*, size_t size) {
                                                                     win_.dispatch_on_cpu(cpu, [&] {
                                                                         if (win_.mod_manager.executable->contains(previous_address_) &&
                                                                             previous_thread_ == win_.current_thread().id)
                                                                         {
                                                                             emit_header("write");
                                                                             out_ << ",\"ip\":" << previous_address_
                                                                                  << ",\"address\":" << address
                                                                                  << ",\"size\":" << std::max(size, write_width_) << "}\n";
                                                                         }
                                                                     });
                                                                 }));
        return true;
    }

    void import_trace::observe_instruction(uint64_t address)
    {
        if (++instructions_ > 10000000)
        {
            throw std::runtime_error("Import trace exceeded ten million instructions");
        }
        const auto& exe = *win_.mod_manager.executable;
        auto& cpu = win_.active_cpu();
        const auto thread = win_.current_thread().id;
        if (exe.contains(address))
        {
            ++image_instructions_;
            std::array<uint8_t, 16> bytes{};
            if (!cpu.try_read_memory(address, bytes.data(), bytes.size()))
            {
                throw std::runtime_error("Cannot read traced instruction");
            }
            const auto decoded = disassembler_.disassemble(cpu, cpu.reg<uint16_t>(x86_register::cs), bytes, 1, address);
            if (decoded.empty())
            {
                throw std::runtime_error("Cannot decode traced instruction");
            }
            const auto& inst = *decoded.begin();
            write_width_ = 0;
            for (size_t index = 0; index < inst.detail->x86.op_count; ++index)
            {
                const auto& operand = inst.detail->x86.operands[index];
                if (operand.type == X86_OP_MEM)
                {
                    write_width_ = std::max(write_width_, static_cast<size_t>(operand.size));
                }
            }
            emit_header("instruction");
            out_ << ",\"address\":" << address << ",\"size\":" << inst.size << ",\"mnemonic\":" << json_string(inst.mnemonic)
                 << ",\"bytes\":";
            emit_bytes(std::span(bytes).first(inst.size));
            emit_context();
            out_ << "}\n";
        }
        else if (exe.contains(previous_address_) && previous_thread_ == thread)
        {
            const auto* mod = win_.mod_manager.find_by_address(address);
            const auto* name = mod && mod->address_names.contains(address) ? &mod->address_names.at(address) : nullptr;
            emit_header(name ? "api" : "escape");
            out_ << ",\"address\":" << address << ",\"from\":" << previous_address_ << ",\"module\":" << json_string(mod ? mod->name : "")
                 << ",\"name\":" << json_string(name ? *name : "");
            emit_context();
            out_ << "}\n" << std::flush;
        }
        previous_address_ = address;
        previous_thread_ = thread;
    }

    void import_trace::finish(bool completed)
    {
        out_ << R"({"event":"result","completed":)" << (completed ? "true" : "false") << ",\"started\":" << (active_ ? "true" : "false")
             << ",\"candidate_count\":" << candidate_count_ << ",\"instructions\":" << instructions_
             << ",\"image_instructions\":" << image_instructions_ << "}\n";
        out_.flush();
        if (!out_)
        {
            throw std::runtime_error("Cannot write import trace");
        }
    }
}
