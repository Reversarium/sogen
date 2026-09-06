#include "std_include.hpp"
#include "runtime_snapshot.hpp"
#include "windows_emulator.hpp"

#include <array>
#include <chrono>
#include <fstream>
#include <limits>
#include <span>

namespace sogen
{
    namespace
    {
        class writer
        {
          public:
            explicit writer(const std::filesystem::path& path)
                : output_(path, std::ios::binary | std::ios::trunc)
            {
                output_.exceptions(std::ios::badbit | std::ios::failbit);
            }

            void bytes(const void* data, const size_t size)
            {
                output_.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
            }

            template <typename T>
            void integer(T value)
            {
                std::array<uint8_t, sizeof(T)> buffer{};
                for (auto& byte : buffer)
                {
                    byte = static_cast<uint8_t>(value & 255);
                    value >>= 8;
                }
                bytes(buffer.data(), buffer.size());
            }

            void string(const std::string_view value)
            {
                if (value.size() > std::numeric_limits<uint32_t>::max())
                {
                    throw std::runtime_error("Snapshot string is too long");
                }
                integer(static_cast<uint32_t>(value.size()));
                bytes(value.data(), value.size());
            }

            void blob(const std::span<const std::byte> value)
            {
                integer(static_cast<uint64_t>(value.size()));
                bytes(value.data(), value.size());
            }

            uint64_t finish(const uint32_t regions)
            {
                const auto size = output_.tellp();
                output_.seekp(32);
                integer(regions);
                output_.close();
                return static_cast<uint64_t>(size);
            }

          private:
            std::ofstream output_;
        };

        struct captured_register
        {
            std::string name;
            std::vector<std::byte> bytes;
        };

        bool capture_register(x86_64_cpu& cpu, const x86_register id, std::string name, const size_t size,
                              std::vector<captured_register>& registers)
        {
            std::array<std::byte, 64> value{};
            try
            {
                if (cpu.read_register(id, value.data(), value.size()) != size)
                {
                    return false;
                }
            }
            catch (const std::runtime_error&)
            {
                return false;
            }
            const auto captured = std::span(value).first(size);
            registers.push_back({.name = std::move(name), .bytes = {captured.begin(), captured.end()}});
            return true;
        }

        void capture_table(x86_64_cpu& cpu, const x86_register id, const std::string& prefix, std::vector<captured_register>& registers,
                           runtime_snapshot_metrics& metrics)
        {
            cpu_interface::descriptor_table_register table{};
            if (!cpu.read_descriptor_table(static_cast<int>(id), table))
            {
                metrics.unavailable_registers.push_back(prefix);
                return;
            }
            if (table.limit > std::numeric_limits<uint16_t>::max())
            {
                throw std::runtime_error("Descriptor table limit exceeds its architectural width");
            }
            std::vector<std::byte> base(8);
            std::vector<std::byte> limit(2);
            for (size_t i = 0; i < base.size(); ++i)
            {
                base.at(i) = static_cast<std::byte>((table.base >> (8 * i)) & 255);
            }
            for (size_t i = 0; i < limit.size(); ++i)
            {
                limit.at(i) = static_cast<std::byte>((table.limit >> (8 * i)) & 255);
            }
            registers.push_back({.name = prefix + "base", .bytes = std::move(base)});
            registers.push_back({.name = prefix + "limit", .bytes = std::move(limit)});
        }

        std::vector<captured_register> capture_context(windows_emulator& win, runtime_snapshot_metrics& metrics)
        {
            auto& cpu = win.active_cpu();
            std::vector<captured_register> registers{};
            const auto scalar = [&](const x86_register id, const std::string& name, const size_t size) {
                if (!capture_register(cpu, id, name, size, registers))
                {
                    metrics.unavailable_registers.push_back(name);
                }
            };

            struct scalar_register
            {
                x86_register id;
                const char* name;
                size_t size;
            };

            constexpr std::array scalars{scalar_register{.id = x86_register::rax, .name = "rax", .size = 8},
                                         scalar_register{.id = x86_register::rbx, .name = "rbx", .size = 8},
                                         scalar_register{.id = x86_register::rcx, .name = "rcx", .size = 8},
                                         scalar_register{.id = x86_register::rdx, .name = "rdx", .size = 8},
                                         scalar_register{.id = x86_register::rsi, .name = "rsi", .size = 8},
                                         scalar_register{.id = x86_register::rdi, .name = "rdi", .size = 8},
                                         scalar_register{.id = x86_register::rbp, .name = "rbp", .size = 8},
                                         scalar_register{.id = x86_register::rsp, .name = "rsp", .size = 8},
                                         scalar_register{.id = x86_register::rip, .name = "rip", .size = 8},
                                         scalar_register{.id = x86_register::rflags, .name = "rflags", .size = 8},
                                         scalar_register{.id = x86_register::cs, .name = "cs", .size = 2},
                                         scalar_register{.id = x86_register::ds, .name = "ds", .size = 2},
                                         scalar_register{.id = x86_register::es, .name = "es", .size = 2},
                                         scalar_register{.id = x86_register::ss, .name = "ss", .size = 2},
                                         scalar_register{.id = x86_register::fs, .name = "fs", .size = 2},
                                         scalar_register{.id = x86_register::gs, .name = "gs", .size = 2},
                                         scalar_register{.id = x86_register::fs_base, .name = "fsbase", .size = 8},
                                         scalar_register{.id = x86_register::gs_base, .name = "gsbase", .size = 8},
                                         scalar_register{.id = x86_register::fpsw, .name = "fpsw", .size = 2},
                                         scalar_register{.id = x86_register::fpcw, .name = "fpcw", .size = 2},
                                         scalar_register{.id = x86_register::fptag, .name = "fptag", .size = 2},
                                         scalar_register{.id = x86_register::fip, .name = "fip", .size = 8},
                                         scalar_register{.id = x86_register::fdp, .name = "fdp", .size = 8},
                                         scalar_register{.id = x86_register::fcs, .name = "fcs", .size = 2},
                                         scalar_register{.id = x86_register::fds, .name = "fds", .size = 2},
                                         scalar_register{.id = x86_register::fop, .name = "fop", .size = 2},
                                         scalar_register{.id = x86_register::mxcsr, .name = "mxcsr", .size = 4},
                                         scalar_register{.id = x86_register::xcr0, .name = "xcr0", .size = 8},
                                         scalar_register{.id = x86_register::cr0, .name = "cr0", .size = 8},
                                         scalar_register{.id = x86_register::cr2, .name = "cr2", .size = 8},
                                         scalar_register{.id = x86_register::cr3, .name = "cr3", .size = 8},
                                         scalar_register{.id = x86_register::cr4, .name = "cr4", .size = 8},
                                         scalar_register{.id = x86_register::cr8, .name = "cr8", .size = 8}};
            for (const auto& reg : scalars)
            {
                scalar(reg.id, reg.name, reg.size);
            }
            for (int i = 0; i < 8; ++i)
            {
                scalar(static_cast<x86_register>(static_cast<int>(x86_register::r8) + i), "r" + std::to_string(i + 8), 8);
                scalar(static_cast<x86_register>(static_cast<int>(x86_register::fp0) + i), "x87r" + std::to_string(i), 10);
                scalar(static_cast<x86_register>(static_cast<int>(x86_register::k0) + i), "k" + std::to_string(i), 8);
                if (i != 4 && i != 5)
                {
                    scalar(static_cast<x86_register>(static_cast<int>(x86_register::dr0) + i), "dr" + std::to_string(i), 8);
                }
            }
            for (int i = 0; i < 32; ++i)
            {
                bool captured{};
                for (const auto& [first, prefix, size] : {std::tuple{x86_register::zmm0, "zmm", size_t{64}},
                                                          {x86_register::ymm0, "ymm", size_t{32}},
                                                          {x86_register::xmm0, "xmm", size_t{16}}})
                {
                    if (capture_register(cpu, static_cast<x86_register>(static_cast<int>(first) + i), prefix + std::to_string(i), size,
                                         registers))
                    {
                        captured = true;
                        break;
                    }
                }
                if (!captured)
                {
                    metrics.unavailable_registers.push_back("vector" + std::to_string(i));
                }
            }
            capture_table(cpu, x86_register::gdtr, "gdtr", registers, metrics);
            capture_table(cpu, x86_register::idtr, "idtr", registers, metrics);
            return registers;
        }

        std::vector<std::byte> pe_headers(const mapped_module& module)
        {
            std::ifstream file(module.path, std::ios::binary | std::ios::ate);
            if (!file)
            {
                return {};
            }
            const auto file_size = file.tellg();
            std::array<uint8_t, 64> dos{};
            file.seekg(0);
            file.read(reinterpret_cast<char*>(dos.data()), dos.size());
            if (!file || dos.at(0) != 'M' || dos.at(1) != 'Z')
            {
                return {};
            }
            uint32_t nt_offset{};
            memcpy(&nt_offset, dos.data() + 60, sizeof(nt_offset));
            if (static_cast<uint64_t>(nt_offset) + 88 > static_cast<uint64_t>(file_size))
            {
                return {};
            }
            file.seekg(nt_offset);
            uint32_t signature{};
            file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
            if (signature != 0x4550)
            {
                return {};
            }
            file.seekg(static_cast<std::streamoff>(nt_offset) + 84);
            uint32_t size{};
            file.read(reinterpret_cast<char*>(&size), sizeof(size));
            if (!file || size < static_cast<uint64_t>(nt_offset) + 88 || size > module.size_of_image ||
                size > static_cast<uint64_t>(file_size))
            {
                return {};
            }
            std::vector<std::byte> bytes(size);
            file.seekg(0);
            file.read(reinterpret_cast<char*>(bytes.data()), size);
            return file ? bytes : std::vector<std::byte>{};
        }

        void write_region(writer& out, windows_emulator& win, const uint64_t address, const size_t size,
                          const memory_permission permissions, const bool observable, runtime_snapshot_metrics& metrics)
        {
            std::vector<std::byte> bytes(size);
            if (!observable || !win.memory.try_read_memory(address, bytes.data(), bytes.size()))
            {
                if (observable && size > 4096)
                {
                    for (size_t offset = 0; offset < size; offset += 4096)
                    {
                        write_region(out, win, address + offset, std::min(size - offset, size_t{4096}), permissions, true, metrics);
                    }
                    return;
                }
                bytes.clear();
            }
            if (metrics.regions == std::numeric_limits<uint32_t>::max())
            {
                throw std::runtime_error("Too many snapshot regions");
            }
            ++metrics.regions;
            metrics.mapped_bytes += size;
            metrics.captured_bytes += bytes.size();
            for (const auto byte : bytes)
            {
                metrics.memory_hash ^= std::to_integer<uint8_t>(byte);
                metrics.memory_hash *= 1099511628211ULL;
            }
            out.integer(address);
            out.integer(static_cast<uint64_t>(size));
            out.integer(static_cast<uint32_t>(permissions));
            out.blob(bytes);
        }
    }

    runtime_snapshot_metrics write_runtime_snapshot(windows_emulator& win, const uint64_t start, const std::filesystem::path& path)
    {
        const auto begin = std::chrono::steady_clock::now();
        if (win.vcpu_count() != 1 || win.mod_manager.get_execution_mode() != execution_mode::native_64bit)
        {
            throw std::runtime_error("Runtime snapshot capture currently requires one x64 vCPU");
        }
        if (win.active_cpu().read_instruction_pointer() != start)
        {
            throw std::runtime_error("Snapshot start does not match the active instruction pointer");
        }
        runtime_snapshot_metrics metrics{};
        const auto registers = capture_context(win, metrics);
        metrics.registers = static_cast<uint32_t>(registers.size());
        metrics.modules = static_cast<uint32_t>(win.mod_manager.modules().size());
        writer out(path);
        out.bytes("RVSNAP01", 8);
        out.integer(uint32_t{1});
        out.integer(uint32_t{0x8664});
        out.integer(start);
        out.integer(metrics.modules);
        out.integer(metrics.registers);
        out.integer(uint32_t{0});
        uint32_t id{};
        for (const auto& [base, module] : win.mod_manager.modules())
        {
            out.integer(++id);
            out.integer(base);
            out.integer(module.size_of_image);
            out.string(module.name);
            out.blob(pe_headers(module));
        }
        for (const auto& reg : registers)
        {
            out.string(reg.name);
            out.blob(reg.bytes);
        }
        for (const auto& [base, reservation] : win.memory.get_reserved_regions())
        {
            if (reservation.kind == memory_region_kind::host_reserved)
            {
                continue;
            }
            for (const auto& [address, region] : reservation.committed_regions)
            {
                for (size_t offset = 0; offset < region.length; offset += 65536)
                {
                    write_region(out, win, address + offset, std::min(region.length - offset, size_t{65536}), region.permissions.common,
                                 reservation.kind != memory_region_kind::mmio, metrics);
                }
            }
        }
        metrics.file_bytes = out.finish(metrics.regions);
        metrics.capture_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - begin).count();
        return metrics;
    }
}
