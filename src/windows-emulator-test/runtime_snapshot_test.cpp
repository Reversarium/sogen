#include "emulation_test_utils.hpp"
#include <runtime_snapshot.hpp>

#include <array>
#include <fstream>
#include <map>

namespace sogen::test
{
    namespace
    {
        class snapshot_file
        {
          public:
            snapshot_file()
                : path(std::filesystem::temp_directory_path() /
                       ("sogen-capture-" + std::to_string(getpid()) + "-" +
                        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".rvs"))
            {
            }

            ~snapshot_file()
            {
                std::error_code ignored{};
                std::filesystem::remove(path, ignored);
            }

            std::filesystem::path path;
        };

        template <typename T>
        T read_integer(std::istream& input)
        {
            T result{};
            for (size_t i = 0; i < sizeof(T); ++i)
            {
                const auto byte = input.get();
                if (byte < 0)
                {
                    throw std::runtime_error("Truncated capture");
                }
                result |= static_cast<T>(byte) << (8 * i);
            }
            return result;
        }

        std::string read_string(std::istream& input, const uint64_t size)
        {
            std::string result(static_cast<size_t>(size), '\0');
            input.read(result.data(), static_cast<std::streamsize>(result.size()));
            if (!input)
            {
                throw std::runtime_error("Truncated capture string");
            }
            return result;
        }
    }

    TEST(RuntimeSnapshot, CapturesActualRegistersAndAnonymousMemory)
    {
        auto win = create_sample_emulator();
        win.setup_process_if_necessary();
        constexpr uint64_t base = 0x60000000;
        ASSERT_TRUE(win.memory.allocate_memory(base, 8192, memory_permission::read_write));
        const std::array<uint8_t, 8> contents{0, 1, 2, 3, 0xfc, 0xfd, 0xfe, 0xff};
        win.memory.write_memory(base, contents.data(), contents.size());
        ASSERT_TRUE(win.memory.protect_memory(base + 4096, 4096, memory_permission::read_exec));
        auto& cpu = win.active_cpu();
        cpu.reg(x86_register::rip, base);
        cpu.reg(x86_register::r10, uint64_t{0x8877665544332211});
        cpu.reg(x86_register::mxcsr, uint32_t{0x1f80});
        cpu.reg(x86_register::fpcw, uint16_t{0x037f});
        std::array<uint8_t, 64> vector{};
        for (size_t i = 0; i < vector.size(); ++i)
        {
            vector.at(i) = static_cast<uint8_t>(i);
        }
        cpu.write_register(x86_register::zmm3, vector.data(), vector.size());
        cpu.reg(x86_register::fpsw, uint16_t{3 << 11});
        const std::array<uint8_t, 10> x87{1, 2, 3, 4, 5, 6, 7, 0x80, 0xff, 0x3f};
        cpu.write_register(x86_register::fp3, x87.data(), x87.size());

        snapshot_file output{};
        const auto metrics = write_runtime_snapshot(win, base, output.path);
        EXPECT_EQ(cpu.reg<uint64_t>(x86_register::r10), 0x8877665544332211ULL);
        EXPECT_EQ(cpu.read_instruction_pointer(), base);
        EXPECT_EQ(metrics.file_bytes, std::filesystem::file_size(output.path));

        std::ifstream file(output.path, std::ios::binary);
        EXPECT_EQ(read_string(file, 8), "RVSNAP01");
        EXPECT_EQ(read_integer<uint32_t>(file), 1u);
        EXPECT_EQ(read_integer<uint32_t>(file), 0x8664u);
        EXPECT_EQ(read_integer<uint64_t>(file), base);
        const auto modules = read_integer<uint32_t>(file);
        const auto registers = read_integer<uint32_t>(file);
        const auto regions = read_integer<uint32_t>(file);
        EXPECT_EQ(modules, metrics.modules);
        EXPECT_EQ(registers, metrics.registers);
        EXPECT_EQ(regions, metrics.regions);
        for (uint32_t i = 0; i < modules; ++i)
        {
            read_integer<uint32_t>(file);
            read_integer<uint64_t>(file);
            read_integer<uint64_t>(file);
            read_string(file, read_integer<uint32_t>(file));
            read_string(file, read_integer<uint64_t>(file));
        }
        std::map<std::string, std::string> values{};
        for (uint32_t i = 0; i < registers; ++i)
        {
            const auto name = read_string(file, read_integer<uint32_t>(file));
            values.emplace(name, read_string(file, read_integer<uint64_t>(file)));
        }
        EXPECT_EQ(values.at("r10"), (std::string("\x11\x22\x33\x44\x55\x66\x77\x88", 8)));
        EXPECT_EQ(values.at("mxcsr"), (std::string("\x80\x1f\0\0", 4)));
        EXPECT_EQ(values.at("fpcw"), (std::string("\x7f\x03", 2)));
        EXPECT_EQ(values.at("fpsw"), (std::string("\0\x18", 2)));
        EXPECT_EQ(values.at("x87r3"), (std::string(reinterpret_cast<const char*>(x87.data()), x87.size())));
        EXPECT_EQ(values.at("zmm3"), (std::string(reinterpret_cast<const char*>(vector.data()), vector.size())));
        EXPECT_FALSE(values.contains("xmm3"));
        EXPECT_FALSE(values.contains("st3"));
        size_t matched{};
        for (uint32_t i = 0; i < regions; ++i)
        {
            const auto address = read_integer<uint64_t>(file);
            const auto size = read_integer<uint64_t>(file);
            const auto permissions = read_integer<uint32_t>(file);
            const auto bytes = read_string(file, read_integer<uint64_t>(file));
            if (address == base)
            {
                ++matched;
                EXPECT_EQ(size, 4096u);
                EXPECT_EQ(permissions, 3u);
                EXPECT_EQ(bytes.substr(0, contents.size()), (std::string(reinterpret_cast<const char*>(contents.data()), contents.size())));
            }
            if (address == base + 4096)
            {
                ++matched;
                EXPECT_EQ(permissions, 5u);
                EXPECT_EQ(bytes, std::string(4096, '\0'));
            }
        }
        EXPECT_EQ(matched, 2u);
        EXPECT_EQ(file.peek(), std::char_traits<char>::eof());
    }

    TEST(RuntimeSnapshot, RejectsMismatchedStartBeforeCreatingOutput)
    {
        auto win = create_sample_emulator();
        win.setup_process_if_necessary();
        snapshot_file output{};
        EXPECT_THROW(write_runtime_snapshot(win, win.active_cpu().read_instruction_pointer() + 1, output.path), std::runtime_error);
        EXPECT_FALSE(std::filesystem::exists(output.path));
    }

    TEST(RuntimeSnapshot, UnicornDescriptorTableReadsSelectTheRequestedTable)
    {
        auto cpu = create_x86_64_emulator(backend_type::unicorn);
        cpu->load_gdt(0x12340000, 0x100);
        cpu_interface::descriptor_table_register gdt{};
        cpu_interface::descriptor_table_register idt{};
        ASSERT_TRUE(cpu->read_descriptor_table(static_cast<int>(x86_register::gdtr), gdt));
        ASSERT_TRUE(cpu->read_descriptor_table(static_cast<int>(x86_register::idtr), idt));
        EXPECT_EQ(gdt.base, 0x12340000u);
        EXPECT_EQ(gdt.limit, 0x100u);
        EXPECT_EQ(idt.base, 0u);
    }
}
