#include <gtest/gtest.h>
#include <backend_selection.hpp>
#include <memory_manager.hpp>
#include <scoped_hook.hpp>

namespace sogen::test
{
    TEST(DynamicHooks, AddedHooksObservePreviouslyTranslatedInstructionsAndWrites)
    {
        auto cpu = create_x86_64_emulator(backend_type::unicorn);
        memory_manager memory{*cpu};
        const auto code = memory.allocate_memory(0x1000, memory_permission::all);
        const std::array<uint8_t, 9> instructions{0x48, 0x89, 0x05, 0xf9, 0x00, 0x00, 0x00, 0xeb, 0xf7};
        memory.write_memory(code, instructions.data(), instructions.size());
        cpu->reg(x86_register::rip, code);
        cpu->reg(x86_register::rax, uint64_t{42});
        size_t blocks{};
        scoped_hook block_hook(*cpu, cpu->hook_basic_block([&](cpu_interface& running, const basic_block&) {
            ++blocks;
            if (blocks == 2 || blocks == 4)
            {
                running.stop();
            }
        }));
        cpu->start();
        ASSERT_EQ(cpu->read_memory<uint64_t>(code + 0x100), 42u);
        std::vector<uint64_t> addresses{};
        size_t writes{};
        scoped_hook code_hook(*cpu, cpu->hook_memory_execution([&](cpu_interface& running, uint64_t address) {
            addresses.push_back(address);
            if (address == code + 7)
            {
                running.stop();
            }
        }));
        scoped_hook write_hook(*cpu,
                               cpu->hook_memory_write(code + 0x100, 8, [&](cpu_interface&, uint64_t address, const void*, size_t size) {
                                   EXPECT_EQ(address, code + 0x100);
                                   EXPECT_EQ(size, 8u);
                                   ++writes;
                               }));
        cpu->reg(x86_register::rip, code);
        cpu->start();
        EXPECT_EQ(addresses, (std::vector<uint64_t>{code, code + 7}));
        EXPECT_EQ(writes, 1u);
    }
}
