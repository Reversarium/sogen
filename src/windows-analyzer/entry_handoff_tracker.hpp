#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <set>

namespace sogen
{
    struct entry_context
    {
        uint64_t rsp{};
        uint64_t return_address{};
        std::array<uint64_t, 8> nonvolatile{};
        std::array<std::array<uint64_t, 2>, 10> xmm{};

        bool operator==(const entry_context&) const = default;
    };

    class entry_handoff_tracker
    {
      public:
        void capture(uint32_t thread, uint64_t address, const entry_context& context)
        {
            if (entry_)
            {
                return;
            }
            thread_ = thread;
            entry_address_ = address;
            entry_ = context;
        }

        bool observe(uint32_t thread, uint64_t address, const entry_context& context)
        {
            if (!entry_ || thread != thread_)
            {
                return false;
            }
            if (context.rsp != entry_->rsp)
            {
                departed_ = true;
                return false;
            }
            if (!departed_ || address == entry_address_ || context != *entry_)
            {
                return false;
            }
            return candidates_.insert(address).second;
        }

        const std::optional<entry_context>& entry() const
        {
            return entry_;
        }

        const std::set<uint64_t>& candidates() const
        {
            return candidates_;
        }

        uint32_t thread() const
        {
            return thread_;
        }

      private:
        std::optional<entry_context> entry_{};
        uint32_t thread_{};
        uint64_t entry_address_{};
        bool departed_{};
        std::set<uint64_t> candidates_{};
    };
}
