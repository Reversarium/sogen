#include <gtest/gtest.h>
#include "../windows-analyzer/entry_handoff_tracker.hpp"

namespace sogen::test
{
    namespace
    {
        entry_context make_entry_context()
        {
            entry_context context{.rsp = 0x100008, .return_address = 0x7ff00000};
            for (size_t i = 0; i < context.nonvolatile.size(); ++i)
            {
                context.nonvolatile.at(i) = 0x12340000 + i;
            }
            for (size_t i = 0; i < context.xmm.size(); ++i)
            {
                context.xmm.at(i) = {i + 10, i + 20};
            }
            return context;
        }

        entry_handoff_tracker departed_tracker(const entry_context& context)
        {
            entry_handoff_tracker tracker{};
            tracker.capture(7, 0x140030000, context);
            auto nested = context;
            nested.rsp -= 0x180;
            EXPECT_FALSE(tracker.observe(7, 0x140040000, nested));
            return tracker;
        }
    }

    TEST(EntryHandoff, RequiresEntryAndStackExcursion)
    {
        entry_handoff_tracker tracker{};
        const auto context = make_entry_context();
        EXPECT_FALSE(tracker.observe(7, 0x4000, context));
        tracker.capture(7, 0x3000, context);
        EXPECT_FALSE(tracker.observe(7, 0x4000, context));
    }

    TEST(EntryHandoff, RejectsPartialRestoration)
    {
        const auto context = make_entry_context();
        auto tracker = departed_tracker(context);
        for (size_t i = 0; i < context.nonvolatile.size(); ++i)
        {
            auto changed = context;
            changed.nonvolatile.at(i) ^= 1;
            EXPECT_FALSE(tracker.observe(7, 0x4000, changed));
        }
        for (size_t i = 0; i < context.xmm.size(); ++i)
        {
            auto changed = context;
            changed.xmm.at(i).at(1) ^= 1;
            EXPECT_FALSE(tracker.observe(7, 0x4000, changed));
        }
        auto changed = context;
        changed.return_address ^= 8;
        EXPECT_FALSE(tracker.observe(7, 0x4000, changed));
        EXPECT_TRUE(tracker.candidates().empty());
    }

    TEST(EntryHandoff, IgnoresOtherThreadsAndReentry)
    {
        const auto context = make_entry_context();
        auto tracker = departed_tracker(context);
        EXPECT_FALSE(tracker.observe(8, 0x4000, context));
        EXPECT_FALSE(tracker.observe(7, 0x140030000, context));
        tracker.capture(8, 0x8000, {});
        EXPECT_TRUE(tracker.observe(7, 0x4000, context));
    }

    TEST(EntryHandoff, AcceptsDestinationOutsideOriginalImage)
    {
        const auto context = make_entry_context();
        auto tracker = departed_tracker(context);
        EXPECT_TRUE(tracker.observe(7, 0x200000000, context));
        EXPECT_EQ(tracker.candidates(), std::set<uint64_t>{0x200000000});
    }

    TEST(EntryHandoff, RetainsAmbiguityInsteadOfPickingFirst)
    {
        const auto context = make_entry_context();
        auto tracker = departed_tracker(context);
        EXPECT_TRUE(tracker.observe(7, 0x4000, context));
        EXPECT_FALSE(tracker.observe(7, 0x4000, context));
        EXPECT_TRUE(tracker.observe(7, 0x5000, context));
        EXPECT_EQ(tracker.candidates().size(), 2);
    }
}
