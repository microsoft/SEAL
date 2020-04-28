// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/keygenerator.h"
#include "seal/randomgen.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <numeric>
#include <set>
#include <thread>
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    namespace
    {
        class SequentialRandomGenerator : public UniformRandomGenerator
        {
        public:
            SequentialRandomGenerator() : UniformRandomGenerator({})
            {}

            ~SequentialRandomGenerator() override = default;

        protected:
            void refill_buffer() override
            {
                iota(reinterpret_cast<uint8_t *>(buffer_begin_), reinterpret_cast<uint8_t *>(buffer_end_), value);

                value = static_cast<uint8_t>(static_cast<size_t>(value) + buffer_size_);
            }

        private:
            uint8_t value = 0;
        };

        class SequentialRandomGeneratorFactory : public UniformRandomGeneratorFactory
        {
        private:
            SEAL_NODISCARD auto create_impl(SEAL_MAYBE_UNUSED random_seed_type seed)
                -> shared_ptr<UniformRandomGenerator> override
            {
                return make_shared<SequentialRandomGenerator>();
            }
        };
    } // namespace

    TEST(RandomGenerator, UniformRandomCreateDefault)
    {
        shared_ptr<UniformRandomGenerator> generator(UniformRandomGeneratorFactory::DefaultFactory()->create());
        bool lower_half = false;
        bool upper_half = false;
        bool even = false;
        bool odd = false;
        for (int i = 0; i < 10; ++i)
        {
            uint32_t value = generator->generate();
            if (value < UINT32_MAX / 2)
            {
                lower_half = true;
            }
            else
            {
                upper_half = true;
            }
            if ((value % 2) == 0)
            {
                even = true;
            }
            else
            {
                odd = true;
            }
        }
        ASSERT_TRUE(lower_half);
        ASSERT_TRUE(upper_half);
        ASSERT_TRUE(even);
        ASSERT_TRUE(odd);
    }

    TEST(RandomGenerator, SequentialRandomGenerator)
    {
        unique_ptr<UniformRandomGenerator> sgen = make_unique<SequentialRandomGenerator>();
        array<uint8_t, 4096> value_list;
        iota(value_list.begin(), value_list.end(), 0);

        array<uint8_t, 4096> compare_list;
        sgen->generate(4096, reinterpret_cast<SEAL_BYTE *>(compare_list.data()));

        ASSERT_TRUE(equal(value_list.cbegin(), value_list.cend(), compare_list.cbegin()));
    }

    TEST(RandomGenerator, RandomUInt64)
    {
        set<uint64_t> values;
        size_t count = 100;
        for (size_t i = 0; i < count; i++)
        {
            values.emplace(random_uint64());
        }
        ASSERT_EQ(count, values.size());
    }

    TEST(RandomGenerator, SeededRNG)
    {
        auto generator1(UniformRandomGeneratorFactory::DefaultFactory()->create({}));
        array<uint32_t, 20> values1;
        generator1->generate(sizeof(values1), reinterpret_cast<SEAL_BYTE *>(values1.data()));

        auto generator2(UniformRandomGeneratorFactory::DefaultFactory()->create({ 1 }));
        array<uint32_t, 20> values2;
        generator2->generate(sizeof(values2), reinterpret_cast<SEAL_BYTE *>(values2.data()));

        auto generator3(UniformRandomGeneratorFactory::DefaultFactory()->create({ 1 }));
        array<uint32_t, 20> values3;
        generator3->generate(sizeof(values3), reinterpret_cast<SEAL_BYTE *>(values3.data()));

        for (size_t i = 0; i < values1.size(); i++)
        {
            ASSERT_NE(values1[i], values2[i]);
            ASSERT_EQ(values2[i], values3[i]);
        }

        uint32_t val1, val2, val3;
        val1 = generator1->generate();
        val2 = generator2->generate();
        val3 = generator3->generate();
        ASSERT_NE(val1, val2);
        ASSERT_EQ(val2, val3);
    }

    TEST(RandomGenerator, RandomSeededRNG)
    {
        auto generator1(UniformRandomGeneratorFactory::DefaultFactory()->create());
        array<uint32_t, 20> values1;
        generator1->generate(sizeof(values1), reinterpret_cast<SEAL_BYTE *>(values1.data()));

        auto generator2(UniformRandomGeneratorFactory::DefaultFactory()->create());
        array<uint32_t, 20> values2;
        generator2->generate(sizeof(values2), reinterpret_cast<SEAL_BYTE *>(values2.data()));

        auto seed3 = generator2->seed();
        auto generator3(UniformRandomGeneratorFactory::DefaultFactory()->create(seed3));
        array<uint32_t, 20> values3;
        generator3->generate(sizeof(values3), reinterpret_cast<SEAL_BYTE *>(values3.data()));

        for (size_t i = 0; i < values1.size(); i++)
        {
            ASSERT_NE(values1[i], values2[i]);
            ASSERT_EQ(values2[i], values3[i]);
        }

        uint32_t val1, val2, val3;
        val1 = generator1->generate();
        val2 = generator2->generate();
        val3 = generator3->generate();
        ASSERT_NE(val1, val2);
        ASSERT_EQ(val2, val3);
    }

    TEST(RandomGenerator, MultiThreaded)
    {
        constexpr size_t thread_count = 2;
        constexpr size_t numbers_per_thread = 50;
        array<uint64_t, thread_count * numbers_per_thread> results;

        auto generator(UniformRandomGeneratorFactory::DefaultFactory()->create());

        vector<thread> th_vec;
        for (size_t i = 0; i < thread_count; i++)
        {
            auto th_func = [&, generator, i]() {
                generator->generate(
                    sizeof(uint64_t) * numbers_per_thread,
                    reinterpret_cast<SEAL_BYTE *>(results.data() + numbers_per_thread * i));
            };
            th_vec.emplace_back(th_func);
        }

        for (auto &th : th_vec)
        {
            th.join();
        }

        auto seed = generator->seed();
        auto generator2(UniformRandomGeneratorFactory::DefaultFactory()->create(seed));
        for (size_t i = 0; i < thread_count * numbers_per_thread; i++)
        {
            uint64_t value = 0;
            generator2->generate(sizeof(value), reinterpret_cast<SEAL_BYTE *>(&value));
            ASSERT_TRUE(find(results.begin(), results.end(), value) != results.end());
        }
    }
} // namespace sealtest
