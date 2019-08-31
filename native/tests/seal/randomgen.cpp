// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/randomgen.h"
#include "seal/keygenerator.h"
#include <cstdint>
#include <memory>
#include <numeric>
#include <set>

using namespace seal;
using namespace std;

namespace SEALTest
{
    namespace
    {
        class SequentialRandomGenerator : public UniformRandomGenerator
        {
        public:
            ~SequentialRandomGenerator() override = default;

        protected:
            void refill_buffer() override
            {
                iota(
                    reinterpret_cast<uint8_t*>(buffer_.data()),
                    reinterpret_cast<uint8_t*>(buffer_.data()) + buffer_.size(),
                    value);

                // Avoiding MSVC warning C4309
                size_t buffer_byte_count = buffer_byte_count_;
                value += static_cast<uint8_t>(buffer_byte_count);
            }

        private:
            uint8_t value = 0;
        };

        class SequentialRandomGeneratorFactory : public UniformRandomGeneratorFactory
        {
        public:
            shared_ptr<UniformRandomGenerator> create() override
            {
                return make_shared<SequentialRandomGenerator>();
            }
        };
    }

    TEST(RandomGenerator, UniformRandomCreateDefault)
    {
        shared_ptr<UniformRandomGenerator> generator(
            UniformRandomGeneratorFactory::default_factory()->create());
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
        unique_ptr<UniformRandomGenerator> sgen =
            make_unique<SequentialRandomGenerator>();
        array<uint8_t, 4096> value_list;
        iota(value_list.begin(), value_list.end(), 0);

        array<uint8_t, 4096> compare_list;
        sgen->generate(4096, reinterpret_cast<SEAL_BYTE*>(compare_list.data()));

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
}
