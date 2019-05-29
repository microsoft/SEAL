// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdexcept>
#include "gtest/gtest.h"
#include "seal/modulus.h"
#include "seal/util/uintcore.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
    TEST(CoeffModTest, CustomExceptionTest)
    {
        // Too small poly_modulus_degree
        ASSERT_THROW(CoeffModulus::Create(1, { 2 }), invalid_argument);

        // Too large poly_modulus_degree
        ASSERT_THROW(CoeffModulus::Create(65536, { 30 }), invalid_argument);

        // Invalid poly_modulus_degree
        ASSERT_THROW(CoeffModulus::Create(1023, { 20 }), invalid_argument);

        // Invalid bit-size
        ASSERT_THROW(CoeffModulus::Create(2048, { 0 }), invalid_argument);
        ASSERT_THROW(CoeffModulus::Create(2048, { -30 }), invalid_argument);
        ASSERT_THROW(CoeffModulus::Create(2048, { 30, -30 }), invalid_argument);

        // Too small primes requested
        ASSERT_THROW(CoeffModulus::Create(2, { 2 }), logic_error);
        ASSERT_THROW(CoeffModulus::Create(2, { 3, 3, 3 }), logic_error);
        ASSERT_THROW(CoeffModulus::Create(1024, { 8 }), logic_error);
    }

    TEST(CoeffModTest, CustomTest)
    {
        auto cm = CoeffModulus::Create(2, { });
        ASSERT_EQ(0, cm.size());

        cm = CoeffModulus::Create(2, { 3 });
        ASSERT_EQ(1, cm.size());
        ASSERT_EQ(uint64_t(5), cm[0].value());

        cm = CoeffModulus::Create(2, { 3, 4 });
        ASSERT_EQ(2, cm.size());
        ASSERT_EQ(uint64_t(5), cm[0].value());
        ASSERT_EQ(uint64_t(13), cm[1].value());

        cm = CoeffModulus::Create(2, { 3, 5, 4, 5 });
        ASSERT_EQ(4, cm.size());
        ASSERT_EQ(uint64_t(5), cm[0].value());
        ASSERT_EQ(uint64_t(17), cm[1].value());
        ASSERT_EQ(uint64_t(13), cm[2].value());
        ASSERT_EQ(uint64_t(29), cm[3].value());

        cm = CoeffModulus::Create(32, { 30, 40, 30, 30, 40 });
        ASSERT_EQ(5, cm.size());
        ASSERT_EQ(30, get_significant_bit_count(cm[0].value()));
        ASSERT_EQ(40, get_significant_bit_count(cm[1].value()));
        ASSERT_EQ(30, get_significant_bit_count(cm[2].value()));
        ASSERT_EQ(30, get_significant_bit_count(cm[3].value()));
        ASSERT_EQ(40, get_significant_bit_count(cm[4].value()));
        ASSERT_EQ(1ULL, cm[0].value() % 64);
        ASSERT_EQ(1ULL, cm[1].value() % 64);
        ASSERT_EQ(1ULL, cm[2].value() % 64);
        ASSERT_EQ(1ULL, cm[3].value() % 64);
        ASSERT_EQ(1ULL, cm[4].value() % 64);
    }
}