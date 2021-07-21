// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/modulus.h"
#include "seal/util/uintcore.h"
#include <stdexcept>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    TEST(ModulusTest, CreateModulus)
    {
        Modulus mod;
        ASSERT_TRUE(mod.is_zero());
        ASSERT_EQ(0ULL, mod.value());
        ASSERT_EQ(0, mod.bit_count());
        ASSERT_EQ(1ULL, mod.uint64_count());
        ASSERT_EQ(0ULL, mod.const_ratio()[0]);
        ASSERT_EQ(0ULL, mod.const_ratio()[1]);
        ASSERT_EQ(0ULL, mod.const_ratio()[2]);
        ASSERT_FALSE(mod.is_prime());

        mod = 3;
        ASSERT_FALSE(mod.is_zero());
        ASSERT_EQ(3ULL, mod.value());
        ASSERT_EQ(2, mod.bit_count());
        ASSERT_EQ(1ULL, mod.uint64_count());
        ASSERT_EQ(6148914691236517205ULL, mod.const_ratio()[0]);
        ASSERT_EQ(6148914691236517205ULL, mod.const_ratio()[1]);
        ASSERT_EQ(1ULL, mod.const_ratio()[2]);
        ASSERT_TRUE(mod.is_prime());

        Modulus mod2(2);
        Modulus mod3(3);
        ASSERT_TRUE(mod != mod2);
        ASSERT_TRUE(mod == mod3);

        mod = 0;
        ASSERT_TRUE(mod.is_zero());
        ASSERT_EQ(0ULL, mod.value());
        ASSERT_EQ(0, mod.bit_count());
        ASSERT_EQ(1ULL, mod.uint64_count());
        ASSERT_EQ(0ULL, mod.const_ratio()[0]);
        ASSERT_EQ(0ULL, mod.const_ratio()[1]);
        ASSERT_EQ(0ULL, mod.const_ratio()[2]);

        mod = 0xF00000F00000F;
        ASSERT_FALSE(mod.is_zero());
        ASSERT_EQ(0xF00000F00000FULL, mod.value());
        ASSERT_EQ(52, mod.bit_count());
        ASSERT_EQ(1ULL, mod.uint64_count());
        ASSERT_EQ(1224979098644774929ULL, mod.const_ratio()[0]);
        ASSERT_EQ(4369ULL, mod.const_ratio()[1]);
        ASSERT_EQ(281470698520321ULL, mod.const_ratio()[2]);
        ASSERT_FALSE(mod.is_prime());

        mod = 0xF00000F000079;
        ASSERT_FALSE(mod.is_zero());
        ASSERT_EQ(0xF00000F000079ULL, mod.value());
        ASSERT_EQ(52, mod.bit_count());
        ASSERT_EQ(1ULL, mod.uint64_count());
        ASSERT_EQ(1224979096621368355ULL, mod.const_ratio()[0]);
        ASSERT_EQ(4369ULL, mod.const_ratio()[1]);
        ASSERT_EQ(1144844808538997ULL, mod.const_ratio()[2]);
        ASSERT_TRUE(mod.is_prime());
    }

    TEST(ModulusTest, CompareModulus)
    {
        Modulus sm0;
        Modulus sm2(2);
        Modulus sm5(5);
        ASSERT_FALSE(sm0 < sm0);
        ASSERT_TRUE(sm0 == sm0);
        ASSERT_TRUE(sm0 <= sm0);
        ASSERT_TRUE(sm0 >= sm0);
        ASSERT_FALSE(sm0 > sm0);

        ASSERT_FALSE(sm5 < sm5);
        ASSERT_TRUE(sm5 == sm5);
        ASSERT_TRUE(sm5 <= sm5);
        ASSERT_TRUE(sm5 >= sm5);
        ASSERT_FALSE(sm5 > sm5);

        ASSERT_FALSE(sm5 < sm2);
        ASSERT_FALSE(sm5 == sm2);
        ASSERT_FALSE(sm5 <= sm2);
        ASSERT_TRUE(sm5 >= sm2);
        ASSERT_TRUE(sm5 > sm2);

        ASSERT_TRUE(sm5 < 6);
        ASSERT_FALSE(sm5 == 6);
        ASSERT_TRUE(sm5 <= 6);
        ASSERT_FALSE(sm5 >= 6);
        ASSERT_FALSE(sm5 > 6);
    }

    TEST(ModulusTest, SaveLoadModulus)
    {
        stringstream stream;

        Modulus mod;
#ifdef SEAL_USE_ZLIB
        compr_mode_type compr_mode = compr_mode_type::zlib;
#elif defined(SEAL_USE_ZSTD)
        compr_mode_type compr_mode = compr_mode_type::zstd;
#else
        compr_mode_type compr_mode = compr_mode_type::none;
#endif
        mod.save(stream, compr_mode);

        Modulus mod2;
        mod2.load(stream);
        ASSERT_EQ(mod2.value(), mod.value());
        ASSERT_EQ(mod2.bit_count(), mod.bit_count());
        ASSERT_EQ(mod2.uint64_count(), mod.uint64_count());
        ASSERT_EQ(mod2.const_ratio()[0], mod.const_ratio()[0]);
        ASSERT_EQ(mod2.const_ratio()[1], mod.const_ratio()[1]);
        ASSERT_EQ(mod2.const_ratio()[2], mod.const_ratio()[2]);
        ASSERT_EQ(mod2.is_prime(), mod.is_prime());

        mod = 3;
        mod.save(stream, compr_mode);
        mod2.load(stream);
        ASSERT_EQ(mod2.value(), mod.value());
        ASSERT_EQ(mod2.bit_count(), mod.bit_count());
        ASSERT_EQ(mod2.uint64_count(), mod.uint64_count());
        ASSERT_EQ(mod2.const_ratio()[0], mod.const_ratio()[0]);
        ASSERT_EQ(mod2.const_ratio()[1], mod.const_ratio()[1]);
        ASSERT_EQ(mod2.const_ratio()[2], mod.const_ratio()[2]);
        ASSERT_EQ(mod2.is_prime(), mod.is_prime());

        mod = 0xF00000F00000F;
        mod.save(stream, compr_mode);
        mod2.load(stream);
        ASSERT_EQ(mod2.value(), mod.value());
        ASSERT_EQ(mod2.bit_count(), mod.bit_count());
        ASSERT_EQ(mod2.uint64_count(), mod.uint64_count());
        ASSERT_EQ(mod2.const_ratio()[0], mod.const_ratio()[0]);
        ASSERT_EQ(mod2.const_ratio()[1], mod.const_ratio()[1]);
        ASSERT_EQ(mod2.const_ratio()[2], mod.const_ratio()[2]);
        ASSERT_EQ(mod2.is_prime(), mod.is_prime());

        mod = 0xF00000F000079;
        mod.save(stream, compr_mode);
        mod2.load(stream);
        ASSERT_EQ(mod2.value(), mod.value());
        ASSERT_EQ(mod2.bit_count(), mod.bit_count());
        ASSERT_EQ(mod2.uint64_count(), mod.uint64_count());
        ASSERT_EQ(mod2.const_ratio()[0], mod.const_ratio()[0]);
        ASSERT_EQ(mod2.const_ratio()[1], mod.const_ratio()[1]);
        ASSERT_EQ(mod2.const_ratio()[2], mod.const_ratio()[2]);
        ASSERT_EQ(mod2.is_prime(), mod.is_prime());
    }

    TEST(ModulusTest, Reduce)
    {
        Modulus mod;
        uint64_t res = 0;
        if (!res)
        {
            ASSERT_THROW(res = mod.reduce(10), logic_error);
        }

        mod = 2;
        ASSERT_EQ(0, mod.reduce(0));
        ASSERT_EQ(1, mod.reduce(1));
        ASSERT_EQ(0, mod.reduce(2));
        ASSERT_EQ(0, mod.reduce(0xF0F0F0));

        mod = 10;
        ASSERT_EQ(0, mod.reduce(0));
        ASSERT_EQ(1, mod.reduce(1));
        ASSERT_EQ(8, mod.reduce(8));
        ASSERT_EQ(7, mod.reduce(1234567));
        ASSERT_EQ(0, mod.reduce(12345670));
    }

    TEST(CoeffModTest, CustomExceptionTest)
    {
        // Too small poly_modulus_degree
        ASSERT_THROW(auto modulus = CoeffModulus::Create(1, { 2 }), invalid_argument);

        // Too large poly_modulus_degree
        ASSERT_THROW(auto modulus = CoeffModulus::Create(262144, { 30 }), invalid_argument);

        // Invalid poly_modulus_degree
        ASSERT_THROW(auto modulus = CoeffModulus::Create(1023, { 20 }), invalid_argument);

        // Invalid bit-size
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2048, { 0 }), invalid_argument);
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2048, { -30 }), invalid_argument);
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2048, { 30, -30 }), invalid_argument);

        // Too small primes requested
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2, { 2 }), logic_error);
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2, { 3, 3, 3 }), logic_error);
        ASSERT_THROW(auto modulus = CoeffModulus::Create(1024, { 8 }), logic_error);

        // Too small poly_modulus_degree
        ASSERT_THROW(auto modulus = CoeffModulus::Create(1, Modulus(2), { 2 }), invalid_argument);

        // Too large poly_modulus_degree
        ASSERT_THROW(auto modulus = CoeffModulus::Create(262144, Modulus(2), { 30 }), invalid_argument);

        // Invalid poly_modulus_degree
        ASSERT_THROW(auto modulus = CoeffModulus::Create(1023, Modulus(2), { 20 }), invalid_argument);

        // Invalid bit-size
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2048, Modulus(2), { 0 }), invalid_argument);
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2048, Modulus(2), { -30 }), invalid_argument);
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2048, Modulus(2), { 30, -30 }), invalid_argument);

        // Too large LCM(2 * poly_modulus_degree, plain_modulus)
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2048, Modulus(uint64_t(1) << 53), { 20 }), logic_error);

        // Too small primes requested
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2, Modulus(2), { 2 }), logic_error);
        ASSERT_THROW(auto modulus = CoeffModulus::Create(2, Modulus(30), { 6, 6 }), logic_error);
        ASSERT_THROW(auto modulus = CoeffModulus::Create(1024, Modulus(257), { 20 }), logic_error);
        ASSERT_THROW(auto modulus = CoeffModulus::Create(1024, Modulus(255), { 22, 22, 22 }), logic_error);
    }

    TEST(CoeffModTest, CustomTest)
    {
        auto cm = CoeffModulus::Create(2, {});
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

        cm = CoeffModulus::Create(2, Modulus(4), {});
        ASSERT_EQ(0, cm.size());

        cm = CoeffModulus::Create(2, Modulus(4), { 3 });
        ASSERT_EQ(1, cm.size());
        ASSERT_EQ(uint64_t(5), cm[0].value());

        cm = CoeffModulus::Create(2, Modulus(4), { 3, 4 });
        ASSERT_EQ(2, cm.size());
        ASSERT_EQ(uint64_t(5), cm[0].value());
        ASSERT_EQ(uint64_t(13), cm[1].value());

        cm = CoeffModulus::Create(2, Modulus(4), { 3, 5, 4, 5 });
        ASSERT_EQ(4, cm.size());
        ASSERT_EQ(uint64_t(5), cm[0].value());
        ASSERT_EQ(uint64_t(17), cm[1].value());
        ASSERT_EQ(uint64_t(13), cm[2].value());
        ASSERT_EQ(uint64_t(29), cm[3].value());

        cm = CoeffModulus::Create(32, Modulus(64), { 30, 40, 30, 30, 40 });
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

        cm = CoeffModulus::Create(1024, Modulus(255), { 22, 22 });
        ASSERT_EQ(2, cm.size());
        ASSERT_EQ(22, get_significant_bit_count(cm[0].value()));
        ASSERT_EQ(22, get_significant_bit_count(cm[1].value()));
        ASSERT_EQ(3133441ULL, cm[0].value());
        ASSERT_EQ(3655681ULL, cm[1].value());
    }
} // namespace sealtest
