// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/uintcore.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/smallmodulus.h"
#include "seal/memorymanager.h"

using namespace seal::util;
using namespace seal;
using namespace std;

namespace SEALTest
{
   namespace util
   {
        TEST(UIntArithSmallMod, IncrementUIntSmallMod)
        {
            SmallModulus mod(2);
            ASSERT_EQ(1ULL, increment_uint_mod(0, mod));
            ASSERT_EQ(0ULL, increment_uint_mod(1ULL, mod));

            mod = 0x10000;
            ASSERT_EQ(1ULL, increment_uint_mod(0, mod));
            ASSERT_EQ(2ULL, increment_uint_mod(1ULL, mod));
            ASSERT_EQ(0ULL, increment_uint_mod(0xFFFFULL, mod));

            mod = 4611686018427289601ULL;
            ASSERT_EQ(1ULL, increment_uint_mod(0, mod));
            ASSERT_EQ(0ULL, increment_uint_mod(4611686018427289600ULL, mod));
            ASSERT_EQ(1ULL, increment_uint_mod(0, mod));
        }

        TEST(UIntArithSmallMod, DecrementUIntSmallMod)
        {
            SmallModulus mod(2);
            ASSERT_EQ(0ULL, decrement_uint_mod(1, mod));
            ASSERT_EQ(1ULL, decrement_uint_mod(0ULL, mod));

            mod = 0x10000;
            ASSERT_EQ(0ULL, decrement_uint_mod(1, mod));
            ASSERT_EQ(1ULL, decrement_uint_mod(2ULL, mod));
            ASSERT_EQ(0xFFFFULL, decrement_uint_mod(0ULL, mod));

            mod = 4611686018427289601ULL;
            ASSERT_EQ(0ULL, decrement_uint_mod(1, mod));
            ASSERT_EQ(4611686018427289600ULL, decrement_uint_mod(0ULL, mod));
            ASSERT_EQ(0ULL, decrement_uint_mod(1, mod));
        }

        TEST(UIntArithSmallMod, NegateUIntSmallMod)
        {
            SmallModulus mod(2);
            ASSERT_EQ(0ULL, negate_uint_mod(0, mod));
            ASSERT_EQ(1ULL, negate_uint_mod(1, mod));

            mod = 0xFFFFULL;
            ASSERT_EQ(0ULL, negate_uint_mod(0, mod));
            ASSERT_EQ(0xFFFEULL, negate_uint_mod(1, mod));
            ASSERT_EQ(0x1ULL, negate_uint_mod(0xFFFEULL, mod));

            mod = 0x10000ULL;
            ASSERT_EQ(0ULL, negate_uint_mod(0, mod));
            ASSERT_EQ(0xFFFFULL, negate_uint_mod(1, mod));
            ASSERT_EQ(0x1ULL, negate_uint_mod(0xFFFFULL, mod));

            mod = 4611686018427289601ULL;
            ASSERT_EQ(0ULL, negate_uint_mod(0, mod));
            ASSERT_EQ(4611686018427289600ULL, negate_uint_mod(1, mod));
        }

        TEST(UIntArithSmallMod, Div2UIntSmallMod)
        {
            SmallModulus mod(3);
            ASSERT_EQ(0ULL, div2_uint_mod(0ULL, mod));
            ASSERT_EQ(2ULL, div2_uint_mod(1ULL, mod));

            mod = 17;
            ASSERT_EQ(11ULL, div2_uint_mod(5ULL, mod));
            ASSERT_EQ(4ULL, div2_uint_mod(8ULL, mod));

            mod = 0xFFFFFFFFFFFFFFFULL;
            ASSERT_EQ(0x800000000000000ULL, div2_uint_mod(1ULL, mod));
            ASSERT_EQ(0x800000000000001ULL, div2_uint_mod(3ULL, mod));
        }

        TEST(UIntArithSmallMod, AddUIntSmallMod)
        {
            SmallModulus mod(2);
            ASSERT_EQ(0ULL, add_uint_uint_mod(0, 0, mod));
            ASSERT_EQ(1ULL, add_uint_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, add_uint_uint_mod(1, 0, mod));
            ASSERT_EQ(0ULL, add_uint_uint_mod(1, 1, mod));

            mod = 10;
            ASSERT_EQ(0ULL, add_uint_uint_mod(0, 0, mod));
            ASSERT_EQ(1ULL, add_uint_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, add_uint_uint_mod(1, 0, mod));
            ASSERT_EQ(2ULL, add_uint_uint_mod(1, 1, mod));
            ASSERT_EQ(4ULL, add_uint_uint_mod(7, 7, mod));
            ASSERT_EQ(3ULL, add_uint_uint_mod(6, 7, mod));

            mod = 4611686018427289601;
            ASSERT_EQ(0ULL, add_uint_uint_mod(0, 0, mod));
            ASSERT_EQ(1ULL, add_uint_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, add_uint_uint_mod(1, 0, mod));
            ASSERT_EQ(2ULL, add_uint_uint_mod(1, 1, mod));
            ASSERT_EQ(0ULL, add_uint_uint_mod(2305843009213644800ULL, 2305843009213644801ULL, mod));
            ASSERT_EQ(1ULL, add_uint_uint_mod(2305843009213644801ULL, 2305843009213644801ULL, mod));
            ASSERT_EQ(4611686018427289599ULL, add_uint_uint_mod(4611686018427289600ULL, 4611686018427289600ULL, mod));
        }

        TEST(UIntArithSmallMod, SubUIntSmallMod)
        {
            SmallModulus mod(2);
            ASSERT_EQ(0ULL, sub_uint_uint_mod(0, 0, mod));
            ASSERT_EQ(1ULL, sub_uint_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, sub_uint_uint_mod(1, 0, mod));
            ASSERT_EQ(0ULL, sub_uint_uint_mod(1, 1, mod));

            mod = 10;
            ASSERT_EQ(0ULL, sub_uint_uint_mod(0, 0, mod));
            ASSERT_EQ(9ULL, sub_uint_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, sub_uint_uint_mod(1, 0, mod));
            ASSERT_EQ(0ULL, sub_uint_uint_mod(1, 1, mod));
            ASSERT_EQ(0ULL, sub_uint_uint_mod(7, 7, mod));
            ASSERT_EQ(9ULL, sub_uint_uint_mod(6, 7, mod));
            ASSERT_EQ(1ULL, sub_uint_uint_mod(7, 6, mod));

            mod = 4611686018427289601ULL;
            ASSERT_EQ(0ULL, sub_uint_uint_mod(0, 0, mod));
            ASSERT_EQ(4611686018427289600ULL, sub_uint_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, sub_uint_uint_mod(1, 0, mod));
            ASSERT_EQ(0ULL, sub_uint_uint_mod(1, 1, mod));
            ASSERT_EQ(4611686018427289600ULL, sub_uint_uint_mod(2305843009213644800ULL, 2305843009213644801ULL, mod));
            ASSERT_EQ(1ULL, sub_uint_uint_mod(2305843009213644801ULL, 2305843009213644800ULL, mod));
            ASSERT_EQ(0ULL, sub_uint_uint_mod(2305843009213644801ULL, 2305843009213644801ULL, mod));
            ASSERT_EQ(0ULL, sub_uint_uint_mod(4611686018427289600ULL, 4611686018427289600ULL, mod));
        }

        TEST(UIntArithSmallMod, BarrettReduce128)
        {
            uint64_t input[2];

            SmallModulus mod(2);
            input[0] = 0;
            input[1] = 0;
            ASSERT_EQ(0ULL, barrett_reduce_128(input, mod));
            input[0] = 1;
            input[1] = 0;
            ASSERT_EQ(1ULL, barrett_reduce_128(input, mod));
            input[0] = 0xFFFFFFFFFFFFFFFFULL;
            input[1] = 0xFFFFFFFFFFFFFFFFULL;
            ASSERT_EQ(1ULL, barrett_reduce_128(input, mod));

            mod = 3;
            input[0] = 0;
            input[1] = 0;
            ASSERT_EQ(0ULL, barrett_reduce_128(input, mod));
            input[0] = 1;
            input[1] = 0;
            ASSERT_EQ(1ULL, barrett_reduce_128(input, mod));
            input[0] = 123;
            input[1] = 456;
            ASSERT_EQ(0ULL, barrett_reduce_128(input, mod));
            input[0] = 0xFFFFFFFFFFFFFFFFULL;
            input[1] = 0xFFFFFFFFFFFFFFFFULL;
            ASSERT_EQ(0ULL, barrett_reduce_128(input, mod));

            mod = 13131313131313ULL;
            input[0] = 0;
            input[1] = 0;
            ASSERT_EQ(0ULL, barrett_reduce_128(input, mod));
            input[0] = 1;
            input[1] = 0;
            ASSERT_EQ(1ULL, barrett_reduce_128(input, mod));
            input[0] = 123;
            input[1] = 456;
            ASSERT_EQ(8722750765283ULL, barrett_reduce_128(input, mod));
            input[0] = 24242424242424;
            input[1] = 79797979797979;
            ASSERT_EQ(1010101010101ULL, barrett_reduce_128(input, mod));
        }

        TEST(UIntArithSmallMod, MultiplyUIntUIntSmallMod)
        {
            SmallModulus mod(2);
            ASSERT_EQ(0ULL, multiply_uint_uint_mod(0, 0, mod));
            ASSERT_EQ(0ULL, multiply_uint_uint_mod(0, 1, mod));
            ASSERT_EQ(0ULL, multiply_uint_uint_mod(1, 0, mod));
            ASSERT_EQ(1ULL, multiply_uint_uint_mod(1, 1, mod));

            mod = 10;
            ASSERT_EQ(0ULL, multiply_uint_uint_mod(0, 0, mod));
            ASSERT_EQ(0ULL, multiply_uint_uint_mod(0, 1, mod));
            ASSERT_EQ(0ULL, multiply_uint_uint_mod(1, 0, mod));
            ASSERT_EQ(1ULL, multiply_uint_uint_mod(1, 1, mod));
            ASSERT_EQ(9ULL, multiply_uint_uint_mod(7, 7, mod));
            ASSERT_EQ(2ULL, multiply_uint_uint_mod(6, 7, mod));
            ASSERT_EQ(2ULL, multiply_uint_uint_mod(7, 6, mod));

            mod = 4611686018427289601ULL;
            ASSERT_EQ(0ULL, multiply_uint_uint_mod(0, 0, mod));
            ASSERT_EQ(0ULL, multiply_uint_uint_mod(0, 1, mod));
            ASSERT_EQ(0ULL, multiply_uint_uint_mod(1, 0, mod));
            ASSERT_EQ(1ULL, multiply_uint_uint_mod(1, 1, mod));
            ASSERT_EQ(1152921504606822400ULL, multiply_uint_uint_mod(2305843009213644800ULL, 2305843009213644801ULL, mod));
            ASSERT_EQ(1152921504606822400ULL, multiply_uint_uint_mod(2305843009213644801ULL, 2305843009213644800ULL, mod));
            ASSERT_EQ(3458764513820467201ULL, multiply_uint_uint_mod(2305843009213644801ULL, 2305843009213644801ULL, mod));
            ASSERT_EQ(1ULL, multiply_uint_uint_mod(4611686018427289600ULL, 4611686018427289600ULL, mod));
        }

        TEST(UIntArithSmallMod, ModuloUIntSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto value(allocate_uint(4, pool));

            SmallModulus mod(2);
            value[0] = 0;
            value[1] = 0;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(0ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            value[0] = 1;
            value[1] = 0;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            value[0] = 2;
            value[1] = 0;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(0ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            value[0] = 3;
            value[1] = 0;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            mod = 0xFFFF;
            value[0] = 9585656442714717620ul;
            value[1] = 1817697005049051848;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(65143ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            mod = 0x1000;
            value[0] = 9585656442714717620ul;
            value[1] = 1817697005049051848;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(0xDB4ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            mod = 0xFFFFFFFFC001ULL;
            value[0] = 9585656442714717620ul;
            value[1] = 1817697005049051848;
            value[2] = 14447416709120365380ul;
            value[3] = 67450014862939159;
            modulo_uint_inplace(value.get(), 4, mod);
            ASSERT_EQ(124510066632001ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);
            ASSERT_EQ(0ULL, value[3]);
        }

        TEST(UIntArithSmallMod, TryInvertUIntSmallMod)
        {
            uint64_t result;
            SmallModulus mod(5);
            ASSERT_FALSE(try_invert_uint_mod(0, mod, result));
            ASSERT_TRUE(try_invert_uint_mod(1, mod, result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(try_invert_uint_mod(2, mod, result));
            ASSERT_EQ(3ULL, result);
            ASSERT_TRUE(try_invert_uint_mod(3, mod, result));
            ASSERT_EQ(2ULL, result);
            ASSERT_TRUE(try_invert_uint_mod(4, mod, result));
            ASSERT_EQ(4ULL, result);

            mod = 6;
            ASSERT_FALSE(try_invert_uint_mod(2, mod, result));
            ASSERT_FALSE(try_invert_uint_mod(3, mod, result));
            ASSERT_TRUE(try_invert_uint_mod(5, mod, result));
            ASSERT_EQ(5ULL, result);

            mod = 1351315121;
            ASSERT_TRUE(try_invert_uint_mod(331975426, mod, result));
            ASSERT_EQ(1052541512ULL, result);
        }

        TEST(UIntArithSmallMod, TryPrimitiveRootSmallMod)
        {
            uint64_t result;
            SmallModulus mod(11);

            ASSERT_TRUE(try_primitive_root(2, mod, result));
            ASSERT_EQ(10ULL, result);

            mod = 29;
            ASSERT_TRUE(try_primitive_root(2, mod, result));
            ASSERT_EQ(28ULL, result);

            vector<uint64_t> corrects{ 12, 17 };
            ASSERT_TRUE(try_primitive_root(4, mod, result));
            ASSERT_TRUE(std::find(corrects.begin(), corrects.end(), result) != corrects.end());

            mod = 1234565441;
            ASSERT_TRUE(try_primitive_root(2, mod, result));
            ASSERT_EQ(1234565440ULL, result);
            corrects = { 984839708, 273658408, 249725733, 960907033 };
            ASSERT_TRUE(try_primitive_root(8, mod, result));
            ASSERT_TRUE(std::find(corrects.begin(), corrects.end(), result) != corrects.end());
        }

        TEST(UIntArithSmallMod, IsPrimitiveRootSmallMod)
        {
            SmallModulus mod(11);
            ASSERT_TRUE(is_primitive_root(10, 2, mod));
            ASSERT_FALSE(is_primitive_root(9, 2, mod));
            ASSERT_FALSE(is_primitive_root(10, 4, mod));

            mod = 29;
            ASSERT_TRUE(is_primitive_root(28, 2, mod));
            ASSERT_TRUE(is_primitive_root(12, 4, mod));
            ASSERT_FALSE(is_primitive_root(12, 2, mod));
            ASSERT_FALSE(is_primitive_root(12, 8, mod));


            mod = 1234565441ULL;
            ASSERT_TRUE(is_primitive_root(1234565440ULL, 2, mod));
            ASSERT_TRUE(is_primitive_root(960907033ULL, 8, mod));
            ASSERT_TRUE(is_primitive_root(1180581915ULL, 16, mod));
            ASSERT_FALSE(is_primitive_root(1180581915ULL, 32, mod));
            ASSERT_FALSE(is_primitive_root(1180581915ULL, 8, mod));
            ASSERT_FALSE(is_primitive_root(1180581915ULL, 2, mod));
        }

        TEST(UIntArithSmallMod, TryMinimalPrimitiveRootSmallMod)
        {
            SmallModulus mod(11);

            uint64_t result;
            ASSERT_TRUE(try_minimal_primitive_root(2, mod, result));
            ASSERT_EQ(10ULL, result);

            mod = 29;
            ASSERT_TRUE(try_minimal_primitive_root(2, mod, result));
            ASSERT_EQ(28ULL, result);
            ASSERT_TRUE(try_minimal_primitive_root(4, mod, result));
            ASSERT_EQ(12ULL, result);

            mod = 1234565441;
            ASSERT_TRUE(try_minimal_primitive_root(2, mod, result));
            ASSERT_EQ(1234565440ULL, result);
            ASSERT_TRUE(try_minimal_primitive_root(8, mod, result));
            ASSERT_EQ(249725733ULL, result);
        }

        TEST(UIntArithSmallMod, ExponentiateUIntSmallMod)
        {
            SmallModulus mod(5);
            ASSERT_EQ(1ULL, exponentiate_uint_mod(1, 0, mod));
            ASSERT_EQ(1ULL, exponentiate_uint_mod(1, 0xFFFFFFFFFFFFFFFFULL, mod));
            ASSERT_EQ(3ULL, exponentiate_uint_mod(2, 0xFFFFFFFFFFFFFFFFULL, mod));

            mod = 0x1000000000000000ULL;
            ASSERT_EQ(0ULL, exponentiate_uint_mod(2, 60, mod));
            ASSERT_EQ(0x800000000000000ULL, exponentiate_uint_mod(2, 59, mod));

            mod = 131313131313;
            ASSERT_EQ(39418477653ULL, exponentiate_uint_mod(2424242424, 16, mod));
        }
   }
}
