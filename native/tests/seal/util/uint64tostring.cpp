// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/common.h"
#include "seal/util/mempool.h"
#include "seal/util/polycore.h"
#include "seal/util/uintcore.h"
#include <cstdint>
#include "gtest/gtest.h"

using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(UInt64ToString, NibbleToUpperHexTest)
        {
            ASSERT_EQ('0', nibble_to_upper_hex(0));
            ASSERT_EQ('1', nibble_to_upper_hex(1));
            ASSERT_EQ('2', nibble_to_upper_hex(2));
            ASSERT_EQ('3', nibble_to_upper_hex(3));
            ASSERT_EQ('4', nibble_to_upper_hex(4));
            ASSERT_EQ('5', nibble_to_upper_hex(5));
            ASSERT_EQ('6', nibble_to_upper_hex(6));
            ASSERT_EQ('7', nibble_to_upper_hex(7));
            ASSERT_EQ('8', nibble_to_upper_hex(8));
            ASSERT_EQ('9', nibble_to_upper_hex(9));
            ASSERT_EQ('A', nibble_to_upper_hex(10));
            ASSERT_EQ('B', nibble_to_upper_hex(11));
            ASSERT_EQ('C', nibble_to_upper_hex(12));
            ASSERT_EQ('D', nibble_to_upper_hex(13));
            ASSERT_EQ('E', nibble_to_upper_hex(14));
            ASSERT_EQ('F', nibble_to_upper_hex(15));
        }

        TEST(UInt64ToString, UInt64ToHexString)
        {
            uint64_t number[] = { 0, 0, 0 };
            string correct = "0";
            ASSERT_EQ(correct, uint_to_hex_string(number, 3));
            ASSERT_EQ(correct, uint_to_hex_string(number, 1));
            ASSERT_EQ(correct, uint_to_hex_string(number, 0));
            ASSERT_EQ(correct, uint_to_hex_string(nullptr, 0));

            number[0] = 1;
            correct = "1";
            ASSERT_EQ(correct, uint_to_hex_string(number, 3));
            ASSERT_EQ(correct, uint_to_hex_string(number, 1));

            number[0] = 0xF;
            correct = "F";
            ASSERT_EQ(correct, uint_to_hex_string(number, 3));

            number[0] = 0x10;
            correct = "10";
            ASSERT_EQ(correct, uint_to_hex_string(number, 3));

            number[0] = 0x100;
            correct = "100";
            ASSERT_EQ(correct, uint_to_hex_string(number, 3));

            number[0] = 0x123;
            correct = "123";
            ASSERT_EQ(correct, uint_to_hex_string(number, 3));

            number[0] = 0;
            number[1] = 1;
            correct = "10000000000000000";
            ASSERT_EQ(correct, uint_to_hex_string(number, 3));

            number[0] = 0x1123456789ABCDEF;
            number[1] = 0x1;
            correct = "11123456789ABCDEF";
            ASSERT_EQ(correct, uint_to_hex_string(number, 3));

            number[0] = 0x3456789ABCDEF123;
            number[1] = 0x23456789ABCDEF12;
            number[2] = 0x123456789ABCDEF1;
            correct = "123456789ABCDEF123456789ABCDEF123456789ABCDEF123";
            ASSERT_EQ(correct, uint_to_hex_string(number, 3));

            number[0] = 0xFFFFFFFFFFFFFFFF;
            number[1] = 0xFFFFFFFFFFFFFFFF;
            number[2] = 0xFFFFFFFFFFFFFFFF;
            correct = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
            ASSERT_EQ(correct, uint_to_hex_string(number, 3));
        }

        TEST(UInt64ToString, UInt64ToDecString)
        {
            uint64_t number[] = { 0, 0, 0 };
            string correct = "0";
            MemoryPool &pool = *global_variables::global_memory_pool;
            ASSERT_EQ(correct, uint_to_dec_string(number, 3, pool));
            ASSERT_EQ(correct, uint_to_dec_string(number, 1, pool));
            ASSERT_EQ(correct, uint_to_dec_string(number, 0, pool));
            ASSERT_EQ(correct, uint_to_dec_string(nullptr, 0, pool));

            number[0] = 1;
            correct = "1";
            ASSERT_EQ(correct, uint_to_dec_string(number, 3, pool));
            ASSERT_EQ(correct, uint_to_dec_string(number, 1, pool));

            number[0] = 9;
            correct = "9";
            ASSERT_EQ(correct, uint_to_dec_string(number, 3, pool));

            number[0] = 10;
            correct = "10";
            ASSERT_EQ(correct, uint_to_dec_string(number, 3, pool));

            number[0] = 123;
            correct = "123";
            ASSERT_EQ(correct, uint_to_dec_string(number, 3, pool));

            number[0] = 987654321;
            correct = "987654321";
            ASSERT_EQ(correct, uint_to_dec_string(number, 3, pool));

            number[0] = 0;
            number[1] = 1;
            correct = "18446744073709551616";
            ASSERT_EQ(correct, uint_to_dec_string(number, 3, pool));
        }

        TEST(UInt64ToString, PolyToHexString)
        {
            uint64_t number[] = { 0, 0, 0, 0 };
            string correct = "0";
            ASSERT_EQ(correct, poly_to_hex_string(number, 0, 1));
            ASSERT_EQ(correct, poly_to_hex_string(number, 4, 0));
            ASSERT_EQ(correct, poly_to_hex_string(number, 1, 1));
            ASSERT_EQ(correct, poly_to_hex_string(number, 4, 1));
            ASSERT_EQ(correct, poly_to_hex_string(number, 2, 2));
            ASSERT_EQ(correct, poly_to_hex_string(number, 1, 4));

            number[0] = 1;
            correct = "1";
            ASSERT_EQ(correct, poly_to_hex_string(number, 4, 1));
            ASSERT_EQ(correct, poly_to_hex_string(number, 2, 2));
            ASSERT_EQ(correct, poly_to_hex_string(number, 1, 4));

            number[0] = 0;
            number[1] = 1;
            correct = "1x^1";
            ASSERT_EQ(correct, poly_to_hex_string(number, 4, 1));
            correct = "10000000000000000";
            ASSERT_EQ(correct, poly_to_hex_string(number, 2, 2));
            ASSERT_EQ(correct, poly_to_hex_string(number, 1, 4));

            number[0] = 1;
            number[1] = 0;
            number[2] = 0;
            number[3] = 1;
            correct = "1x^3 + 1";
            ASSERT_EQ(correct, poly_to_hex_string(number, 4, 1));
            correct = "10000000000000000x^1 + 1";
            ASSERT_EQ(correct, poly_to_hex_string(number, 2, 2));
            correct = "1000000000000000000000000000000000000000000000001";
            ASSERT_EQ(correct, poly_to_hex_string(number, 1, 4));

            number[0] = 0xF00000000000000F;
            number[1] = 0xF0F0F0F0F0F0F0F0;
            number[2] = 0;
            number[3] = 0;
            correct = "F0F0F0F0F0F0F0F0x^1 + F00000000000000F";
            ASSERT_EQ(correct, poly_to_hex_string(number, 4, 1));
            correct = "F0F0F0F0F0F0F0F0F00000000000000F";

            number[2] = 0xF0FF0F0FF0F0FF0F;
            number[3] = 0xBABABABABABABABA;
            correct = "BABABABABABABABAF0FF0F0FF0F0FF0Fx^1 + F0F0F0F0F0F0F0F0F00000000000000F";
            ASSERT_EQ(correct, poly_to_hex_string(number, 2, 2));
            correct = "BABABABABABABABAx^3 + F0FF0F0FF0F0FF0Fx^2 + F0F0F0F0F0F0F0F0x^1 + F00000000000000F";
            ASSERT_EQ(correct, poly_to_hex_string(number, 4, 1));
        }
    } // namespace util
} // namespace sealtest
