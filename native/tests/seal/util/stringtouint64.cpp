// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include <cstdint>
#include <cstring>

using namespace seal::util;
using namespace std;

namespace SEALTest
{
   namespace util
   {
        TEST(StringToUInt64, IsHexCharTest)
        {
            ASSERT_TRUE(is_hex_char('0'));
            ASSERT_TRUE(is_hex_char('1'));
            ASSERT_TRUE(is_hex_char('2'));
            ASSERT_TRUE(is_hex_char('3'));
            ASSERT_TRUE(is_hex_char('4'));
            ASSERT_TRUE(is_hex_char('5'));
            ASSERT_TRUE(is_hex_char('6'));
            ASSERT_TRUE(is_hex_char('7'));
            ASSERT_TRUE(is_hex_char('8'));
            ASSERT_TRUE(is_hex_char('9'));
            ASSERT_TRUE(is_hex_char('A'));
            ASSERT_TRUE(is_hex_char('B'));
            ASSERT_TRUE(is_hex_char('C'));
            ASSERT_TRUE(is_hex_char('D'));
            ASSERT_TRUE(is_hex_char('E'));
            ASSERT_TRUE(is_hex_char('F'));
            ASSERT_TRUE(is_hex_char('a'));
            ASSERT_TRUE(is_hex_char('b'));
            ASSERT_TRUE(is_hex_char('c'));
            ASSERT_TRUE(is_hex_char('d'));
            ASSERT_TRUE(is_hex_char('e'));
            ASSERT_TRUE(is_hex_char('f'));

            ASSERT_FALSE(is_hex_char('/'));
            ASSERT_FALSE(is_hex_char(' '));
            ASSERT_FALSE(is_hex_char('+'));
            ASSERT_FALSE(is_hex_char('\\'));
            ASSERT_FALSE(is_hex_char('G'));
            ASSERT_FALSE(is_hex_char('g'));
            ASSERT_FALSE(is_hex_char('Z'));
            ASSERT_FALSE(is_hex_char('Z'));
        }

        TEST(StringToUInt64, HexToNibbleTest)
        {
            ASSERT_EQ(0, hex_to_nibble('0'));
            ASSERT_EQ(1, hex_to_nibble('1'));
            ASSERT_EQ(2, hex_to_nibble('2'));
            ASSERT_EQ(3, hex_to_nibble('3'));
            ASSERT_EQ(4, hex_to_nibble('4'));
            ASSERT_EQ(5, hex_to_nibble('5'));
            ASSERT_EQ(6, hex_to_nibble('6'));
            ASSERT_EQ(7, hex_to_nibble('7'));
            ASSERT_EQ(8, hex_to_nibble('8'));
            ASSERT_EQ(9, hex_to_nibble('9'));
            ASSERT_EQ(10, hex_to_nibble('A'));
            ASSERT_EQ(11, hex_to_nibble('B'));
            ASSERT_EQ(12, hex_to_nibble('C'));
            ASSERT_EQ(13, hex_to_nibble('D'));
            ASSERT_EQ(14, hex_to_nibble('E'));
            ASSERT_EQ(15, hex_to_nibble('F'));
            ASSERT_EQ(10, hex_to_nibble('a'));
            ASSERT_EQ(11, hex_to_nibble('b'));
            ASSERT_EQ(12, hex_to_nibble('c'));
            ASSERT_EQ(13, hex_to_nibble('d'));
            ASSERT_EQ(14, hex_to_nibble('e'));
            ASSERT_EQ(15, hex_to_nibble('f'));
        }

        TEST(StringToUInt64, GetHexStringBitCount)
        {
            ASSERT_EQ(0, get_hex_string_bit_count(nullptr, 0));
            ASSERT_EQ(0, get_hex_string_bit_count("0", 1));
            ASSERT_EQ(0, get_hex_string_bit_count("000000000", 9));
            ASSERT_EQ(1, get_hex_string_bit_count("1", 1));
            ASSERT_EQ(1, get_hex_string_bit_count("00001", 5));
            ASSERT_EQ(2, get_hex_string_bit_count("2", 1));
            ASSERT_EQ(2, get_hex_string_bit_count("00002", 5));
            ASSERT_EQ(2, get_hex_string_bit_count("3", 1));
            ASSERT_EQ(2, get_hex_string_bit_count("0003", 4));
            ASSERT_EQ(3, get_hex_string_bit_count("4", 1));
            ASSERT_EQ(3, get_hex_string_bit_count("5", 1));
            ASSERT_EQ(3, get_hex_string_bit_count("6", 1));
            ASSERT_EQ(3, get_hex_string_bit_count("7", 1));
            ASSERT_EQ(4, get_hex_string_bit_count("8", 1));
            ASSERT_EQ(4, get_hex_string_bit_count("9", 1));
            ASSERT_EQ(4, get_hex_string_bit_count("A", 1));
            ASSERT_EQ(4, get_hex_string_bit_count("B", 1));
            ASSERT_EQ(4, get_hex_string_bit_count("C", 1));
            ASSERT_EQ(4, get_hex_string_bit_count("D", 1));
            ASSERT_EQ(4, get_hex_string_bit_count("E", 1));
            ASSERT_EQ(4, get_hex_string_bit_count("F", 1));
            ASSERT_EQ(5, get_hex_string_bit_count("10", 2));
            ASSERT_EQ(5, get_hex_string_bit_count("00010", 5));
            ASSERT_EQ(5, get_hex_string_bit_count("11", 2));
            ASSERT_EQ(5, get_hex_string_bit_count("1F", 2));
            ASSERT_EQ(6, get_hex_string_bit_count("20", 2));
            ASSERT_EQ(6, get_hex_string_bit_count("2F", 2));
            ASSERT_EQ(7, get_hex_string_bit_count("7F", 2));
            ASSERT_EQ(7, get_hex_string_bit_count("0007F", 5));
            ASSERT_EQ(8, get_hex_string_bit_count("80", 2));
            ASSERT_EQ(8, get_hex_string_bit_count("FF", 2));
            ASSERT_EQ(8, get_hex_string_bit_count("00FF", 4));
            ASSERT_EQ(9, get_hex_string_bit_count("100", 3));
            ASSERT_EQ(9, get_hex_string_bit_count("000100", 6));
            ASSERT_EQ(22, get_hex_string_bit_count("200000", 6));
            ASSERT_EQ(35, get_hex_string_bit_count("7FFF30001", 9));

            ASSERT_EQ(15, get_hex_string_bit_count("7FFF30001", 4));
            ASSERT_EQ(3, get_hex_string_bit_count("7FFF30001", 1));
            ASSERT_EQ(0, get_hex_string_bit_count("7FFF30001", 0));
        }

        TEST(StringToUInt64, HexStringToUInt64)
        {
            uint64_t correct[3];
            uint64_t parsed[3];

            correct[0] = 0;
            correct[1] = 0;
            correct[2] = 0;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("0", 1, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("0", 1, 1, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 1 * sizeof(uint64_t)));
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint(nullptr, 0, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 1;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("1", 1, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("01", 2, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("001", 3, 1, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 1 * sizeof(uint64_t)));

            correct[0] = 0xF;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("F", 1, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0x10;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("10", 2, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("010", 3, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0x100;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("100", 3, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0x123;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("123", 3, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("00000123", 8, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0;
            correct[1] = 1;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("10000000000000000", 17, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0x1123456789ABCDEF;
            correct[1] = 0x1;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("11123456789ABCDEF", 17, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("000011123456789ABCDEF", 21, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0x3456789ABCDEF123;
            correct[1] = 0x23456789ABCDEF12;
            correct[2] = 0x123456789ABCDEF1;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("123456789ABCDEF123456789ABCDEF123456789ABCDEF123", 48, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0xFFFFFFFFFFFFFFFF;
            correct[1] = 0xFFFFFFFFFFFFFFFF;
            correct[2] = 0xFFFFFFFFFFFFFFFF;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 48, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0x100;
            correct[1] = 0;
            correct[2] = 0;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("100", 3, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0x10;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("100", 2, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0x1;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("100", 1, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));

            correct[0] = 0;
            parsed[0] = 0x123;
            parsed[1] = 0x123;
            parsed[2] = 0x123;
            hex_string_to_uint("100", 0, 3, parsed);
            ASSERT_EQ(0, memcmp(correct, parsed, 3 * sizeof(uint64_t)));
        }
   }
}
