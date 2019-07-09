// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/common.h"
#include <cstdint>

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
    namespace util
    {
        TEST(Common, Constants)
        {
            ASSERT_EQ(4, bits_per_nibble);
            ASSERT_EQ(8, bits_per_byte);
            ASSERT_EQ(4, bytes_per_uint32);
            ASSERT_EQ(8, bytes_per_uint64);
            ASSERT_EQ(32, bits_per_uint32);
            ASSERT_EQ(64, bits_per_uint64);
            ASSERT_EQ(2, nibbles_per_byte);
            ASSERT_EQ(2, uint32_per_uint64);
            ASSERT_EQ(16, nibbles_per_uint64);
            ASSERT_EQ(static_cast<uint64_t>(INT64_MAX) + 1, uint64_high_bit);
        }

        TEST(Common, UnsignedComparisons)
        {
            int pos_i = 5;
            int neg_i = -5;
            unsigned pos_u = 6;
            signed pos_s = 6;
            unsigned char pos_uc = 1;
            char neg_c = -1;
            char pos_c = 1;
            unsigned char pos_uc_max = 0xFF;
            unsigned long long pos_ull = 1;
            unsigned long long pos_ull_max = 0xFFFFFFFFFFFFFFFF;
            long long neg_ull = -1;

            ASSERT_TRUE(unsigned_eq(pos_i, pos_i));
            ASSERT_FALSE(unsigned_eq(pos_i, neg_i));
            ASSERT_TRUE(unsigned_gt(pos_u, pos_i));
            ASSERT_TRUE(unsigned_lt(pos_i, neg_i));
            ASSERT_TRUE(unsigned_geq(pos_u, pos_s));
            ASSERT_TRUE(unsigned_gt(neg_c, pos_c));
            ASSERT_TRUE(unsigned_geq(neg_c, pos_c));
            ASSERT_FALSE(unsigned_eq(neg_c, pos_c));
            ASSERT_FALSE(unsigned_gt(pos_u, neg_c));
            ASSERT_TRUE(unsigned_eq(pos_uc, pos_c));
            ASSERT_TRUE(unsigned_geq(pos_uc, pos_c));
            ASSERT_TRUE(unsigned_leq(pos_uc, pos_c));
            ASSERT_TRUE(unsigned_lt(pos_uc_max, neg_c));
            ASSERT_TRUE(unsigned_eq(neg_c, pos_ull_max));
            ASSERT_TRUE(unsigned_eq(neg_ull, pos_ull_max));
            ASSERT_FALSE(unsigned_lt(neg_ull, pos_ull_max));
            ASSERT_TRUE(unsigned_lt(pos_ull, pos_ull_max));
        }

        TEST(Common, SafeArithmetic)
        {
            int pos_i = 5;
            int neg_i = -5;
            unsigned pos_u = 6;
            unsigned char pos_uc_max = 0xFF;
            unsigned long long pos_ull_max = 0xFFFFFFFFFFFFFFFF;
            long long neg_ull = -1;

            ASSERT_EQ(25, mul_safe(pos_i, pos_i));
            ASSERT_EQ(25, mul_safe(neg_i, neg_i));
            ASSERT_EQ(10, add_safe(pos_i, pos_i));
            ASSERT_EQ(-10, add_safe(neg_i, neg_i));
            ASSERT_EQ(0, add_safe(pos_i, neg_i));
            ASSERT_EQ(0, add_safe(neg_i, pos_i));
            ASSERT_EQ(10, sub_safe(pos_i, neg_i));
            ASSERT_EQ(-10, sub_safe(neg_i, pos_i));
            ASSERT_EQ(unsigned(0), sub_safe(pos_u, pos_u));
            ASSERT_THROW(sub_safe(unsigned(0), pos_u), out_of_range);
            ASSERT_THROW(sub_safe(unsigned(4), pos_u), out_of_range);
            ASSERT_THROW(add_safe(pos_uc_max, (unsigned char)1), out_of_range);
            ASSERT_TRUE(pos_uc_max == add_safe(pos_uc_max, (unsigned char)0));
            ASSERT_THROW(mul_safe(pos_ull_max, pos_ull_max), out_of_range);
            ASSERT_EQ(0ULL, mul_safe(0ULL, pos_ull_max));
            ASSERT_TRUE((long long)1 == mul_safe(neg_ull, neg_ull));
            ASSERT_THROW(mul_safe(pos_uc_max, pos_uc_max), out_of_range);
            ASSERT_EQ(15, add_safe(pos_i, -pos_i, pos_i, pos_i, pos_i));
            ASSERT_EQ(6, add_safe(0, -pos_i, pos_i, 1, pos_i));
            ASSERT_EQ(0, mul_safe(pos_i, pos_i, pos_i, 0, pos_i));
            ASSERT_EQ(625, mul_safe(pos_i, pos_i, pos_i, pos_i));
            ASSERT_THROW(mul_safe(
                pos_i, pos_i, pos_i, pos_i, pos_i, pos_i, pos_i,
                pos_i, pos_i, pos_i, pos_i, pos_i, pos_i, pos_i), out_of_range);
        }

        TEST(Common, FitsIn)
        {
            int neg_i = -5;
            signed pos_s = 6;
            unsigned char pos_uc = 1;
            unsigned char pos_uc_max = 0xFF;
            float f = 1.234f;
            double d = -1234;

            ASSERT_TRUE(fits_in<unsigned>(pos_s));
            ASSERT_TRUE(fits_in<char>(pos_uc));
            ASSERT_FALSE(fits_in<unsigned>(neg_i));
            ASSERT_FALSE(fits_in<char>(pos_uc_max));
            ASSERT_TRUE(fits_in<float>(d));
            ASSERT_TRUE(fits_in<double>(f));
            ASSERT_TRUE(fits_in<int>(d));
            ASSERT_TRUE(fits_in<unsigned>(f));
            ASSERT_FALSE(fits_in<unsigned>(d));
        }

        TEST(Common, DivideRoundUp)
        {
            ASSERT_EQ(0, divide_round_up(0, 4));
            ASSERT_EQ(1, divide_round_up(1, 4));
            ASSERT_EQ(1, divide_round_up(2, 4));
            ASSERT_EQ(1, divide_round_up(3, 4));
            ASSERT_EQ(1, divide_round_up(4, 4));
            ASSERT_EQ(2, divide_round_up(5, 4));
            ASSERT_EQ(2, divide_round_up(6, 4));
            ASSERT_EQ(2, divide_round_up(7, 4));
            ASSERT_EQ(2, divide_round_up(8, 4));
            ASSERT_EQ(3, divide_round_up(9, 4));
            ASSERT_EQ(3, divide_round_up(12, 4));
            ASSERT_EQ(4, divide_round_up(13, 4));
        }

        TEST(Common, GetUInt64Byte)
        {
            uint64_t number[2];
            number[0] = 0x3456789ABCDEF121;
            number[1] = 0x23456789ABCDEF12;
            ASSERT_TRUE(SEAL_BYTE(0x21) == *get_uint64_byte(number, 0));
            ASSERT_TRUE(SEAL_BYTE(0xF1) == *get_uint64_byte(number, 1));
            ASSERT_TRUE(SEAL_BYTE(0xDE) == *get_uint64_byte(number, 2));
            ASSERT_TRUE(SEAL_BYTE(0xBC) == *get_uint64_byte(number, 3));
            ASSERT_TRUE(SEAL_BYTE(0x9A) == *get_uint64_byte(number, 4));
            ASSERT_TRUE(SEAL_BYTE(0x78) == *get_uint64_byte(number, 5));
            ASSERT_TRUE(SEAL_BYTE(0x56) == *get_uint64_byte(number, 6));
            ASSERT_TRUE(SEAL_BYTE(0x34) == *get_uint64_byte(number, 7));
            ASSERT_TRUE(SEAL_BYTE(0x12) == *get_uint64_byte(number, 8));
            ASSERT_TRUE(SEAL_BYTE(0xEF) == *get_uint64_byte(number, 9));
            ASSERT_TRUE(SEAL_BYTE(0xCD) == *get_uint64_byte(number, 10));
            ASSERT_TRUE(SEAL_BYTE(0xAB) == *get_uint64_byte(number, 11));
            ASSERT_TRUE(SEAL_BYTE(0x89) == *get_uint64_byte(number, 12));
            ASSERT_TRUE(SEAL_BYTE(0x67) == *get_uint64_byte(number, 13));
            ASSERT_TRUE(SEAL_BYTE(0x45) == *get_uint64_byte(number, 14));
            ASSERT_TRUE(SEAL_BYTE(0x23) == *get_uint64_byte(number, 15));
        }

        template<typename T>
        void ReverseBits32Helper()
        {
            ASSERT_EQ(static_cast<T>(0), reverse_bits(static_cast<T>(0)));
            ASSERT_EQ(static_cast<T>(0x80000000), reverse_bits(static_cast<T>(1)));
            ASSERT_EQ(static_cast<T>(0x40000000), reverse_bits(static_cast<T>(2)));
            ASSERT_EQ(static_cast<T>(0xC0000000), reverse_bits(static_cast<T>(3)));
            ASSERT_EQ(static_cast<T>(0x00010000), reverse_bits(static_cast<T>(0x00008000)));
            ASSERT_EQ(static_cast<T>(0xFFFF0000), reverse_bits(static_cast<T>(0x0000FFFF)));
            ASSERT_EQ(static_cast<T>(0x0000FFFF), reverse_bits(static_cast<T>(0xFFFF0000)));
            ASSERT_EQ(static_cast<T>(0x00008000), reverse_bits(static_cast<T>(0x00010000)));
            ASSERT_EQ(static_cast<T>(3), reverse_bits(static_cast<T>(0xC0000000)));
            ASSERT_EQ(static_cast<T>(2), reverse_bits(static_cast<T>(0x40000000)));
            ASSERT_EQ(static_cast<T>(1), reverse_bits(static_cast<T>(0x80000000)));
            ASSERT_EQ(static_cast<T>(0xFFFFFFFF), reverse_bits(static_cast<T>(0xFFFFFFFF)));

            // Reversing a 0-bit item should return 0
            ASSERT_EQ(static_cast<T>(0), reverse_bits(static_cast<T>(0xFFFFFFFF), 0));

            // Reversing a 32-bit item returns is same as normal reverse
            ASSERT_EQ(static_cast<T>(0), reverse_bits(static_cast<T>(0), 32));
            ASSERT_EQ(static_cast<T>(0x80000000), reverse_bits(static_cast<T>(1), 32));
            ASSERT_EQ(static_cast<T>(0x40000000), reverse_bits(static_cast<T>(2), 32));
            ASSERT_EQ(static_cast<T>(0xC0000000), reverse_bits(static_cast<T>(3), 32));
            ASSERT_EQ(static_cast<T>(0x00010000), reverse_bits(static_cast<T>(0x00008000), 32));
            ASSERT_EQ(static_cast<T>(0xFFFF0000), reverse_bits(static_cast<T>(0x0000FFFF), 32));
            ASSERT_EQ(static_cast<T>(0x0000FFFF), reverse_bits(static_cast<T>(0xFFFF0000), 32));
            ASSERT_EQ(static_cast<T>(0x00008000), reverse_bits(static_cast<T>(0x00010000), 32));
            ASSERT_EQ(static_cast<T>(3), reverse_bits(static_cast<T>(0xC0000000), 32));
            ASSERT_EQ(static_cast<T>(2), reverse_bits(static_cast<T>(0x40000000), 32));
            ASSERT_EQ(static_cast<T>(1), reverse_bits(static_cast<T>(0x80000000), 32));
            ASSERT_EQ(static_cast<T>(0xFFFFFFFF), reverse_bits(static_cast<T>(0xFFFFFFFF), 32));

            // 16-bit reversal
            ASSERT_EQ(static_cast<T>(0), reverse_bits(static_cast<T>(0), 16));
            ASSERT_EQ(static_cast<T>(0x00008000), reverse_bits(static_cast<T>(1), 16));
            ASSERT_EQ(static_cast<T>(0x00004000), reverse_bits(static_cast<T>(2), 16));
            ASSERT_EQ(static_cast<T>(0x0000C000), reverse_bits(static_cast<T>(3), 16));
            ASSERT_EQ(static_cast<T>(0x00000001), reverse_bits(static_cast<T>(0x00008000), 16));
            ASSERT_EQ(static_cast<T>(0x0000FFFF), reverse_bits(static_cast<T>(0x0000FFFF), 16));
            ASSERT_EQ(static_cast<T>(0x00000000), reverse_bits(static_cast<T>(0xFFFF0000), 16));
            ASSERT_EQ(static_cast<T>(0x00000000), reverse_bits(static_cast<T>(0x00010000), 16));
            ASSERT_EQ(static_cast<T>(3), reverse_bits(static_cast<T>(0x0000C000), 16));
            ASSERT_EQ(static_cast<T>(2), reverse_bits(static_cast<T>(0x00004000), 16));
            ASSERT_EQ(static_cast<T>(1), reverse_bits(static_cast<T>(0x00008000), 16));
            ASSERT_EQ(static_cast<T>(0x0000FFFF), reverse_bits(static_cast<T>(0xFFFFFFFF), 16));
        }

        TEST(Common, ReverseBits32)
        {
            ReverseBits32Helper<uint32_t>();

            // Other types
#ifdef SEAL_USE_IF_CONSTEXPR
            SEAL_IF_CONSTEXPR (sizeof(unsigned) == 4)
                ReverseBits32Helper<unsigned>();

            SEAL_IF_CONSTEXPR (sizeof(unsigned long) == 4)
                ReverseBits32Helper<unsigned long>();

            SEAL_IF_CONSTEXPR (sizeof(unsigned long long) == 4)
                ReverseBits32Helper<unsigned long long>();

            SEAL_IF_CONSTEXPR (sizeof(size_t) == 4)
                ReverseBits32Helper<size_t>();
#endif
        }

        template<typename T>
        void ReverseBits64Helper()
        {
            ASSERT_EQ(0ULL, reverse_bits<T>(0ULL));
            ASSERT_EQ(1ULL << 63, reverse_bits<T>(1ULL));
            ASSERT_EQ(1ULL << 32, reverse_bits<T>(1ULL << 31));
            ASSERT_EQ(0xFFFFULL << 32, reverse_bits<T>(0xFFFFULL << 16));
            ASSERT_EQ(0x0000FFFFFFFF0000ULL, reverse_bits<T>(0x0000FFFFFFFF0000ULL));
            ASSERT_EQ(0x0000FFFF0000FFFFULL, reverse_bits<T>(0xFFFF0000FFFF0000ULL));

            ASSERT_EQ(0ULL, reverse_bits<T>(0ULL, 0));
            ASSERT_EQ(0ULL, reverse_bits<T>(0ULL, 1));
            ASSERT_EQ(0ULL, reverse_bits<T>(0ULL, 32));
            ASSERT_EQ(0ULL, reverse_bits<T>(0ULL, 64));

            ASSERT_EQ(0ULL, reverse_bits<T>(1ULL, 0));
            ASSERT_EQ(1ULL, reverse_bits<T>(1ULL, 1));
            ASSERT_EQ(1ULL << 31, reverse_bits<T>(1ULL, 32));
            ASSERT_EQ(1ULL << 63, reverse_bits<T>(1ULL, 64));

            ASSERT_EQ(0ULL, reverse_bits<T>(1ULL << 31, 0));
            ASSERT_EQ(0ULL, reverse_bits<T>(1ULL << 31, 1));
            ASSERT_EQ(1ULL, reverse_bits<T>(1ULL << 31, 32));
            ASSERT_EQ(1ULL << 32, reverse_bits<T>(1ULL << 31, 64));

            ASSERT_EQ(0ULL, reverse_bits<T>(0xFFFFULL << 16, 0));
            ASSERT_EQ(0ULL, reverse_bits<T>(0xFFFFULL << 16, 1));
            ASSERT_EQ(0xFFFFULL, reverse_bits<T>(0xFFFFULL << 16, 32));
            ASSERT_EQ(0xFFFFULL << 32, reverse_bits<T>(0xFFFFULL << 16, 64));

            ASSERT_EQ(0ULL, reverse_bits<T>(0x0000FFFFFFFF0000ULL, 0));
            ASSERT_EQ(0ULL, reverse_bits<T>(0x0000FFFFFFFF0000ULL, 1));
            ASSERT_EQ(0xFFFFULL, reverse_bits<T>(0x0000FFFFFFFF0000ULL, 32));
            ASSERT_EQ(0x0000FFFFFFFF0000ULL, reverse_bits<T>(0x0000FFFFFFFF0000ULL, 64));

            ASSERT_EQ(0ULL, reverse_bits<T>(0xFFFF0000FFFF0000ULL, 0));
            ASSERT_EQ(0ULL, reverse_bits<T>(0xFFFF0000FFFF0000ULL, 1));
            ASSERT_EQ(0xFFFFULL, reverse_bits<T>(0xFFFF0000FFFF0000ULL, 32));
            ASSERT_EQ(0x0000FFFF0000FFFFULL, reverse_bits<T>(0xFFFF0000FFFF0000ULL, 64));
        }

        TEST(Common, ReverseBits64)
        {
            ReverseBits64Helper<uint64_t>();

            // Other types
#ifdef SEAL_USE_IF_CONSTEXPR
            SEAL_IF_CONSTEXPR (sizeof(unsigned) == 8)
                ReverseBits64Helper<unsigned>();

            SEAL_IF_CONSTEXPR (sizeof(unsigned long) == 8)
                ReverseBits64Helper<unsigned long>();

            SEAL_IF_CONSTEXPR (sizeof(unsigned long long) == 8)
                ReverseBits64Helper<unsigned long long>();

            SEAL_IF_CONSTEXPR (sizeof(size_t) == 8)
                ReverseBits64Helper<size_t>();
#endif
        }

        TEST(Common, GetSignificantBitCount)
        {
            ASSERT_EQ(0, get_significant_bit_count(0));
            ASSERT_EQ(1, get_significant_bit_count(1));
            ASSERT_EQ(2, get_significant_bit_count(2));
            ASSERT_EQ(2, get_significant_bit_count(3));
            ASSERT_EQ(3, get_significant_bit_count(4));
            ASSERT_EQ(3, get_significant_bit_count(5));
            ASSERT_EQ(3, get_significant_bit_count(6));
            ASSERT_EQ(3, get_significant_bit_count(7));
            ASSERT_EQ(4, get_significant_bit_count(8));
            ASSERT_EQ(63, get_significant_bit_count(0x7000000000000000));
            ASSERT_EQ(63, get_significant_bit_count(0x7FFFFFFFFFFFFFFF));
            ASSERT_EQ(64, get_significant_bit_count(0x8000000000000000));
            ASSERT_EQ(64, get_significant_bit_count(0xFFFFFFFFFFFFFFFF));
        }

        TEST(Common, GetMSBIndexGeneric)
        {
            unsigned long result;
            get_msb_index_generic(&result, 1);
            ASSERT_EQ(static_cast<unsigned long>(0), result);
            get_msb_index_generic(&result, 2);
            ASSERT_EQ(static_cast<unsigned long>(1), result);
            get_msb_index_generic(&result, 3);
            ASSERT_EQ(static_cast<unsigned long>(1), result);
            get_msb_index_generic(&result, 4);
            ASSERT_EQ(static_cast<unsigned long>(2), result);
            get_msb_index_generic(&result, 16);
            ASSERT_EQ(static_cast<unsigned long>(4), result);
            get_msb_index_generic(&result, 0xFFFFFFFF);
            ASSERT_EQ(static_cast<unsigned long>(31), result);
            get_msb_index_generic(&result, 0x100000000);
            ASSERT_EQ(static_cast<unsigned long>(32), result);
            get_msb_index_generic(&result, 0xFFFFFFFFFFFFFFFF);
            ASSERT_EQ(static_cast<unsigned long>(63), result);
        }
    }
}
