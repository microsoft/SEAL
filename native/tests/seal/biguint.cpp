// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/biguint.h"
#include "seal/util/defines.h"

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(BigUnsignedInt, EmptyBigUInt)
    {
        BigUInt uint;
        ASSERT_EQ(0, uint.bit_count());
        ASSERT_TRUE(nullptr == uint.data());
        ASSERT_EQ(0ULL, uint.byte_count());
        ASSERT_EQ(0ULL, uint.uint64_count());
        ASSERT_EQ(0, uint.significant_bit_count());
        ASSERT_TRUE("0" == uint.to_string());
        ASSERT_TRUE(uint.is_zero());
        ASSERT_FALSE(uint.is_alias());
        uint.set_zero();

        BigUInt uint2;
        ASSERT_TRUE(uint == uint2);
        ASSERT_FALSE(uint != uint2);

        uint.resize(1);
        ASSERT_EQ(1, uint.bit_count());
        ASSERT_TRUE(nullptr != uint.data());
        ASSERT_FALSE(uint.is_alias());

        uint.resize(0);
        ASSERT_EQ(0, uint.bit_count());
        ASSERT_TRUE(nullptr == uint.data());
        ASSERT_FALSE(uint.is_alias());
    }

    TEST(BigUnsignedInt, BigUInt64Bits)
    {
        BigUInt uint(64);
        ASSERT_EQ(64, uint.bit_count());
        ASSERT_TRUE(nullptr != uint.data());
        ASSERT_EQ(8ULL, uint.byte_count());
        ASSERT_EQ(1ULL, uint.uint64_count());
        ASSERT_EQ(0, uint.significant_bit_count());
        ASSERT_TRUE("0" == uint.to_string());
        ASSERT_TRUE(uint.is_zero());
        ASSERT_EQ(static_cast<uint64_t>(0), *uint.data());
        ASSERT_TRUE(SEAL_BYTE(0) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[7]);

        uint = "1";
        ASSERT_EQ(1, uint.significant_bit_count());
        ASSERT_TRUE("1" == uint.to_string());
        ASSERT_FALSE(uint.is_zero());
        ASSERT_EQ(1ULL, *uint.data());
        ASSERT_TRUE(SEAL_BYTE(1) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[7]);
        uint.set_zero();
        ASSERT_TRUE(uint.is_zero());
        ASSERT_EQ(static_cast<uint64_t>(0), *uint.data());

        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_EQ(63, uint.significant_bit_count());
        ASSERT_TRUE("7FFFFFFFFFFFFFFF" == uint.to_string());
        ASSERT_EQ(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF), *uint.data());
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0x7F) == uint[7]);
        ASSERT_FALSE(uint.is_zero());

        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_EQ(64, uint.significant_bit_count());
        ASSERT_TRUE("FFFFFFFFFFFFFFFF" == uint.to_string());
        ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), *uint.data());
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[7]);
        ASSERT_FALSE(uint.is_zero());

        uint = 0x8001;
        ASSERT_EQ(16, uint.significant_bit_count());
        ASSERT_TRUE("8001" == uint.to_string());
        ASSERT_EQ(static_cast<uint64_t>(0x8001), *uint.data());
        ASSERT_TRUE(SEAL_BYTE(0x01) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0x80) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[7]);
    }

    TEST(BigUnsignedInt, BigUInt99Bits)
    {
        BigUInt uint(99);
        ASSERT_EQ(99, uint.bit_count());
        ASSERT_TRUE(nullptr != uint.data());
        ASSERT_EQ(13ULL, uint.byte_count());
        ASSERT_EQ(2ULL, uint.uint64_count());
        ASSERT_EQ(0, uint.significant_bit_count());
        ASSERT_TRUE("0" == uint.to_string());
        ASSERT_TRUE(uint.is_zero());
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[0]);
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[7]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[8]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[9]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[10]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[11]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[12]);

        uint = "1";
        ASSERT_EQ(1, uint.significant_bit_count());
        ASSERT_TRUE("1" == uint.to_string());
        ASSERT_FALSE(uint.is_zero());
        ASSERT_EQ(1ULL, uint.data()[0]);
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
        ASSERT_TRUE(SEAL_BYTE(1) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[7]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[8]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[9]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[10]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[11]);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[12]);
        uint.set_zero();
        ASSERT_TRUE(uint.is_zero());
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[0]);
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);

        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_EQ(99, uint.significant_bit_count());
        ASSERT_TRUE("7FFFFFFFFFFFFFFFFFFFFFFFF" == uint.to_string());
        ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), uint.data()[0]);
        ASSERT_EQ(static_cast<uint64_t>(0x7FFFFFFFF), uint.data()[1]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[7]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[8]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[9]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[10]);
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[11]);
        ASSERT_TRUE(SEAL_BYTE(0x07) == uint[12]);
        ASSERT_FALSE(uint.is_zero());
        uint.set_zero();
        ASSERT_TRUE(uint.is_zero());
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[0]);
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);

        uint = "4000000000000000000000000";
        ASSERT_EQ(99, uint.significant_bit_count());
        ASSERT_TRUE("4000000000000000000000000" == uint.to_string());
        ASSERT_EQ(static_cast<uint64_t>(0x0000000000000000), uint.data()[0]);
        ASSERT_EQ(static_cast<uint64_t>(0x400000000), uint.data()[1]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[7]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[8]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[9]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[10]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[11]);
        ASSERT_TRUE(SEAL_BYTE(0x04) == uint[12]);
        ASSERT_FALSE(uint.is_zero());

        uint = 0x8001;
        ASSERT_EQ(16, uint.significant_bit_count());
        ASSERT_TRUE("8001" == uint.to_string());
        ASSERT_EQ(static_cast<uint64_t>(0x8001), uint.data()[0]);
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
        ASSERT_TRUE(SEAL_BYTE(0x01) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0x80) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[7]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[8]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[9]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[10]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[11]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[12]);

        BigUInt uint2("123");
        ASSERT_FALSE(uint == uint2);
        ASSERT_FALSE(uint2 == uint);
        ASSERT_TRUE(uint != uint2);
        ASSERT_TRUE(uint2 != uint);

        uint = uint2;
        ASSERT_TRUE(uint == uint2);
        ASSERT_FALSE(uint != uint2);
        ASSERT_EQ(9, uint.significant_bit_count());
        ASSERT_TRUE("123" == uint.to_string());
        ASSERT_EQ(static_cast<uint64_t>(0x123), uint.data()[0]);
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
        ASSERT_TRUE(SEAL_BYTE(0x23) == uint[0]);
        ASSERT_TRUE(SEAL_BYTE(0x01) == uint[1]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[2]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[3]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[4]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[5]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[6]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[7]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[8]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[9]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[10]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[11]);
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[12]);

        uint.resize(8);
        ASSERT_EQ(8, uint.bit_count());
        ASSERT_EQ(1ULL, uint.uint64_count());
        ASSERT_TRUE("23" == uint.to_string());

        uint.resize(100);
        ASSERT_EQ(100, uint.bit_count());
        ASSERT_EQ(2ULL, uint.uint64_count());
        ASSERT_TRUE("23" == uint.to_string());

        uint.resize(0);
        ASSERT_EQ(0, uint.bit_count());
        ASSERT_EQ(0ULL, uint.uint64_count());
        ASSERT_TRUE(nullptr == uint.data());
    }

    TEST(BigUnsignedInt, SaveLoadUInt)
    {
        stringstream stream;

        BigUInt value;
        BigUInt value2("100");
        value.save(stream);
        value2.load(stream);
        ASSERT_TRUE(value == value2);

        value = "123";
        value.save(stream);
        value2.load(stream);
        ASSERT_TRUE(value == value2);

        value = "FFFFFFFFFFFFFFFFFFFFFFFFFF";
        value.save(stream);
        value2.load(stream);
        ASSERT_TRUE(value == value2);

        value = "0";
        value.save(stream);
        value2.load(stream);
        ASSERT_TRUE(value == value2);
    }

    TEST(BigUnsignedInt, DuplicateTo)
    {
        BigUInt original(123);
        original = 56789;

        BigUInt target;

        original.duplicate_to(target);
        ASSERT_EQ(target.bit_count(), original.bit_count());
        ASSERT_TRUE(target == original);
    }

    TEST(BigUnsignedInt, DuplicateFrom)
    {
        BigUInt original(123);
        original = 56789;

        BigUInt target;

        target.duplicate_from(original);
        ASSERT_EQ(target.bit_count(), original.bit_count());
        ASSERT_TRUE(target == original);
    }

    TEST(BigUnsignedInt, BigUIntCopyMoveAssign)
    {
        {
            BigUInt p1("123");
            BigUInt p2("456");
            BigUInt p3;

            p1.operator =(p2);
            p3.operator =(p1);
            ASSERT_TRUE(p1 == p2);
            ASSERT_TRUE(p3 == p1);
        }
        {
            BigUInt p1("123");
            BigUInt p2("456");
            BigUInt p3;
            BigUInt p4(p2);

            p1.operator =(move(p2));
            p3.operator =(move(p1));
            ASSERT_TRUE(p3 == p4);
            ASSERT_TRUE(p1 == p2);
            ASSERT_TRUE(p3 == p1);
        }
        {
            uint64_t p1_anchor = 123;
            uint64_t p2_anchor = 456;
            BigUInt p1(64, &p1_anchor);
            BigUInt p2(64, &p2_anchor);
            BigUInt p3;

            p1.operator =(p2);
            p3.operator =(p1);
            ASSERT_TRUE(p1 == p2);
            ASSERT_TRUE(p3 == p1);
        }
        {
            uint64_t p1_anchor = 123;
            uint64_t p2_anchor = 456;
            BigUInt p1(64, &p1_anchor);
            BigUInt p2(64, &p2_anchor);
            BigUInt p3;
            BigUInt p4(p2);

            p1.operator =(move(p2));
            p3.operator =(move(p1));
            ASSERT_TRUE(p3 == p4);
            ASSERT_TRUE(p2 == 456);
            ASSERT_TRUE(p1 == 456);
            ASSERT_TRUE(p3 == 456);
        }
    }
}
