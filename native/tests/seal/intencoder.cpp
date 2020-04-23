// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/context.h"
#include "seal/intencoder.h"
#include <cstddef>
#include <cstdint>
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    TEST(Encoder, IntEncodeDecodeBigUInt)
    {
        Modulus modulus(0xFFFFFFFFFFFFFFF);
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_plain_modulus(modulus);
        auto context = SEALContext::Create(parms);
        IntegerEncoder encoder(context);

        BigUInt value(64);
        value = "0";
        Plaintext poly = encoder.encode(value);
        ASSERT_EQ(0ULL, poly.significant_coeff_count());
        ASSERT_TRUE(poly.is_zero());
        ASSERT_TRUE(value == encoder.decode_biguint(poly));

        value = "1";
        Plaintext poly1 = encoder.encode(value);
        ASSERT_EQ(1ULL, poly1.coeff_count());
        ASSERT_TRUE("1" == poly1.to_string());
        ASSERT_TRUE(value == encoder.decode_biguint(poly1));

        value = "2";
        Plaintext poly2 = encoder.encode(value);
        ASSERT_EQ(2ULL, poly2.coeff_count());
        ASSERT_TRUE("1x^1" == poly2.to_string());
        ASSERT_TRUE(value == encoder.decode_biguint(poly2));

        value = "3";
        Plaintext poly3 = encoder.encode(value);
        ASSERT_EQ(2ULL, poly3.coeff_count());
        ASSERT_TRUE("1x^1 + 1" == poly3.to_string());
        ASSERT_TRUE(value == encoder.decode_biguint(poly3));

        value = "FFFFFFFFFFFFFFFF";
        Plaintext poly4 = encoder.encode(value);
        ASSERT_EQ(64ULL, poly4.coeff_count());
        for (size_t i = 0; i < 64; ++i)
        {
            ASSERT_TRUE(poly4[i] == 1);
        }
        ASSERT_TRUE(value == encoder.decode_biguint(poly4));

        value = "80F02";
        Plaintext poly5 = encoder.encode(value);
        ASSERT_EQ(20ULL, poly5.coeff_count());
        for (size_t i = 0; i < 20; ++i)
        {
            if (i == 19 || (i >= 8 && i <= 11) || i == 1)
            {
                ASSERT_TRUE(poly5[i] == 1);
            }
            else
            {
                ASSERT_TRUE(poly5[i] == 0);
            }
        }
        ASSERT_TRUE(value == encoder.decode_biguint(poly5));

        Plaintext poly6(3);
        poly6[0] = 1;
        poly6[1] = 500;
        poly6[2] = 1023;
        value = 1 + 500 * 2 + 1023 * 4;
        ASSERT_TRUE(value == encoder.decode_biguint(poly6));

        modulus = 1024;
        parms.set_plain_modulus(modulus);
        auto context2 = SEALContext::Create(parms);
        IntegerEncoder encoder2(context2);
        Plaintext poly7(4);
        poly7[0] = 1023; // -1   (*1)
        poly7[1] = 512;  // -512 (*2)
        poly7[2] = 511;  // 511  (*4)
        poly7[3] = 1;    // 1    (*8)
        value = -1 + -512 * 2 + 511 * 4 + 1 * 8;
        ASSERT_TRUE(value == encoder2.decode_biguint(poly7));
    }

    TEST(Encoder, IntEncodeDecodeUInt64)
    {
        Modulus modulus(0xFFFFFFFFFFFFFFF);
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_plain_modulus(modulus);
        auto context = SEALContext::Create(parms);
        IntegerEncoder encoder(context);

        Plaintext poly = encoder.encode(static_cast<uint64_t>(0));
        ASSERT_EQ(0ULL, poly.significant_coeff_count());
        ASSERT_TRUE(poly.is_zero());
        ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(poly));

        Plaintext poly1 = encoder.encode(1u);
        ASSERT_EQ(1ULL, poly1.coeff_count());
        ASSERT_TRUE("1" == poly1.to_string());
        ASSERT_EQ(1ULL, encoder.decode_uint64(poly1));

        Plaintext poly2 = encoder.encode(static_cast<uint64_t>(2));
        ASSERT_EQ(2ULL, poly2.coeff_count());
        ASSERT_TRUE("1x^1" == poly2.to_string());
        ASSERT_EQ(static_cast<uint64_t>(2), encoder.decode_uint64(poly2));

        Plaintext poly3 = encoder.encode(static_cast<uint64_t>(3));
        ASSERT_EQ(2ULL, poly3.coeff_count());
        ASSERT_TRUE("1x^1 + 1" == poly3.to_string());
        ASSERT_EQ(static_cast<uint64_t>(3), encoder.decode_uint64(poly3));

        Plaintext poly4 = encoder.encode(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF));
        ASSERT_EQ(64ULL, poly4.coeff_count());
        for (size_t i = 0; i < 64; ++i)
        {
            ASSERT_TRUE(poly4[i] == 1);
        }
        ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), encoder.decode_uint64(poly4));

        Plaintext poly5 = encoder.encode(static_cast<uint64_t>(0x80F02));
        ASSERT_EQ(20ULL, poly5.coeff_count());
        for (size_t i = 0; i < 20; ++i)
        {
            if (i == 19 || (i >= 8 && i <= 11) || i == 1)
            {
                ASSERT_TRUE(poly5[i] == 1);
            }
            else
            {
                ASSERT_TRUE(poly5[i] == 0);
            }
        }
        ASSERT_EQ(static_cast<uint64_t>(0x80F02), encoder.decode_uint64(poly5));

        Plaintext poly6(3);
        poly6[0] = 1;
        poly6[1] = 500;
        poly6[2] = 1023;
        ASSERT_EQ(static_cast<uint64_t>(1 + 500 * 2 + 1023 * 4), encoder.decode_uint64(poly6));

        modulus = 1024;
        parms.set_plain_modulus(modulus);
        auto context2 = SEALContext::Create(parms);
        IntegerEncoder encoder2(context2);
        Plaintext poly7(4);
        poly7[0] = 1023; // -1   (*1)
        poly7[1] = 512;  // -512 (*2)
        poly7[2] = 511;  // 511  (*4)
        poly7[3] = 1;    // 1    (*8)
        ASSERT_EQ(static_cast<uint64_t>(-1 + -512 * 2 + 511 * 4 + 1 * 8), encoder2.decode_uint64(poly7));
    }

    TEST(Encoder, IntEncodeDecodeUInt32)
    {
        Modulus modulus(0xFFFFFFFFFFFFFFF);
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_plain_modulus(modulus);
        auto context = SEALContext::Create(parms);
        IntegerEncoder encoder(context);

        Plaintext poly = encoder.encode(static_cast<uint32_t>(0));
        ASSERT_EQ(0ULL, poly.significant_coeff_count());
        ASSERT_TRUE(poly.is_zero());
        ASSERT_EQ(static_cast<uint32_t>(0), encoder.decode_uint32(poly));

        Plaintext poly1 = encoder.encode(static_cast<uint32_t>(1));
        ASSERT_EQ(1ULL, poly1.significant_coeff_count());
        ASSERT_TRUE("1" == poly1.to_string());
        ASSERT_EQ(static_cast<uint32_t>(1), encoder.decode_uint32(poly1));

        Plaintext poly2 = encoder.encode(static_cast<uint32_t>(2));
        ASSERT_EQ(2ULL, poly2.significant_coeff_count());
        ASSERT_TRUE("1x^1" == poly2.to_string());
        ASSERT_EQ(static_cast<uint32_t>(2), encoder.decode_uint32(poly2));

        Plaintext poly3 = encoder.encode(static_cast<uint32_t>(3));
        ASSERT_EQ(2ULL, poly3.significant_coeff_count());
        ASSERT_TRUE("1x^1 + 1" == poly3.to_string());
        ASSERT_EQ(static_cast<uint32_t>(3), encoder.decode_uint32(poly3));

        Plaintext poly4 = encoder.encode(static_cast<uint32_t>(0xFFFFFFFF));
        ASSERT_EQ(32ULL, poly4.significant_coeff_count());
        for (size_t i = 0; i < 32; ++i)
        {
            ASSERT_TRUE(1 == poly4[i]);
        }
        ASSERT_EQ(static_cast<uint32_t>(0xFFFFFFFF), encoder.decode_uint32(poly4));

        Plaintext poly5 = encoder.encode(static_cast<uint32_t>(0x80F02));
        ASSERT_EQ(20ULL, poly5.significant_coeff_count());
        for (size_t i = 0; i < 20; ++i)
        {
            if (i == 19 || (i >= 8 && i <= 11) || i == 1)
            {
                ASSERT_TRUE(1 == poly5[i]);
            }
            else
            {
                ASSERT_TRUE(poly5[i] == 0);
            }
        }
        ASSERT_EQ(static_cast<uint32_t>(0x80F02), encoder.decode_uint32(poly5));

        Plaintext poly6(3);
        poly6[0] = 1;
        poly6[1] = 500;
        poly6[2] = 1023;
        ASSERT_EQ(static_cast<uint32_t>(1 + 500 * 2 + 1023 * 4), encoder.decode_uint32(poly6));

        modulus = 1024;
        parms.set_plain_modulus(modulus);
        auto context2 = SEALContext::Create(parms);
        IntegerEncoder encoder2(context2);
        Plaintext poly7(4);
        poly7[0] = 1023; // -1   (*1)
        poly7[1] = 512;  // -512 (*2)
        poly7[2] = 511;  // 511  (*4)
        poly7[3] = 1;    // 1    (*8)
        ASSERT_EQ(static_cast<uint32_t>(-1 + -512 * 2 + 511 * 4 + 1 * 8), encoder2.decode_uint32(poly7));
    }

    TEST(Encoder, IntEncodeDecodeInt64)
    {
        Modulus modulus(0x7FFFFFFFFFFFF);
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_plain_modulus(modulus);
        auto context = SEALContext::Create(parms);
        IntegerEncoder encoder(context);

        Plaintext poly = encoder.encode(static_cast<int64_t>(0));
        ASSERT_EQ(0ULL, poly.significant_coeff_count());
        ASSERT_TRUE(poly.is_zero());
        ASSERT_EQ(static_cast<uint64_t>(0), static_cast<uint64_t>(encoder.decode_int64(poly)));

        Plaintext poly1 = encoder.encode(static_cast<int64_t>(1));
        ASSERT_EQ(1ULL, poly1.significant_coeff_count());
        ASSERT_TRUE("1" == poly1.to_string());
        ASSERT_EQ(1ULL, static_cast<uint64_t>(encoder.decode_int64(poly1)));

        Plaintext poly2 = encoder.encode(static_cast<int64_t>(2));
        ASSERT_EQ(2ULL, poly2.significant_coeff_count());
        ASSERT_TRUE("1x^1" == poly2.to_string());
        ASSERT_EQ(static_cast<uint64_t>(2), static_cast<uint64_t>(encoder.decode_int64(poly2)));

        Plaintext poly3 = encoder.encode(static_cast<int64_t>(3));
        ASSERT_EQ(2ULL, poly3.significant_coeff_count());
        ASSERT_TRUE("1x^1 + 1" == poly3.to_string());
        ASSERT_EQ(static_cast<uint64_t>(3), static_cast<uint64_t>(encoder.decode_int64(poly3)));

        Plaintext poly4 = encoder.encode(static_cast<int64_t>(-1));
        ASSERT_EQ(1ULL, poly4.significant_coeff_count());
        ASSERT_TRUE("7FFFFFFFFFFFE" == poly4.to_string());
        ASSERT_EQ(static_cast<uint64_t>(-1), static_cast<uint64_t>(encoder.decode_int64(poly4)));

        Plaintext poly5 = encoder.encode(static_cast<int64_t>(-2));
        ASSERT_EQ(2ULL, poly5.significant_coeff_count());
        ASSERT_TRUE("7FFFFFFFFFFFEx^1" == poly5.to_string());
        ASSERT_EQ(static_cast<uint64_t>(-2), static_cast<uint64_t>(encoder.decode_int64(poly5)));

        Plaintext poly6 = encoder.encode(static_cast<int64_t>(-3));
        ASSERT_EQ(2ULL, poly6.significant_coeff_count());
        ASSERT_TRUE("7FFFFFFFFFFFEx^1 + 7FFFFFFFFFFFE" == poly6.to_string());
        ASSERT_EQ(static_cast<uint64_t>(-3), static_cast<uint64_t>(encoder.decode_int64(poly6)));

        Plaintext poly7 = encoder.encode(static_cast<int64_t>(0x7FFFFFFFFFFFF));
        ASSERT_EQ(51ULL, poly7.significant_coeff_count());
        for (size_t i = 0; i < 51; ++i)
        {
            ASSERT_TRUE(1 == poly7[i]);
        }
        ASSERT_EQ(static_cast<uint64_t>(0x7FFFFFFFFFFFF), static_cast<uint64_t>(encoder.decode_int64(poly7)));

        Plaintext poly8 = encoder.encode(static_cast<int64_t>(0x8000000000000));
        ASSERT_EQ(52ULL, poly8.significant_coeff_count());
        ASSERT_TRUE(poly8[51] == 1);
        for (size_t i = 0; i < 51; ++i)
        {
            ASSERT_TRUE(poly8[i] == 0);
        }
        ASSERT_EQ(static_cast<uint64_t>(0x8000000000000), static_cast<uint64_t>(encoder.decode_int64(poly8)));

        Plaintext poly9 = encoder.encode(static_cast<int64_t>(0x80F02));
        ASSERT_EQ(20ULL, poly9.significant_coeff_count());
        for (size_t i = 0; i < 20; ++i)
        {
            if (i == 19 || (i >= 8 && i <= 11) || i == 1)
            {
                ASSERT_TRUE(1 == poly9[i]);
            }
            else
            {
                ASSERT_TRUE(poly9[i] == 0);
            }
        }
        ASSERT_EQ(static_cast<uint64_t>(0x80F02), static_cast<uint64_t>(encoder.decode_int64(poly9)));

        Plaintext poly10 = encoder.encode(static_cast<int64_t>(-1073));
        ASSERT_EQ(11ULL, poly10.significant_coeff_count());
        ASSERT_TRUE(0x7FFFFFFFFFFFE == poly10[10]);
        ASSERT_TRUE(poly10[9] == 0);
        ASSERT_TRUE(poly10[8] == 0);
        ASSERT_TRUE(poly10[7] == 0);
        ASSERT_TRUE(poly10[6] == 0);
        ASSERT_TRUE(0x7FFFFFFFFFFFE == poly10[5]);
        ASSERT_TRUE(0x7FFFFFFFFFFFE == poly10[4]);
        ASSERT_TRUE(poly10[3] == 0);
        ASSERT_TRUE(poly10[2] == 0);
        ASSERT_TRUE(poly10[1] == 0);
        ASSERT_TRUE(0x7FFFFFFFFFFFE == poly10[0]);
        ASSERT_EQ(static_cast<uint64_t>(-1073), static_cast<uint64_t>(encoder.decode_int64(poly10)));

        modulus = 0xFFFF;
        parms.set_plain_modulus(modulus);
        auto context2 = SEALContext::Create(parms);
        IntegerEncoder encoder2(context2);
        Plaintext poly11(6);
        poly11[0] = 1;
        poly11[1] = 0xFFFE; // -1
        poly11[2] = 0xFFFD; // -2
        poly11[3] = 0x8000; // -32767
        poly11[4] = 0x7FFF; // 32767
        poly11[5] = 0x7FFE; // 32766
        ASSERT_EQ(
            static_cast<uint64_t>(1 + -1 * 2 + -2 * 4 + -32767 * 8 + 32767 * 16 + 32766 * 32),
            static_cast<uint64_t>(encoder2.decode_int64(poly11)));
    }

    TEST(Encoder, IntEncodeDecodeInt32)
    {
        Modulus modulus(0x7FFFFFFFFFFFFF);
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_plain_modulus(modulus);
        auto context = SEALContext::Create(parms);
        IntegerEncoder encoder(context);

        Plaintext poly = encoder.encode(static_cast<int32_t>(0));
        ASSERT_EQ(0ULL, poly.significant_coeff_count());
        ASSERT_TRUE(poly.is_zero());
        ASSERT_EQ(static_cast<int32_t>(0), encoder.decode_int32(poly));

        Plaintext poly1 = encoder.encode(static_cast<int32_t>(1));
        ASSERT_EQ(1ULL, poly1.significant_coeff_count());
        ASSERT_TRUE("1" == poly1.to_string());
        ASSERT_EQ(static_cast<int32_t>(1), encoder.decode_int32(poly1));

        Plaintext poly2 = encoder.encode(static_cast<int32_t>(2));
        ASSERT_EQ(2ULL, poly2.significant_coeff_count());
        ASSERT_TRUE("1x^1" == poly2.to_string());
        ASSERT_EQ(static_cast<int32_t>(2), encoder.decode_int32(poly2));

        Plaintext poly3 = encoder.encode(static_cast<int32_t>(3));
        ASSERT_EQ(2ULL, poly3.significant_coeff_count());
        ASSERT_TRUE("1x^1 + 1" == poly3.to_string());
        ASSERT_EQ(static_cast<int32_t>(3), encoder.decode_int32(poly3));

        Plaintext poly4 = encoder.encode(static_cast<int32_t>(-1));
        ASSERT_EQ(1ULL, poly4.significant_coeff_count());
        ASSERT_TRUE("7FFFFFFFFFFFFE" == poly4.to_string());
        ASSERT_EQ(static_cast<int32_t>(-1), encoder.decode_int32(poly4));

        Plaintext poly5 = encoder.encode(static_cast<int32_t>(-2));
        ASSERT_EQ(2ULL, poly5.significant_coeff_count());
        ASSERT_TRUE("7FFFFFFFFFFFFEx^1" == poly5.to_string());
        ASSERT_EQ(static_cast<int32_t>(-2), encoder.decode_int32(poly5));

        Plaintext poly6 = encoder.encode(static_cast<int32_t>(-3));
        ASSERT_EQ(2ULL, poly6.significant_coeff_count());
        ASSERT_TRUE("7FFFFFFFFFFFFEx^1 + 7FFFFFFFFFFFFE" == poly6.to_string());
        ASSERT_EQ(static_cast<int32_t>(-3), encoder.decode_int32(poly6));

        Plaintext poly7 = encoder.encode(static_cast<int32_t>(0x7FFFFFFF));
        ASSERT_EQ(31ULL, poly7.significant_coeff_count());
        for (size_t i = 0; i < 31; ++i)
        {
            ASSERT_TRUE(1 == poly7[i]);
        }
        ASSERT_EQ(static_cast<int32_t>(0x7FFFFFFF), encoder.decode_int32(poly7));

        Plaintext poly8 = encoder.encode(static_cast<int32_t>(0x80000000));
        ASSERT_EQ(32ULL, poly8.significant_coeff_count());
        ASSERT_TRUE(0x7FFFFFFFFFFFFE == poly8[31]);
        for (size_t i = 0; i < 31; ++i)
        {
            ASSERT_TRUE(poly8[i] == 0);
        }
        ASSERT_EQ(static_cast<int32_t>(0x80000000), encoder.decode_int32(poly8));

        Plaintext poly9 = encoder.encode(static_cast<int32_t>(0x80F02));
        ASSERT_EQ(20ULL, poly9.significant_coeff_count());
        for (size_t i = 0; i < 20; ++i)
        {
            if (i == 19 || (i >= 8 && i <= 11) || i == 1)
            {
                ASSERT_TRUE(1 == poly9[i]);
            }
            else
            {
                ASSERT_TRUE(poly9[i] == 0);
            }
        }
        ASSERT_EQ(static_cast<int32_t>(0x80F02), encoder.decode_int32(poly9));

        Plaintext poly10 = encoder.encode(static_cast<int32_t>(-1073));
        ASSERT_EQ(11ULL, poly10.significant_coeff_count());
        ASSERT_TRUE(0x7FFFFFFFFFFFFE == poly10[10]);
        ASSERT_TRUE(poly10[9] == 0);
        ASSERT_TRUE(poly10[8] == 0);
        ASSERT_TRUE(poly10[7] == 0);
        ASSERT_TRUE(poly10[6] == 0);
        ASSERT_TRUE(0x7FFFFFFFFFFFFE == poly10[5]);
        ASSERT_TRUE(0x7FFFFFFFFFFFFE == poly10[4]);
        ASSERT_TRUE(poly10[3] == 0);
        ASSERT_TRUE(poly10[2] == 0);
        ASSERT_TRUE(poly10[1] == 0);
        ASSERT_TRUE(0x7FFFFFFFFFFFFE == poly10[0]);
        ASSERT_EQ(static_cast<int32_t>(-1073), encoder.decode_int32(poly10));

        modulus = 0xFFFF;
        parms.set_plain_modulus(modulus);
        auto context2 = SEALContext::Create(parms);
        IntegerEncoder encoder2(context2);
        Plaintext poly11(6);
        poly11[0] = 1;
        poly11[1] = 0xFFFE; // -1
        poly11[2] = 0xFFFD; // -2
        poly11[3] = 0x8000; // -32767
        poly11[4] = 0x7FFF; // 32767
        poly11[5] = 0x7FFE; // 32766
        ASSERT_EQ(
            static_cast<int32_t>(1 + -1 * 2 + -2 * 4 + -32767 * 8 + 32767 * 16 + 32766 * 32),
            encoder2.decode_int32(poly11));
    }
} // namespace sealtest
