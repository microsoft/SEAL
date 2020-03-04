// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/memorymanager.h"
#include "seal/util/baseconverter.h"
#include "seal/util/numth.h"
#include <cstdint>
#include <vector>
#include "gtest/gtest.h"

using namespace seal::util;
using namespace seal;
using namespace std;

namespace SEALTest
{
    namespace util
    {
        TEST(BaseConverter, Initialize)
        {
            int poly_modulus_degree = 32;
            int coeff_base_count = 4;
            int prime_bit_count = 20;

            SmallModulus plain_t = 65537;
            vector<SmallModulus> coeff_base = get_primes(poly_modulus_degree, prime_bit_count, coeff_base_count);

            BaseConverter base_converter(poly_modulus_degree, coeff_base, plain_t, MemoryManager::GetPool());
            ASSERT_TRUE(base_converter.is_initialized());

            // Succeeds with 0 plain_modulus (case of CKKS)
            ASSERT_TRUE(base_converter.initialize(poly_modulus_degree, coeff_base, 0));

            // Fails when poly_modulus_degree is too small
            ASSERT_FALSE(base_converter.initialize(1, coeff_base, plain_t));

            // Fails when coeff_modulus is not relatively prime
            coeff_base.push_back(coeff_base.back());
            ASSERT_FALSE(base_converter.initialize(poly_modulus_degree, coeff_base, plain_t));
            coeff_base.pop_back();
        }

        TEST(BaseConverter, FastBConvMTilde)
        {
            // This function multiplies an input array with m_tilde (modulo q-base) and subsequently
            // performs base conversion to Bsk U {m_tilde}.

            SmallModulus plain_t = 0;
            auto pool = MemoryManager::GetPool();

            {
                size_t poly_modulus_degree = 2;
                size_t coeff_mod_count = 1;
                BaseConverter base_converter(poly_modulus_degree, { 3 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(poly_modulus_degree * coeff_mod_count);
                vector<uint64_t> out(poly_modulus_degree * base_converter.base_Bsk_m_tilde_size());
                set_zero_uint(in.size(), in.data());
                base_converter.fastbconv_m_tilde(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                in[0] = 1;
                in[1] = 2;
                base_converter.fastbconv_m_tilde(in.data(), out.data(), pool);
                uint64_t temp = base_converter.m_tilde().value() % 3;
                uint64_t temp2 = (2 * base_converter.m_tilde().value()) % 3;
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[0].value(), out[0]);
                ASSERT_EQ(temp2 % base_converter.base_Bsk_m_tilde()[0].value(), out[1]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[1].value(), out[2]);
                ASSERT_EQ(temp2 % base_converter.base_Bsk_m_tilde()[1].value(), out[3]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[2].value(), out[4]);
                ASSERT_EQ(temp2 % base_converter.base_Bsk_m_tilde()[2].value(), out[5]);
            }
            {
                size_t poly_modulus_degree = 2;
                size_t coeff_mod_count = 2;
                BaseConverter base_converter(poly_modulus_degree, { 3, 5 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(poly_modulus_degree * coeff_mod_count);
                vector<uint64_t> out(poly_modulus_degree * base_converter.base_Bsk_m_tilde_size());
                set_zero_uint(in.size(), in.data());
                base_converter.fastbconv_m_tilde(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                in[0] = 1;
                in[1] = 0;
                in[2] = 2;
                in[3] = 0;
                base_converter.fastbconv_m_tilde(in.data(), out.data(), pool);
                uint64_t m_tilde = base_converter.m_tilde().value();
                uint64_t temp = ((2 * m_tilde) % 3) * 5 + ((4 * m_tilde) % 5) * 3;
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[0].value(), out[0]);
                ASSERT_EQ(0, out[1]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[1].value(), out[2]);
                ASSERT_EQ(0, out[3]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[2].value(), out[4]);
                ASSERT_EQ(0, out[5]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[3].value(), out[6]);
                ASSERT_EQ(0, out[7]);
            }
        }

        // TEST(BaseConverter, FastBConv)
        //{
        //    {
        //        MemoryPoolMT& pool = *MemoryPoolMT::default_pool();
        //        vector<SmallModulus> coeff_base;
        //        vector<SmallModulus> aux_base;
        //        SmallModulus plain_t = small_mods[9];
        //        int coeff_base_count = 2;
        //        int aux_base_count = 2;

        //        for (int i = 0; i < coeff_base_count; ++i)
        //        {
        //            coeff_base.push_back(small_mods[i]);
        //            aux_base.push_back(small_mods[i + coeff_base_count + 2]);
        //        }

        //        BaseConverter base_converter(coeff_base, 1, plain_t);
        //        Pointer input(allocate_uint(2, pool));
        //        Pointer output(allocate_uint(3, pool));

        //        // the composed input is 0xffffffffffffff00ffffffffffffff

        //        input[0] = 4395513236581707780;
        //        input[1] = 4395513390924464132;

        //        output[0] = 0xFFFFFFFFFFFFFFFF;
        //        output[1] = 0xFFFFFFFFFFFFFFFF;
        //        output[2] = 0;

        //        Assert::IsTrue(base_converter.fastbconv(input.get(), output.get()));
        //        Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[0]);
        //        Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[1]);
        //        Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[2]);
        //    }

        //    {
        //        MemoryPoolMT& pool = *MemoryPoolMT::default_pool();
        //        vector<SmallModulus> coeff_base;
        //        vector<SmallModulus> aux_base;
        //        SmallModulus mtilde = small_mods[10];
        //        SmallModulus msk = small_mods[11];
        //        SmallModulus plain_t = small_mods[9];
        //        int coeff_base_count = 2;
        //        int aux_base_count = 2;

        //        for (int i = 0; i < coeff_base_count; ++i)
        //        {
        //            coeff_base.push_back(small_mods[i]);
        //            aux_base.push_back(small_mods[i + coeff_base_count + 2]);
        //        }
        //        BaseConverter base_converter(coeff_base, 4, plain_t);
        //        Pointer input(allocate_uint(8, pool));
        //        Pointer output(allocate_uint(12, pool));

        //        // the composed input is 0xffffffffffffff00ffffffffffffff for all coeffs
        //        // mod q1
        //        input[0] = 4395513236581707780; // cons
        //        input[1] = 4395513236581707780; // x
        //        input[2] = 4395513236581707780; // x^2
        //        input[3] = 4395513236581707780; // x^3

        //        //mod q2
        //        input[4] = 4395513390924464132;
        //        input[5] = 4395513390924464132;
        //        input[6] = 4395513390924464132;
        //        input[7] = 4395513390924464132;

        //        output[0] = 0xFFFFFFFFFFFFFFFF;
        //        output[1] = 0xFFFFFFFFFFFFFFFF;
        //        output[2] = 0;

        //        Assert::IsTrue(base_converter.fastbconv(input.get(), output.get()));
        //        Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[0]);
        //        Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[1]);
        //        Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[2]);
        //        Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[3]);

        //        Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[4]);
        //        Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[5]);
        //        Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[6]);
        //        Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[7]);

        //        Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[8]);
        //        Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[9]);
        //        Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[10]);
        //        Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[11]);
        //    }
        //}

        // TEST(BaseConverter, FastBConvSK)
        //{
        //    {
        //        MemoryPoolMT& pool = *MemoryPoolMT::default_pool();
        //        vector<SmallModulus> coeff_base;
        //        vector<SmallModulus> aux_base;
        //        SmallModulus mtilde = small_mods[10];
        //        SmallModulus msk = small_mods[4];
        //        SmallModulus plain_t = small_mods[9];

        //        int coeff_base_count = 2;
        //        int aux_base_count = 2;
        //        for (int i = 0; i < coeff_base_count; ++i)
        //        {
        //            coeff_base.push_back(small_mods[i]);
        //            aux_base.push_back(small_mods[i + coeff_base_count]);
        //        }

        //        BaseConverter base_converter(coeff_base, 1, plain_t);
        //        Pointer input(allocate_uint(3, pool));
        //        Pointer output(allocate_uint(2, pool));

        //        // The composed input is 0xffffffffffffff00ffffffffffffff

        //        input[0] = 4395583330278772740;
        //        input[1] = 4396634741790752772;
        //        input[2] = 4396375252835237892;    // mod msk

        //        output[0] = 0xFFFFFFFFFFFFFFF;
        //        output[1] = 0xFFFFFFFFFFFFFFF;

        //        Assert::IsTrue(base_converter.fastbconv_sk(input.get(), output.get()));
        //        Assert::AreEqual(static_cast<uint64_t>(2494482839790051254), output[0]);
        //        Assert::AreEqual(static_cast<uint64_t>(218180408843610743), output[1]);
        //    }

        //    {
        //        MemoryPoolMT& pool = *MemoryPoolMT::default_pool();
        //        vector<SmallModulus> coeff_base;
        //        vector<SmallModulus> aux_base;
        //        SmallModulus mtilde = small_mods[10];
        //        SmallModulus msk = small_mods[4];
        //        SmallModulus plain_t = small_mods[9];

        //        int coeff_base_count = 2;
        //        int aux_base_count = 2;
        //        for (int i = 0; i < coeff_base_count; ++i)
        //        {
        //            coeff_base.push_back(small_mods[i]);
        //            aux_base.push_back(small_mods[i + coeff_base_count]);
        //        }

        //        BaseConverter base_converter(coeff_base, 4, plain_t);
        //        Pointer input(allocate_uint(12, pool));
        //        Pointer output(allocate_uint(8, pool));

        //        // The composed input is 0xffffffffffffff00ffffffffffffff

        //        input[0] = 4395583330278772740;    // cons
        //        input[1] = 4395583330278772740; // x
        //        input[2] = 4395583330278772740; // x^2
        //        input[3] = 4395583330278772740; // x^3

        //        input[4] = 4396634741790752772;
        //        input[5] = 4396634741790752772;
        //        input[6] = 4396634741790752772;
        //        input[7] = 4396634741790752772;

        //        input[8] = 4396375252835237892;    // mod msk
        //        input[9] = 4396375252835237892;
        //        input[10] = 4396375252835237892;
        //        input[11] = 4396375252835237892;

        //        output[0] = 0xFFFFFFFFFFFFFFF;
        //        output[1] = 0xFFFFFFFFFFFFFFF;

        //        Assert::IsTrue(base_converter.fastbconv_sk(input.get(), output.get()));
        //        Assert::AreEqual(static_cast<uint64_t>(2494482839790051254), output[0]); //mod q1
        //        Assert::AreEqual(static_cast<uint64_t>(2494482839790051254), output[1]);
        //        Assert::AreEqual(static_cast<uint64_t>(2494482839790051254), output[2]);
        //        Assert::AreEqual(static_cast<uint64_t>(2494482839790051254), output[3]);

        //        Assert::AreEqual(static_cast<uint64_t>(218180408843610743), output[4]); //mod q2
        //        Assert::AreEqual(static_cast<uint64_t>(218180408843610743), output[5]);
        //        Assert::AreEqual(static_cast<uint64_t>(218180408843610743), output[6]);
        //        Assert::AreEqual(static_cast<uint64_t>(218180408843610743), output[7]);
        //    }

        //}

        // TEST(BaseConverter, MontRq)
        //{
        //    {
        //        MemoryPoolMT& pool = *MemoryPoolMT::default_pool();
        //        vector<SmallModulus> coeff_base;
        //        vector<SmallModulus> aux_base;
        //        SmallModulus mtilde = small_mods[5];
        //        SmallModulus msk = small_mods[4];
        //        SmallModulus plain_t = small_mods[9];

        //        int coeff_base_count = 2;
        //        int aux_base_count = 2;
        //        for (int i = 0; i < coeff_base_count; ++i)
        //        {
        //            coeff_base.push_back(small_mods[i]);
        //            aux_base.push_back(small_mods[i + coeff_base_count]);
        //        }

        //        BaseConverter base_converter(coeff_base, 1, plain_t);
        //        Pointer input(allocate_uint(4, pool));
        //        Pointer output(allocate_uint(3, pool));

        //        // The composed input is 0xffffffffffffff00ffffffffffffff

        //        input[0] = 4395583330278772740;  // mod m1
        //        input[1] = 4396634741790752772;  // mod m2
        //        input[2] = 4396375252835237892;     // mod msk
        //        input[3] = 4396146554501595140;  // mod m_tilde

        //        output[0] = 0xfffffffff;
        //        output[1] = 0x00fffffff;
        //        output[2] = 0;

        //        Assert::IsTrue(base_converter.mont_rq(input.get(), output.get()));
        //        Assert::AreEqual(static_cast<uint64_t>(1412154008057360306), output[0]);
        //        Assert::AreEqual(static_cast<uint64_t>(3215947095329058299), output[1]);
        //        Assert::AreEqual(static_cast<uint64_t>(1636465626706639696), output[2]);
        //    }
        //    {
        //        MemoryPoolMT& pool = *MemoryPoolMT::default_pool();
        //        vector<SmallModulus> coeff_base;
        //        vector<SmallModulus> aux_base;
        //        SmallModulus mtilde = small_mods[5];
        //        SmallModulus msk = small_mods[4];
        //        SmallModulus plain_t = small_mods[9];

        //        int coeff_base_count = 2;
        //        int aux_base_count = 2;
        //        for (int i = 0; i < coeff_base_count; ++i)
        //        {
        //            coeff_base.push_back(small_mods[i]);
        //            aux_base.push_back(small_mods[i + coeff_base_count]);
        //        }

        //        BaseConverter base_converter(coeff_base, 3, plain_t);
        //        Pointer input(allocate_uint(12, pool));
        //        Pointer output(allocate_uint(9, pool));

        //        // The composed input is 0xffffffffffffff00ffffffffffffff for all coeffs

        //        input[0] = 4395583330278772740;  // cons mod m1
        //        input[1] = 4395583330278772740;  // x mod m1
        //        input[2] = 4395583330278772740;  // x^2 mod m1

        //        input[3] = 4396634741790752772;  // cons mod m2
        //        input[4] = 4396634741790752772;  // x mod m2
        //        input[5] = 4396634741790752772;  // x^2 mod m2

        //        input[6] = 4396375252835237892;     // cons mod msk
        //        input[7] = 4396375252835237892;     // x mod msk
        //        input[8] = 4396375252835237892;     // x^2 mod msk

        //        input[9] = 4396146554501595140;  // cons mod m_tilde
        //        input[10] = 4396146554501595140;  // x mod m_tilde
        //        input[11] = 4396146554501595140;  // x^2 mod m_tilde

        //        output[0] = 0xfffffffff;
        //        output[1] = 0x00fffffff;
        //        output[2] = 0;

        //        Assert::IsTrue(base_converter.mont_rq(input.get(), output.get()));
        //        Assert::AreEqual(static_cast<uint64_t>(1412154008057360306), output[0]);
        //        Assert::AreEqual(static_cast<uint64_t>(1412154008057360306), output[1]);
        //        Assert::AreEqual(static_cast<uint64_t>(1412154008057360306), output[2]);

        //        Assert::AreEqual(static_cast<uint64_t>(3215947095329058299), output[3]);
        //        Assert::AreEqual(static_cast<uint64_t>(3215947095329058299), output[4]);
        //        Assert::AreEqual(static_cast<uint64_t>(3215947095329058299), output[5]);

        //        Assert::AreEqual(static_cast<uint64_t>(1636465626706639696), output[6]);
        //        Assert::AreEqual(static_cast<uint64_t>(1636465626706639696), output[7]);
        //        Assert::AreEqual(static_cast<uint64_t>(1636465626706639696), output[8]);
        //    }
        //}

        // TEST(BaseConverter, FastFloor)
        //{
        //    {
        //        MemoryPoolMT& pool = *MemoryPoolMT::default_pool();
        //        vector<SmallModulus> coeff_base;
        //        vector<SmallModulus> aux_base;
        //        SmallModulus mtilde = small_mods[5];
        //        SmallModulus msk = small_mods[4];
        //        SmallModulus plain_t = small_mods[9];

        //        int coeff_base_count = 2;
        //        int aux_base_count = 2;
        //        for (int i = 0; i < coeff_base_count; ++i)
        //        {
        //            coeff_base.push_back(small_mods[i]);
        //            aux_base.push_back(small_mods[i + coeff_base_count]);
        //        }

        //        BaseConverter base_converter(coeff_base, 1, plain_t);
        //        Pointer input(allocate_uint(5, pool));
        //        Pointer output(allocate_uint(3, pool));

        //        // The composed input is 0xffffffffffffff00ffffffffffffff

        //        input[0] = 4395513236581707780;        // mod q1
        //        input[1] = 4395513390924464132;        // mod q2
        //        input[2] = 4395583330278772740;        // mod m1
        //        input[3] = 4396634741790752772;        // mod m2
        //        input[4] = 4396375252835237892;        // mod msk

        //        output[0] = 0xfffffffff;
        //        output[1] = 0x00fffffff;
        //        output[2] = 0;

        //        Assert::IsTrue(base_converter.fast_floor(input.get(), output.get()));

        //        // The result for all moduli is equal to -1 since the composed input is small
        //        // Assert::AreEqual(static_cast<uint64_t>(4611686018393899008), output[0]);
        //        // Assert::AreEqual(static_cast<uint64_t>(4611686018293432320), output[1]);
        //        // Assert::AreEqual(static_cast<uint64_t>(4611686018309947392), output[2]);

        //        // The composed input is 0xffffffffffffff00ffffffffffffff00ff

        //        input[0] = 17574536613119;        // mod q1
        //        input[1] = 10132675570633983;        // mod q2
        //        input[2] = 3113399115422302529;        // mod m1
        //        input[3] = 1298513899176416785;        // mod m2
        //        input[4] = 3518991311999157564;        // mod msk

        //        output[0] = 0xfffffffff;
        //        output[1] = 0x00fffffff;
        //        output[2] = 0;

        //        // Since input > q1*q2, the result should be floor(x/(q1*q2)) - alpha (alpha = {0 or 1})
        //        Assert::IsTrue(base_converter.fast_floor(input.get(), output.get()));
        //        Assert::AreEqual(static_cast<uint64_t>(0xfff), output[0]);
        //        Assert::AreEqual(static_cast<uint64_t>(0xfff), output[1]);
        //        Assert::AreEqual(static_cast<uint64_t>(0xfff), output[2]);

        //        // The composed input is 0xffffffffffffff00ffffffffffffff00ffff

        //        input[0] = 4499081372958719;        // mod q1
        //        input[1] = 2593964946082299903;        // mod q2
        //        input[2] = 4013821342825660755;        // mod m1
        //        input[3] = 457963018288239031;        // mod m2
        //        input[4] = 1691919900291185724;        // mod msk

        //        output[0] = 0xfffffffff;
        //        output[1] = 0x00fffffff;
        //        output[2] = 0;

        //        // Since input > q1*q2, the result should be floor(x/(q1*q2)) - alpha (alpha = {0 or 1})
        //        Assert::IsTrue(base_converter.fast_floor(input.get(), output.get()));
        //        Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[0]);
        //        Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[1]);
        //        Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[2]);
        //    }

        //    {
        //        MemoryPoolMT& pool = *MemoryPoolMT::default_pool();
        //        vector<SmallModulus> coeff_base;
        //        vector<SmallModulus> aux_base;
        //        SmallModulus plain_t = small_mods[9];

        //        int coeff_base_count = 2;
        //        int aux_base_count = 2;
        //        for (int i = 0; i < coeff_base_count; ++i)
        //        {
        //            coeff_base.push_back(small_mods[i]);
        //        }

        //        BaseConverter base_converter(coeff_base, 2, plain_t);
        //        Pointer input(allocate_uint(10, pool));
        //        Pointer output(allocate_uint(6, pool));

        //        input[0] = 4499081372958719;    // mod q1
        //        input[1] = 4499081372958719;    // mod q1

        //        input[2] = 2593964946082299903; // mod q2
        //        input[3] = 2593964946082299903; // mod q2

        //        input[4] = 4013821342825660755; // mod m1
        //        input[5] = 4013821342825660755; // mod m1

        //        input[6] = 457963018288239031;  // mod m2
        //        input[7] = 457963018288239031;  // mod m2

        //        input[8] = 1691919900291185724; // mod msk
        //        input[9] = 1691919900291185724; // mod msk

        //        output[0] = 0xfffffffff;
        //        output[1] = 0x00fffffff;
        //        output[2] = 0;

        //        // Since input > q1*q2, the result should be floor(x/(q1*q2)) - alpha (alpha = {0 or 1})
        //        Assert::IsTrue(base_converter.fast_floor(input.get(), output.get()));
        //        Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[0]);
        //        Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[1]);

        //        Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[2]);
        //        Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[3]);

        //        Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[4]);
        //        Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[5]);
        //    }

        //}

        // TEST(BaseConverter, FastBConver_mtilde)
        //{
        //    MemoryPoolMT& pool = *MemoryPoolMT::default_pool();
        //    vector<SmallModulus> coeff_base;
        //    vector<SmallModulus> aux_base;
        //    SmallModulus mtilde = small_mods[5];
        //    SmallModulus msk = small_mods[4];
        //    SmallModulus plain_t = small_mods[9];

        //    int coeff_base_count = 2;
        //    int aux_base_count = 2;
        //    for (int i = 0; i < coeff_base_count; ++i)
        //    {
        //        coeff_base.push_back(small_mods[i]);
        //        aux_base.push_back(small_mods[i + coeff_base_count]);
        //    }

        //    BaseConverter base_converter(coeff_base, 3, plain_t);
        //    Pointer input(allocate_uint(6, pool));
        //    Pointer output(allocate_uint(12, pool));

        //    // The composed input is 0xffffffffffffff00ffffffffffffff for all coeffs

        //    input[0] = 4395513236581707780; // cons mod q1
        //    input[1] = 4395513236581707780; // x mod q1
        //    input[2] = 4395513236581707780; // x^2 mod q1

        //    input[3] = 4395513390924464132; // cons mod q2
        //    input[4] = 4395513390924464132; // x mod q2
        //    input[5] = 4395513390924464132; // x^2 mod q2

        //    output[0] = 0xffffffff;
        //    output[1] = 0;
        //    output[2] = 0xffffff;
        //    output[3] = 0xffffff;

        //    Assert::IsTrue(base_converter.fastbconv_mtilde(input.get(), output.get()));
        //    Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[0]); //mod m1
        //    Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[1]);
        //    Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[2]);

        //    Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[3]); //mod m2
        //    Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[4]);
        //    Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[5]);

        //    Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[6]); //mod msk
        //    Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[7]);
        //    Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[8]);

        //    Assert::AreEqual(static_cast<uint64_t>(849325434816160659), output[9]); //mod m_tilde
        //    Assert::AreEqual(static_cast<uint64_t>(849325434816160659), output[10]);
        //    Assert::AreEqual(static_cast<uint64_t>(849325434816160659), output[11]);
        //}

        // TEST(BaseConverter, FastBConvert_plain_gamma)
        //{
        //    MemoryPoolMT& pool = *MemoryPoolMT::default_pool();
        //    vector<SmallModulus> coeff_base;
        //    vector<SmallModulus> aux_base;
        //    SmallModulus plain_t = small_mods[9];

        //    int coeff_base_count = 2;
        //    int aux_base_count = 2;
        //    for (int i = 0; i < coeff_base_count; ++i)
        //    {
        //        coeff_base.push_back(small_mods[i]);
        //        aux_base.push_back(small_mods[i + coeff_base_count]);
        //    }

        //    BaseConverter base_converter(coeff_base, 3, plain_t);
        //    Pointer input(allocate_uint(6, pool));
        //    Pointer output(allocate_uint(6, pool));

        //    // The composed input is 0xffffffffffffff00ffffffffffffff for all coeffs

        //    input[0] = 4395513236581707780;        // cons mod q1
        //    input[1] = 4395513236581707780;        // x mod q1
        //    input[2] = 4395513236581707780;        // x^2 mod q1

        //    input[3] = 4395513390924464132;        // cons mod q2
        //    input[4] = 4395513390924464132;        // x mod q2
        //    input[5] = 4395513390924464132;        // x^2 mod q2

        //    output[0] = 0xffffffff;
        //    output[1] = 0;
        //    output[2] = 0xffffff;
        //    output[3] = 0xffffff;

        //    Assert::IsTrue(base_converter.fastbconv_plain_gamma(input.get(), output.get()));
        //    Assert::AreEqual(static_cast<uint64_t>(1950841694949736435), output[0]); //mod plain modulus
        //    Assert::AreEqual(static_cast<uint64_t>(1950841694949736435), output[1]);
        //    Assert::AreEqual(static_cast<uint64_t>(1950841694949736435), output[2]);

        //    Assert::AreEqual(static_cast<uint64_t>(3744510248429639755), output[3]); //mod gamma
        //    Assert::AreEqual(static_cast<uint64_t>(3744510248429639755), output[4]);
        //    Assert::AreEqual(static_cast<uint64_t>(3744510248429639755), output[5]);
        //}
    } // namespace util
} // namespace SEALTest
