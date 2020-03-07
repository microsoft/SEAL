// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/memorymanager.h"
#include "seal/util/baseconverter.h"
#include "seal/util/numth.h"
#include <cmath>
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
        TEST(BaseConverterTest, Initialize)
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

        TEST(BaseConverterTest, FastBConvMTilde)
        {
            // This function multiplies an input array with m_tilde (modulo q-base) and subsequently
            // performs base conversion to Bsk U {m_tilde}.

            SmallModulus plain_t = 0;
            auto pool = MemoryManager::GetPool();

            {
                size_t poly_modulus_degree = 2;
                BaseConverter base_converter(poly_modulus_degree, { 3 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(poly_modulus_degree * base_converter.base_q_size());
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

                // These are results for fase base conversion for a length-2 array ((m_tilde), (2*m_tilde))
                // before reduction to target base.
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
                in[1] = 1;
                in[2] = 2;
                in[3] = 2;
                base_converter.fastbconv_m_tilde(in.data(), out.data(), pool);
                uint64_t m_tilde = base_converter.m_tilde().value();

                // This is the result of fast base conversion for a length-2 array
                // ((m_tilde, 2*m_tilde), (m_tilde, 2*m_tilde)) before reduction to target base.
                uint64_t temp = ((2 * m_tilde) % 3) * 5 + ((4 * m_tilde) % 5) * 3;

                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[0].value(), out[0]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[0].value(), out[1]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[1].value(), out[2]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[1].value(), out[3]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[2].value(), out[4]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[2].value(), out[5]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[3].value(), out[6]);
                ASSERT_EQ(temp % base_converter.base_Bsk_m_tilde()[3].value(), out[7]);
            }
        }

        TEST(BaseConverterTest, MontgomeryReduction)
        {
            // This function assumes the input is in base Bsk U {m_tilde}. If the input is
            // |[c*m_tilde]_q + qu|_m for m in Bsk U {m_tilde}, then the output is c' in Bsk
            // such that c' = c mod q. In other words, this function cancels the extra multiples
            // of q in the Bsk U {m_tilde} representation. The functions works correctly for
            // sufficiently small values of u.

            SmallModulus plain_t = 0;
            auto pool = MemoryManager::GetPool();

            {
                size_t poly_modulus_degree = 2;
                BaseConverter base_converter(poly_modulus_degree, { 3 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(poly_modulus_degree * base_converter.base_Bsk_m_tilde_size());
                vector<uint64_t> out(poly_modulus_degree * base_converter.base_Bsk_size());
                set_zero_uint(in.size(), in.data());
                base_converter.montgomery_reduction(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // Input base is Bsk U {m_tilde}, in this case consisting of 3 primes.
                // Note that m_tilde is always smaller than the primes in Bsk (61 bits).
                // Set the length-2 array to have values 1*m_tilde and 2*m_tilde.
                in[0] = base_converter.m_tilde().value();
                in[1] = 2 * base_converter.m_tilde().value();
                in[2] = base_converter.m_tilde().value();
                in[3] = 2 * base_converter.m_tilde().value();

                // Modulo m_tilde
                in[4] = 0;
                in[5] = 0;

                // This should simply get rid of the m_tilde factor
                base_converter.montgomery_reduction(in.data(), out.data(), pool);

                ASSERT_EQ(1, out[0]);
                ASSERT_EQ(2, out[1]);
                ASSERT_EQ(1, out[2]);
                ASSERT_EQ(2, out[3]);

                // Next add a multiple of q to the input and see if it is reduced properly
                in[0] = base_converter.base_q()[0].value();
                in[1] = base_converter.base_q()[0].value();
                in[2] = base_converter.base_q()[0].value();
                in[3] = base_converter.base_q()[0].value();
                in[4] = base_converter.base_q()[0].value();
                in[5] = base_converter.base_q()[0].value();

                base_converter.montgomery_reduction(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }
            }
            {
                size_t poly_modulus_degree = 2;
                BaseConverter base_converter(poly_modulus_degree, { 3, 5 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(poly_modulus_degree * base_converter.base_Bsk_m_tilde_size());
                vector<uint64_t> out(poly_modulus_degree * base_converter.base_Bsk_size());
                set_zero_uint(in.size(), in.data());
                base_converter.montgomery_reduction(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // Input base is Bsk U {m_tilde}, in this case consisting of 6 primes.
                // Note that m_tilde is always smaller than the primes in Bsk (61 bits).
                // Set the length-2 array to have values 1*m_tilde and 2*m_tilde.
                in[0] = base_converter.m_tilde().value();
                in[1] = 2 * base_converter.m_tilde().value();
                in[2] = base_converter.m_tilde().value();
                in[3] = 2 * base_converter.m_tilde().value();
                in[4] = base_converter.m_tilde().value();
                in[5] = 2 * base_converter.m_tilde().value();

                // Modulo m_tilde
                in[6] = 0;
                in[7] = 0;

                // This should simply get rid of the m_tilde factor
                base_converter.montgomery_reduction(in.data(), out.data(), pool);

                ASSERT_EQ(1, out[0]);
                ASSERT_EQ(2, out[1]);
                ASSERT_EQ(1, out[2]);
                ASSERT_EQ(2, out[3]);
                ASSERT_EQ(1, out[4]);
                ASSERT_EQ(2, out[5]);

                // Next add a multiple of q to the input and see if it is reduced properly
                in[0] = 15;
                in[1] = 30;
                in[2] = 15;
                in[3] = 30;
                in[4] = 15;
                in[5] = 30;
                in[6] = 15;
                in[7] = 30;

                base_converter.montgomery_reduction(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // Now with a multiple of m_tilde + multiple of q
                in[0] = 2 * base_converter.m_tilde().value() + 15;
                in[1] = 2 * base_converter.m_tilde().value() + 30;
                in[2] = 2 * base_converter.m_tilde().value() + 15;
                in[3] = 2 * base_converter.m_tilde().value() + 30;
                in[4] = 2 * base_converter.m_tilde().value() + 15;
                in[5] = 2 * base_converter.m_tilde().value() + 30;
                in[6] = 2 * base_converter.m_tilde().value() + 15;
                in[7] = 2 * base_converter.m_tilde().value() + 30;

                base_converter.montgomery_reduction(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(2, val);
                }
            }
        }

        TEST(BaseConverterTest, FastFloor)
        {
            // This function assumes the input is in base q U Bsk. It outputs an approximation of
            // the value divided by q floored in base Bsk. The approximation has absolute value up
            // to k-1, where k is the number of primes in the base q.

            SmallModulus plain_t = 0;
            auto pool = MemoryManager::GetPool();

            {
                size_t poly_modulus_degree = 2;
                BaseConverter base_converter(poly_modulus_degree, { 3 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(
                    poly_modulus_degree * (base_converter.base_Bsk_size() + base_converter.base_q_size()));
                vector<uint64_t> out(poly_modulus_degree * base_converter.base_Bsk_size());
                set_zero_uint(in.size(), in.data());
                base_converter.fast_floor(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // The size of q U Bsk is 3. We set the input to have values 15 and 5, and divide by 3 (i.e., q).
                in[0] = 15;
                in[1] = 3;
                in[2] = 15;
                in[3] = 3;
                in[4] = 15;
                in[5] = 3;

                // We get an exact result in this case since input base only has size 1
                base_converter.fast_floor(in.data(), out.data(), pool);
                ASSERT_EQ(5ULL, out[0]);
                ASSERT_EQ(1ULL, out[1]);
                ASSERT_EQ(5ULL, out[2]);
                ASSERT_EQ(1ULL, out[3]);

                // Now a case where the floor really shows up
                in[0] = 17;
                in[1] = 4;
                in[2] = 17;
                in[3] = 4;
                in[4] = 17;
                in[5] = 4;

                // We get an exact result in this case since input base only has size 1
                base_converter.fast_floor(in.data(), out.data(), pool);
                ASSERT_EQ(5ULL, out[0]);
                ASSERT_EQ(1ULL, out[1]);
                ASSERT_EQ(5ULL, out[2]);
                ASSERT_EQ(1ULL, out[3]);
            }
            {
                size_t poly_modulus_degree = 2;
                BaseConverter base_converter(poly_modulus_degree, { 3, 5 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(
                    poly_modulus_degree * (base_converter.base_Bsk_size() + base_converter.base_q_size()));
                vector<uint64_t> out(poly_modulus_degree * base_converter.base_Bsk_size());
                set_zero_uint(in.size(), in.data());
                base_converter.fast_floor(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // The size of q U Bsk is now 5. We set the input to multiples of 15 an divide by 15 (i.e., q).
                in[0] = 15;
                in[1] = 30;
                in[2] = 15;
                in[3] = 30;
                in[4] = 15;
                in[5] = 30;
                in[6] = 15;
                in[7] = 30;
                in[8] = 15;
                in[9] = 30;

                // We get an exact result in this case
                base_converter.fast_floor(in.data(), out.data(), pool);
                ASSERT_EQ(1ULL, out[0]);
                ASSERT_EQ(2ULL, out[1]);
                ASSERT_EQ(1ULL, out[2]);
                ASSERT_EQ(2ULL, out[3]);
                ASSERT_EQ(1ULL, out[4]);
                ASSERT_EQ(2ULL, out[5]);

                // Now a case where the floor really shows up
                in[0] = 21;
                in[1] = 32;
                in[2] = 21;
                in[3] = 32;
                in[4] = 21;
                in[5] = 32;
                in[6] = 21;
                in[7] = 32;
                in[8] = 21;
                in[9] = 32;

                // The result is not exact but differs at most by 1
                base_converter.fast_floor(in.data(), out.data(), pool);
                ASSERT_TRUE(fabs(1ULL - out[0]) <= 1);
                ASSERT_TRUE(fabs(2ULL - out[1]) <= 1);
                ASSERT_TRUE(fabs(1ULL - out[2]) <= 1);
                ASSERT_TRUE(fabs(2ULL - out[3]) <= 1);
                ASSERT_TRUE(fabs(1ULL - out[4]) <= 1);
                ASSERT_TRUE(fabs(2ULL - out[5]) <= 1);
            }
        }

        TEST(BaseConverterTest, FastBConvSK)
        {
            // This function assumes the input is in base Bsk and outputs a fast base conversion
            // with Shenoy-Kumaresan correction to base q. The conversion is exact.

            SmallModulus plain_t = 0;
            auto pool = MemoryManager::GetPool();

            {
                size_t poly_modulus_degree = 2;
                BaseConverter base_converter(poly_modulus_degree, { 3 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(poly_modulus_degree * base_converter.base_Bsk_size());
                vector<uint64_t> out(poly_modulus_degree * base_converter.base_q_size());
                set_zero_uint(in.size(), in.data());
                base_converter.fastbconv_sk(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // The size of Bsk is 2
                in[0] = 1;
                in[1] = 2;
                in[2] = 1;
                in[3] = 2;

                base_converter.fastbconv_sk(in.data(), out.data(), pool);
                ASSERT_EQ(1ULL, out[0]);
                ASSERT_EQ(2ULL, out[1]);
            }
            {
                size_t poly_modulus_degree = 2;
                BaseConverter base_converter(poly_modulus_degree, { 3, 5 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(poly_modulus_degree * base_converter.base_Bsk_size());
                vector<uint64_t> out(poly_modulus_degree * base_converter.base_q_size());
                set_zero_uint(in.size(), in.data());
                base_converter.fastbconv_sk(in.data(), out.data(), pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // The size of Bsk is 3
                in[0] = 1;
                in[1] = 2;
                in[2] = 1;
                in[3] = 2;
                in[4] = 1;
                in[5] = 2;

                base_converter.fastbconv_sk(in.data(), out.data(), pool);
                ASSERT_EQ(1ULL, out[0]);
                ASSERT_EQ(2ULL, out[1]);
                ASSERT_EQ(1ULL, out[2]);
                ASSERT_EQ(2ULL, out[3]);
            }
        }

        TEST(BaseConverterTest, ExactScaleAndRound)
        {
            // This function computes [round(t/q * |input|_q)]_t exactly using the gamma-correction technique.

            auto pool = MemoryManager::GetPool();

            size_t poly_modulus_degree = 2;
            SmallModulus plain_t = 3;
            BaseConverter base_converter(poly_modulus_degree, { 5, 7 }, plain_t, pool);
            ASSERT_TRUE(base_converter.is_initialized());

            vector<uint64_t> in(poly_modulus_degree * base_converter.base_Bsk_size());
            vector<uint64_t> out(poly_modulus_degree * base_converter.base_q_size());
            set_zero_uint(in.size(), in.data());
            base_converter.exact_scale_and_round(in.data(), out.data(), pool);
            for (auto val : out)
            {
                ASSERT_EQ(0, val);
            }

            // The size of Bsk is 2. Both values here are multiples of 35 (i.e., q).
            in[0] = 35;
            in[1] = 70;
            in[2] = 35;
            in[3] = 70;

            // We expect to get a zero output in this case
            base_converter.exact_scale_and_round(in.data(), out.data(), pool);
            ASSERT_EQ(0ULL, out[0]);
            ASSERT_EQ(0ULL, out[1]);

            // Now try a non-trivial case
            in[0] = 29;
            in[1] = 30 + 35;
            in[2] = 29;
            in[3] = 30 + 35;

            // Here 29 will scale and round to 2 and 30 will scale and round to 0.
            // The added 35 should not make a difference.
            base_converter.exact_scale_and_round(in.data(), out.data(), pool);
            ASSERT_EQ(2ULL, out[0]);
            ASSERT_EQ(0ULL, out[1]);
        }

        TEST(BaseConverterTest, DivideAndRoundQLastInplace)
        {
            // This function approximately divides the input values by the last prime in the base q.
            // Input is in base q; the last RNS component becomes invalid.

            auto pool = MemoryManager::GetPool();

            {
                size_t poly_modulus_degree = 2;
                SmallModulus plain_t = 0;
                BaseConverter base_converter(poly_modulus_degree, { 13, 7 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(poly_modulus_degree * base_converter.base_q_size());
                set_zero_uint(in.size(), in.data());
                base_converter.divide_and_round_q_last_inplace(in.data(), pool);
                ASSERT_EQ(0ULL, in[0]);
                ASSERT_EQ(0ULL, in[1]);

                // The size of q is 2. We set some values here and divide by the last modulus (i.e., 7).
                in[0] = 1;
                in[1] = 2;
                in[2] = 1;
                in[3] = 2;

                // We expect to get a zero output also in this case
                base_converter.divide_and_round_q_last_inplace(in.data(), pool);
                ASSERT_EQ(0ULL, in[0]);
                ASSERT_EQ(0ULL, in[1]);

                // Next a case with non-trivial rounding
                in[0] = 4;
                in[1] = 12;
                in[2] = 4;
                in[3] = 12;

                base_converter.divide_and_round_q_last_inplace(in.data(), pool);
                ASSERT_EQ(1ULL, in[0]);
                ASSERT_EQ(2ULL, in[1]);

                // Input array (19, 15)
                in[0] = 6;
                in[1] = 2;
                in[2] = 5;
                in[3] = 1;

                base_converter.divide_and_round_q_last_inplace(in.data(), pool);
                ASSERT_EQ(3ULL, in[0]);
                ASSERT_EQ(2ULL, in[1]);
            }
            {
                size_t poly_modulus_degree = 2;
                SmallModulus plain_t = 0;
                BaseConverter base_converter(poly_modulus_degree, { 3, 5, 7, 11 }, plain_t, pool);
                ASSERT_TRUE(base_converter.is_initialized());

                vector<uint64_t> in(poly_modulus_degree * base_converter.base_q_size());
                set_zero_uint(in.size(), in.data());
                base_converter.divide_and_round_q_last_inplace(in.data(), pool);
                ASSERT_EQ(0ULL, in[0]);
                ASSERT_EQ(0ULL, in[1]);
                ASSERT_EQ(0ULL, in[2]);
                ASSERT_EQ(0ULL, in[3]);
                ASSERT_EQ(0ULL, in[4]);
                ASSERT_EQ(0ULL, in[5]);

                // The size of q is 4. We set some values here and divide by the last modulus (i.e., 11).
                in[0] = 1;
                in[1] = 2;
                in[2] = 1;
                in[3] = 2;
                in[4] = 1;
                in[5] = 2;
                in[6] = 1;
                in[7] = 2;

                // We expect to get a zero output also in this case
                base_converter.divide_and_round_q_last_inplace(in.data(), pool);
                ASSERT_EQ(0ULL, in[0]);
                ASSERT_EQ(0ULL, in[1]);
                ASSERT_EQ(0ULL, in[2]);
                ASSERT_EQ(0ULL, in[3]);
                ASSERT_EQ(0ULL, in[4]);
                ASSERT_EQ(0ULL, in[5]);

                // Next a case with non-trivial rounding; array is (60, 70)
                in[0] = 0;
                in[1] = 1;
                in[2] = 0;
                in[3] = 0;
                in[4] = 4;
                in[5] = 0;
                in[6] = 5;
                in[7] = 4;

                // We get only approximate result in this case
                base_converter.divide_and_round_q_last_inplace(in.data(), pool);
                ASSERT_TRUE((3ULL + 2ULL - in[0]) % 3ULL <= 1);
                ASSERT_TRUE((3ULL + 0ULL - in[1]) % 3ULL <= 1);
                ASSERT_TRUE((5ULL + 0ULL - in[2]) % 5ULL <= 1);
                ASSERT_TRUE((5ULL + 1ULL - in[3]) % 5ULL <= 1);
                ASSERT_TRUE((7ULL + 5ULL - in[4]) % 7ULL <= 1);
                ASSERT_TRUE((7ULL + 6ULL - in[5]) % 7ULL <= 1);
            }
        }

        TEST(BaseConverterTest, DivideAndRoundQLastNTTInplace)
        {
            // This function approximately divides the input values by the last prime in the base q.
            // The input and output are both in NTT form. Input is in base q; the last RNS component
            // becomes invalid.

            auto pool = MemoryManager::GetPool();

            size_t poly_modulus_degree = 2;
            SmallNTTTables ntt[]{ { 1, SmallModulus(53) }, { 1, SmallModulus(13) } };
            auto ntt_ptr = Pointer<SmallNTTTables>::Aliasing(ntt);
            SmallModulus plain_t = 0;
            BaseConverter base_converter(poly_modulus_degree, { 53, 13 }, plain_t, pool);
            ASSERT_TRUE(base_converter.is_initialized());

            vector<uint64_t> in(poly_modulus_degree * base_converter.base_q_size());
            set_zero_uint(in.size(), in.data());
            base_converter.divide_and_round_q_last_inplace(in.data(), pool);
            ASSERT_EQ(0ULL, in[0]);
            ASSERT_EQ(0ULL, in[1]);

            // The size of q is 2. We set some values here and divide by the last modulus (i.e., 13).
            in[0] = 1;
            in[1] = 2;
            in[2] = 1;
            in[3] = 2;
            ntt_negacyclic_harvey(in.data(), ntt[0]);
            ntt_negacyclic_harvey(in.data() + poly_modulus_degree, ntt[1]);

            // We expect to get a zero output also in this case
            base_converter.divide_and_round_q_last_ntt_inplace(in.data(), ntt_ptr, pool);
            inverse_ntt_negacyclic_harvey(in.data(), ntt[0]);
            ASSERT_EQ(0ULL, in[0]);
            ASSERT_EQ(0ULL, in[1]);

            // Next a case with non-trivial rounding
            in[0] = 4;
            in[1] = 12;
            in[2] = 4;
            in[3] = 12;
            ntt_negacyclic_harvey(in.data(), ntt[0]);
            ntt_negacyclic_harvey(in.data() + poly_modulus_degree, ntt[1]);

            base_converter.divide_and_round_q_last_ntt_inplace(in.data(), ntt_ptr, pool);
            inverse_ntt_negacyclic_harvey(in.data(), ntt[0]);
            ASSERT_TRUE((53ULL + 1ULL - in[0]) % 53ULL <= 1);
            ASSERT_TRUE((53ULL + 2ULL - in[1]) % 53ULL <= 1);

            // Input array (25, 35)
            in[0] = 25;
            in[1] = 35;
            in[2] = 12;
            in[3] = 9;
            ntt_negacyclic_harvey(in.data(), ntt[0]);
            ntt_negacyclic_harvey(in.data() + poly_modulus_degree, ntt[1]);

            base_converter.divide_and_round_q_last_ntt_inplace(in.data(), ntt_ptr, pool);
            inverse_ntt_negacyclic_harvey(in.data(), ntt[0]);
            ASSERT_TRUE((53ULL + 2ULL - in[0]) % 53ULL <= 1);
            ASSERT_TRUE((53ULL + 3ULL - in[1]) % 53ULL <= 1);
        }
    } // namespace util
} // namespace SEALTest
