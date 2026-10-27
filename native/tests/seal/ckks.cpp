// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ciphertext.h"
#include "seal/ckks.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include "seal/valcheck.h"
#include <cmath>
#include <cstdint>
#include <limits>
#include <vector>
#include "gtest/gtest.h"
#include "testseed.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    TEST(CKKSEncoderTest, CKKSEncoderEncodeVectorDecodeTest)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            size_t slots = 32;
            parms.set_poly_modulus_degree(slots << 1);
            parms.set_coeff_modulus(CoeffModulus::Create(slots << 1, { 40, 40, 40, 40 }));
            SEALContext context(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(0.0, 0.0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 16);
            Plaintext plain;
            encoder.encode(values, context.first_parms_id(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            size_t slots = 32;
            parms.set_poly_modulus_degree(slots << 1);
            parms.set_coeff_modulus(CoeffModulus::Create(slots << 1, { 60, 60, 60, 60 }));
            SEALContext context(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(seal_test_seed);
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context.first_parms_id(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            size_t slots = 64;
            parms.set_poly_modulus_degree(slots << 1);
            parms.set_coeff_modulus(CoeffModulus::Create(slots << 1, { 60, 60, 60 }));
            SEALContext context(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(seal_test_seed);
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context.first_parms_id(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            size_t slots = 64;
            parms.set_poly_modulus_degree(slots << 1);
            parms.set_coeff_modulus(CoeffModulus::Create(slots << 1, { 30, 30, 30, 30, 30 }));
            SEALContext context(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(seal_test_seed);
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context.first_parms_id(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            size_t slots = 32;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30, 30 }));
            SEALContext context(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(seal_test_seed);
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context.first_parms_id(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Many primes
            size_t slots = 32;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(
                CoeffModulus::Create(
                    128, { 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 }));
            SEALContext context(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(seal_test_seed);
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context.first_parms_id(), delta, plain);
            vector<complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            size_t slots = 64;
            parms.set_poly_modulus_degree(slots << 1);
            parms.set_coeff_modulus(CoeffModulus::Create(slots << 1, { 40, 40, 40, 40, 40 }));
            SEALContext context(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(seal_test_seed);
            int data_bound = (1 << 20);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            {
                // Use a very large scale
                double delta = pow(2.0, 110);
                Plaintext plain;
                encoder.encode(values, context.first_parms_id(), delta, plain);
                vector<complex<double>> result;
                encoder.decode(plain, result);

                for (size_t i = 0; i < slots; ++i)
                {
                    auto tmp = abs(values[i].real() - result[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
            {
                // Use a scale over 128 bits
                double delta = pow(2.0, 130);
                Plaintext plain;
                encoder.encode(values, context.first_parms_id(), delta, plain);
                vector<complex<double>> result;
                encoder.decode(plain, result);

                for (size_t i = 0; i < slots; ++i)
                {
                    auto tmp = abs(values[i].real() - result[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(CKKSEncoderTest, CKKSEncoderRejectsTransformOverflow)
    {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(4096);
        parms.set_coeff_modulus(CoeffModulus::Create(4096, { 60, 40, 40, 60 }));
        SEALContext context(parms, false, sec_level_type::none);
        CKKSEncoder encoder(context);

        vector<double> values(encoder.slot_count());
        uint64_t state = 0x243F6A8885A308D3ULL;
        auto next_random = [&state]() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            return state;
        };

        constexpr double two_pow_52 = 4503599627370496.0;
        for (auto &value : values)
        {
            uint64_t bits = next_random();
            double significand = 1.0 + static_cast<double>(bits & 0xFFFFFFFFFFFFFULL) / two_pow_52;
            value = ldexp(significand, 1023);
            if (bits & (1ULL << 63))
            {
                value = -value;
            }
            ASSERT_TRUE(isfinite(value));
        }

        Plaintext plain;
        EXPECT_THROW(encoder.encode(values, context.first_parms_id(), pow(2.0, 40), plain), invalid_argument);
    }

    TEST(CKKSEncoderTest, CKKSScaleValidation)
    {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(8);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40, 40 }));
        SEALContext context(parms, false, sec_level_type::none);
        CKKSEncoder encoder(context);

        vector<double> values(encoder.slot_count(), 0.0);
        Plaintext plain;
        Ciphertext encrypted(context);
        double min_normal = (numeric_limits<double>::min)();
        encoder.encode(values, context.first_parms_id(), min_normal, plain);
        encrypted.scale() = min_normal;
        ASSERT_TRUE(is_metadata_valid_for(plain, context));
        ASSERT_TRUE(is_metadata_valid_for(encrypted, context));

        double invalid_scales[]{ 0.0, -1.0, numeric_limits<double>::denorm_min(), numeric_limits<double>::infinity(),
                                 numeric_limits<double>::quiet_NaN() };
        for (double scale : invalid_scales)
        {
            plain.scale() = scale;
            encrypted.scale() = scale;
            ASSERT_FALSE(is_metadata_valid_for(plain, context));
            ASSERT_FALSE(is_metadata_valid_for(encrypted, context));
        }

        ASSERT_THROW(
            encoder.encode(values, context.first_parms_id(), numeric_limits<double>::denorm_min(), plain),
            invalid_argument);
    }

    TEST(CKKSEncoderTest, CKKSSingleValueScaleValidation)
    {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(8);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40, 40 }));
        SEALContext context(parms, false, sec_level_type::none);
        CKKSEncoder encoder(context);

        vector<double> values(encoder.slot_count(), 0.25);
        Plaintext plain;
        int total_bit_count = context.first_context_data()->total_coeff_modulus_bit_count();

        // The single-value and vector overloads accept and reject the same scales
        double largest_scale = ldexp(1.0, total_bit_count - 2);
        ASSERT_NO_THROW(encoder.encode(values, largest_scale, plain));
        ASSERT_NO_THROW(encoder.encode(0.25, largest_scale, plain));
        for (double scale : { ldexp(1.0, total_bit_count - 1), numeric_limits<double>::denorm_min() })
        {
            ASSERT_THROW(encoder.encode(values, scale, plain), invalid_argument);
            ASSERT_THROW(encoder.encode(0.25, scale, plain), invalid_argument);
        }
    }

    TEST(CKKSEncoderTest, CKKSEncoderEncodeIntegerSignedTest)
    {
        {
            EncryptionParameters parms(scheme_type::ckks);
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 40, 40, 60 }));
            SEALContext context(parms, false, sec_level_type::none);
            CKKSEncoder encoder(context);

            // The chain holds 40-bit primes, so these magnitudes straddle the individual moduli.
            int64_t values[]{ 0,
                              5,
                              -5,
                              -(int64_t(1) << 39),
                              -(int64_t(1) << 40),
                              -(int64_t(1) << 41),
                              (int64_t(1) << 41),
                              -(int64_t(1) << 62),
                              (numeric_limits<int64_t>::min)() };

            Plaintext plain;
            vector<complex<double>> result;
            for (int64_t value : values)
            {
                encoder.encode(value, context.first_parms_id(), plain);
                encoder.decode(plain, result);

                double expected = static_cast<double>(value);
                double tolerance = 0.5 + abs(expected) * 1e-9;
                for (size_t i = 0; i < encoder.slot_count(); i++)
                {
                    ASSERT_TRUE(abs(result[i].real() - expected) < tolerance);
                    ASSERT_TRUE(abs(result[i].imag()) < tolerance);
                }
            }

            // The integer overload must agree with the floating-point overload at unit scale.
            Plaintext plain_double;
            vector<complex<double>> result_double;
            for (int64_t value : values)
            {
                if (value < -(int64_t(1) << 53))
                {
                    continue;
                }
                encoder.encode(value, context.first_parms_id(), plain);
                encoder.encode(static_cast<double>(value), context.first_parms_id(), 1.0, plain_double);
                encoder.decode(plain, result);
                encoder.decode(plain_double, result_double);
                ASSERT_TRUE(abs(result[0].real() - result_double[0].real()) < 0.5);
            }
        }
        {
            // The unsigned magnitude drives the range check, including for INT64_MIN.
            EncryptionParameters parms(scheme_type::ckks);
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30 }));
            SEALContext context(parms, false, sec_level_type::none);
            CKKSEncoder encoder(context);

            Plaintext plain;
            ASSERT_THROW(
                encoder.encode((numeric_limits<int64_t>::min)(), context.first_parms_id(), plain), invalid_argument);
            ASSERT_THROW(encoder.encode(-(int64_t(1) << 40), context.first_parms_id(), plain), invalid_argument);
            encoder.encode(int64_t(-100), context.first_parms_id(), plain);
        }
    }

    TEST(CKKSEncoderTest, CKKSEncoderEncodeSingleDecodeTest)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            size_t slots = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40, 40 }));
            SEALContext context(parms, false, sec_level_type::none);
            CKKSEncoder encoder(context);

            srand(seal_test_seed);
            int data_bound = (1 << 30);
            double delta = (1ULL << 16);
            Plaintext plain;
            vector<complex<double>> result;

            for (int iRun = 0; iRun < 50; iRun++)
            {
                double value = static_cast<double>(rand() % data_bound);
                encoder.encode(value, context.first_parms_id(), delta, plain);
                encoder.decode(plain, result);

                for (size_t i = 0; i < slots; ++i)
                {
                    auto tmp = abs(value - result[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            size_t slots = 32;
            parms.set_poly_modulus_degree(slots << 1);
            parms.set_coeff_modulus(CoeffModulus::Create(slots << 1, { 40, 40, 40, 40, 40 }));
            SEALContext context(parms, false, sec_level_type::none);
            CKKSEncoder encoder(context);

            srand(seal_test_seed);
            {
                int data_bound = (1 << 30);
                Plaintext plain;
                vector<complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, context.first_parms_id(), plain);
                    encoder.decode(plain, result);

                    for (size_t i = 0; i < slots; ++i)
                    {
                        auto tmp = abs(value - result[i].real());
                        ASSERT_TRUE(tmp < 0.5);
                    }
                }
            }
            {
                // Use a very large scale
                double delta = pow(2.0, 110);
                int data_bound = (1 << 20);
                Plaintext plain;
                vector<complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, context.first_parms_id(), delta, plain);
                    encoder.decode(plain, result);

                    for (size_t i = 0; i < slots; ++i)
                    {
                        auto tmp = abs(value - result[i].real());
                        ASSERT_TRUE(tmp < 0.5);
                    }
                }
            }
            {
                // Use a scale over 128 bits
                double delta = pow(2.0, 130);
                int data_bound = (1 << 20);
                Plaintext plain;
                vector<complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, context.first_parms_id(), delta, plain);
                    encoder.decode(plain, result);

                    for (size_t i = 0; i < slots; ++i)
                    {
                        auto tmp = abs(value - result[i].real());
                        ASSERT_TRUE(tmp < 0.5);
                    }
                }
            }
        }
    }
} // namespace sealtest
