// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ckks.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include <ctime>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    TEST(CKKSEncoderTest, CKKSEncoderEncodeVectorDecodeTest)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            size_t slots = 32;
            parms.set_poly_modulus_degree(slots << 1);
            parms.set_coeff_modulus(CoeffModulus::Create(slots << 1, { 40, 40, 40, 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(0.0, 0.0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 16);
            Plaintext plain;
            encoder.encode(values, context->first_parms_id(), delta, plain);
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
            auto context = SEALContext::Create(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context->first_parms_id(), delta, plain);
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
            auto context = SEALContext::Create(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context->first_parms_id(), delta, plain);
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
            auto context = SEALContext::Create(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context->first_parms_id(), delta, plain);
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
            auto context = SEALContext::Create(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context->first_parms_id(), delta, plain);
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
            parms.set_coeff_modulus(CoeffModulus::Create(
                128, { 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, context->first_parms_id(), delta, plain);
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
            auto context = SEALContext::Create(parms, false, sec_level_type::none);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
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
                encoder.encode(values, context->first_parms_id(), delta, plain);
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
                encoder.encode(values, context->first_parms_id(), delta, plain);
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

    TEST(CKKSEncoderTest, CKKSEncoderEncodeSingleDecodeTest)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            size_t slots = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40, 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            CKKSEncoder encoder(context);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);
            double delta = (1ULL << 16);
            Plaintext plain;
            vector<complex<double>> result;

            for (int iRun = 0; iRun < 50; iRun++)
            {
                double value = static_cast<double>(rand() % data_bound);
                encoder.encode(value, context->first_parms_id(), delta, plain);
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
            parms.set_coeff_modulus(CoeffModulus::Create(slots << 1, { 40, 40, 40, 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            CKKSEncoder encoder(context);

            srand(static_cast<unsigned>(time(NULL)));
            {
                int data_bound = (1 << 30);
                Plaintext plain;
                vector<complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, context->first_parms_id(), plain);
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
                int data_bound = (1 << 20);
                Plaintext plain;
                vector<complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, context->first_parms_id(), plain);
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
                int data_bound = (1 << 20);
                Plaintext plain;
                vector<complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, context->first_parms_id(), plain);
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
