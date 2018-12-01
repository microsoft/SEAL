// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/ckks.h"
#include "seal/context.h"
#include "seal/defaultparams.h"
#include "seal/keygenerator.h"
#include <vector>
#include <ctime>

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
    TEST(CKKSEncoderTest, CKKSEncoderEncodeVectorDecodeTest)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            uint32_t slots = 32;
            parms.set_poly_modulus_degree(2 * slots);
            parms.set_coeff_modulus({ small_mods_40bit(0), small_mods_40bit(1),
                small_mods_40bit(2), small_mods_40bit(3) });
            auto context = SEALContext::Create(parms);

            std::vector<std::complex<double>> values(slots);

            for (size_t i = 0; i < slots; i++)
            {
                std::complex<double> value(0.0, 0.0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 16);
            Plaintext plain;
            encoder.encode(values, parms.parms_id(), delta, plain);
            std::vector<std::complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            uint32_t slots = 32;
            parms.set_poly_modulus_degree(2 * slots);
            parms.set_coeff_modulus({ small_mods_60bit(0), small_mods_60bit(1),
                small_mods_60bit(2), small_mods_60bit(3) });
            auto context = SEALContext::Create(parms);

            std::vector<std::complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                std::complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, parms.parms_id(), delta, plain);
            std::vector<std::complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            uint32_t slots = 64;
            parms.set_poly_modulus_degree(2 * slots);
            parms.set_coeff_modulus({ small_mods_60bit(0),
                small_mods_60bit(1), small_mods_60bit(2) });
            auto context = SEALContext::Create(parms);

            std::vector<std::complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                std::complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, parms.parms_id(), delta, plain);
            std::vector<std::complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            uint32_t slots = 64;
            parms.set_poly_modulus_degree(2 * slots);
            parms.set_coeff_modulus({ small_mods_30bit(0), small_mods_30bit(1),
                small_mods_30bit(2), small_mods_30bit(3), small_mods_30bit(4) });
            auto context = SEALContext::Create(parms);

            std::vector<std::complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                std::complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, parms.parms_id(), delta, plain);
            std::vector<std::complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            uint32_t slots = 32;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus({ small_mods_30bit(0), small_mods_30bit(1),
                small_mods_30bit(2), small_mods_30bit(3), small_mods_30bit(4) });
            auto context = SEALContext::Create(parms);

            std::vector<std::complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);

            for (size_t i = 0; i < slots; i++)
            {
                std::complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            double delta = (1ULL << 40);
            Plaintext plain;
            encoder.encode(values, parms.parms_id(), delta, plain);
            std::vector<std::complex<double>> result;
            encoder.decode(plain, result);

            for (size_t i = 0; i < slots; ++i)
            {
                auto tmp = abs(values[i].real() - result[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            uint32_t slots = 64;
            parms.set_poly_modulus_degree(2 * slots);
            parms.set_coeff_modulus({ small_mods_40bit(0), small_mods_40bit(1),
                small_mods_40bit(2), small_mods_40bit(3), small_mods_40bit(4) });
            auto context = SEALContext::Create(parms);

            std::vector<std::complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 20);

            for (size_t i = 0; i < slots; i++)
            {
                std::complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            {
                // Use a very large scale
                double delta = pow(2.0, 110);
                Plaintext plain;
                encoder.encode(values, parms.parms_id(), delta, plain);
                std::vector<std::complex<double>> result;
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
                encoder.encode(values, parms.parms_id(), delta, plain);
                std::vector<std::complex<double>> result;
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
            uint32_t slots = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus({ small_mods_40bit(0), small_mods_40bit(1),
                small_mods_40bit(2), small_mods_40bit(3) });
            auto context = SEALContext::Create(parms);
            CKKSEncoder encoder(context);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 30);
            double delta = (1ULL << 16);
            Plaintext plain;
            std::vector<std::complex<double>> result;

            for (int iRun = 0; iRun < 50; iRun++)
            {
                double value = static_cast<double>(rand() % data_bound);
                encoder.encode(value, parms.parms_id(), delta, plain);
                encoder.decode(plain, result);

                for (size_t i = 0; i < slots; ++i)
                {
                    auto tmp = abs(value - result[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            uint32_t slots = 32;
            parms.set_poly_modulus_degree(slots * 2);
            parms.set_coeff_modulus({ small_mods_40bit(0), small_mods_40bit(1),
                small_mods_40bit(2), small_mods_40bit(3) });
            auto context = SEALContext::Create(parms);
            CKKSEncoder encoder(context);

            srand(static_cast<unsigned>(time(NULL)));
            {
                int data_bound = (1 << 30);
                Plaintext plain;
                std::vector<std::complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, parms.parms_id(), plain);
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
                std::vector<std::complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, parms.parms_id(), plain);
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
                std::vector<std::complex<double>> result;

                for (int iRun = 0; iRun < 50; iRun++)
                {
                    int value = static_cast<int>(rand() % data_bound);
                    encoder.encode(value, parms.parms_id(), plain);
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
}
