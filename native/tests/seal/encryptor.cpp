// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/context.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include "seal/keygenerator.h"
#include "seal/batchencoder.h"
#include "seal/ckks.h"
#include "seal/intencoder.h"
#include "seal/modulus.h"
#include <cstdint>
#include <cstddef>
#include <ctime>

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(EncryptorTest, BFVEncryptDecrypt)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x12345678ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(1), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(1ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(2), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(2ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFD)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFDULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFE)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFEULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFFULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(314159265ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x12345678ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(1), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(1ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(2), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(2ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFD)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFDULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFE)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFEULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFFULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(314159265ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }

        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 40, 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x12345678ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(1), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(1ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(2), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(2ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFD)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFDULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFE)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFEULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFFULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(314159265ULL, encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, BFVEncryptZeroDecrypt)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        encryptor.encrypt_zero(ct);
        ASSERT_FALSE(ct.is_ntt_form());
        ASSERT_FALSE(ct.is_transparent());
        ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        Plaintext pt;
        decryptor.decrypt(ct, pt);
        ASSERT_TRUE(pt.is_zero());

        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        encryptor.encrypt_zero(next_parms, ct);
        ASSERT_FALSE(ct.is_ntt_form());
        ASSERT_FALSE(ct.is_transparent());
        ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        ASSERT_EQ(ct.parms_id(), next_parms);
        decryptor.decrypt(ct, pt);
        ASSERT_TRUE(pt.is_zero());
    }

    TEST(EncryptorTest, CKKSEncryptZeroDecrypt)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        encryptor.encrypt_zero(ct);
        ASSERT_FALSE(ct.is_transparent());
        ASSERT_TRUE(ct.is_ntt_form());
        ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        ct.scale() = std::pow(2.0, 20);
        Plaintext pt;
        decryptor.decrypt(ct, pt);

        std::vector<std::complex<double>> res;
        encoder.decode(pt, res);
        for (auto val : res)
        {
            ASSERT_NEAR(val.real(), 0.0, 0.01);
            ASSERT_NEAR(val.imag(), 0.0, 0.01);
        }

        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        encryptor.encrypt_zero(next_parms, ct);
        ASSERT_FALSE(ct.is_transparent());
        ASSERT_TRUE(ct.is_ntt_form());
        ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        ct.scale() = std::pow(2.0, 20);
        ASSERT_EQ(ct.parms_id(), next_parms);
        decryptor.decrypt(ct, pt);
        ASSERT_EQ(pt.parms_id(), next_parms);

        encoder.decode(pt, res);
        for (auto val : res)
        {
            ASSERT_NEAR(val.real(), 0.0, 0.01);
            ASSERT_NEAR(val.imag(), 0.0, 0.01);
        }
    }

    TEST(EncryptorTest, CKKSEncryptDecrypt)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            //input consists of ones
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            encoder.encode(input, context->first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);

            //check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);

            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            //input consists of zeros
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 0.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            encoder.encode(input, context->first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);

            //check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);

            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Input is a random mix of positive and negative integers
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size);
            std::vector<std::complex<double>> output(slot_size);

            srand(static_cast<unsigned>(time(NULL)));
            int input_bound = 1 << 30;
            const double delta = static_cast<double>(1ULL << 50);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = pow(-1.0, rand() % 2) * static_cast<double>(rand() % input_bound);
                }

                encoder.encode(input, context->first_parms_id(), delta, plain);
                encryptor.encrypt(plain, encrypted);

                //check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Input is a random mix of positive and negative integers
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size);
            std::vector<std::complex<double>> output(slot_size);

            srand(static_cast<unsigned>(time(NULL)));
            int input_bound = 1 << 30;
            const double delta = static_cast<double>(1ULL << 60);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = pow(-1.0, rand() % 2) * static_cast<double>(rand() % input_bound);
                }

                encoder.encode(input, context->first_parms_id(), delta, plain);
                encryptor.encrypt(plain, encrypted);

                //check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plain, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            ASSERT_NE(nullptr, first_context_data.get());
            auto second_context_data = first_context_data->next_context_data();
            ASSERT_NE(nullptr, second_context_data.get());
            auto second_parms_id = second_context_data->parms_id();

            encoder.encode(input, second_parms_id, delta, plain);
            encryptor.encrypt(plain, encrypted);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == second_parms_id);

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);

            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
    }
}
