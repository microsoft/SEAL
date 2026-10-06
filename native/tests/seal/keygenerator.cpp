// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/evaluator.h"
#include "seal/keygenerator.h"
#include "seal/valcheck.h"
#include <cstring>
#include <sstream>
#include <string>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    TEST(KeyGeneratorTest, BFVKeyGeneration)
    {
        EncryptionParameters parms(scheme_type::bfv);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));
            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            ASSERT_THROW(auto evk = keygen.create_relin_keys(), logic_error);
            ASSERT_THROW(auto galk = keygen.create_galois_keys(), logic_error);
        }
        {
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60 }));
            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.create_relin_keys(evk);
            ASSERT_TRUE(evk.parms_id() == context.key_parms_id());
            ASSERT_EQ(1ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(evk, context));

            GaloisKeys galks;
            keygen.create_galois_keys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(galks, context));

            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(10ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(1ULL, galks.key(5).size());
            ASSERT_EQ(1ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 127 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(127).size());
            ASSERT_EQ(1ULL, galks.size());
        }
        {
            parms.set_poly_modulus_degree(256);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 60, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.create_relin_keys(evk);
            ASSERT_TRUE(evk.parms_id() == context.key_parms_id());
            ASSERT_EQ(2ULL, evk.key(2).size());

            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(evk, context));

            GaloisKeys galks;
            keygen.create_galois_keys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(galks, context));

            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(14ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(2ULL, galks.key(5).size());
            ASSERT_EQ(2ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 511 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(511).size());
            ASSERT_EQ(1ULL, galks.size());
        }
    }

    TEST(KeyGeneratorTest, BGVKeyGeneration)
    {
        EncryptionParameters parms(scheme_type::bgv);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));
            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            ASSERT_THROW(auto evk = keygen.create_relin_keys(), logic_error);
            ASSERT_THROW(auto galk = keygen.create_galois_keys(), logic_error);
        }
        {
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60 }));
            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.create_relin_keys(evk);
            ASSERT_TRUE(evk.parms_id() == context.key_parms_id());
            ASSERT_EQ(1ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(evk, context));

            GaloisKeys galks;
            keygen.create_galois_keys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(galks, context));

            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(10ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(1ULL, galks.key(5).size());
            ASSERT_EQ(1ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 127 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(127).size());
            ASSERT_EQ(1ULL, galks.size());
        }
        {
            parms.set_poly_modulus_degree(256);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 60, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.create_relin_keys(evk);
            ASSERT_TRUE(evk.parms_id() == context.key_parms_id());
            ASSERT_EQ(2ULL, evk.key(2).size());

            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(evk, context));

            GaloisKeys galks;
            keygen.create_galois_keys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(galks, context));

            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(14ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(2ULL, galks.key(5).size());
            ASSERT_EQ(2ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 511 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(511).size());
            ASSERT_EQ(1ULL, galks.size());
        }
    }

    TEST(KeyGeneratorTest, CKKSKeyGeneration)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));
            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            ASSERT_THROW(auto evk = keygen.create_relin_keys(), logic_error);
            ASSERT_THROW(auto galk = keygen.create_galois_keys(), logic_error);
        }
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.create_relin_keys(evk);
            ASSERT_TRUE(evk.parms_id() == context.key_parms_id());
            ASSERT_EQ(1ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(evk, context));

            GaloisKeys galks;
            keygen.create_galois_keys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(galks, context));

            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(10ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(1ULL, galks.key(5).size());
            ASSERT_EQ(1ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 127 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(127).size());
            ASSERT_EQ(1ULL, galks.size());
        }
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 60, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys evk;
            keygen.create_relin_keys(evk);
            ASSERT_TRUE(evk.parms_id() == context.key_parms_id());
            ASSERT_EQ(2ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(evk, context));

            GaloisKeys galks;
            keygen.create_galois_keys(galks);
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(galks, context));

            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(14ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1, 3, 5, 7 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(2ULL, galks.key(5).size());
            ASSERT_EQ(2ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 1 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            keygen.create_galois_keys(vector<uint32_t>{ 511 }, galks);
            ASSERT_TRUE(galks.parms_id() == context.key_parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(511).size());
            ASSERT_EQ(1ULL, galks.size());
        }
    }

    TEST(KeyGeneratorTest, Constructors)
    {
        auto constructors = [](scheme_type scheme) {
            EncryptionParameters parms(scheme);
            parms.set_poly_modulus_degree(128);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 60, 50, 40 }));
            SEALContext context(parms, false, sec_level_type::none);
            Evaluator evaluator(context);

            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            auto sk = keygen.secret_key();
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);
            GaloisKeys galk;
            keygen.create_galois_keys(galk);

            ASSERT_TRUE(is_valid_for(rlk, context));
            ASSERT_TRUE(is_valid_for(galk, context));

            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, sk);
            Plaintext pt("1x^2 + 2"), ptres;
            Ciphertext ct;
            encryptor.encrypt(pt, ct);
            evaluator.square_inplace(ct);
            evaluator.relinearize_inplace(ct, rlk);
            decryptor.decrypt(ct, ptres);
            ASSERT_EQ("1x^4 + 4x^2 + 4", ptres.to_string());

            KeyGenerator keygen2(context, sk);
            auto sk2 = keygen.secret_key();
            PublicKey pk2;
            keygen2.create_public_key(pk2);
            ASSERT_EQ(sk2.data(), sk.data());

            RelinKeys rlk2;
            keygen2.create_relin_keys(rlk2);
            GaloisKeys galk2;
            keygen2.create_galois_keys(galk2);

            ASSERT_TRUE(is_valid_for(rlk2, context));
            ASSERT_TRUE(is_valid_for(galk2, context));

            Encryptor encryptor2(context, pk2);
            Decryptor decryptor2(context, sk2);
            pt = "1x^2 + 2";
            ptres.set_zero();
            encryptor.encrypt(pt, ct);
            evaluator.square_inplace(ct);
            evaluator.relinearize_inplace(ct, rlk2);
            decryptor.decrypt(ct, ptres);
            ASSERT_EQ("1x^4 + 4x^2 + 4", ptres.to_string());

            PublicKey pk3;
            keygen2.create_public_key(pk3);

            // There is a small random chance for this to fail
            for (size_t i = 0; i < pk3.data().dyn_array().size(); i++)
            {
                ASSERT_NE(pk3.data().data()[i], pk2.data().data()[i]);
            }
        };

        constructors(scheme_type::bfv);
        constructors(scheme_type::bgv);
    }

    TEST(KeyGeneratorTest, SaveFormatVersion)
    {
        // Keys are NTT-form ciphertexts or plaintexts, but their serialization is unchanged since Microsoft SEAL 4.0.
        auto minor_of = [](const string &blob, size_t offset = 0) {
            Serialization::SEALHeader header;
            Serialization::LoadHeader(
                reinterpret_cast<const seal_byte *>(blob.data()) + offset, blob.size() - offset, header);
            EXPECT_EQ(Serialization::format_version_major, header.version_major);
            return header.version_minor;
        };

        // Checks the outer header and each nested PublicKey header; compr_mode_type::none only
        auto check_kswitch_keys = [&](const string &blob) {
            ASSERT_EQ(Serialization::format_version_minor, minor_of(blob));
            size_t offset = Serialization::seal_header_size + sizeof(parms_id_type);
            auto read_u64 = [&]() {
                uint64_t value;
                memcpy(&value, blob.data() + offset, sizeof(uint64_t));
                offset += sizeof(uint64_t);
                return value;
            };
            size_t nested_count = 0;
            for (uint64_t i = 0, dim1 = read_u64(); i < dim1; i++)
            {
                for (uint64_t j = 0, dim2 = read_u64(); j < dim2; j++)
                {
                    Serialization::SEALHeader header;
                    Serialization::LoadHeader(
                        reinterpret_cast<const seal_byte *>(blob.data()) + offset, blob.size() - offset, header);
                    ASSERT_EQ(Serialization::format_version_major, header.version_major);
                    ASSERT_EQ(Serialization::format_version_minor, header.version_minor);
                    offset += static_cast<size_t>(header.size);
                    nested_count++;
                }
            }
            ASSERT_EQ(blob.size(), offset);
            ASSERT_LT(0, nested_count);
        };

        auto save = [](const auto &obj, compr_mode_type compr_mode = Serialization::compr_mode_default) {
            stringstream ss;
            obj.save(ss, compr_mode);
            return ss.str();
        };

        for (auto scheme : { scheme_type::bfv, scheme_type::bgv, scheme_type::ckks })
        {
            EncryptionParameters parms(scheme);
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60 }));
            if (scheme != scheme_type::ckks)
            {
                parms.set_plain_modulus(65537);
            }
            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            ASSERT_EQ(Serialization::format_version_minor, minor_of(save(parms)));
            ASSERT_EQ(Serialization::format_version_minor, minor_of(save(keygen.secret_key())));

            PublicKey pk;
            keygen.create_public_key(pk);
            ASSERT_TRUE(pk.data().is_ntt_form());
            ASSERT_EQ(Serialization::format_version_minor, minor_of(save(pk)));
            ASSERT_EQ(Serialization::format_version_minor, minor_of(save(keygen.create_public_key())));
            vector<seal_byte> buffer(static_cast<size_t>(pk.save_size()));
            auto out_size = pk.save(buffer.data(), buffer.size());
            ASSERT_EQ(
                Serialization::format_version_minor,
                minor_of(string(reinterpret_cast<const char *>(buffer.data()), static_cast<size_t>(out_size))));

            RelinKeys rlk;
            keygen.create_relin_keys(rlk);
            check_kswitch_keys(save(rlk, compr_mode_type::none));
            check_kswitch_keys(save(keygen.create_relin_keys(), compr_mode_type::none));
            ASSERT_EQ(Serialization::format_version_minor, minor_of(save(rlk)));

            GaloisKeys glk;
            keygen.create_galois_keys(vector<int>{ 1 }, glk);
            check_kswitch_keys(save(glk, compr_mode_type::none));
            check_kswitch_keys(save(keygen.create_galois_keys(vector<int>{ 1 }), compr_mode_type::none));

            // Loading still works
            PublicKey pk2;
            stringstream pk_stream(save(pk));
            pk2.load(context, pk_stream);
            ASSERT_TRUE(pk2.data().is_ntt_form());
            RelinKeys rlk2;
            stringstream rlk_stream(save(rlk));
            rlk2.load(context, rlk_stream);
            ASSERT_EQ(rlk.size(), rlk2.size());
        }
    }
} // namespace sealtest
