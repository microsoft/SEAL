// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <sstream>
#include <fstream>
#include "gtest/gtest.h"
#include "seal/serialization.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/encryptor.h"
#include "seal/ciphertext.h"

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(SerializationTest, Plaintext)
    {
        Plaintext pt("3x^4 + 1x^2 + 1x^1 + 2");
        Plaintext pt2;

        stringstream ss;
        auto out_size = Serialization::Save(pt, ss, compr_mode_type::none);
        auto in_size = Serialization::UnsafeLoad(ss, pt2);
        ASSERT_EQ(pt, pt2);
        ASSERT_EQ(out_size, in_size);

        out_size = Serialization::Save(pt, ss, compr_mode_type::zlib);
        in_size = Serialization::UnsafeLoad(ss, pt2);
        ASSERT_EQ(pt, pt2);
        ASSERT_EQ(out_size, in_size);
    }

    TEST(SerializationTest, Keys)
    {
        EncryptionParameters parms(scheme_type::BFV);
        size_t poly_modulus_degree = 16;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 20, 20 }));
        parms.set_plain_modulus(4);

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk = keygen.public_key(), pk2;
        SecretKey sk = keygen.secret_key(), sk2;
        RelinKeys rlk = keygen.relin_keys(), rlk2;
        GaloisKeys galk = keygen.galois_keys(), galk2;

        stringstream ss;
        
        // PublicKey
        auto out_size = Serialization::Save(pk, ss, compr_mode_type::none);
        auto in_size = Serialization::UnsafeLoad(ss, pk2);
        ASSERT_EQ(pk.data().uint64_count(), pk2.data().uint64_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < pk.data().uint64_count(); i++)
        {
            ASSERT_EQ(pk.data().data()[i], pk2.data().data()[i]);
        }

        out_size = Serialization::Save(pk, ss, compr_mode_type::none);
        in_size = Serialization::Load(context, ss, pk2);
        ASSERT_EQ(pk.data().uint64_count(), pk2.data().uint64_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < pk.data().uint64_count(); i++)
        {
            ASSERT_EQ(pk.data().data()[i], pk2.data().data()[i]);
        }

        out_size = Serialization::Save(pk, ss, compr_mode_type::zlib);
        in_size = Serialization::UnsafeLoad(ss, pk2);
        ASSERT_EQ(pk.data().uint64_count(), pk2.data().uint64_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < pk.data().uint64_count(); i++)
        {
            ASSERT_EQ(pk.data().data()[i], pk2.data().data()[i]);
        }

        out_size = Serialization::Save(pk, ss, compr_mode_type::zlib);
        in_size = Serialization::Load(context, ss, pk2);
        ASSERT_EQ(pk.data().uint64_count(), pk2.data().uint64_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < pk.data().uint64_count(); i++)
        {
            ASSERT_EQ(pk.data().data()[i], pk2.data().data()[i]);
        }

        // SecretKey
        out_size = Serialization::Save(sk, ss, compr_mode_type::none);
        in_size = Serialization::UnsafeLoad(ss, sk2);
        ASSERT_EQ(sk.data().coeff_count(), sk2.data().coeff_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < sk.data().coeff_count(); i++)
        {
            ASSERT_EQ(sk.data().data()[i], sk2.data().data()[i]);
        }

        out_size = Serialization::Save(sk, ss, compr_mode_type::none);
        in_size = Serialization::Load(context, ss, sk2);
        ASSERT_EQ(sk.data().coeff_count(), sk2.data().coeff_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < sk.data().coeff_count(); i++)
        {
            ASSERT_EQ(sk.data().data()[i], sk2.data().data()[i]);
        }

        out_size = Serialization::Save(sk, ss, compr_mode_type::zlib);
        in_size = Serialization::UnsafeLoad(ss, sk2);
        ASSERT_EQ(sk.data().coeff_count(), sk2.data().coeff_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < sk.data().coeff_count(); i++)
        {
            ASSERT_EQ(sk.data().data()[i], sk2.data().data()[i]);
        }

        out_size = Serialization::Save(sk, ss, compr_mode_type::zlib);
        in_size = Serialization::Load(context, ss, sk2);
        ASSERT_EQ(sk.data().coeff_count(), sk2.data().coeff_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < sk.data().coeff_count(); i++)
        {
            ASSERT_EQ(sk.data().data()[i], sk2.data().data()[i]);
        }

        // RelinKeys
        out_size = Serialization::Save(rlk, ss, compr_mode_type::none);
        in_size = Serialization::UnsafeLoad(ss, rlk2);
        ASSERT_EQ(out_size, in_size);
        for (size_t k = 0; k < rlk.data().size(); k++)
        {
            for (size_t j = 0; j < rlk.data()[k].size(); j++)
            {
                ASSERT_EQ(rlk.data()[k][j].data().uint64_count(), rlk2.data()[k][j].data().uint64_count());
                for (size_t i = 0; i < rlk.data()[k][j].data().uint64_count(); i++)
                {
                    ASSERT_EQ(rlk.data()[k][j].data()[i], rlk2.data()[k][j].data()[i]);
                }
            }
        }

        out_size = Serialization::Save(rlk, ss, compr_mode_type::none);
        in_size = Serialization::Load(context, ss, rlk2);
        ASSERT_EQ(out_size, in_size);
        for (size_t k = 0; k < rlk.data().size(); k++)
        {
            for (size_t j = 0; j < rlk.data()[k].size(); j++)
            {
                ASSERT_EQ(rlk.data()[k][j].data().uint64_count(), rlk2.data()[k][j].data().uint64_count());
                for (size_t i = 0; i < rlk.data()[k][j].data().uint64_count(); i++)
                {
                    ASSERT_EQ(rlk.data()[k][j].data()[i], rlk2.data()[k][j].data()[i]);
                }
            }
        }

        out_size = Serialization::Save(rlk, ss, compr_mode_type::zlib);
        in_size = Serialization::UnsafeLoad(ss, rlk2);
        ASSERT_EQ(out_size, in_size);
        for (size_t k = 0; k < rlk.data().size(); k++)
        {
            for (size_t j = 0; j < rlk.data()[k].size(); j++)
            {
                ASSERT_EQ(rlk.data()[k][j].data().uint64_count(), rlk2.data()[k][j].data().uint64_count());
                for (size_t i = 0; i < rlk.data()[k][j].data().uint64_count(); i++)
                {
                    ASSERT_EQ(rlk.data()[k][j].data()[i], rlk2.data()[k][j].data()[i]);
                }
            }
        }

        out_size = Serialization::Save(rlk, ss, compr_mode_type::zlib);
        in_size = Serialization::Load(context, ss, rlk2);
        ASSERT_EQ(out_size, in_size);
        for (size_t k = 0; k < rlk.data().size(); k++)
        {
            for (size_t j = 0; j < rlk.data()[k].size(); j++)
            {
                ASSERT_EQ(rlk.data()[k][j].data().uint64_count(), rlk2.data()[k][j].data().uint64_count());
                for (size_t i = 0; i < rlk.data()[k][j].data().uint64_count(); i++)
                {
                    ASSERT_EQ(rlk.data()[k][j].data()[i], rlk2.data()[k][j].data()[i]);
                }
            }
        }

        // GaloisKeys
        out_size = Serialization::Save(galk, ss, compr_mode_type::none);
        in_size = Serialization::UnsafeLoad(ss, galk2);
        ASSERT_EQ(out_size, in_size);
        for (size_t k = 0; k < galk.data().size(); k++)
        {
            for (size_t j = 0; j < galk.data()[k].size(); j++)
            {
                ASSERT_EQ(galk.data()[k][j].data().uint64_count(), galk2.data()[k][j].data().uint64_count());
                for (size_t i = 0; i < galk.data()[k][j].data().uint64_count(); i++)
                {
                    ASSERT_EQ(galk.data()[k][j].data()[i], galk2.data()[k][j].data()[i]);
                }
            }
        }

        out_size = Serialization::Save(galk, ss, compr_mode_type::none);
        in_size = Serialization::Load(context, ss, galk2);
        ASSERT_EQ(out_size, in_size);
        for (size_t k = 0; k < galk.data().size(); k++)
        {
            for (size_t j = 0; j < galk.data()[k].size(); j++)
            {
                ASSERT_EQ(galk.data()[k][j].data().uint64_count(), galk2.data()[k][j].data().uint64_count());
                for (size_t i = 0; i < galk.data()[k][j].data().uint64_count(); i++)
                {
                    ASSERT_EQ(galk.data()[k][j].data()[i], galk2.data()[k][j].data()[i]);
                }
            }
        }

        out_size = Serialization::Save(galk, ss, compr_mode_type::zlib);
        in_size = Serialization::UnsafeLoad(ss, galk2);
        ASSERT_EQ(out_size, in_size);
        for (size_t k = 0; k < galk.data().size(); k++)
        {
            for (size_t j = 0; j < galk.data()[k].size(); j++)
            {
                ASSERT_EQ(galk.data()[k][j].data().uint64_count(), galk2.data()[k][j].data().uint64_count());
                for (size_t i = 0; i < galk.data()[k][j].data().uint64_count(); i++)
                {
                    ASSERT_EQ(galk.data()[k][j].data()[i], galk2.data()[k][j].data()[i]);
                }
            }
        }

        out_size = Serialization::Save(galk, ss, compr_mode_type::zlib);
        in_size = Serialization::Load(context, ss, galk2);
        ASSERT_EQ(out_size, in_size);
        for (size_t k = 0; k < galk.data().size(); k++)
        {
            for (size_t j = 0; j < galk.data()[k].size(); j++)
            {
                ASSERT_EQ(galk.data()[k][j].data().uint64_count(), galk2.data()[k][j].data().uint64_count());
                for (size_t i = 0; i < galk.data()[k][j].data().uint64_count(); i++)
                {
                    ASSERT_EQ(galk.data()[k][j].data()[i], galk2.data()[k][j].data()[i]);
                }
            }
        }
    }

    TEST(SerializationTest, Ciphertext)
    {
        EncryptionParameters parms(scheme_type::BFV);
        size_t poly_modulus_degree = 16;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 20, 20 }));
        parms.set_plain_modulus(4);

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk = keygen.public_key();
        Encryptor encryptor(context, pk);

        Ciphertext ct, ct2;
        encryptor.encrypt(Plaintext("1x^5 + 2x^4 + 3x^2 + 3x^1 + 1"), ct);

        stringstream ss;
        
        auto out_size = Serialization::Save(ct, ss, compr_mode_type::none);
        auto in_size = Serialization::UnsafeLoad(ss, ct2);
        ASSERT_EQ(ct.uint64_count(), ct2.uint64_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < ct.uint64_count(); i++)
        {
            ASSERT_EQ(ct.data()[i], ct2.data()[i]);
        }

        out_size = Serialization::Save(ct, ss, compr_mode_type::none);
        in_size = Serialization::Load(context, ss, ct2);
        ASSERT_EQ(ct.uint64_count(), ct2.uint64_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < ct.uint64_count(); i++)
        {
            ASSERT_EQ(ct.data()[i], ct2.data()[i]);
        }

        out_size = Serialization::Save(ct, ss, compr_mode_type::zlib);
        in_size = Serialization::UnsafeLoad(ss, ct2);
        ASSERT_EQ(ct.uint64_count(), ct2.uint64_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < ct.uint64_count(); i++)
        {
            ASSERT_EQ(ct.data()[i], ct2.data()[i]);
        }

        out_size = Serialization::Save(ct, ss, compr_mode_type::zlib);
        in_size = Serialization::Load(context, ss, ct2);
        ASSERT_EQ(ct.uint64_count(), ct2.uint64_count());
        ASSERT_EQ(out_size, in_size);
        for (size_t i = 0; i < ct.uint64_count(); i++)
        {
            ASSERT_EQ(ct.data()[i], ct2.data()[i]);
        }
    }
}
