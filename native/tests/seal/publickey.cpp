// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include "seal/publickey.h"
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    TEST(PublicKeyTest, SaveLoadPublicKey)
    {
        auto save_load_public_key = [](scheme_type scheme) {
            stringstream stream;
            {
                EncryptionParameters parms(scheme);
                parms.set_poly_modulus_degree(64);
                parms.set_plain_modulus(1 << 6);
                parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));

                SEALContext context(parms, false, sec_level_type::none);
                KeyGenerator keygen(context);

                PublicKey pk;
                keygen.create_public_key(pk);
                ASSERT_TRUE(pk.parms_id() == context.key_parms_id());
                pk.save(stream);

                PublicKey pk2;
                pk2.load(context, stream);

                ASSERT_EQ(pk.data().dyn_array().size(), pk2.data().dyn_array().size());
                for (size_t i = 0; i < pk.data().dyn_array().size(); i++)
                {
                    ASSERT_EQ(pk.data().data()[i], pk2.data().data()[i]);
                }
                ASSERT_TRUE(pk.parms_id() == pk2.parms_id());
            }
            {
                EncryptionParameters parms(scheme);
                parms.set_poly_modulus_degree(256);
                parms.set_plain_modulus(1 << 20);
                parms.set_coeff_modulus(CoeffModulus::Create(256, { 30, 40 }));

                SEALContext context(parms, false, sec_level_type::none);
                KeyGenerator keygen(context);

                PublicKey pk;
                keygen.create_public_key(pk);
                ASSERT_TRUE(pk.parms_id() == context.key_parms_id());
                pk.save(stream);

                PublicKey pk2;
                pk2.load(context, stream);

                ASSERT_EQ(pk.data().dyn_array().size(), pk2.data().dyn_array().size());
                for (size_t i = 0; i < pk.data().dyn_array().size(); i++)
                {
                    ASSERT_EQ(pk.data().data()[i], pk2.data().data()[i]);
                }
                ASSERT_TRUE(pk.parms_id() == pk2.parms_id());
            }
        };

        save_load_public_key(scheme_type::bfv);
        save_load_public_key(scheme_type::bgv);
    }

    // A public key has size 2, and loading rejects larger keys before allocating memory for them.
    TEST(PublicKeyTest, LoadRejectsLargeKey)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(4096);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(4096, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);

        PublicKey key;
        key.data().resize(context, context.key_parms_id(), SEAL_CIPHERTEXT_SIZE_MIN + 1);
        key.data().is_ntt_form() = true;
        stringstream stream;
        key.save(stream, compr_mode_type::none);
        string bytes = stream.str();

        // Keys loaded into loaded are allocated from pool
        MemoryPoolHandle pool = MemoryPoolHandle::New();
        unique_ptr<PublicKey> loaded;
        {
            MMProfGuard guard(make_unique<MMProfFixed>(pool));
            loaded = make_unique<PublicKey>();
        }
        ASSERT_TRUE(loaded->pool() == pool);

        stringstream in(bytes);
        ASSERT_THROW(loaded->load(context, in), logic_error);
        ASSERT_THROW(
            loaded->load(context, reinterpret_cast<const seal_byte *>(bytes.data()), bytes.size()), logic_error);
        stringstream trusted_in(bytes);
        ASSERT_THROW(loaded->unsafe_load(context, trusted_in), logic_error);
        ASSERT_THROW(
            loaded->unsafe_load(context, reinterpret_cast<const seal_byte *>(bytes.data()), bytes.size()), logic_error);
        ASSERT_EQ(size_t(0), pool.alloc_byte_count());
    }
} // namespace sealtest
