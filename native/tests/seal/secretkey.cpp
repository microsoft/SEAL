// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include "seal/secretkey.h"
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    TEST(SecretKeyTest, SaveLoadSecretKey)
    {
        auto save_load_secret_key = [](scheme_type scheme) {
            stringstream stream;
            {
                EncryptionParameters parms(scheme);
                parms.set_poly_modulus_degree(64);
                parms.set_plain_modulus(1 << 6);
                parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));

                SEALContext context(parms, false, sec_level_type::none);
                KeyGenerator keygen(context);

                SecretKey sk = keygen.secret_key();
                ASSERT_TRUE(sk.parms_id() == context.key_parms_id());
                sk.save(stream);

                SecretKey sk2;
                sk2.load(context, stream);

                ASSERT_TRUE(sk.data() == sk2.data());
                ASSERT_TRUE(sk.parms_id() == sk2.parms_id());
            }
            {
                EncryptionParameters parms(scheme);
                parms.set_poly_modulus_degree(256);
                parms.set_plain_modulus(1 << 20);
                parms.set_coeff_modulus(CoeffModulus::Create(256, { 30, 40 }));

                SEALContext context(parms, false, sec_level_type::none);
                KeyGenerator keygen(context);

                SecretKey sk = keygen.secret_key();
                ASSERT_TRUE(sk.parms_id() == context.key_parms_id());
                sk.save(stream);

                SecretKey sk2;
                sk2.load(context, stream);

                ASSERT_TRUE(sk.data() == sk2.data());
                ASSERT_TRUE(sk.parms_id() == sk2.parms_id());
            }
        };

        save_load_secret_key(scheme_type::bfv);
        save_load_secret_key(scheme_type::bgv);
    }
} // namespace sealtest
