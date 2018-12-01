// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/publickey.h"
#include "seal/context.h"
#include "seal/defaultparams.h"
#include "seal/keygenerator.h"

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(PublicKeyTest, SaveLoadPublicKey)
    {
        stringstream stream;
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_noise_standard_deviation(3.20);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(1 << 6);
            parms.set_coeff_modulus({ small_mods_60bit(0) });
            auto context = SEALContext::Create(parms);
            KeyGenerator keygen(context);

            PublicKey pk = keygen.public_key();
            ASSERT_TRUE(pk.parms_id() == parms.parms_id());
            pk.save(stream);

            PublicKey pk2;
            pk2.load(context, stream);

            ASSERT_EQ(pk.data().uint64_count(), pk2.data().uint64_count());
            for (size_t i = 0; i < pk.data().uint64_count(); i++)
            {
                ASSERT_EQ(pk.data().data()[i], pk2.data().data()[i]);
            }
            ASSERT_TRUE(pk.parms_id() == pk2.parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_noise_standard_deviation(3.20);
            parms.set_poly_modulus_degree(256);
            parms.set_plain_modulus(1 << 20);
            parms.set_coeff_modulus({ small_mods_30bit(0), small_mods_40bit(0) });
            auto context = SEALContext::Create(parms);
            KeyGenerator keygen(context);

            PublicKey pk = keygen.public_key();
            ASSERT_TRUE(pk.parms_id() == parms.parms_id());
            pk.save(stream);

            PublicKey pk2;
            pk2.load(context, stream);

            ASSERT_EQ(pk.data().uint64_count(), pk2.data().uint64_count());
            for (size_t i = 0; i < pk.data().uint64_count(); i++)
            {
                ASSERT_EQ(pk.data().data()[i], pk2.data().data()[i]);
            }
            ASSERT_TRUE(pk.parms_id() == pk2.parms_id());
        }
    }
}
