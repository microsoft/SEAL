// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/galoiskeys.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/util/uintcore.h"
#include "seal/modulus.h"
#include <vector>

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
    TEST(GaloisKeysTest, GaloisKeysSaveLoad)
    {
        stringstream stream;
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            GaloisKeys keys;
            GaloisKeys test_keys;
            keys.save(stream);
            test_keys.unsafe_load(stream);
            ASSERT_EQ(keys.data().size(), test_keys.data().size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(0ULL, keys.data().size());

            keys = keygen.galois_keys();
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.data().size(), test_keys.data().size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            for (size_t j = 0; j < test_keys.data().size(); j++)
            {
                for (size_t i = 0; i < test_keys.data()[j].size(); i++)
                {
                    ASSERT_EQ(keys.data()[j][i].data().size(), test_keys.data()[j][i].data().size());
                    ASSERT_EQ(keys.data()[j][i].data().uint64_count(), test_keys.data()[j][i].data().uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.data()[j][i].data().data(), test_keys.data()[j][i].data().data(), keys.data()[j][i].data().uint64_count()));
                }
            }
            ASSERT_EQ(64ULL, keys.data().size());
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_poly_modulus_degree(256);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 60, 50 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            GaloisKeys keys;
            GaloisKeys test_keys;
            keys.save(stream);
            test_keys.unsafe_load(stream);
            ASSERT_EQ(keys.data().size(), test_keys.data().size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(0ULL, keys.data().size());

            keys = keygen.galois_keys();
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.data().size(), test_keys.data().size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            for (size_t j = 0; j < test_keys.data().size(); j++)
            {
                for (size_t i = 0; i < test_keys.data()[j].size(); i++)
                {
                    ASSERT_EQ(keys.data()[j][i].data().size(), test_keys.data()[j][i].data().size());
                    ASSERT_EQ(keys.data()[j][i].data().uint64_count(), test_keys.data()[j][i].data().uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.data()[j][i].data().data(), test_keys.data()[j][i].data().data(), keys.data()[j][i].data().uint64_count()));
                }
            }
            ASSERT_EQ(256ULL, keys.data().size());
        }
    }
}