// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/relinkeys.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/util/uintcore.h"
#include "seal/modulus.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
    TEST(RelinKeysTest, RelinKeysSaveLoad)
    {
        stringstream stream;
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(1 << 6);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys keys;
            RelinKeys test_keys;
            keys = keygen.relin_keys();
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                {
                    ASSERT_EQ(keys.key(j + 2)[i].data().size(), test_keys.key(j + 2)[i].data().size());
                    ASSERT_EQ(keys.key(j + 2)[i].data().uint64_count(), test_keys.key(j + 2)[i].data().uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.key(j + 2)[i].data().data(), test_keys.key(j + 2)[i].data().data(), keys.key(j + 2)[i].data().uint64_count()));
                }
            }
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_poly_modulus_degree(256);
            parms.set_plain_modulus(1 << 6);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 60, 50 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys keys;
            RelinKeys test_keys;
            keys = keygen.relin_keys();
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                {
                    ASSERT_EQ(keys.key(j + 2)[i].data().size(), test_keys.key(j + 2)[i].data().size());
                    ASSERT_EQ(keys.key(j + 2)[i].data().uint64_count(), test_keys.key(j + 2)[i].data().uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.key(j + 2)[i].data().data(), test_keys.key(j + 2)[i].data().data(), keys.key(j + 2)[i].data().uint64_count()));
                }
            }
        }
    }
}