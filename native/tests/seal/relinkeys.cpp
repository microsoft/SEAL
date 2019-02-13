// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/relinkeys.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/util/uintcore.h"
#include "seal/defaultparams.h"

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
            parms.set_noise_standard_deviation(3.20);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(1 << 6);
            parms.set_coeff_modulus({ DefaultParams::small_mods_60bit(0) });
            auto context = SEALContext::Create(parms);
            KeyGenerator keygen(context);

            RelinKeys keys;
            RelinKeys test_keys;
            keys = keygen.relin_keys(1, 1);
            ASSERT_EQ(keys.decomposition_bit_count(), 1);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                {
                    ASSERT_EQ(keys.key(j + 2)[i].size(), test_keys.key(j + 2)[i].size());
                    ASSERT_EQ(keys.key(j + 2)[i].uint64_count(), test_keys.key(j + 2)[i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.key(j + 2)[i].data(), test_keys.key(j + 2)[i].data(), keys.key(j + 2)[i].uint64_count()));
                }
            }

            keys = keygen.relin_keys(2, 1);
            ASSERT_EQ(keys.decomposition_bit_count(), 2);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                {
                    ASSERT_EQ(keys.key(j + 2)[i].size(), test_keys.key(j + 2)[i].size());
                    ASSERT_EQ(keys.key(j + 2)[i].uint64_count(), test_keys.key(j + 2)[i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.key(j + 2)[i].data(), test_keys.key(j + 2)[i].data(), keys.key(j + 2)[i].uint64_count()));
                }
            }

            keys = keygen.relin_keys(59, 2);
            ASSERT_EQ(keys.decomposition_bit_count(), 59);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                {
                    ASSERT_EQ(keys.key(j + 2)[i].size(), test_keys.key(j + 2)[i].size());
                    ASSERT_EQ(keys.key(j + 2)[i].uint64_count(), test_keys.key(j + 2)[i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.key(j + 2)[i].data(), test_keys.key(j + 2)[i].data(), keys.key(j + 2)[i].uint64_count()));
                }
            }

            keys = keygen.relin_keys(60, 5);
            ASSERT_EQ(keys.decomposition_bit_count(), 60);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                {
                    ASSERT_EQ(keys.key(j + 2)[i].size(), test_keys.key(j + 2)[i].size());
                    ASSERT_EQ(keys.key(j + 2)[i].uint64_count(), test_keys.key(j + 2)[i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.key(j + 2)[i].data(), test_keys.key(j + 2)[i].data(), keys.key(j + 2)[i].uint64_count()));
                }
            }
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_noise_standard_deviation(3.20);
            parms.set_poly_modulus_degree(256);
            parms.set_plain_modulus(1 << 6);
            parms.set_coeff_modulus({ DefaultParams::small_mods_60bit(0), DefaultParams::small_mods_50bit(0) });
            auto context = SEALContext::Create(parms);
            KeyGenerator keygen(context);

            RelinKeys keys;
            RelinKeys test_keys;
            keys = keygen.relin_keys(8, 1);
            ASSERT_EQ(keys.decomposition_bit_count(), 8);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                {
                    ASSERT_EQ(keys.key(j + 2)[i].size(), test_keys.key(j + 2)[i].size());
                    ASSERT_EQ(keys.key(j + 2)[i].uint64_count(), test_keys.key(j + 2)[i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.key(j + 2)[i].data(), test_keys.key(j + 2)[i].data(), keys.key(j + 2)[i].uint64_count()));
                }
            }

            keys = keygen.relin_keys(8, 2);
            ASSERT_EQ(keys.decomposition_bit_count(), 8);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                {
                    ASSERT_EQ(keys.key(j + 2)[i].size(), test_keys.key(j + 2)[i].size());
                    ASSERT_EQ(keys.key(j + 2)[i].uint64_count(), test_keys.key(j + 2)[i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.key(j + 2)[i].data(), test_keys.key(j + 2)[i].data(), keys.key(j + 2)[i].uint64_count()));
                }
            }

            keys = keygen.relin_keys(59, 2);
            ASSERT_EQ(keys.decomposition_bit_count(), 59);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                {
                    ASSERT_EQ(keys.key(j + 2)[i].size(), test_keys.key(j + 2)[i].size());
                    ASSERT_EQ(keys.key(j + 2)[i].uint64_count(), test_keys.key(j + 2)[i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.key(j + 2)[i].data(), test_keys.key(j + 2)[i].data(), keys.key(j + 2)[i].uint64_count()));
                }
            }

            keys = keygen.relin_keys(60, 5);
            ASSERT_EQ(keys.decomposition_bit_count(), 60);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                {
                    ASSERT_EQ(keys.key(j + 2)[i].size(), test_keys.key(j + 2)[i].size());
                    ASSERT_EQ(keys.key(j + 2)[i].uint64_count(), test_keys.key(j + 2)[i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.key(j + 2)[i].data(), test_keys.key(j + 2)[i].data(), keys.key(j + 2)[i].uint64_count()));
                }
            }
        }
    }
}
