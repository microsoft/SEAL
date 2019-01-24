// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/galoiskeys.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/util/uintcore.h"
#include "seal/defaultparams.h"
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
            parms.set_noise_standard_deviation(3.20);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus({ small_mods_60bit(0) });
            auto context = SEALContext::Create(parms);
            KeyGenerator keygen(context);

            GaloisKeys keys;
            GaloisKeys test_keys;
            ASSERT_EQ(keys.decomposition_bit_count(), 0);
            keys.save(stream);
            test_keys.unsafe_load(stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            ASSERT_EQ(0ULL, keys.size());

            keys = keygen.galois_keys(1);
            ASSERT_EQ(keys.decomposition_bit_count(), 1);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.data()[j].size(); i++)
                {
                    ASSERT_EQ(keys.data()[j][i].size(), test_keys.data()[j][i].size());
                    ASSERT_EQ(keys.data()[j][i].uint64_count(), test_keys.data()[j][i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.data()[j][i].data(), test_keys.data()[j][i].data(), keys.data()[j][i].uint64_count()));
                }
            }
            ASSERT_EQ(10ULL, keys.size());

            keys = keygen.galois_keys(8);
            ASSERT_EQ(keys.decomposition_bit_count(), 8);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.data()[j].size(); i++)
                {
                    ASSERT_EQ(keys.data()[j][i].size(), test_keys.data()[j][i].size());
                    ASSERT_EQ(keys.data()[j][i].uint64_count(), test_keys.data()[j][i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.data()[j][i].data(), test_keys.data()[j][i].data(), keys.data()[j][i].uint64_count()));
                }
            }
            ASSERT_EQ(10ULL, keys.size());

            keys = keygen.galois_keys(60);
            ASSERT_EQ(keys.decomposition_bit_count(), 60);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.data()[j].size(); i++)
                {
                    ASSERT_EQ(keys.data()[j][i].size(), test_keys.data()[j][i].size());
                    ASSERT_EQ(keys.data()[j][i].uint64_count(), test_keys.data()[j][i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.data()[j][i].data(), test_keys.data()[j][i].data(), keys.data()[j][i].uint64_count()));
                }
            }
            ASSERT_EQ(10ULL, keys.size());
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_noise_standard_deviation(3.20);
            parms.set_poly_modulus_degree(256);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus({ small_mods_60bit(0), small_mods_50bit(0) });
            auto context = SEALContext::Create(parms);
            KeyGenerator keygen(context);

            GaloisKeys keys;
            GaloisKeys test_keys;
            ASSERT_EQ(keys.decomposition_bit_count(), 0);
            keys.save(stream);
            test_keys.unsafe_load(stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            ASSERT_EQ(0ULL, keys.size());

            keys = keygen.galois_keys(8);
            ASSERT_EQ(keys.decomposition_bit_count(), 8);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.data()[j].size(); i++)
                {
                    ASSERT_EQ(keys.data()[j][i].size(), test_keys.data()[j][i].size());
                    ASSERT_EQ(keys.data()[j][i].uint64_count(), test_keys.data()[j][i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.data()[j][i].data(), test_keys.data()[j][i].data(), keys.data()[j][i].uint64_count()));
                }
            }
            ASSERT_EQ(14ULL, keys.size());

            keys = keygen.galois_keys(60);
            ASSERT_EQ(keys.decomposition_bit_count(), 60);
            keys.save(stream);
            test_keys.load(context, stream);
            ASSERT_EQ(keys.size(), test_keys.size());
            ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
            ASSERT_EQ(keys.decomposition_bit_count(), test_keys.decomposition_bit_count());
            for (size_t j = 0; j < test_keys.size(); j++)
            {
                for (size_t i = 0; i < test_keys.data()[j].size(); i++)
                {
                    ASSERT_EQ(keys.data()[j][i].size(), test_keys.data()[j][i].size());
                    ASSERT_EQ(keys.data()[j][i].uint64_count(), test_keys.data()[j][i].uint64_count());
                    ASSERT_TRUE(is_equal_uint_uint(keys.data()[j][i].data(), test_keys.data()[j][i].data(), keys.data()[j][i].uint64_count()));
                }
            }
            ASSERT_EQ(14ULL, keys.size());
        }
    }
}
