// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/util/polycore.h"
#include "seal/defaultparams.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
    TEST(KeyGeneratorTest, FVKeyGeneration)
    {
        EncryptionParameters parms(scheme_type::BFV);
        {
            parms.set_noise_standard_deviation(3.20);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(1 << 6);
            parms.set_coeff_modulus({ small_mods_60bit(0) });
            auto context = SEALContext::Create(parms);
            KeyGenerator keygen(context);

            RelinKeys evk = keygen.relin_keys(60);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(2ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            evk = keygen.relin_keys(30, 1);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(4ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            evk = keygen.relin_keys(2, 2);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(60ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            GaloisKeys galks = keygen.galois_keys(60);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(2ULL, galks.key(3)[0].size());
            ASSERT_EQ(10ULL, galks.size());

            galks = keygen.galois_keys(30);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(4ULL, galks.key(3)[0].size());
            ASSERT_EQ(10ULL, galks.size());

            galks = keygen.galois_keys(2);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(60ULL, galks.key(3)[0].size());
            ASSERT_EQ(10ULL, galks.size());

            galks = keygen.galois_keys(60, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(2ULL, galks.key(1)[0].size());
            ASSERT_EQ(2ULL, galks.key(3)[0].size());
            ASSERT_EQ(2ULL, galks.key(5)[0].size());
            ASSERT_EQ(2ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(4ULL, galks.key(1)[0].size());
            ASSERT_EQ(4ULL, galks.key(3)[0].size());
            ASSERT_EQ(4ULL, galks.key(5)[0].size());
            ASSERT_EQ(4ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(2, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(60ULL, galks.key(1)[0].size());
            ASSERT_EQ(60ULL, galks.key(3)[0].size());
            ASSERT_EQ(60ULL, galks.key(5)[0].size());
            ASSERT_EQ(60ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 1 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(4ULL, galks.key(1)[0].size());
            ASSERT_EQ(1ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 127 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(127));
            ASSERT_EQ(4ULL, galks.key(127)[0].size());
            ASSERT_EQ(1ULL, galks.size());
        }
        {
            parms.set_noise_standard_deviation(3.20);
            parms.set_poly_modulus_degree(256);
            parms.set_plain_modulus(1 << 6);
            parms.set_coeff_modulus({ small_mods_60bit(0), small_mods_30bit(0), small_mods_30bit(1) });
            auto context = SEALContext::Create(parms);
            KeyGenerator keygen(context);

            RelinKeys evk = keygen.relin_keys(60, 2);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(2ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            evk = keygen.relin_keys(30, 2);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(4ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            evk = keygen.relin_keys(4, 1);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(30ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            GaloisKeys galks = keygen.galois_keys(60);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(2ULL, galks.key(3)[0].size());
            ASSERT_EQ(14ULL, galks.size());

            galks = keygen.galois_keys(30);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(4ULL, galks.key(3)[0].size());
            ASSERT_EQ(14ULL, galks.size());

            galks = keygen.galois_keys(2);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(60ULL, galks.key(3)[0].size());
            ASSERT_EQ(14ULL, galks.size());

            galks = keygen.galois_keys(60, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1)[0].size());
            ASSERT_EQ(2ULL, galks.key(3)[0].size());
            ASSERT_EQ(2ULL, galks.key(5)[0].size());
            ASSERT_EQ(2ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(4ULL, galks.key(1)[0].size());
            ASSERT_EQ(4ULL, galks.key(3)[0].size());
            ASSERT_EQ(4ULL, galks.key(5)[0].size());
            ASSERT_EQ(4ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(2, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(60ULL, galks.key(1)[0].size());
            ASSERT_EQ(60ULL, galks.key(3)[0].size());
            ASSERT_EQ(60ULL, galks.key(5)[0].size());
            ASSERT_EQ(60ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 1 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(4ULL, galks.key(1)[0].size());
            ASSERT_EQ(1ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 511 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(511));
            ASSERT_EQ(4ULL, galks.key(511)[0].size());
            ASSERT_EQ(1ULL, galks.size());
        }
    }

    TEST(KeyGeneratorTest, CKKSKeyGeneration)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            parms.set_noise_standard_deviation(3.20);
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus({ small_mods_60bit(0) });
            auto context = SEALContext::Create(parms);
            KeyGenerator keygen(context);

            RelinKeys evk = keygen.relin_keys(60);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(2ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            evk = keygen.relin_keys(30, 1);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(4ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            evk = keygen.relin_keys(2, 2);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(60ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            GaloisKeys galks = keygen.galois_keys(60);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(2ULL, galks.key(3)[0].size());
            ASSERT_EQ(10ULL, galks.size());

            galks = keygen.galois_keys(30);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(4ULL, galks.key(3)[0].size());
            ASSERT_EQ(10ULL, galks.size());

            galks = keygen.galois_keys(2);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(60ULL, galks.key(3)[0].size());
            ASSERT_EQ(10ULL, galks.size());

            galks = keygen.galois_keys(60, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(2ULL, galks.key(1)[0].size());
            ASSERT_EQ(2ULL, galks.key(3)[0].size());
            ASSERT_EQ(2ULL, galks.key(5)[0].size());
            ASSERT_EQ(2ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(4ULL, galks.key(1)[0].size());
            ASSERT_EQ(4ULL, galks.key(3)[0].size());
            ASSERT_EQ(4ULL, galks.key(5)[0].size());
            ASSERT_EQ(4ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(2, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(60ULL, galks.key(1)[0].size());
            ASSERT_EQ(60ULL, galks.key(3)[0].size());
            ASSERT_EQ(60ULL, galks.key(5)[0].size());
            ASSERT_EQ(60ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 1 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(4ULL, galks.key(1)[0].size());
            ASSERT_EQ(1ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 127 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(127));
            ASSERT_EQ(4ULL, galks.key(127)[0].size());
            ASSERT_EQ(1ULL, galks.size());
        }
        {
            parms.set_noise_standard_deviation(3.20);
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus({ small_mods_60bit(0), small_mods_30bit(0), small_mods_30bit(1) });
            auto context = SEALContext::Create(parms);
            KeyGenerator keygen(context);

            RelinKeys evk = keygen.relin_keys(60, 2);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(2ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            evk = keygen.relin_keys(30, 2);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(4ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            evk = keygen.relin_keys(4, 1);
            ASSERT_TRUE(evk.parms_id() == parms.parms_id());
            ASSERT_EQ(30ULL, evk.key(2)[0].size());
            for (size_t j = 0; j < evk.size(); j++)
            {
                for (size_t i = 0; i < evk.key(j + 2).size(); i++)
                {
                    for (size_t k = 0; k < evk.key(j + 2)[i].size(); k++)
                    {
                        ASSERT_FALSE(is_zero_poly(evk.key(j + 2)[i].data(k), evk.key(j + 2)[i].poly_modulus_degree(), evk.key(j + 2)[i].coeff_mod_count()));
                    }
                }
            }

            GaloisKeys galks = keygen.galois_keys(60);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(2ULL, galks.key(3)[0].size());
            ASSERT_EQ(14ULL, galks.size());

            galks = keygen.galois_keys(30);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(4ULL, galks.key(3)[0].size());
            ASSERT_EQ(14ULL, galks.size());

            galks = keygen.galois_keys(2);
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_EQ(60ULL, galks.key(3)[0].size());
            ASSERT_EQ(14ULL, galks.size());

            galks = keygen.galois_keys(60, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1)[0].size());
            ASSERT_EQ(2ULL, galks.key(3)[0].size());
            ASSERT_EQ(2ULL, galks.key(5)[0].size());
            ASSERT_EQ(2ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(4ULL, galks.key(1)[0].size());
            ASSERT_EQ(4ULL, galks.key(3)[0].size());
            ASSERT_EQ(4ULL, galks.key(5)[0].size());
            ASSERT_EQ(4ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(2, vector<uint64_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(60ULL, galks.key(1)[0].size());
            ASSERT_EQ(60ULL, galks.key(3)[0].size());
            ASSERT_EQ(60ULL, galks.key(5)[0].size());
            ASSERT_EQ(60ULL, galks.key(7)[0].size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 1 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(4ULL, galks.key(1)[0].size());
            ASSERT_EQ(1ULL, galks.size());

            galks = keygen.galois_keys(30, vector<uint64_t>{ 511 });
            ASSERT_TRUE(galks.parms_id() == parms.parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(511));
            ASSERT_EQ(4ULL, galks.key(511)[0].size());
            ASSERT_EQ(1ULL, galks.size());
        }
    }

    TEST(KeyGeneratorTest, FVSecretKeyGeneration)
    {
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_noise_standard_deviation(3.20);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus({ small_mods_60bit(0) });
        auto context = SEALContext::Create(parms);
        {
            KeyGenerator keygen(context);
            auto pk = keygen.public_key();
            auto sk = keygen.secret_key();

            KeyGenerator keygen2(context, sk);
            auto sk2 = keygen.secret_key();
            auto pk2 = keygen2.public_key();

            ASSERT_EQ(sk.data().coeff_count(), sk2.data().coeff_count());
            for (size_t i = 0; i < sk.data().coeff_count(); i++)
            {
                ASSERT_EQ(sk.data()[i], sk2.data()[i]);
            }

            ASSERT_EQ(pk.data().uint64_count(), pk2.data().uint64_count());
            for (size_t i = 0; i < pk.data().uint64_count(); i++)
            {
                ASSERT_NE(pk.data()[i], pk2.data()[i]);
            }

            Encryptor encryptor(context, pk2);
            Decryptor decryptor(context, sk);
            Ciphertext ctxt;
            Plaintext pt1("1x^63 + 2x^33 + 3x^23 + 4x^13 + 5x^1 + 6");
            Plaintext pt2;
            encryptor.encrypt(pt1, ctxt);
            decryptor.decrypt(ctxt, pt2);
            ASSERT_TRUE(pt1 == pt2);
        }
        {
            KeyGenerator keygen(context);
            auto pk = keygen.public_key();
            auto sk = keygen.secret_key();

            KeyGenerator keygen2(context, sk, pk);
            auto sk2 = keygen.secret_key();
            auto pk2 = keygen2.public_key();

            ASSERT_EQ(sk.data().coeff_count(), sk2.data().coeff_count());
            for (size_t i = 0; i < sk.data().coeff_count(); i++)
            {
                ASSERT_EQ(sk.data()[i], sk2.data()[i]);
            }

            ASSERT_EQ(pk.data().uint64_count(), pk2.data().uint64_count());
            for (size_t i = 0; i < pk.data().uint64_count(); i++)
            {
                ASSERT_EQ(pk.data()[i], pk2.data()[i]);
            }
        }
    }
}
