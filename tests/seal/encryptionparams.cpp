// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/encryptionparams.h"
#include "seal/defaultparams.h"

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(EncryptionParametersTest, EncryptionParametersSet)
    {
        auto scheme = scheme_type::BFV;
        EncryptionParameters parms(scheme);
        parms.set_noise_standard_deviation(3.20);
        parms.set_coeff_modulus({ 2, 3 });
        parms.set_plain_modulus(2);
        parms.set_poly_modulus_degree(2);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());

        ASSERT_TRUE(scheme == parms.scheme());
        ASSERT_EQ(3.20, parms.noise_standard_deviation());
        ASSERT_EQ(3.20 * 6, parms.noise_max_deviation());
        ASSERT_TRUE(parms.coeff_modulus()[0] == 2);
        ASSERT_TRUE(parms.coeff_modulus()[1] == 3);
        ASSERT_TRUE(parms.plain_modulus() == 2);
        ASSERT_TRUE(parms.poly_modulus_degree() == 2);
        ASSERT_TRUE(parms.random_generator() == UniformRandomGeneratorFactory::default_factory());

        parms.set_noise_standard_deviation(3.20);
        parms.set_coeff_modulus({
            small_mods_30bit(0), small_mods_40bit(0), small_mods_50bit(0)
            });
        parms.set_plain_modulus(2);
        parms.set_poly_modulus_degree(128);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());

        ASSERT_EQ(3.20, parms.noise_standard_deviation());
        ASSERT_EQ(3.20 * 6, parms.noise_max_deviation());
        ASSERT_TRUE(parms.coeff_modulus()[0] == small_mods_30bit(0));
        ASSERT_TRUE(parms.coeff_modulus()[1] == small_mods_40bit(0));
        ASSERT_TRUE(parms.coeff_modulus()[2] == small_mods_50bit(0));
        ASSERT_TRUE(parms.plain_modulus() == 2);
        ASSERT_TRUE(parms.poly_modulus_degree() == 128);
        ASSERT_TRUE(parms.random_generator() == UniformRandomGeneratorFactory::default_factory());
    }

    TEST(EncryptionParametersTest, EncryptionParametersCompare)
    {
        auto scheme = scheme_type::BFV;
        EncryptionParameters parms1(scheme);
        parms1.set_noise_standard_deviation(3.20);
        parms1.set_coeff_modulus({ small_mods_30bit(0) });
        parms1.set_plain_modulus(1 << 6);
        parms1.set_poly_modulus_degree(64);
        parms1.set_random_generator(UniformRandomGeneratorFactory::default_factory());

        EncryptionParameters parms2(parms1);
        ASSERT_TRUE(parms1 == parms2);

        EncryptionParameters parms3(scheme);
        parms3 = parms2;
        ASSERT_TRUE(parms3 == parms2);
        parms3.set_coeff_modulus({ small_mods_30bit(1) });
        ASSERT_FALSE(parms3 == parms2);

        parms3 = parms2;
        ASSERT_TRUE(parms3 == parms2);
        parms3.set_coeff_modulus({
            small_mods_30bit(0), small_mods_30bit(1)
            });
        ASSERT_FALSE(parms3 == parms2);

        parms3 = parms2;
        parms3.set_poly_modulus_degree(128);
        ASSERT_FALSE(parms3 == parms1);

        parms3 = parms2;
        parms3.set_plain_modulus((1 << 6) + 1);
        ASSERT_FALSE(parms3 == parms2);

        parms3 = parms2;
        parms3.set_noise_standard_deviation(3.18);
        ASSERT_FALSE(parms3 == parms2);

        parms3 = parms2;
        parms3.set_random_generator(nullptr);
        ASSERT_TRUE(parms3 == parms2);

        parms3 = parms2;
        parms3.set_poly_modulus_degree(128);
        parms3.set_poly_modulus_degree(64);
        ASSERT_TRUE(parms3 == parms1);

        parms3 = parms2;
        parms3.set_coeff_modulus({ 2 });
        parms3.set_coeff_modulus({ small_mods_50bit(0) });
        parms3.set_coeff_modulus(parms2.coeff_modulus());
        ASSERT_TRUE(parms3 == parms2);
    }

    TEST(EncryptionParametersTest, EncryptionParametersSaveLoad)
    {
        stringstream stream;

        auto scheme = scheme_type::BFV;
        EncryptionParameters parms(scheme);
        EncryptionParameters parms2(scheme);
        parms.set_noise_standard_deviation(3.20);
        parms.set_coeff_modulus({ small_mods_30bit(0) });
        parms.set_plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        EncryptionParameters::Save(parms, stream);
        parms2 = EncryptionParameters::Load(stream);
        ASSERT_TRUE(parms.scheme() == parms2.scheme());
        ASSERT_EQ(parms.noise_standard_deviation(), parms2.noise_standard_deviation());
        ASSERT_EQ(parms.noise_max_deviation(), parms2.noise_max_deviation());
        ASSERT_TRUE(parms.coeff_modulus() == parms2.coeff_modulus());
        ASSERT_TRUE(parms.plain_modulus() == parms2.plain_modulus());
        ASSERT_TRUE(parms.poly_modulus_degree() == parms2.poly_modulus_degree());
        ASSERT_TRUE(parms == parms2);

        parms.set_noise_standard_deviation(3.20);
        parms.set_coeff_modulus({
            small_mods_30bit(0), small_mods_60bit(0), small_mods_60bit(1)
            });
        parms.set_plain_modulus(1 << 30);
        parms.set_poly_modulus_degree(256);

        EncryptionParameters::Save(parms, stream);
        parms2 = EncryptionParameters::Load(stream);
        ASSERT_TRUE(parms.scheme() == parms2.scheme());
        ASSERT_EQ(parms.noise_standard_deviation(), parms2.noise_standard_deviation());
        ASSERT_EQ(parms.noise_max_deviation(), parms2.noise_max_deviation());
        ASSERT_TRUE(parms.coeff_modulus() == parms2.coeff_modulus());
        ASSERT_TRUE(parms.plain_modulus() == parms2.plain_modulus());
        ASSERT_TRUE(parms.poly_modulus_degree() == parms2.poly_modulus_degree());
        ASSERT_TRUE(parms == parms2);
    }
}
