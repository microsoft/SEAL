// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/encryptionparams.h"
#include "seal/modulus.h"
#include "seal/util/numth.h"
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    TEST(EncryptionParametersTest, EncryptionParametersSet)
    {
        auto encryption_parameters_test = [](scheme_type scheme) {
            EncryptionParameters parms(scheme);
            parms.set_coeff_modulus({ 2, 3 });
            if (scheme == scheme_type::BFV)
                parms.set_plain_modulus(2);
            parms.set_poly_modulus_degree(2);
            parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());

            ASSERT_TRUE(scheme == parms.scheme());
            ASSERT_TRUE(parms.coeff_modulus()[0] == 2);
            ASSERT_TRUE(parms.coeff_modulus()[1] == 3);
            if (scheme == scheme_type::BFV)
            {
                ASSERT_TRUE(parms.plain_modulus().value() == 2);
            }
            else if (scheme == scheme_type::CKKS)
            {
                ASSERT_TRUE(parms.plain_modulus().value() == 0);
            }
            ASSERT_TRUE(parms.poly_modulus_degree() == 2);
            ASSERT_TRUE(parms.random_generator() == UniformRandomGeneratorFactory::DefaultFactory());

            parms.set_coeff_modulus(CoeffModulus::Create(2, { 30, 40, 50 }));
            if (scheme == scheme_type::BFV)
                parms.set_plain_modulus(2);
            parms.set_poly_modulus_degree(128);
            parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());

            ASSERT_TRUE(util::is_prime(parms.coeff_modulus()[0]));
            ASSERT_TRUE(util::is_prime(parms.coeff_modulus()[1]));
            ASSERT_TRUE(util::is_prime(parms.coeff_modulus()[2]));

            if (scheme == scheme_type::BFV)
            {
                ASSERT_TRUE(parms.plain_modulus().value() == 2);
            }
            else if (scheme == scheme_type::CKKS)
            {
                ASSERT_TRUE(parms.plain_modulus().value() == 0);
            }
            ASSERT_TRUE(parms.poly_modulus_degree() == 128);
            ASSERT_TRUE(parms.random_generator() == UniformRandomGeneratorFactory::DefaultFactory());
        };
        encryption_parameters_test(scheme_type::BFV);
        encryption_parameters_test(scheme_type::CKKS);
    }

    TEST(EncryptionParametersTest, EncryptionParametersCompare)
    {
        auto scheme = scheme_type::BFV;
        EncryptionParameters parms1(scheme);
        parms1.set_coeff_modulus(CoeffModulus::Create(64, { 30 }));
        if (scheme == scheme_type::BFV)
            parms1.set_plain_modulus(1 << 6);
        parms1.set_poly_modulus_degree(64);
        parms1.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());

        EncryptionParameters parms2(parms1);
        ASSERT_TRUE(parms1 == parms2);

        EncryptionParameters parms3(scheme);
        parms3 = parms2;
        ASSERT_TRUE(parms3 == parms2);
        parms3.set_coeff_modulus(CoeffModulus::Create(64, { 32 }));
        ASSERT_FALSE(parms3 == parms2);

        parms3 = parms2;
        ASSERT_TRUE(parms3 == parms2);
        parms3.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30 }));
        ASSERT_FALSE(parms3 == parms2);

        parms3 = parms2;
        parms3.set_poly_modulus_degree(128);
        ASSERT_FALSE(parms3 == parms1);

        parms3 = parms2;
        if (scheme == scheme_type::BFV)
            parms3.set_plain_modulus((1 << 6) + 1);
        ASSERT_FALSE(parms3 == parms2);

        parms3 = parms2;
        ASSERT_TRUE(parms3 == parms2);

        parms3 = parms2;
        parms3.set_random_generator(nullptr);
        ASSERT_TRUE(parms3 == parms2);

        parms3 = parms2;
        parms3.set_poly_modulus_degree(128);
        parms3.set_poly_modulus_degree(64);
        ASSERT_TRUE(parms3 == parms1);

        parms3 = parms2;
        parms3.set_coeff_modulus({ 2 });
        parms3.set_coeff_modulus(CoeffModulus::Create(64, { 50 }));
        parms3.set_coeff_modulus(parms2.coeff_modulus());
        ASSERT_TRUE(parms3 == parms2);
    }

    TEST(EncryptionParametersTest, EncryptionParametersSaveLoad)
    {
        stringstream stream;

        auto scheme = scheme_type::BFV;
        EncryptionParameters parms(scheme);
        EncryptionParameters parms2(scheme);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 30 }));
        if (scheme == scheme_type::BFV)
            parms.set_plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.save(stream);
        parms2.load(stream);
        ASSERT_TRUE(parms.scheme() == parms2.scheme());
        ASSERT_TRUE(parms.coeff_modulus() == parms2.coeff_modulus());
        ASSERT_TRUE(parms.plain_modulus() == parms2.plain_modulus());
        ASSERT_TRUE(parms.poly_modulus_degree() == parms2.poly_modulus_degree());
        ASSERT_TRUE(parms == parms2);

        parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 60, 60 }));

        if (scheme == scheme_type::BFV)
            parms.set_plain_modulus(1 << 30);
        parms.set_poly_modulus_degree(256);

        parms.save(stream);
        parms2.load(stream);
        ASSERT_TRUE(parms.scheme() == parms2.scheme());
        ASSERT_TRUE(parms.coeff_modulus() == parms2.coeff_modulus());
        ASSERT_TRUE(parms.plain_modulus() == parms2.plain_modulus());
        ASSERT_TRUE(parms.poly_modulus_degree() == parms2.poly_modulus_degree());
        ASSERT_TRUE(parms == parms2);
    }
} // namespace sealtest
