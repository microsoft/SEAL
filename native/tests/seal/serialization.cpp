// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <sstream>
#include "gtest/gtest.h"
#include "seal/serialization.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/encryptor.h"
#include "seal/ciphertext.h"

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(SerializationTest, Plaintext)
    {
        EncryptionParameters parms(scheme_type::BFV);
        size_t poly_modulus_degree = 16;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 10 }));
        parms.set_plain_modulus(4);

        Plaintext pt("3x^4 + 1x^2 + 1x^1 + 2");
        Plaintext pt2;

        stringstream ss;
        auto out_size = Serialization::Save(pt, ss, compr_mode_type::none);
        auto in_size = Serialization::UnsafeLoad(ss, pt2);
        ASSERT_EQ(pt, pt2);
        ASSERT_EQ(out_size, in_size);

        out_size = Serialization::Save(pt, ss, compr_mode_type::zlib);
        in_size = Serialization::UnsafeLoad(ss, pt2);
        ASSERT_EQ(pt, pt2);
        ASSERT_EQ(out_size, in_size);
    }
}
