// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/batchencoder.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    TEST(DecryptorTest, InvariantNoiseAndBudget)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));
        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk, keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;

        encryptor.encrypt_zero(ct);
        auto invariant_noise = decryptor.invariant_noise(ct);
        auto invariant_noise_budget = decryptor.invariant_noise_budget(ct);

        auto calculated_noise_budget = floor(-log2(2. * invariant_noise));

        ASSERT_DOUBLE_EQ(calculated_noise_budget, static_cast<double>(invariant_noise_budget));
    }
}