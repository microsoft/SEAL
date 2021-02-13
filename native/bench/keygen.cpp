// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/seal.h"
#include "seal/util/rlwe.h"
#include "bench.h"

using namespace benchmark;
using namespace sealbench;
using namespace seal;
using namespace std;

/**
This file defines benchmarks for KeyGen-related HE primitives.
*/

namespace seal
{
    struct KeyGenerator::KeyGeneratorPrivateHelper
    {
        static void generate_sk(KeyGenerator *keygen)
        {
            return keygen->generate_sk();
        }
    };
} // namespace seal

namespace sealbench
{
    void bm_keygen_secret(State &state, shared_ptr<BMEnv> bm_env)
    {
        KeyGenerator keygen(bm_env->context());
        for (auto _ : state)
        {
            KeyGenerator::KeyGeneratorPrivateHelper::generate_sk(&keygen);
        }
    }

    void bm_keygen_public(State &state, shared_ptr<BMEnv> bm_env)
    {
        shared_ptr<KeyGenerator> keygen = bm_env->keygen();
        PublicKey pk;
        for (auto _ : state)
        {
            keygen->create_public_key(pk);
        }
    }

    void bm_keygen_relin(State &state, shared_ptr<BMEnv> bm_env)
    {
        shared_ptr<KeyGenerator> keygen = bm_env->keygen();
        RelinKeys rlk;
        for (auto _ : state)
        {
            keygen->create_relin_keys(rlk);
        }
    }

    void bm_keygen_galois(State &state, shared_ptr<BMEnv> bm_env)
    {
        shared_ptr<KeyGenerator> keygen = bm_env->keygen();
        GaloisKeys glk;
        size_t slot_count = bm_env->parms().poly_modulus_degree() >> 1;

        auto random_one_step = [&]() {
            vector<int> res;
            res.emplace_back(rand() & static_cast<int>(slot_count - 1));
            return res;
        };

        for (auto _ : state)
        {
            keygen->create_galois_keys({ random_one_step() }, glk);
        }
    }
} // namespace sealbench
