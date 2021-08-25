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
This file defines benchmarks for CKKS-specific HE primitives.
*/

namespace sealbench
{
    void bm_ckks_encrypt_secret(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_pt_ckks(pt);
        for (auto _ : state)
        {
            bm_env->encryptor()->encrypt_symmetric(pt, ct[2]);
        }
    }

    void bm_ckks_encrypt_public(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_pt_ckks(pt);
        for (auto _ : state)
        {
            bm_env->encryptor()->encrypt(pt, ct[2]);
        }
    }

    void bm_ckks_decrypt(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_ct_ckks(ct[0]);
        for (auto _ : state)
        {
            bm_env->decryptor()->decrypt(ct[0], pt);
        }
    }

    void bm_ckks_encode_double(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<double> msg = bm_env->msg_double();
        bm_env->randomize_message_double(msg);
        Plaintext pt = bm_env->pt()[0];
        parms_id_type parms_id = bm_env->context().first_parms_id();
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            bm_env->ckks_encoder()->encode(msg, parms_id, scale, pt);
        }
    }

    void bm_ckks_decode_double(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<double> msg = bm_env->msg_double();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_pt_ckks(pt);

        for (auto _ : state)
        {
            bm_env->ckks_encoder()->decode(pt, msg);
        }
    }

    void bm_ckks_add_ct(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        double scale = bm_env->safe_scale();
        bm_env->randomize_ct_ckks(ct[0]);
        ct[0].scale() = scale;
        bm_env->randomize_ct_ckks(ct[1]);
        ct[1].scale() = scale;
        Ciphertext res;
        for (auto _ : state)
        {
            bm_env->evaluator()->add(ct[0], ct[1], res);
        }
    }

    void bm_ckks_add_pt(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        Plaintext pt = bm_env->pt()[0];
        double scale = bm_env->safe_scale();
        bm_env->randomize_ct_ckks(ct[0]);
        ct[0].scale() = scale;
        bm_env->randomize_pt_ckks(pt);
        pt.scale() = scale;
        for (auto _ : state)
        {
            bm_env->evaluator()->add_plain(ct[0], pt, ct[2]);
        }
    }

    void bm_ckks_mul_ct(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        double scale = bm_env->safe_scale();
        bm_env->randomize_ct_ckks(ct[0]);
        ct[0].scale() = scale;
        bm_env->randomize_ct_ckks(ct[1]);
        ct[1].scale() = scale;
        for (auto _ : state)
        {
            bm_env->evaluator()->multiply(ct[0], ct[1], ct[2]);
        }
    }

    void bm_ckks_mul_pt(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        Plaintext pt = bm_env->pt()[0];
        double scale = bm_env->safe_scale();
        bm_env->randomize_ct_ckks(ct[0]);
        ct[0].scale() = scale;
        bm_env->randomize_pt_ckks(pt);
        pt.scale() = scale;
        for (auto _ : state)
        {
            bm_env->evaluator()->multiply_plain(ct[0], pt, ct[2]);
        }
    }

    void bm_ckks_square(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        double scale = bm_env->safe_scale();
        bm_env->randomize_ct_ckks(ct[0]);
        ct[0].scale() = scale;
        bm_env->randomize_ct_ckks(ct[1]);
        ct[1].scale() = scale;
        for (auto _ : state)
        {
            bm_env->evaluator()->square(ct[0], ct[2]);
        }
    }

    void bm_ckks_rescale(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        double scale = bm_env->safe_scale() * pow(2.0, 20);
        bm_env->randomize_ct_ckks(ct[0]);
        ct[0].scale() = scale;
        for (auto _ : state)
        {
            bm_env->evaluator()->rescale_to_next(ct[0], ct[1]);
        }
    }

    void bm_ckks_relin(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        ct[0].resize(bm_env->context(), size_t(3));
        bm_env->randomize_ct_ckks(ct[0]);
        for (auto _ : state)
        {
            bm_env->evaluator()->relinearize(ct[0], bm_env->rlk(), ct[1]);
        }
    }

    void bm_ckks_rotate(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        bm_env->randomize_ct_ckks(ct[0]);
        for (auto _ : state)
        {
            bm_env->evaluator()->rotate_vector(ct[0], 1, bm_env->glk(), ct[2]);
        }
    }
} // namespace sealbench
