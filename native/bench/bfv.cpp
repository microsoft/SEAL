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
This file defines benchmarks for BFV-specific HE primitives.
*/

namespace sealbench
{
    void bm_bfv_encrypt_secret(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_pt_bfv(pt);
        for (auto _ : state)
        {
            bm_env->encryptor()->encrypt_symmetric(pt, ct[2]);
        }
    }

    void bm_bfv_encrypt_public(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_pt_bfv(pt);
        for (auto _ : state)
        {
            bm_env->encryptor()->encrypt(pt, ct[2]);
        }
    }

    void bm_bfv_decrypt(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_ct_bfv(ct[0]);
        for (auto _ : state)
        {
            bm_env->decryptor()->decrypt(ct[0], pt);
        }
    }

    void bm_bfv_encode_batch(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<uint64_t> &msg = bm_env->msg_uint64();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_message_uint64(msg);
        for (auto _ : state)
        {
            bm_env->batch_encoder()->encode(msg, pt);
        }
    }

    void bm_bfv_decode_batch(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<uint64_t> &msg = bm_env->msg_uint64();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_pt_bfv(pt);
        for (auto _ : state)
        {
            bm_env->batch_encoder()->decode(pt, msg);
        }
    }

    void bm_bfv_add_ct(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        bm_env->randomize_ct_bfv(ct[0]);
        bm_env->randomize_ct_bfv(ct[1]);
        Ciphertext res;
        for (auto _ : state)
        {
            bm_env->evaluator()->add(ct[0], ct[1], res);
        }
    }

    void bm_bfv_add_pt(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_ct_bfv(ct[0]);
        bm_env->randomize_pt_bfv(pt);
        for (auto _ : state)
        {
            bm_env->evaluator()->add_plain(ct[0], pt, ct[2]);
        }
    }

    void bm_bfv_mul_ct(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        bm_env->randomize_ct_bfv(ct[0]);
        bm_env->randomize_ct_bfv(ct[1]);
        for (auto _ : state)
        {
            bm_env->evaluator()->multiply(ct[0], ct[1], ct[2]);
        }
    }

    void bm_bfv_mul_pt(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        Plaintext pt = bm_env->pt()[0];
        bm_env->randomize_ct_bfv(ct[0]);
        bm_env->randomize_pt_bfv(pt);
        for (auto _ : state)
        {
            bm_env->evaluator()->multiply_plain(ct[0], pt, ct[2]);
        }
    }

    void bm_bfv_square(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        bm_env->randomize_ct_bfv(ct[0]);
        bm_env->randomize_ct_bfv(ct[1]);
        for (auto _ : state)
        {
            bm_env->evaluator()->square(ct[0], ct[2]);
        }
    }

    void bm_bfv_modswitch(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        bm_env->randomize_ct_bfv(ct[0]);
        for (auto _ : state)
        {
            bm_env->evaluator()->mod_switch_to_next(ct[0], ct[1]);
        }
    }

    void bm_bfv_relin(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        bm_env->randomize_ct_bfv(ct[0]);
        ct[0].resize(bm_env->context(), size_t(3));
        for (auto _ : state)
        {
            bm_env->evaluator()->relinearize(ct[0], bm_env->rlk(), ct[1]);
        }
    }

    void bm_bfv_rotate_rows(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        bm_env->randomize_ct_bfv(ct[0]);
        for (auto _ : state)
        {
            bm_env->evaluator()->rotate_rows(ct[0], 1, bm_env->glk(), ct[2]);
        }
    }

    void bm_bfv_rotate_cols(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> ct = bm_env->ct();
        bm_env->randomize_ct_bfv(ct[0]);
        for (auto _ : state)
        {
            bm_env->evaluator()->rotate_columns(ct[0], bm_env->glk(), ct[2]);
        }
    }
} // namespace sealbench
