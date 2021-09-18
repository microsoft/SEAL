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
This file defines benchmarks for NTT-related HE primitives.
*/

namespace sealbench
{
    void bm_util_ntt_forward(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_bfv(ct[0]);

            state.ResumeTiming();
            bm_env->evaluator()->transform_to_ntt(ct[0], ct[2]);
        }
    }

    void bm_util_ntt_inverse(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_bfv(ct[0]);
            bm_env->evaluator()->transform_to_ntt_inplace(ct[0]);

            state.ResumeTiming();
            bm_env->evaluator()->transform_from_ntt(ct[0], ct[2]);
        }
    }

    void bm_util_ntt_forward_low_level(State &state, shared_ptr<BMEnv> bm_env)
    {
        parms_id_type parms_id = bm_env->context().first_parms_id();
        auto context_data = bm_env->context().get_context_data(parms_id);
        const auto &small_ntt_tables = context_data->small_ntt_tables();
        vector<Ciphertext> &ct = bm_env->ct();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_bfv(ct[0]);

            state.ResumeTiming();
            ntt_negacyclic_harvey(ct[0].data(), small_ntt_tables[0]);
        }
    }

    void bm_util_ntt_inverse_low_level(State &state, shared_ptr<BMEnv> bm_env)
    {
        parms_id_type parms_id = bm_env->context().first_parms_id();
        auto context_data = bm_env->context().get_context_data(parms_id);
        const auto &small_ntt_tables = context_data->small_ntt_tables();
        vector<Ciphertext> &ct = bm_env->ct();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_bfv(ct[0]);

            state.ResumeTiming();
            inverse_ntt_negacyclic_harvey(ct[0].data(), small_ntt_tables[0]);
        }
    }

    void bm_util_ntt_forward_low_level_lazy(State &state, shared_ptr<BMEnv> bm_env)
    {
        parms_id_type parms_id = bm_env->context().first_parms_id();
        auto context_data = bm_env->context().get_context_data(parms_id);
        const auto &small_ntt_tables = context_data->small_ntt_tables();
        vector<Ciphertext> &ct = bm_env->ct();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_bfv(ct[0]);

            state.ResumeTiming();
            ntt_negacyclic_harvey_lazy(ct[0].data(), small_ntt_tables[0]);
        }
    }

    void bm_util_ntt_inverse_low_level_lazy(State &state, shared_ptr<BMEnv> bm_env)
    {
        parms_id_type parms_id = bm_env->context().first_parms_id();
        auto context_data = bm_env->context().get_context_data(parms_id);
        const auto &small_ntt_tables = context_data->small_ntt_tables();
        vector<Ciphertext> &ct = bm_env->ct();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_bfv(ct[0]);

            state.ResumeTiming();
            inverse_ntt_negacyclic_harvey_lazy(ct[0].data(), small_ntt_tables[0]);
        }
    }
} // namespace sealbench
