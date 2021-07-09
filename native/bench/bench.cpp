// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/seal.h"
#include "bench.h"
#include <iomanip>

using namespace benchmark;
using namespace seal;
using namespace sealbench;
using namespace std;

namespace sealbench
{
    /**
    Wraps benchmark::RegisterBenchmark to use microsecond and accepts std::string name.
    Each benchmark runs for 10 rather than a dynamically chosen amount of iterations.
    If more runs are needed for more accurate measurements, either remove line 26, or run benchmarks in repetition.
    */
#define SEAL_BENCHMARK_REGISTER(category, n, log_q, name, func, ...)                                                  \
    RegisterBenchmark(                                                                                                \
        (string("n=") + to_string(n) + string(" / log(q)=") + to_string(log_q) + string(" / " #category " / " #name)) \
            .c_str(),                                                                                                 \
        [=](State &st) { func(st, __VA_ARGS__); })                                                                    \
        ->Unit(benchmark::kMicrosecond)                                                                               \
        ->Iterations(10);

    void register_bm_family(
        const pair<size_t, vector<Modulus>> &parms, unordered_map<EncryptionParameters, shared_ptr<BMEnv>> &bm_env_map)
    {
        // For BFV benchmark cases (default to 20-bit plain_modulus)
        EncryptionParameters parms_bfv(scheme_type::bfv);
        parms_bfv.set_poly_modulus_degree(parms.first);
        parms_bfv.set_coeff_modulus(parms.second);
        parms_bfv.set_plain_modulus(PlainModulus::Batching(parms.first, 20));
        shared_ptr<BMEnv> bm_env_bfv = bm_env_map.find(parms_bfv)->second;

        // For BGV benchmark cases (default to 20-bit plain_modulus)
        EncryptionParameters parms_bgv(scheme_type::bgv);
        parms_bgv.set_poly_modulus_degree(parms.first);
        parms_bgv.set_coeff_modulus(parms.second);
        parms_bgv.set_plain_modulus(PlainModulus::Batching(parms.first, 20));
        shared_ptr<BMEnv> bm_env_bgv = bm_env_map.find(parms_bgv)->second;

        // For CKKS / KeyGen / Util benchmark cases
        EncryptionParameters parms_ckks(scheme_type::ckks);
        parms_ckks.set_poly_modulus_degree(parms.first);
        parms_ckks.set_coeff_modulus(parms.second);
        shared_ptr<BMEnv> bm_env_ckks = bm_env_map.find(parms_ckks)->second;

        // Registration / display order:
        // 1. KeyGen
        // 2. BFV
        // 3. BGV
        // 4. CKKS
        // 5. Util
        int n = static_cast<int>(parms.first);
        int log_q = static_cast<int>(
            bm_env_map.find(parms_ckks)->second->context().key_context_data()->total_coeff_modulus_bit_count());
        SEAL_BENCHMARK_REGISTER(KeyGen, n, log_q, Secret, bm_keygen_secret, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(KeyGen, n, log_q, Public, bm_keygen_public, bm_env_bfv);
        if (bm_env_bfv->context().using_keyswitching())
        {
            SEAL_BENCHMARK_REGISTER(KeyGen, n, log_q, Relin, bm_keygen_relin, bm_env_bfv);
            SEAL_BENCHMARK_REGISTER(KeyGen, n, log_q, Galois, bm_keygen_galois, bm_env_bfv);
        }

        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EncryptSecret, bm_bfv_encrypt_secret, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EncryptPublic, bm_bfv_encrypt_public, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, Decrypt, bm_bfv_decrypt, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EncodeBatch, bm_bfv_encode_batch, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, DecodeBatch, bm_bfv_decode_batch, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateAddCt, bm_bfv_add_ct, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateAddPt, bm_bfv_add_pt, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateNegate, bm_bfv_negate, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateSubCt, bm_bfv_sub_ct, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateSubPt, bm_bfv_sub_pt, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateMulCt, bm_bfv_mul_ct, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateMulPt, bm_bfv_mul_pt, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateSquare, bm_bfv_square, bm_env_bfv);
        if (bm_env_bfv->context().first_context_data()->parms().coeff_modulus().size() > 1)
        {
            SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateModSwitchInplace, bm_bfv_modswitch_inplace, bm_env_bfv);
        }
        if (bm_env_bfv->context().using_keyswitching())
        {
            SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateRelinInplace, bm_bfv_relin_inplace, bm_env_bfv);
            SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateRotateRows, bm_bfv_rotate_rows, bm_env_bfv);
            SEAL_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateRotateCols, bm_bfv_rotate_cols, bm_env_bfv);
        }

        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EncryptSecret, bm_bgv_encrypt_secret, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EncryptPublic, bm_bgv_encrypt_public, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, Decrypt, bm_bgv_decrypt, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EncodeBatch, bm_bgv_encode_batch, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, DecodeBatch, bm_bgv_decode_batch, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateNegate, bm_bgv_negate, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateNegateInplace, bm_bgv_negate_inplace, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateAddCt, bm_bgv_add_ct, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateAddCtInplace, bm_bgv_add_ct_inplace, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateAddPt, bm_bgv_add_pt, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateAddPtInplace, bm_bgv_add_pt_inplace, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateMulCt, bm_bgv_mul_ct, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateMulCtInplace, bm_bgv_mul_ct_inplace, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateMulPt, bm_bgv_mul_pt, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateMulPtInplace, bm_bgv_mul_pt_inplace, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateSquare, bm_bgv_square, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateSquareInplace, bm_bgv_square_inplace, bm_env_bgv);
        if (bm_env_bgv->context().first_context_data()->parms().coeff_modulus().size() > 1)
        {
            SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateModSwitchInplace, bm_bgv_modswitch_inplace, bm_env_bgv);
        }
        if (bm_env_bgv->context().using_keyswitching())
        {
            SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateRelinInplace, bm_bgv_relin_inplace, bm_env_bgv);
            SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateRotateRows, bm_bgv_rotate_rows, bm_env_bgv);
            SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateRotateRowsInplace, bm_bgv_rotate_rows_inplace, bm_env_bgv);
            SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateRotateCols, bm_bgv_rotate_cols, bm_env_bgv);
            SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateRotateColsInplace, bm_bgv_rotate_cols_inplace, bm_env_bgv);
        }
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateToNTTInplace, bm_bgv_to_ntt_inplace, bm_env_bgv);
        SEAL_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateFromNTTInplace, bm_bgv_from_ntt_inplace, bm_env_bgv);

        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EncryptSecret, bm_ckks_encrypt_secret, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EncryptPublic, bm_ckks_encrypt_public, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, Decrypt, bm_ckks_decrypt, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EncodeDouble, bm_ckks_encode_double, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, DecodeDouble, bm_ckks_decode_double, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateAddCt, bm_ckks_add_ct, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateAddPt, bm_ckks_add_pt, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateNegate, bm_ckks_negate, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateSubCt, bm_ckks_sub_ct, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateSubPt, bm_ckks_sub_pt, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateMulCt, bm_ckks_mul_ct, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateMulPt, bm_ckks_mul_pt, bm_env_ckks);
        SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateSquare, bm_ckks_square, bm_env_ckks);
        if (bm_env_ckks->context().first_context_data()->parms().coeff_modulus().size() > 1)
        {
            SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateRescaleInplace, bm_ckks_rescale_inplace, bm_env_ckks);
        }
        if (bm_env_ckks->context().using_keyswitching())
        {
            SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateRelinInplace, bm_ckks_relin_inplace, bm_env_ckks);
            SEAL_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateRotate, bm_ckks_rotate, bm_env_ckks);
        }
        SEAL_BENCHMARK_REGISTER(UTIL, n, log_q, NTTForward, bm_util_ntt_forward, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(UTIL, n, log_q, NTTInverse, bm_util_ntt_inverse, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(UTIL, n, 0, NTTForwardLowLevel, bm_util_ntt_forward_low_level, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(UTIL, n, 0, NTTInverseLowLevel, bm_util_ntt_inverse_low_level, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(UTIL, n, 0, NTTForwardLowLevelLazy, bm_util_ntt_forward_low_level_lazy, bm_env_bfv);
        SEAL_BENCHMARK_REGISTER(UTIL, n, 0, NTTInverseLowLevelLazy, bm_util_ntt_inverse_low_level_lazy, bm_env_bfv);
    }

} // namespace sealbench

int main(int argc, char **argv)
{
    Initialize(&argc, argv);

    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
    cout << "Running precomputations ..." << endl;

    vector<pair<size_t, vector<Modulus>>> bm_parms_vec;
    unordered_map<EncryptionParameters, shared_ptr<BMEnv>> bm_env_map;

    // Initialize bm_parms_vec with BFV default paramaters with 128-bit security.
    // Advanced users may replace this section with custom parameters.
    // SEAL benchmarks allow insecure parameters for experimental purposes.
    // DO NOT USE SEAL BENCHMARKS AS EXAMPLES.
    auto default_parms = seal::util::global_variables::GetDefaultCoeffModulus128();
    for (auto &i : default_parms)
    {
        bm_parms_vec.emplace_back(i);
    }

    // Initialize bm_env_map with bm_parms_vec each of which creates EncryptionParameters for BFV, BGV and CKKS,
    // respectively.
    for (auto &i : default_parms)
    {
        EncryptionParameters parms_bfv(scheme_type::bfv);
        parms_bfv.set_poly_modulus_degree(i.first);
        parms_bfv.set_coeff_modulus(i.second);
        parms_bfv.set_plain_modulus(PlainModulus::Batching(i.first, 20));
        EncryptionParameters parms_bgv(scheme_type::bgv);
        parms_bgv.set_poly_modulus_degree(i.first);
        parms_bgv.set_coeff_modulus(i.second);
        parms_bgv.set_plain_modulus(PlainModulus::Batching(i.first, 20));
        EncryptionParameters parms_ckks(scheme_type::ckks);
        parms_ckks.set_poly_modulus_degree(i.first);
        parms_ckks.set_coeff_modulus(i.second);

        if (bm_env_map.emplace(make_pair(parms_bfv, make_shared<BMEnv>(parms_bfv))).second == false)
        {
            throw invalid_argument("duplicate parameter sets");
        }
        if (bm_env_map.emplace(make_pair(parms_bgv, make_shared<BMEnv>(parms_bgv))).second == false)
        {
            throw invalid_argument("duplicate parameter sets");
        }
        if (bm_env_map.emplace(make_pair(parms_ckks, make_shared<BMEnv>(parms_ckks))).second == false)
        {
            throw invalid_argument("duplicate parameter sets");
        }
    }

    // Now that precomputation have taken place, here is the total memory consumption by SEAL memory pool.
    cout << "[" << setw(7) << right << (seal::MemoryManager::GetPool().alloc_byte_count() >> 20) << " MB] "
         << "Total allocation from the memory pool" << endl;

    // For each parameter set in bm_parms_vec, register a family of benchmark cases.
    for (auto &i : bm_parms_vec)
    {
        sealbench::register_bm_family(i, bm_env_map);
    }

    RunSpecifiedBenchmarks();

    // After running all benchmark cases, we print again the total memory consumption by SEAL memory pool.
    // This value should be larger than the previous amount but not by much.
    cout << "[" << setw(7) << right << (seal::MemoryManager::GetPool().alloc_byte_count() >> 20) << " MB] "
         << "Total allocation from the memory pool" << endl;
}
