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

    /**
    Warm up the major SEAL kernels for a given BMEnv before timed benchmarks run.
    This primes the instruction cache, the SEAL memory pool, and the page tables, so that the first
    timed benchmark batch is no longer 2-6x slower than subsequent batches on cold systems.
    See https://github.com/microsoft/SEAL/issues/625.
    */
    void warmup_family(unordered_map<EncryptionParameters, shared_ptr<BMEnv>> &bm_env_map)
    {
        for (auto &kv : bm_env_map)
        {
            const auto &parms = kv.first;
            auto bm_env = kv.second;
            auto encryptor = bm_env->encryptor();
            auto decryptor = bm_env->decryptor();
            auto evaluator = bm_env->evaluator();
            const auto &context = bm_env->context();

            Plaintext pt;
            Ciphertext ct_a, ct_b, ct_dest;

            switch (parms.scheme())
            {
            case scheme_type::bfv:
            {
                bm_env->randomize_pt_bfv(pt);
                encryptor->encrypt(pt, ct_a);
                encryptor->encrypt(pt, ct_b);
                Plaintext pt_out;
                decryptor->decrypt(ct_a, pt_out);
                evaluator->add(ct_a, ct_b, ct_dest);
                evaluator->multiply(ct_a, ct_b, ct_dest);
                if (context.using_keyswitching())
                {
                    evaluator->relinearize_inplace(ct_dest, bm_env->rlk());
                }
                break;
            }
            case scheme_type::bgv:
            {
                bm_env->randomize_pt_bgv(pt);
                encryptor->encrypt(pt, ct_a);
                encryptor->encrypt(pt, ct_b);
                Plaintext pt_out;
                decryptor->decrypt(ct_a, pt_out);
                evaluator->add(ct_a, ct_b, ct_dest);
                evaluator->multiply(ct_a, ct_b, ct_dest);
                if (context.using_keyswitching())
                {
                    evaluator->relinearize_inplace(ct_dest, bm_env->rlk());
                }
                break;
            }
            case scheme_type::ckks:
            {
                vector<double> msg;
                bm_env->randomize_message_double(msg);
                bm_env->ckks_encoder()->encode(msg, bm_env->safe_scale(), pt);
                encryptor->encrypt(pt, ct_a);
                encryptor->encrypt(pt, ct_b);
                Plaintext pt_out;
                decryptor->decrypt(ct_a, pt_out);
                evaluator->add(ct_a, ct_b, ct_dest);
                evaluator->multiply(ct_a, ct_b, ct_dest);
                if (context.using_keyswitching())
                {
                    evaluator->relinearize_inplace(ct_dest, bm_env->rlk());
                }
                break;
            }
            default:
                break;
            }
        }
    }

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
        // 6. Serialize
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

        // Serialization cases save and load a ciphertext (per scheme) and the keys under each supported
        // compression mode, reporting the serialized size in bytes as the counter "size". Keys have the same
        // size and content shape in every scheme, so they are registered once, under the BFV environment. Note
        // that the Galois keys here contain two elements; full rotation key sets scale the numbers linearly.
#define SEAL_BENCHMARK_REGISTER_SERIALIZE(name, func, env, mode) \
    SEAL_BENCHMARK_REGISTER(SERIALIZE, n, log_q, name, func, env, seal::compr_mode_type::mode)

        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextBFVNone, bm_serialize_save_ct, bm_env_bfv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextBFVNone, bm_serialize_load_ct, bm_env_bfv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextBGVNone, bm_serialize_save_ct, bm_env_bgv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextBGVNone, bm_serialize_load_ct, bm_env_bgv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextCKKSNone, bm_serialize_save_ct, bm_env_ckks, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextCKKSNone, bm_serialize_load_ct, bm_env_ckks, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SavePublicKeyNone, bm_serialize_save_pk, bm_env_bfv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadPublicKeyNone, bm_serialize_load_pk, bm_env_bfv, none);
#ifdef SEAL_USE_ZLIB
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextBFVZlib, bm_serialize_save_ct, bm_env_bfv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextBFVZlib, bm_serialize_load_ct, bm_env_bfv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextBGVZlib, bm_serialize_save_ct, bm_env_bgv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextBGVZlib, bm_serialize_load_ct, bm_env_bgv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextCKKSZlib, bm_serialize_save_ct, bm_env_ckks, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextCKKSZlib, bm_serialize_load_ct, bm_env_ckks, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SavePublicKeyZlib, bm_serialize_save_pk, bm_env_bfv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadPublicKeyZlib, bm_serialize_load_pk, bm_env_bfv, zlib);
#endif
#ifdef SEAL_USE_ZSTD
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextBFVZstd, bm_serialize_save_ct, bm_env_bfv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextBFVZstd, bm_serialize_load_ct, bm_env_bfv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextBGVZstd, bm_serialize_save_ct, bm_env_bgv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextBGVZstd, bm_serialize_load_ct, bm_env_bgv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextCKKSZstd, bm_serialize_save_ct, bm_env_ckks, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextCKKSZstd, bm_serialize_load_ct, bm_env_ckks, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SavePublicKeyZstd, bm_serialize_save_pk, bm_env_bfv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadPublicKeyZstd, bm_serialize_load_pk, bm_env_bfv, zstd);
#endif
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextBFVBitPack, bm_serialize_save_ct, bm_env_bfv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextBFVBitPack, bm_serialize_load_ct, bm_env_bfv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextBGVBitPack, bm_serialize_save_ct, bm_env_bgv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextBGVBitPack, bm_serialize_load_ct, bm_env_bgv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveCiphertextCKKSBitPack, bm_serialize_save_ct, bm_env_ckks, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadCiphertextCKKSBitPack, bm_serialize_load_ct, bm_env_ckks, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SavePublicKeyBitPack, bm_serialize_save_pk, bm_env_bfv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadPublicKeyBitPack, bm_serialize_load_pk, bm_env_bfv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSecretKeyNone, bm_serialize_save_sk, bm_env_bfv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSecretKeyNone, bm_serialize_load_sk, bm_env_bfv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededCiphertextBFVNone, bm_serialize_save_seeded_ct, bm_env_bfv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededCiphertextBFVNone, bm_serialize_load_seeded_ct, bm_env_bfv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededCiphertextBGVNone, bm_serialize_save_seeded_ct, bm_env_bgv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededCiphertextBGVNone, bm_serialize_load_seeded_ct, bm_env_bgv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededCiphertextCKKSNone, bm_serialize_save_seeded_ct, bm_env_ckks, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededCiphertextCKKSNone, bm_serialize_load_seeded_ct, bm_env_ckks, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededPublicKeyNone, bm_serialize_save_seeded_pk, bm_env_bfv, none);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededPublicKeyNone, bm_serialize_load_seeded_pk, bm_env_bfv, none);
#ifdef SEAL_USE_ZLIB
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSecretKeyZlib, bm_serialize_save_sk, bm_env_bfv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSecretKeyZlib, bm_serialize_load_sk, bm_env_bfv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededCiphertextBFVZlib, bm_serialize_save_seeded_ct, bm_env_bfv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededCiphertextBFVZlib, bm_serialize_load_seeded_ct, bm_env_bfv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededCiphertextBGVZlib, bm_serialize_save_seeded_ct, bm_env_bgv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededCiphertextBGVZlib, bm_serialize_load_seeded_ct, bm_env_bgv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededCiphertextCKKSZlib, bm_serialize_save_seeded_ct, bm_env_ckks, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededCiphertextCKKSZlib, bm_serialize_load_seeded_ct, bm_env_ckks, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededPublicKeyZlib, bm_serialize_save_seeded_pk, bm_env_bfv, zlib);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededPublicKeyZlib, bm_serialize_load_seeded_pk, bm_env_bfv, zlib);
#endif
#ifdef SEAL_USE_ZSTD
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSecretKeyZstd, bm_serialize_save_sk, bm_env_bfv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSecretKeyZstd, bm_serialize_load_sk, bm_env_bfv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededCiphertextBFVZstd, bm_serialize_save_seeded_ct, bm_env_bfv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededCiphertextBFVZstd, bm_serialize_load_seeded_ct, bm_env_bfv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededCiphertextBGVZstd, bm_serialize_save_seeded_ct, bm_env_bgv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededCiphertextBGVZstd, bm_serialize_load_seeded_ct, bm_env_bgv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededCiphertextCKKSZstd, bm_serialize_save_seeded_ct, bm_env_ckks, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededCiphertextCKKSZstd, bm_serialize_load_seeded_ct, bm_env_ckks, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededPublicKeyZstd, bm_serialize_save_seeded_pk, bm_env_bfv, zstd);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededPublicKeyZstd, bm_serialize_load_seeded_pk, bm_env_bfv, zstd);
#endif
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSecretKeyBitPack, bm_serialize_save_sk, bm_env_bfv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSecretKeyBitPack, bm_serialize_load_sk, bm_env_bfv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(
            SaveSeededCiphertextBFVBitPack, bm_serialize_save_seeded_ct, bm_env_bfv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(
            LoadSeededCiphertextBFVBitPack, bm_serialize_load_seeded_ct, bm_env_bfv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(
            SaveSeededCiphertextBGVBitPack, bm_serialize_save_seeded_ct, bm_env_bgv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(
            LoadSeededCiphertextBGVBitPack, bm_serialize_load_seeded_ct, bm_env_bgv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(
            SaveSeededCiphertextCKKSBitPack, bm_serialize_save_seeded_ct, bm_env_ckks, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(
            LoadSeededCiphertextCKKSBitPack, bm_serialize_load_seeded_ct, bm_env_ckks, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededPublicKeyBitPack, bm_serialize_save_seeded_pk, bm_env_bfv, bitpack);
        SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededPublicKeyBitPack, bm_serialize_load_seeded_pk, bm_env_bfv, bitpack);
        if (bm_env_bfv->context().using_keyswitching())
        {
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveRelinKeysNone, bm_serialize_save_rlk, bm_env_bfv, none);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadRelinKeysNone, bm_serialize_load_rlk, bm_env_bfv, none);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveGaloisKeysNone, bm_serialize_save_glk, bm_env_bfv, none);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadGaloisKeysNone, bm_serialize_load_glk, bm_env_bfv, none);
#ifdef SEAL_USE_ZLIB
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveRelinKeysZlib, bm_serialize_save_rlk, bm_env_bfv, zlib);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadRelinKeysZlib, bm_serialize_load_rlk, bm_env_bfv, zlib);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveGaloisKeysZlib, bm_serialize_save_glk, bm_env_bfv, zlib);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadGaloisKeysZlib, bm_serialize_load_glk, bm_env_bfv, zlib);
#endif
#ifdef SEAL_USE_ZSTD
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveRelinKeysZstd, bm_serialize_save_rlk, bm_env_bfv, zstd);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadRelinKeysZstd, bm_serialize_load_rlk, bm_env_bfv, zstd);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveGaloisKeysZstd, bm_serialize_save_glk, bm_env_bfv, zstd);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadGaloisKeysZstd, bm_serialize_load_glk, bm_env_bfv, zstd);
#endif
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveRelinKeysBitPack, bm_serialize_save_rlk, bm_env_bfv, bitpack);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadRelinKeysBitPack, bm_serialize_load_rlk, bm_env_bfv, bitpack);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveGaloisKeysBitPack, bm_serialize_save_glk, bm_env_bfv, bitpack);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadGaloisKeysBitPack, bm_serialize_load_glk, bm_env_bfv, bitpack);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededRelinKeysNone, bm_serialize_save_seeded_rlk, bm_env_bfv, none);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededRelinKeysNone, bm_serialize_load_seeded_rlk, bm_env_bfv, none);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededGaloisKeysNone, bm_serialize_save_seeded_glk, bm_env_bfv, none);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededGaloisKeysNone, bm_serialize_load_seeded_glk, bm_env_bfv, none);
#ifdef SEAL_USE_ZLIB
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededRelinKeysZlib, bm_serialize_save_seeded_rlk, bm_env_bfv, zlib);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededRelinKeysZlib, bm_serialize_load_seeded_rlk, bm_env_bfv, zlib);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededGaloisKeysZlib, bm_serialize_save_seeded_glk, bm_env_bfv, zlib);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededGaloisKeysZlib, bm_serialize_load_seeded_glk, bm_env_bfv, zlib);
#endif
#ifdef SEAL_USE_ZSTD
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededRelinKeysZstd, bm_serialize_save_seeded_rlk, bm_env_bfv, zstd);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededRelinKeysZstd, bm_serialize_load_seeded_rlk, bm_env_bfv, zstd);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(SaveSeededGaloisKeysZstd, bm_serialize_save_seeded_glk, bm_env_bfv, zstd);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(LoadSeededGaloisKeysZstd, bm_serialize_load_seeded_glk, bm_env_bfv, zstd);
#endif
            SEAL_BENCHMARK_REGISTER_SERIALIZE(
                SaveSeededRelinKeysBitPack, bm_serialize_save_seeded_rlk, bm_env_bfv, bitpack);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(
                LoadSeededRelinKeysBitPack, bm_serialize_load_seeded_rlk, bm_env_bfv, bitpack);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(
                SaveSeededGaloisKeysBitPack, bm_serialize_save_seeded_glk, bm_env_bfv, bitpack);
            SEAL_BENCHMARK_REGISTER_SERIALIZE(
                LoadSeededGaloisKeysBitPack, bm_serialize_load_seeded_glk, bm_env_bfv, bitpack);
        }
#undef SEAL_BENCHMARK_REGISTER_SERIALIZE
    }

} // namespace sealbench

int main(int argc, char **argv)
{
    // Scan for the --no-warmup flag and strip it from argv before handing the
    // remaining arguments to google-benchmark, which would otherwise warn about
    // an unknown flag. Disabling warmup is useful when measuring cold-start cost.
    bool run_warmup = true;
    for (int i = 1; i < argc; i++)
    {
        if (string(argv[i]) == "--no-warmup")
        {
            run_warmup = false;
            for (int j = i; j < argc - 1; j++)
            {
                argv[j] = argv[j + 1];
            }
            argv[argc - 1] = nullptr;
            argc--;
            i--;
        }
    }

    Initialize(&argc, argv);
    benchmark::AddCustomContext("Warmup", run_warmup ? "enabled" : "disabled");

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

    // Exercise the main SEAL kernels once before the timed cases run, so that the first batch is
    // not penalized by cold-start costs (instruction cache misses, first-touch page faults, and an
    // empty SEAL memory pool) relative to subsequent batches. Skip this with --no-warmup to
    // measure the cold-start path instead.
    if (run_warmup)
    {
        cout << "Running warmup pass (disable with `--no-warmup`) ..." << endl;
        sealbench::warmup_family(bm_env_map);
    }

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
