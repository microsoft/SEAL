// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/seal.h"
#include "bench.h"

using namespace benchmark;
using namespace sealbench;
using namespace seal;
using namespace std;

/**
This file defines benchmarks for serialization: saving and loading ciphertexts and keys under each supported
compression mode. Every case reports the serialized object size in bytes as the counter "size". Loading is
measured through the load() member functions and therefore includes the validity checks they perform.
*/

namespace sealbench
{
    namespace
    {
        template <typename T>
        void bm_serialize_save(State &state, const T &in, compr_mode_type compr_mode)
        {
            vector<seal_byte> buf(static_cast<size_t>(in.save_size(compr_mode)));
            streamoff size = 0;
            for (auto _ : state)
            {
                size = in.save(buf.data(), buf.size(), compr_mode);
            }
            state.counters["size"] = static_cast<double>(size);
        }

        template <typename T>
        void bm_serialize_load_from(State &state, const SEALContext &context, const vector<seal_byte> &buf, size_t size)
        {
            T out;
            for (auto _ : state)
            {
                out.load(context, buf.data(), size);
            }
            state.counters["size"] = static_cast<double>(size);
        }

        template <typename T>
        void bm_serialize_load(State &state, const SEALContext &context, const T &in, compr_mode_type compr_mode)
        {
            vector<seal_byte> buf(static_cast<size_t>(in.save_size(compr_mode)));
            size_t size = static_cast<size_t>(in.save(buf.data(), buf.size(), compr_mode));
            bm_serialize_load_from<T>(state, context, buf, size);
        }

        // Loading a seeded object expands the seed into the full object, so the times below include the PRNG
        // sampling that regenerates the seeded polynomials.
        template <typename T>
        void bm_serialize_load_seeded(
            State &state, const SEALContext &context, const Serializable<T> &in, compr_mode_type compr_mode)
        {
            vector<seal_byte> buf(static_cast<size_t>(in.save_size(compr_mode)));
            size_t size = static_cast<size_t>(in.save(buf.data(), buf.size(), compr_mode));
            bm_serialize_load_from<T>(state, context, buf, size);
        }

        void randomize_ct(shared_ptr<BMEnv> &bm_env, Ciphertext &ct)
        {
            switch (bm_env->parms().scheme())
            {
            case scheme_type::bfv:
                bm_env->randomize_ct_bfv(ct);
                break;
            case scheme_type::bgv:
                bm_env->randomize_ct_bgv(ct);
                break;
            case scheme_type::ckks:
                bm_env->randomize_ct_ckks(ct);
                break;
            default:
                break;
            }
        }

        void randomize_pt(shared_ptr<BMEnv> &bm_env, Plaintext &pt)
        {
            switch (bm_env->parms().scheme())
            {
            case scheme_type::bfv:
                bm_env->randomize_pt_bfv(pt);
                break;
            case scheme_type::bgv:
                bm_env->randomize_pt_bgv(pt);
                break;
            case scheme_type::ckks:
                bm_env->randomize_pt_ckks(pt);
                break;
            default:
                break;
            }
        }

        Serializable<Ciphertext> make_seeded_ct(shared_ptr<BMEnv> &bm_env)
        {
            Plaintext &pt = bm_env->pt()[0];
            randomize_pt(bm_env, pt);
            return bm_env->encryptor()->encrypt_symmetric(pt);
        }
    } // namespace

    void bm_serialize_save_ct(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        Ciphertext &ct = bm_env->ct()[0];
        randomize_ct(bm_env, ct);
        bm_serialize_save(state, ct, compr_mode);
    }

    void bm_serialize_load_ct(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        Ciphertext &ct = bm_env->ct()[0];
        randomize_ct(bm_env, ct);
        bm_serialize_load(state, bm_env->context(), ct, compr_mode);
    }

    void bm_serialize_save_pk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        bm_serialize_save(state, bm_env->pk(), compr_mode);
    }

    void bm_serialize_load_pk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        bm_serialize_load(state, bm_env->context(), bm_env->pk(), compr_mode);
    }

    void bm_serialize_save_rlk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        bm_serialize_save(state, bm_env->rlk(), compr_mode);
    }

    void bm_serialize_load_rlk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        bm_serialize_load(state, bm_env->context(), bm_env->rlk(), compr_mode);
    }

    void bm_serialize_save_glk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        bm_serialize_save(state, bm_env->glk(), compr_mode);
    }

    void bm_serialize_load_glk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        bm_serialize_load(state, bm_env->context(), bm_env->glk(), compr_mode);
    }

    void bm_serialize_save_sk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        bm_serialize_save(state, bm_env->sk(), compr_mode);
    }

    void bm_serialize_load_sk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        bm_serialize_load(state, bm_env->context(), bm_env->sk(), compr_mode);
    }

    void bm_serialize_save_seeded_ct(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        auto seeded = make_seeded_ct(bm_env);
        bm_serialize_save(state, seeded, compr_mode);
    }

    void bm_serialize_load_seeded_ct(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        auto seeded = make_seeded_ct(bm_env);
        bm_serialize_load_seeded(state, bm_env->context(), seeded, compr_mode);
    }

    void bm_serialize_save_seeded_pk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        auto seeded = bm_env->keygen()->create_public_key();
        bm_serialize_save(state, seeded, compr_mode);
    }

    void bm_serialize_load_seeded_pk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        auto seeded = bm_env->keygen()->create_public_key();
        bm_serialize_load_seeded(state, bm_env->context(), seeded, compr_mode);
    }

    void bm_serialize_save_seeded_rlk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        auto seeded = bm_env->keygen()->create_relin_keys();
        bm_serialize_save(state, seeded, compr_mode);
    }

    void bm_serialize_load_seeded_rlk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        auto seeded = bm_env->keygen()->create_relin_keys();
        bm_serialize_load_seeded(state, bm_env->context(), seeded, compr_mode);
    }

    void bm_serialize_save_seeded_glk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        auto seeded = bm_env->keygen()->create_galois_keys(bm_env->galois_elts_all());
        bm_serialize_save(state, seeded, compr_mode);
    }

    void bm_serialize_load_seeded_glk(State &state, shared_ptr<BMEnv> bm_env, compr_mode_type compr_mode)
    {
        auto seeded = bm_env->keygen()->create_galois_keys(bm_env->galois_elts_all());
        bm_serialize_load_seeded(state, bm_env->context(), seeded, compr_mode);
    }
} // namespace sealbench
