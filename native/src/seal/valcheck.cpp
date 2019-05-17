// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/valcheck.h"
#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/plaintext.h"
#include "seal/ciphertext.h"
#include "seal/secretkey.h"
#include "seal/publickey.h"
#include "seal/kswitchkeys.h"
#include "seal/relinkeys.h"
#include "seal/galoiskeys.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    bool is_metadata_valid_for(
        const Plaintext &in,
        shared_ptr<const SEALContext> context)
    {
        // Verify parameters
        if (!context || !context->parameters_set())
        {
            return false;
        }

        if (in.is_ntt_form())
        {

            // Are the parameters valid for given plaintext? This check is slightly
            // non-trivial because we need to consider both the case where key_parms_id
            // equals first_parms_id, and cases where they are different.
            auto context_data_ptr = context->get_context_data(in.parms_id());
            if (!context_data_ptr ||
                context_data_ptr->chain_index() > context->first_context_data()->chain_index())
            {
                return false;
            }

            auto &parms = context_data_ptr->parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t poly_modulus_degree = parms.poly_modulus_degree();
            if (mul_safe(coeff_modulus.size(), poly_modulus_degree) != in.coeff_count())
            {
                return false;
            }
        }
        else
        {
            auto &parms = context->first_context_data()->parms();
            if (parms.scheme() != scheme_type::BFV)
            {
                return false;
            }

            size_t poly_modulus_degree = parms.poly_modulus_degree();
            if (in.coeff_count() > poly_modulus_degree)
            {
                return false;
            }
        }

        return true;
    }

    bool is_metadata_valid_for(
        const Ciphertext &in,
        shared_ptr<const SEALContext> context)
    {
        // Verify parameters
        if (!context || !context->parameters_set())
        {
            return false;
        }

        // Are the parameters valid for given ciphertext? This check is slightly
        // non-trivial because we need to consider both the case where key_parms_id
        // equals first_parms_id, and cases where they are different.
        auto context_data_ptr = context->get_context_data(in.parms_id());
        if (!context_data_ptr ||
            context_data_ptr->chain_index() > context->first_context_data()->chain_index())
        {
            return false;
        }

        // Check that the metadata matches
        auto &coeff_modulus = context_data_ptr->parms().coeff_modulus();
        size_t poly_modulus_degree = context_data_ptr->parms().poly_modulus_degree();
        if ((coeff_modulus.size() != in.coeff_mod_count()) ||
            (poly_modulus_degree != in.poly_modulus_degree()))
        {
            return false;
        }

        // Check that size is either 0 or within right bounds
        auto size = in.size();
        if ((size < SEAL_CIPHERTEXT_SIZE_MIN && size != 0) ||
            size > SEAL_CIPHERTEXT_SIZE_MAX)
        {
            return false;
        }

        return true;
    }

    bool is_metadata_valid_for(
        const SecretKey &in,
        shared_ptr<const SEALContext> context)
    {
        // Verify parameters
        if (!context || !context->parameters_set())
        {
            return false;
        }

        // Are the parameters valid for given secret key?
        if (in.parms_id() != context->key_parms_id())
        {
            return false;
        }

        auto context_data_ptr = context->key_context_data();
        auto &parms = context_data_ptr->parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t poly_modulus_degree = parms.poly_modulus_degree();
        if (mul_safe(coeff_modulus.size(), poly_modulus_degree) != in.data().coeff_count())
        {
            return false;
        }

        return true;
    }

    bool is_metadata_valid_for(
        const PublicKey &in,
        shared_ptr<const SEALContext> context)
    {
        // Verify parameters
        if (!context || !context->parameters_set())
        {
            return false;
        }

        // Are the parameters valid for given public key?
        if (in.parms_id() != context->key_parms_id() || !in.data().is_ntt_form())
        {
            return false;
        }

        // Check that the metadata matches
        auto context_data_ptr = context->key_context_data();
        auto &coeff_modulus = context_data_ptr->parms().coeff_modulus();
        size_t poly_modulus_degree = context_data_ptr->parms().poly_modulus_degree();
        if ((coeff_modulus.size() != in.data().coeff_mod_count()) ||
            (poly_modulus_degree != in.data().poly_modulus_degree()))
        {
            return false;
        }

        // Check that size is right; for public key it should be exactly 2
        if (in.data().size() != SEAL_CIPHERTEXT_SIZE_MIN)
        {
            return false;
        }

        return true;
    }

    bool is_metadata_valid_for(
        const KSwitchKeys &in,
        shared_ptr<const SEALContext> context)
    {
        // Verify parameters
        if (!context || !context->parameters_set())
        {
            return false;
        }

        // Are the parameters valid for given relinearization keys?
        if (in.parms_id() != context->key_parms_id())
        {
            return false;
        }

        for (auto &a : in.data())
        {
            for (auto &b : a)
            {
                // Check that b is a valid public key (metadata only); this also
                // checks that its parms_id matches key_parms_id.
                if (!is_metadata_valid_for(b, context))
                {
                    return false;
                }
            }
        }

        return true;
    }

    bool is_metadata_valid_for(
        const RelinKeys &in,
        shared_ptr<const SEALContext> context)
    {
        // Check that the size is within bounds.
        bool size_check = !in.size() ||
            (in.size() <= SEAL_CIPHERTEXT_SIZE_MAX - 2 &&
                in.size() >= SEAL_CIPHERTEXT_SIZE_MIN - 2);
        return is_metadata_valid_for(
            static_cast<const KSwitchKeys &>(in), move(context)) && size_check;
    }

    bool is_metadata_valid_for(
        const GaloisKeys &in,
        shared_ptr<const SEALContext> context)
    {
        return is_metadata_valid_for(
            static_cast<const KSwitchKeys &>(in), move(context));
    }

    bool is_valid_for(
        const Plaintext &in,
        shared_ptr<const SEALContext> context)
    {
        // Check metadata
        if (!is_metadata_valid_for(in, context))
        {
            return false;
        }

        // Check the data
        if (in.is_ntt_form())
        {
            auto context_data_ptr = context->get_context_data(in.parms_id());
            auto &parms = context_data_ptr->parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();

            const Plaintext::pt_coeff_type *ptr = in.data();
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                uint64_t modulus = coeff_modulus[j].value();
                size_t poly_modulus_degree = parms.poly_modulus_degree();
                for (; poly_modulus_degree--; ptr++)
                {
                    if (*ptr >= modulus)
                    {
                        return false;
                    }
                }
            }
        }
        else
        {
            auto &parms = context->first_context_data()->parms();
            uint64_t modulus = parms.plain_modulus().value();
            const Plaintext::pt_coeff_type *ptr = in.data();
            auto size = in.coeff_count();
            for (size_t k = 0; k < size; k++, ptr++)
            {
                if (*ptr >= modulus)
                {
                    return false;
                }
            }
        }

        return true;
    }

    bool is_valid_for(
        const Ciphertext &in,
        shared_ptr<const SEALContext> context)
    {
        // Check metadata
        if (!is_metadata_valid_for(in, context))
        {
            return false;
        }

        // Check the data
        auto context_data_ptr = context->get_context_data(in.parms_id());
        const auto &coeff_modulus = context_data_ptr->parms().coeff_modulus();
        size_t coeff_mod_count = coeff_modulus.size();

        const Ciphertext::ct_coeff_type *ptr = in.data();
        auto size = in.size();

        for (size_t i = 0; i < size; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                uint64_t modulus = coeff_modulus[j].value();
                auto poly_modulus_degree = in.poly_modulus_degree();
                for (; poly_modulus_degree--; ptr++)
                {
                    if (*ptr >= modulus)
                    {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    bool is_valid_for(
        const SecretKey &in,
        shared_ptr<const SEALContext> context)
    {
        // Check metadata
        if (!is_metadata_valid_for(in, context))
        {
            return false;
        }

        // Check the data
        auto context_data_ptr = context->key_context_data();
        auto &parms = context_data_ptr->parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_mod_count = coeff_modulus.size();

        const Plaintext::pt_coeff_type *ptr = in.data().data();
        for (size_t j = 0; j < coeff_mod_count; j++)
        {
            uint64_t modulus = coeff_modulus[j].value();
            size_t poly_modulus_degree = parms.poly_modulus_degree();
            for (; poly_modulus_degree--; ptr++)
            {
                if (*ptr >= modulus)
                {
                    return false;
                }
            }
        }

        return true;
    }

    bool is_valid_for(
        const PublicKey &in,
        shared_ptr<const SEALContext> context)
    {
        // Check metadata
        if (!is_metadata_valid_for(in, context))
        {
            return false;
        }

        // Check the data
        auto context_data_ptr = context->key_context_data();
        const auto &coeff_modulus = context_data_ptr->parms().coeff_modulus();
        size_t coeff_mod_count = coeff_modulus.size();

        const Ciphertext::ct_coeff_type *ptr = in.data().data();
        auto size = in.data().size();

        for (size_t i = 0; i < size; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                uint64_t modulus = coeff_modulus[j].value();
                auto poly_modulus_degree = in.data().poly_modulus_degree();
                for (; poly_modulus_degree--; ptr++)
                {
                    if (*ptr >= modulus)
                    {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    bool is_valid_for(
        const KSwitchKeys &in,
        shared_ptr<const SEALContext> context)
    {
        // Verify parameters
        if (!context || !context->parameters_set())
        {
            return false;
        }

        // Are the parameters valid for given relinearization keys?
        if (in.parms_id() != context->key_parms_id())
        {
            return false;
        }

        for (auto &a : in.data())
        {
            for (auto &b : a)
            {
                // Check that b is a valid public key; this also checks that its
                // parms_id matches key_parms_id.
                if (!is_valid_for(b, context))
                {
                    return false;
                }
            }
        }

        return true;
    }

    bool is_valid_for(
        const RelinKeys &in,
        shared_ptr<const SEALContext> context)
    {
        return is_valid_for(static_cast<const KSwitchKeys &>(in), move(context));
    }

    bool is_valid_for(
        const GaloisKeys &in,
        shared_ptr<const SEALContext> context)
    {
        return is_valid_for(static_cast<const KSwitchKeys &>(in), move(context));
    }
}