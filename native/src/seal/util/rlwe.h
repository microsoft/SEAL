// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include "seal/randomgen.h"
#include "seal/encryptionparams.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/publickey.h"
#include "seal/ciphertext.h"
#include "seal/context.h"

namespace seal
{
    namespace util
    {
        void sample_poly_ternary(
            std::uint64_t *poly,
            std::shared_ptr<UniformRandomGenerator> random,
            const EncryptionParameters &parms);

        void sample_poly_normal(
            std::uint64_t *poly,
            std::shared_ptr<UniformRandomGenerator> random,
            const EncryptionParameters &parms);

        void sample_poly_uniform(
            std::uint64_t *poly,
            std::shared_ptr<UniformRandomGenerator> random,
            const EncryptionParameters &parms);

        void encrypt_zero_asymmetric(
            const PublicKey &public_key,
            std::shared_ptr<SEALContext> context,
            parms_id_type parms_id,
            std::shared_ptr<UniformRandomGenerator> random,
            bool is_ntt_form,
            Ciphertext &destination,
            MemoryPoolHandle pool);

        void encrypt_zero_symmetric(
            const SecretKey &secret_key,
            std::shared_ptr<SEALContext> context,
            parms_id_type parms_id,
            std::shared_ptr<UniformRandomGenerator> random,
            bool is_ntt_form,
            Ciphertext &destination,
            MemoryPoolHandle pool);
        
        void multiply_plain_with_scaling_variant(
            const std::uint64_t *plain, std::size_t plain_coeff_count,
            const SEALContext::ContextData &context_data, std::uint64_t *destination);
        
        void divide_plain_by_scaling_variant(std::uint64_t *plain,
            const SEALContext::ContextData &context_data, std::uint64_t *destination,
            MemoryPoolHandle pool);
    }
}