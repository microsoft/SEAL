// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/randomgen.h"
#include "seal/encryptionparams.h"

namespace seal
{
    namespace util
    {
        void sample_poly_ternary(
            uint64_t *poly,
            std::shared_ptr<UniformRandomGenerator> random,
            const EncryptionParameters &parms);

        void sample_poly_normal(
                uint64_t *poly, 
                std::shared_ptr<UniformRandomGenerator> random,
                const EncryptionParameters &parms);

        void sample_poly_uniform(
                uint64_t *poly,
                std::shared_ptr<UniformRandomGenerator> random,
                const EncryptionParameters &parms);
    }
}