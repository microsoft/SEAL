// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/uintcore.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/polycore.h"
#include "seal/util/polyarith.h"
#include "seal/util/polyarithmod.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void poly_infty_norm_coeffmod(const uint64_t *poly, size_t coeff_count,
            size_t coeff_uint64_count, const uint64_t *modulus, uint64_t *result,
            MemoryPool &pool)
        {
            // Construct negative threshold (first negative modulus value) to compute
            // absolute values of coeffs.
            auto modulus_neg_threshold(allocate_uint(coeff_uint64_count, pool));

            // Set to value of (modulus + 1) / 2. To prevent overflowing with the +1, just
            // add 1 to the result if modulus was odd.
            half_round_up_uint(modulus, coeff_uint64_count, modulus_neg_threshold.get());

            // Mod out the poly coefficients and choose a symmetric representative from
            // [-modulus,modulus). Keep track of the max.
            set_zero_uint(coeff_uint64_count, result);
            auto coeff_abs_value(allocate_uint(coeff_uint64_count, pool));
            for (size_t i = 0; i < coeff_count; i++, poly += coeff_uint64_count)
            {
                if (is_greater_than_or_equal_uint_uint(
                    poly, modulus_neg_threshold.get(), coeff_uint64_count))
                {
                    sub_uint_uint(modulus, poly, coeff_uint64_count, coeff_abs_value.get());
                }
                else
                {
                    set_uint_uint(poly, coeff_uint64_count, coeff_abs_value.get());
                }
                if (is_greater_than_uint_uint(coeff_abs_value.get(), result,
                    coeff_uint64_count))
                {
                    set_uint_uint(coeff_abs_value.get(), coeff_uint64_count, result);
                }
            }
        }
    }
}
