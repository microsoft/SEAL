// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/encryptor.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/scalingvariant.h"
#include "seal/util/uintarith.h"
#include <stdexcept>

using namespace std;

namespace seal
{
    namespace util
    {
        void multiply_add_plain_with_scaling_variant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, RNSIter destination)
        {
            auto &parms = context_data.parms();
            size_t plain_coeff_count = plain.coeff_count();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            auto plain_modulus = context_data.parms().plain_modulus();
            auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
            uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
            uint64_t q_mod_t = context_data.coeff_modulus_mod_plain_modulus();
#ifdef SEAL_DEBUG
            // Verify parameters.
            if (destination.poly_modulus_degree() != parms.poly_modulus_degree())
            {
                throw invalid_argument("destination is not valid for encryption parameters");
            }
#endif
            // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
            // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
            // floor((q * m + floor((t+1) / 2)) / t).
            SEAL_ITERATE(iter(plain.data(), size_t(0)), plain_coeff_count, [&](auto I) {
                // Compute numerator = (q mod t) * m[i] + (t+1)/2
                unsigned long long prod[2]{ 0, 0 };
                uint64_t numerator[2]{ 0, 0 };
                multiply_uint64(get<0>(I), q_mod_t, prod);
                unsigned char carry = add_uint64(*prod, plain_upper_half_threshold, numerator);
                numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

                // Compute fix[0] = floor(numerator / t)
                uint64_t fix[2] = { 0, 0 };
                divide_uint128_inplace(numerator, plain_modulus.value(), fix);

                // Add to ciphertext: floor(q / t) * m + increment
                size_t coeff_index = get<1>(I);
                SEAL_ITERATE(
                    iter(destination, coeff_modulus, coeff_div_plain_modulus), coeff_modulus_size, [&](auto J) {
                        uint64_t scaled_rounded_coeff = multiply_add_uint_mod(get<0>(I), get<2>(J), fix[0], get<1>(J));
                        get<0>(J)[coeff_index] = add_uint_mod(get<0>(J)[coeff_index], scaled_rounded_coeff, get<1>(J));
                    });
            });
        }

        void multiply_sub_plain_with_scaling_variant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, RNSIter destination)
        {
            auto &parms = context_data.parms();
            size_t plain_coeff_count = plain.coeff_count();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            auto plain_modulus = context_data.parms().plain_modulus();
            auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
            uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
            uint64_t q_mod_t = context_data.coeff_modulus_mod_plain_modulus();
#ifdef SEAL_DEBUG
            // Verify parameters.
            if (destination.poly_modulus_degree() != parms.poly_modulus_degree())
            {
                throw invalid_argument("destination is not valid for encryption parameters");
            }
#endif
            // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
            // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
            // floor((q * m + floor((t+1) / 2)) / t).
            SEAL_ITERATE(iter(plain.data(), size_t(0)), plain_coeff_count, [&](auto I) {
                // Compute numerator = (q mod t) * m[i] + (t+1)/2
                unsigned long long prod[2]{ 0, 0 };
                uint64_t numerator[2]{ 0, 0 };
                multiply_uint64(get<0>(I), q_mod_t, prod);
                unsigned char carry = add_uint64(*prod, plain_upper_half_threshold, numerator);
                numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

                // Compute fix[0] = floor(numerator / t)
                uint64_t fix[2] = { 0, 0 };
                divide_uint128_inplace(numerator, plain_modulus.value(), fix);

                // Add to ciphertext: floor(q / t) * m + increment
                size_t coeff_index = get<1>(I);
                SEAL_ITERATE(
                    iter(destination, coeff_modulus, coeff_div_plain_modulus), coeff_modulus_size, [&](auto J) {
                        uint64_t scaled_rounded_coeff = multiply_add_uint_mod(get<0>(I), get<2>(J), fix[0], get<1>(J));
                        get<0>(J)[coeff_index] = sub_uint_mod(get<0>(J)[coeff_index], scaled_rounded_coeff, get<1>(J));
                    });
            });
        }
    } // namespace util
} // namespace seal
