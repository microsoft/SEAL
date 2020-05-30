// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/encryptor.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/scalingvariant.h"
#include "seal/util/uintarith.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void multiply_add_plain_with_scaling_variant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, uint64_t *destination)
        {
            auto &parms = context_data.parms();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t plain_coeff_count = plain.coeff_count();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            auto plain_modulus = context_data.parms().plain_modulus();
            auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
            uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
            uint64_t q_mod_t = context_data.coeff_modulus_mod_plain_modulus();

            // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
            // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
            // floor((q * m + floor((t+1) / 2)) / t).
            for (size_t i = 0; i < plain_coeff_count; i++, destination++)
            {
                // Compute numerator = (q mod t) * m[i] + (t+1)/2
                unsigned long long prod[2]{ 0, 0 };
                uint64_t numerator[2]{ 0, 0 };
                multiply_uint64(plain.data()[i], q_mod_t, prod);
                unsigned char carry = add_uint64(*prod, plain_upper_half_threshold, numerator);
                numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

                // Compute fix[0] = floor(numerator / t)
                uint64_t fix[2] = { 0, 0 };
                divide_uint128_inplace(numerator, plain_modulus.value(), fix);

                // Add to ciphertext: floor(q / t) * m + increment
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    destination[j * coeff_count] = add_uint64_mod(
                        multiply_add_uint_mod(coeff_div_plain_modulus[j], plain.data()[i], fix[0], coeff_modulus[j]),
                        destination[j * coeff_count], coeff_modulus[j]);
                }
            }
        }

        void multiply_sub_plain_with_scaling_variant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, uint64_t *destination)
        {
            auto &parms = context_data.parms();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t plain_coeff_count = plain.coeff_count();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            auto plain_modulus = context_data.parms().plain_modulus();
            auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
            uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
            uint64_t q_mod_t = context_data.coeff_modulus_mod_plain_modulus();

            // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
            // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
            // floor((q * m + floor((t+1) / 2)) / t).
            for (size_t i = 0; i < plain_coeff_count; i++, destination++)
            {
                // Compute numerator = (q mod t) * m[i] + (t+1)/2
                unsigned long long prod[2]{ 0, 0 };
                uint64_t numerator[2]{ 0, 0 };
                multiply_uint64(plain[i], q_mod_t, prod);
                unsigned char carry = add_uint64(*prod, plain_upper_half_threshold, numerator);
                numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

                // Compute fix[0] = floor(numerator / t)
                uint64_t fix[2] = { 0, 0 };
                divide_uint128_inplace(numerator, plain_modulus.value(), fix);

                // Add to ciphertext: floor(q / t) * m + increment
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    destination[j * coeff_count] = sub_uint64_mod(
                        destination[j * coeff_count],
                        multiply_add_uint_mod(coeff_div_plain_modulus[j], plain.data()[i], fix[0], coeff_modulus[j]),
                        coeff_modulus[j]);
                }
            }
        }
    } // namespace util
} // namespace seal
