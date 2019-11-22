// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/scalingvariant.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarith.h"
#include "seal/encryptor.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void multiply_add_plain_with_scaling_variant(
            const Plaintext &plain,
            const SEALContext::ContextData &context_data,
            uint64_t *destination)
        {
            auto &parms = context_data.parms();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t plain_coeff_count = plain.coeff_count();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            auto plain_modulus = context_data.parms().plain_modulus();
            auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
            uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
            uint64_t q_mod_t = context_data.coeff_mod_plain_modulus();

            // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
            // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
            // floor((q * m + floor((t+1) / 2)) / t).
            for (size_t i = 0; i < plain_coeff_count; i++, destination++)
            {
                // compute numerator = (q mod t) * m[i] + (t+1)/2
                unsigned long long prod[2] { 0, 0 };
                uint64_t numerator[2] { 0, 0 };
                multiply_uint64(plain.data()[i], q_mod_t, prod);
                unsigned char carry = add_uint64(*prod, plain_upper_half_threshold, numerator);
                numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);
                // compute fix[0] = floor( numerator / t )
                uint64_t fix[2] = { 0, 0 };
                divide_uint128_uint64_inplace(numerator, plain_modulus.value(), fix);

                // Add to ciphertext: floor(q / t) * m + increment
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    unsigned long long temp[2] { 0, 0 };
                    multiply_uint64(coeff_div_plain_modulus[j], plain.data()[i], temp);
                    temp[1] += static_cast<unsigned long long>(add_uint64(*temp, fix[0], 0, temp));
                    uint64_t scaled_plain_coeff = barrett_reduce_128(temp, coeff_modulus[j]);
                    destination[j * coeff_count] = add_uint_uint_mod(
                        destination[j * coeff_count], scaled_plain_coeff, coeff_modulus[j]);
                }
            }
        }

        void multiply_sub_plain_with_scaling_variant(
            const Plaintext &plain,
            const SEALContext::ContextData &context_data,
            uint64_t *destination)
        {
            auto &parms = context_data.parms();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t plain_coeff_count = plain.coeff_count();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            auto plain_modulus = context_data.parms().plain_modulus();
            auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
            uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
            uint64_t q_mod_t = context_data.coeff_mod_plain_modulus();

            // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
            // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
            // floor((q * m + floor((t+1) / 2)) / t).
            for (size_t i = 0; i < plain_coeff_count; i++, destination++)
            {
                // compute numerator = (q mod t) * m[i] + (t+1)/2
                unsigned long long prod[2] { 0, 0 };
                uint64_t numerator[2] { 0, 0 };
                multiply_uint64(plain[i], q_mod_t, prod);
                unsigned char carry = add_uint64(*prod, plain_upper_half_threshold, numerator);
                numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);
                // compute fix[0] = floor( numerator / t )
                uint64_t fix[2] = { 0, 0 };
                divide_uint128_uint64_inplace(numerator, plain_modulus.value(), fix);

                // Add to ciphertext: floor(q / t) * m + increment
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    unsigned long long temp[2] { 0, 0 };
                    multiply_uint64(coeff_div_plain_modulus[j], plain[i], temp);
                    temp[1] += static_cast<unsigned long long>(add_uint64(*temp, fix[0], 0, temp));
                    uint64_t scaled_plain_coeff = barrett_reduce_128(temp, coeff_modulus[j]);
                    destination[j * coeff_count] = sub_uint_uint_mod(
                        destination[j * coeff_count], scaled_plain_coeff, coeff_modulus[j]);
                }
            }
        }

        void divide_phase_by_scaling_variant(
            const uint64_t *phase,
            const SEALContext::ContextData &context_data,
            uint64_t *destination,
            MemoryPoolHandle pool)
        {
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t coeff_mod_count = coeff_modulus.size();

            auto &base_converter = context_data.base_converter();
            auto &plain_gamma_product = base_converter->get_plain_gamma_product();
            auto &plain_gamma_array = base_converter->get_plain_gamma_array();
            auto &neg_inv_coeff = base_converter->get_neg_inv_coeff();
            auto inv_gamma = base_converter->get_inv_gamma();

            // The number of uint64 count for plain_modulus and gamma together
            size_t plain_gamma_uint64_count = 2;

            auto temp(allocate_zero_poly(coeff_count, coeff_mod_count, pool));

            // Compute |gamma * plain|qi * ct(s)
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                multiply_poly_scalar_coeffmod(
                    phase + (i * coeff_count), coeff_count,
                    plain_gamma_product[i], coeff_modulus[i],
                    temp.get() + (i * coeff_count));
            }

            // Make another temp destination to get the poly in
            // mod {gamma U plain_modulus}
            auto tmp_dest_plain_gamma(
                allocate_poly(coeff_count, plain_gamma_uint64_count, pool));

            // Compute FastBConvert from q to {gamma, plain_modulus}
            base_converter->fastbconv_plain_gamma(
                temp.get(), tmp_dest_plain_gamma.get(), pool);

            // Compute result multiply by coeff_modulus inverse in mod {gamma U plain_modulus}
            for (size_t i = 0; i < plain_gamma_uint64_count; i++)
            {
                multiply_poly_scalar_coeffmod(
                    tmp_dest_plain_gamma.get() + (i * coeff_count),
                    coeff_count, neg_inv_coeff[i], plain_gamma_array[i],
                    tmp_dest_plain_gamma.get() + (i * coeff_count));
            }

            // First correct the values which are larger than floor(gamma/2)
            uint64_t gamma_div_2 = plain_gamma_array[1].value() >> 1;

            // Now compute the subtraction to remove error and perform final multiplication by
            // gamma inverse mod plain_modulus
            for (size_t i = 0; i < coeff_count; i++)
            {
                // Need correction beacuse of center mod
                if (tmp_dest_plain_gamma[i + coeff_count] > gamma_div_2)
                {
                    // Compute -(gamma - a) instead of (a - gamma)
                    tmp_dest_plain_gamma[i + coeff_count] = plain_gamma_array[1].value() -
                        tmp_dest_plain_gamma[i + coeff_count];
                    tmp_dest_plain_gamma[i + coeff_count] %= plain_gamma_array[0].value();
                    destination[i] = add_uint_uint_mod(tmp_dest_plain_gamma[i],
                        tmp_dest_plain_gamma[i + coeff_count], plain_gamma_array[0]);
                }
                // No correction needed
                else
                {
                    tmp_dest_plain_gamma[i + coeff_count] %= plain_gamma_array[0].value();
                    destination[i] = sub_uint_uint_mod(tmp_dest_plain_gamma[i],
                        tmp_dest_plain_gamma[i + coeff_count], plain_gamma_array[0]);
                }
                if (0 != destination[i])
                {
                    // Perform final multiplication by gamma inverse mod plain_modulus
                    destination[i] = multiply_uint_uint_mod(destination[i], inv_gamma,
                        plain_gamma_array[0]);
                }
            }
        }
    }
}
