// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <algorithm>
#include <stdexcept>
#include <cmath>
#include <limits>
#include <functional>
#include "seal/evaluator.h"
#include "seal/util/common.h"
#include "seal/util/uintarith.h"
#include "seal/util/polycore.h"
#include "seal/util/polyarithsmallmod.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    namespace
    {
        template<typename T, typename S>
        bool are_same_scale(T value1, S value2)
        {
            return util::are_close<double>(value1.scale(), value2.scale());
        }
    }

    Evaluator::Evaluator(shared_ptr<SEALContext> context) : context_(move(context))
    {
        // Verify parameters
        if (!context_)
        {
            throw invalid_argument("invalid context");
        }
        if (!context_->parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        // Calculate map from Zmstar to generator representation
        populate_Zmstar_to_generator();
    }

    void Evaluator::populate_Zmstar_to_generator()
    {
        uint64_t n = static_cast<uint64_t>(
            context_->context_data()->parms().poly_modulus_degree());
        uint64_t m = n << 1;

        for (uint64_t i = 0; i < n / 2; i++)
        {
            uint64_t galois_elt = exponentiate_uint64(3, i) & (m - 1);
            pair<uint64_t, uint64_t> temp_pair1{ i, 0 };
            Zmstar_to_generator_.emplace(galois_elt, temp_pair1);
            galois_elt = (exponentiate_uint64(3, i) * (m - 1)) & (m - 1);
            pair<uint64_t, uint64_t> temp_pair2{ i, 1 };
            Zmstar_to_generator_.emplace(galois_elt, temp_pair2);
        }
    }

    void Evaluator::negate_inplace(Ciphertext &encrypted)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();

        // Negate each poly in the array
        for (size_t j = 0; j < encrypted_size; j++)
        {
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                negate_poly_coeffmod(encrypted.data(j) + (i * coeff_count),
                    coeff_count, coeff_modulus[i], encrypted.data(j) + (i * coeff_count));
            }
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::add_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2)
    {
        // Verify parameters.
        if (!encrypted1.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!encrypted2.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.is_ntt_form() != encrypted2.is_ntt_form())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (!are_same_scale(encrypted1, encrypted2))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);

        // Size check
        if (!product_fits_in(max_count, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        // Prepare destination
        encrypted1.resize(context_, parms.parms_id(), max_count);

        // Add ciphertexts
        for (size_t j = 0; j < min_count; j++)
        {
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                add_poly_poly_coeffmod(encrypted1.data(j) + (i * coeff_count),
                    encrypted2.data(j) + (i * coeff_count), coeff_count, coeff_modulus[i],
                    encrypted1.data(j) + (i * coeff_count));
            }
        }

        // Copy the remainding polys of the array with larger count into encrypted1
        if (encrypted1_size < encrypted2_size)
        {
            set_poly_poly(encrypted2.data(min_count),
                coeff_count * (encrypted2_size - encrypted1_size),
                coeff_mod_count, encrypted1.data(encrypted1_size));
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted1.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::add_many(const vector<Ciphertext> &encrypteds, Ciphertext &destination)
    {
        if (encrypteds.empty())
        {
            throw invalid_argument("encrypteds cannot be empty");
        }
        for (size_t i = 0; i < encrypteds.size(); i++)
        {
            if (&encrypteds[i] == &destination)
            {
                throw invalid_argument("encrypteds must be different from destination");
            }
        }
        destination = encrypteds[0];
        for (size_t i = 1; i < encrypteds.size(); i++)
        {
            add_inplace(destination, encrypteds[i]);
        }
    }

    void Evaluator::sub_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2)
    {
        // Verify parameters.
        if (!encrypted1.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!encrypted2.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.is_ntt_form() != encrypted2.is_ntt_form())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (!are_same_scale(encrypted1, encrypted2))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);

        // Size check
        if (!product_fits_in(max_count, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        // Prepare destination
        encrypted1.resize(context_, parms.parms_id(), max_count);

        // Subtract polynomials.
        for (size_t j = 0; j < min_count; j++)
        {
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                sub_poly_poly_coeffmod(encrypted1.data(j) + (i * coeff_count),
                    encrypted2.data(j) + (i * coeff_count), coeff_count, coeff_modulus[i],
                    encrypted1.data(j) + (i * coeff_count));
            }
        }

        // If encrypted2 has larger count, negate remaining entries
        if (encrypted1_size < encrypted2_size)
        {
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                negate_poly_coeffmod(encrypted2.data(encrypted1_size) + (i * coeff_count),
                    coeff_count * (encrypted2_size - encrypted1_size), coeff_modulus[i],
                    encrypted1.data(encrypted1_size) + (i * coeff_count));
            }
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted1.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::multiply_inplace(Ciphertext &encrypted1, 
        const Ciphertext &encrypted2, MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!encrypted1.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!encrypted2.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }

        auto context_data_ptr = context_->context_data(encrypted1.parms_id());
        switch (context_data_ptr->parms().scheme())
        {
        case scheme_type::BFV:
            bfv_multiply(encrypted1, encrypted2, pool);
            break;

        case scheme_type::CKKS:
            ckks_multiply(encrypted1, encrypted2, pool);
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted1.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::bfv_multiply(Ciphertext &encrypted1, 
        const Ciphertext &encrypted2, MemoryPoolHandle pool)
    {
        if (encrypted1.is_ntt_form() || encrypted2.is_ntt_form())
        {
            throw invalid_argument("encrypted1 or encrypted2 cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();

        uint64_t plain_modulus = parms.plain_modulus().value();
        auto &base_converter = context_data.base_converter();
        auto &bsk_modulus = base_converter->get_bsk_mod_array();
        size_t bsk_base_mod_count = base_converter->bsk_base_mod_count();
        size_t bsk_mtilde_count = add_safe(bsk_base_mod_count, size_t(1));
        auto &coeff_small_ntt_tables = context_data.small_ntt_tables();
        auto &bsk_small_ntt_tables = base_converter->get_bsk_small_ntt_tables();

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_count = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_count, coeff_count, bsk_mtilde_count))
        {
            throw logic_error("invalid parameters");
        }

        // Prepare destination
        encrypted1.resize(context_, parms.parms_id(), dest_count);

        size_t encrypted_ptr_increment = coeff_count * coeff_mod_count;
        size_t encrypted_bsk_mtilde_ptr_increment = coeff_count * bsk_mtilde_count;
        size_t encrypted_bsk_ptr_increment = coeff_count * bsk_base_mod_count;

        // Make temp polys for FastBConverter result from q ---> Bsk U {m_tilde}
        auto tmp_encrypted1_bsk_mtilde(allocate_poly(
            coeff_count * encrypted1_size, bsk_mtilde_count, pool));
        auto tmp_encrypted2_bsk_mtilde(allocate_poly(
            coeff_count * encrypted2_size, bsk_mtilde_count, pool));

        // Make temp polys for FastBConverter result from Bsk U {m_tilde} -----> Bsk
        auto tmp_encrypted1_bsk(allocate_poly(
            coeff_count * encrypted1_size, bsk_base_mod_count, pool));
        auto tmp_encrypted2_bsk(allocate_poly(
            coeff_count * encrypted2_size, bsk_base_mod_count, pool));

        // Step 0: fast base convert from q to Bsk U {m_tilde}
        // Step 1: reduce q-overflows in Bsk
        // Iterate over all the ciphertexts inside encrypted1
        for (size_t i = 0; i < encrypted1_size; i++)
        {
            base_converter->fastbconv_mtilde(
                encrypted1.data(i),
                tmp_encrypted1_bsk_mtilde.get() + (i * encrypted_bsk_mtilde_ptr_increment),
                pool);
            base_converter->mont_rq(
                tmp_encrypted1_bsk_mtilde.get() + (i * encrypted_bsk_mtilde_ptr_increment),
                tmp_encrypted1_bsk.get() + (i * encrypted_bsk_ptr_increment));
        }

        // Iterate over all the ciphertexts inside encrypted2
        for (size_t i = 0; i < encrypted2_size; i++)
        {
            base_converter->fastbconv_mtilde(
                encrypted2.data(i),
                tmp_encrypted2_bsk_mtilde.get() + (i * encrypted_bsk_mtilde_ptr_increment), pool);
            base_converter->mont_rq(
                tmp_encrypted2_bsk_mtilde.get() + (i * encrypted_bsk_mtilde_ptr_increment),
                tmp_encrypted2_bsk.get() + (i * encrypted_bsk_ptr_increment));
        }

        // Step 2: compute product and multiply plain modulus to the result
        // We need to multiply both in q and Bsk. Values in encrypted_safe are in
        // base q and values in tmp_encrypted_bsk are in base Bsk. We iterate over
        // destination poly array and generate each poly based on the indices of
        // inputs (arbitrary sizes for ciphertexts). First allocate two temp polys:
        // one for results in base q and the other for the result in base Bsk. These
        // need to be zero for the arbitrary size multiplication; not for 2x2 though
        auto tmp_des_coeff_base(allocate_zero_poly(
            coeff_count * dest_count, coeff_mod_count, pool));
        auto tmp_des_bsk_base(allocate_zero_poly(
            coeff_count * dest_count, bsk_base_mod_count, pool));

        // Allocate two tmp polys: one for NTT multiplication results in base q and
        // one for result in base Bsk
        auto tmp1_poly_coeff_base(allocate_poly(coeff_count, coeff_mod_count, pool));
        auto tmp1_poly_bsk_base(allocate_poly(coeff_count, bsk_base_mod_count, pool));
        auto tmp2_poly_coeff_base(allocate_poly(coeff_count, coeff_mod_count, pool));
        auto tmp2_poly_bsk_base(allocate_poly(coeff_count, bsk_base_mod_count, pool));

        size_t current_encrypted1_limit = 0;

        // First convert all the inputs into NTT form
        auto copy_encrypted1_ntt_coeff_mod(allocate_poly(
            coeff_count * encrypted1_size, coeff_mod_count, pool));
        set_poly_poly(encrypted1.data(), coeff_count * encrypted1_size,
            coeff_mod_count, copy_encrypted1_ntt_coeff_mod.get());

        auto copy_encrypted1_ntt_bsk_base_mod(allocate_poly(
            coeff_count * encrypted1_size, bsk_base_mod_count, pool));
        set_poly_poly(tmp_encrypted1_bsk.get(), coeff_count * encrypted1_size,
            bsk_base_mod_count, copy_encrypted1_ntt_bsk_base_mod.get());

        auto copy_encrypted2_ntt_coeff_mod(allocate_poly(
            coeff_count * encrypted2_size, coeff_mod_count, pool));
        set_poly_poly(encrypted2.data(), coeff_count * encrypted2_size,
            coeff_mod_count, copy_encrypted2_ntt_coeff_mod.get());

        auto copy_encrypted2_ntt_bsk_base_mod(allocate_poly(
            coeff_count * encrypted2_size, bsk_base_mod_count, pool));
        set_poly_poly(tmp_encrypted2_bsk.get(), coeff_count * encrypted2_size,
            bsk_base_mod_count, copy_encrypted2_ntt_bsk_base_mod.get());

        for (size_t i = 0; i < encrypted1_size; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                // Lazy reduction
                ntt_negacyclic_harvey_lazy(copy_encrypted1_ntt_coeff_mod.get() +
                    (j * coeff_count) + (i * encrypted_ptr_increment), coeff_small_ntt_tables[j]);
            }
            for (size_t j = 0; j < bsk_base_mod_count; j++)
            {
                // Lazy reduction
                ntt_negacyclic_harvey_lazy(copy_encrypted1_ntt_bsk_base_mod.get() +
                    (j * coeff_count) + (i * encrypted_bsk_ptr_increment), bsk_small_ntt_tables[j]);
            }
        }

        for (size_t i = 0; i < encrypted2_size; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                // Lazy reduction
                ntt_negacyclic_harvey_lazy(copy_encrypted2_ntt_coeff_mod.get() +
                    (j * coeff_count) + (i * encrypted_ptr_increment), coeff_small_ntt_tables[j]);
            }
            for (size_t j = 0; j < bsk_base_mod_count; j++)
            {
                // Lazy reduction
                ntt_negacyclic_harvey_lazy(copy_encrypted2_ntt_bsk_base_mod.get() +
                    (j * coeff_count) + (i * encrypted_bsk_ptr_increment), bsk_small_ntt_tables[j]);
            }
        }

        // Perform multiplication on arbitrary size ciphertexts
        for (size_t secret_power_index = 0; 
            secret_power_index < dest_count; secret_power_index++)
        {
            // Loop over encrypted1 components [i], seeing if a match exists with an encrypted2
            // component [j] such that [i+j]=[secret_power_index]
            // Only need to check encrypted1 components up to and including [secret_power_index],
            // and strictly less than [encrypted_array.size()]
            current_encrypted1_limit = min(encrypted1_size, secret_power_index + 1);

            for (size_t encrypted1_index = 0; 
                encrypted1_index < current_encrypted1_limit; encrypted1_index++)
            {
                // check if a corresponding component in encrypted2 exists
                if (encrypted2_size > secret_power_index - encrypted1_index)
                {
                    size_t encrypted2_index = secret_power_index - encrypted1_index;

                    // NTT Multiplication and addition for results in q
                    for (size_t i = 0; i < coeff_mod_count; i++)
                    {
                        dyadic_product_coeffmod(
                            copy_encrypted1_ntt_coeff_mod.get() + (i * coeff_count) +
                            (encrypted_ptr_increment * encrypted1_index),
                            copy_encrypted2_ntt_coeff_mod.get() + (i * coeff_count) +
                            (encrypted_ptr_increment * encrypted2_index),
                            coeff_count, coeff_modulus[i],
                            tmp1_poly_coeff_base.get() + (i * coeff_count));
                        add_poly_poly_coeffmod(
                            tmp1_poly_coeff_base.get() + (i * coeff_count),
                            tmp_des_coeff_base.get() + (i * coeff_count) +
                            (secret_power_index * coeff_count * coeff_mod_count),
                            coeff_count, coeff_modulus[i],
                            tmp_des_coeff_base.get() + (i * coeff_count) +
                            (secret_power_index * coeff_count * coeff_mod_count));
                    }

                    // NTT Multiplication and addition for results in Bsk
                    for (size_t i = 0; i < bsk_base_mod_count; i++)
                    {
                        dyadic_product_coeffmod(
                            copy_encrypted1_ntt_bsk_base_mod.get() + (i * coeff_count) +
                            (encrypted_bsk_ptr_increment * encrypted1_index),
                            copy_encrypted2_ntt_bsk_base_mod.get() + (i * coeff_count) +
                            (encrypted_bsk_ptr_increment * encrypted2_index),
                            coeff_count, bsk_modulus[i],
                            tmp1_poly_bsk_base.get() + (i * coeff_count));
                        add_poly_poly_coeffmod(
                            tmp1_poly_bsk_base.get() + (i * coeff_count),
                            tmp_des_bsk_base.get() + (i * coeff_count) +
                            (secret_power_index * coeff_count * bsk_base_mod_count),
                            coeff_count, bsk_modulus[i],
                            tmp_des_bsk_base.get() + (i * coeff_count) +
                            (secret_power_index * coeff_count * bsk_base_mod_count));
                    }
                }
            }
        }

        // Convert back outputs from NTT form
        for (size_t i = 0; i < dest_count; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                inverse_ntt_negacyclic_harvey(
                    tmp_des_coeff_base.get() + (i * (encrypted_ptr_increment)) +
                    (j * coeff_count), coeff_small_ntt_tables[j]);
            }
            for (size_t j = 0; j < bsk_base_mod_count; j++)
            {
                inverse_ntt_negacyclic_harvey(
                    tmp_des_bsk_base.get() + (i * (encrypted_bsk_ptr_increment)) +
                    (j * coeff_count), bsk_small_ntt_tables[j]);
            }
        }

        // Now we multiply plain modulus to both results in base q and Bsk and 
        // allocate them together in one container as 
        // (te0)q(te'0)Bsk | ... |te count)q (te' count)Bsk to make it ready for 
        // fast_floor
        auto tmp_coeff_bsk_together(allocate_poly(
            coeff_count, dest_count * (coeff_mod_count + bsk_base_mod_count), pool));
        uint64_t *tmp_coeff_bsk_together_ptr = tmp_coeff_bsk_together.get();

        // Base q
        for (size_t i = 0; i < dest_count; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                multiply_poly_scalar_coeffmod(
                    tmp_des_coeff_base.get() + (j * coeff_count) + (i * encrypted_ptr_increment),
                    coeff_count, plain_modulus, coeff_modulus[j],
                    tmp_coeff_bsk_together_ptr + (j * coeff_count));
            }
            tmp_coeff_bsk_together_ptr += encrypted_ptr_increment;

            for (size_t k = 0; k < bsk_base_mod_count; k++)
            {
                multiply_poly_scalar_coeffmod(
                    tmp_des_bsk_base.get() + (k * coeff_count) + (i * encrypted_bsk_ptr_increment),
                    coeff_count, plain_modulus, bsk_modulus[k],
                    tmp_coeff_bsk_together_ptr + (k * coeff_count));
            }
            tmp_coeff_bsk_together_ptr += encrypted_bsk_ptr_increment;
        }

        // Allocate a new poly for fast floor result in Bsk
        auto tmp_result_bsk(allocate_poly(
            coeff_count, dest_count * bsk_base_mod_count, pool));
        for (size_t i = 0; i < dest_count; i++)
        {
            // Step 3: fast floor from q U {Bsk} to Bsk
            base_converter->fast_floor(
                tmp_coeff_bsk_together.get() +
                (i * (encrypted_ptr_increment + encrypted_bsk_ptr_increment)),
                tmp_result_bsk.get() + (i * encrypted_bsk_ptr_increment), pool);

            // Step 4: fast base convert from Bsk to q
            base_converter->fastbconv_sk(
                tmp_result_bsk.get() + (i * encrypted_bsk_ptr_increment),
                encrypted1.data(i), pool);
        }
    }

    void Evaluator::ckks_multiply(Ciphertext &encrypted1, 
        const Ciphertext &encrypted2, MemoryPoolHandle pool)
    {
        if (!(encrypted1.is_ntt_form() && encrypted2.is_ntt_form()))
        {
            throw invalid_argument("encrypted1 or encrypted2 must be in NTT form");
        } 

        // Extract encryption parameters.
        auto &context_data = *context_->context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();

        double new_scale = encrypted1.scale() * encrypted2.scale(); 
        
        // Check that scale is positive and not too large
        if (new_scale <= 0 || (static_cast<int>(log2(new_scale)) >=
            context_data.total_coeff_modulus_bit_count()))
        {
            throw invalid_argument("scale out of bounds");
        }

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_count = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_count, coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // Prepare destination
        encrypted1.resize(context_, parms.parms_id(), dest_count);

        //pointer increment to switch to a next polynomial
        size_t encrypted_ptr_increment = coeff_count * coeff_mod_count;

        //Step 1: naive multiplication modulo the coefficient modulus
        //First allocate two temp polys :
        //one for results in base q. This need to be zero
        //for the arbitrary size multiplication; not for 2x2 though
        auto tmp_des(allocate_zero_poly(
            coeff_count * dest_count, coeff_mod_count, pool));

        //Allocate tmp polys for NTT multiplication results in base q
        auto tmp1_poly(allocate_poly(coeff_count, coeff_mod_count, pool));
        auto tmp2_poly(allocate_poly(coeff_count, coeff_mod_count, pool));

        // First convert all the inputs into NTT form
        auto copy_encrypted1_ntt(allocate_poly(
            coeff_count * encrypted1_size, coeff_mod_count, pool));
        set_poly_poly(encrypted1.data(), coeff_count * encrypted1_size,
            coeff_mod_count, copy_encrypted1_ntt.get());

        auto copy_encrypted2_ntt(allocate_poly(
            coeff_count * encrypted2_size, coeff_mod_count, pool));
        set_poly_poly(encrypted2.data(), coeff_count * encrypted2_size,
            coeff_mod_count, copy_encrypted2_ntt.get());

        // Perform multiplication on arbitrary size ciphertexts

        // Loop over encrypted1 components [i], seeing if a match exists with an encrypted2
        // component [j] such that [i+j]=[secret_power_index]
        // Only need to check encrypted1 components up to and including [secret_power_index],
        // and strictly less than [encrypted_array.size()]

        // Number of encrypted1 components to check
        size_t current_encrypted1_limit = 0;

        for (size_t secret_power_index = 0;
            secret_power_index < dest_count; secret_power_index++)
        {
            current_encrypted1_limit = min(encrypted1_size, secret_power_index + 1);

            for (size_t encrypted1_index = 0;
                encrypted1_index < current_encrypted1_limit; encrypted1_index++)
            {
                // check if a corresponding component in encrypted2 exists
                if (encrypted2_size > secret_power_index - encrypted1_index)
                {
                    size_t encrypted2_index = secret_power_index - encrypted1_index;

                    // NTT Multiplication and addition for results in q
                    for (size_t i = 0; i < coeff_mod_count; i++)
                    {
                        // ci * dj
                        dyadic_product_coeffmod(
                            copy_encrypted1_ntt.get() + (i * coeff_count) +
                            (encrypted_ptr_increment * encrypted1_index),
                            copy_encrypted2_ntt.get() + (i * coeff_count) +
                            (encrypted_ptr_increment * encrypted2_index),
                            coeff_count, coeff_modulus[i],
                            tmp1_poly.get() + (i * coeff_count));
                        // Dest[i+j]
                        add_poly_poly_coeffmod(
                            tmp1_poly.get() + (i * coeff_count),
                            tmp_des.get() + (i * coeff_count) +
                            (secret_power_index * coeff_count * coeff_mod_count),
                            coeff_count, coeff_modulus[i],
                            tmp_des.get() + (i * coeff_count) +
                            (secret_power_index * coeff_count * coeff_mod_count));
                    }
                }
            }
        }

        // Set the final result
        set_poly_poly(tmp_des.get(), coeff_count * dest_count,
            coeff_mod_count, encrypted1.data());

        // Set the scale
        encrypted1.scale() = new_scale;
    }

    void Evaluator::square_inplace(Ciphertext &encrypted, MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_->context_data(encrypted.parms_id());
        switch (context_data_ptr->parms().scheme())
        {
        case scheme_type::BFV:
            bfv_square(encrypted, move(pool));
            break;

        case scheme_type::CKKS:
            ckks_square(encrypted, move(pool));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::bfv_square(Ciphertext &encrypted, MemoryPoolHandle pool)
    {
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();

        uint64_t plain_modulus = parms.plain_modulus().value();
        auto &base_converter = context_data.base_converter();
        auto &bsk_modulus = base_converter->get_bsk_mod_array();
        size_t bsk_base_mod_count = base_converter->bsk_base_mod_count();
        size_t bsk_mtilde_count = add_safe(bsk_base_mod_count, size_t(1));
        auto &coeff_small_ntt_tables = context_data.small_ntt_tables();
        auto &bsk_small_ntt_tables = base_converter->get_bsk_small_ntt_tables();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            bfv_multiply(encrypted, encrypted, move(pool));
            return;
        }

        // Determine destination_array.size()
        size_t dest_count = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_count, coeff_count, bsk_mtilde_count))
        {
            throw logic_error("invalid parameters");
        }

        size_t encrypted_ptr_increment = coeff_count * coeff_mod_count;
        size_t encrypted_bsk_mtilde_ptr_increment = coeff_count * bsk_mtilde_count;
        size_t encrypted_bsk_ptr_increment = coeff_count * bsk_base_mod_count;

        // Prepare destination
        encrypted.resize(context_, parms.parms_id(), dest_count);

        // Make temp poly for FastBConverter result from q ---> Bsk U {m_tilde}
        auto tmp_encrypted_bsk_mtilde(allocate_poly(
            coeff_count * encrypted_size, bsk_mtilde_count, pool));

        // Make temp poly for FastBConverter result from Bsk U {m_tilde} -----> Bsk
        auto tmp_encrypted_bsk(allocate_poly(
            coeff_count * encrypted_size, bsk_base_mod_count, pool));

        // Step 0: fast base convert from q to Bsk U {m_tilde}
        // Step 1: reduce q-overflows in Bsk
        // Iterate over all the ciphertexts inside encrypted1
        for (size_t i = 0; i < encrypted_size; i++)
        {
            base_converter->fastbconv_mtilde(
                encrypted.data(i),
                tmp_encrypted_bsk_mtilde.get() +
                (i * encrypted_bsk_mtilde_ptr_increment), pool);
            base_converter->mont_rq(
                tmp_encrypted_bsk_mtilde.get() +
                (i * encrypted_bsk_mtilde_ptr_increment),
                tmp_encrypted_bsk.get() + (i * encrypted_bsk_ptr_increment));
        }

        // Step 2: compute product and multiply plain modulus to the result.
        // We need to multiply both in q and Bsk. Values in encrypted_safe are
        // in base q and values in tmp_encrypted_bsk are in base Bsk. We iterate
        // over destination poly array and generate each poly based on the indices
        // of inputs (arbitrary sizes for ciphertexts). First allocate two temp polys:
        // one for results in base q and the other for the result in base Bsk.
        auto tmp_des_coeff_base(allocate_poly(
            coeff_count * dest_count, coeff_mod_count, pool));
        auto tmp_des_bsk_base(allocate_poly(
            coeff_count * dest_count, bsk_base_mod_count, pool));

        // First convert all the inputs into NTT form
        auto copy_encrypted_ntt_coeff_mod(allocate_poly(
            coeff_count * encrypted_size, coeff_mod_count, pool));
        set_poly_poly(encrypted.data(), coeff_count * encrypted_size,
            coeff_mod_count, copy_encrypted_ntt_coeff_mod.get());

        auto copy_encrypted_ntt_bsk_base_mod(allocate_poly(
            coeff_count * encrypted_size, bsk_base_mod_count, pool));
        set_poly_poly(tmp_encrypted_bsk.get(), coeff_count * encrypted_size,
            bsk_base_mod_count, copy_encrypted_ntt_bsk_base_mod.get());

        for (size_t i = 0; i < encrypted_size; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                ntt_negacyclic_harvey_lazy(
                    copy_encrypted_ntt_coeff_mod.get() + (j * coeff_count) +
                    (i * encrypted_ptr_increment), coeff_small_ntt_tables[j]);
            }
            for (size_t j = 0; j < bsk_base_mod_count; j++)
            {
                ntt_negacyclic_harvey_lazy(
                    copy_encrypted_ntt_bsk_base_mod.get() + (j * coeff_count) +
                    (i * encrypted_bsk_ptr_increment), bsk_small_ntt_tables[j]);
            }
        }

        // Perform fast squaring
        // Compute c0^2 in base q
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // Des[0] in q
            dyadic_product_coeffmod(
                copy_encrypted_ntt_coeff_mod.get() + (i * coeff_count),
                copy_encrypted_ntt_coeff_mod.get() + (i * coeff_count),
                coeff_count, coeff_modulus[i],
                tmp_des_coeff_base.get() + (i * coeff_count));

            // Des[2] in q
            dyadic_product_coeffmod(
                copy_encrypted_ntt_coeff_mod.get() + (i * coeff_count) + encrypted_ptr_increment,
                copy_encrypted_ntt_coeff_mod.get() + (i * coeff_count) + encrypted_ptr_increment,
                coeff_count, coeff_modulus[i],
                tmp_des_coeff_base.get() + (i * coeff_count) + (2 * encrypted_ptr_increment));
        }

        // Compute c0^2 in base bsk
        for (size_t i = 0; i < bsk_base_mod_count; i++)
        {
            // Des[0] in bsk
            dyadic_product_coeffmod(
                copy_encrypted_ntt_bsk_base_mod.get() + (i * coeff_count),
                copy_encrypted_ntt_bsk_base_mod.get() + (i * coeff_count),
                coeff_count, bsk_modulus[i],
                tmp_des_bsk_base.get() + (i * coeff_count));

            // Des[2] in bsk
            dyadic_product_coeffmod(
                copy_encrypted_ntt_bsk_base_mod.get() + (i * coeff_count) + encrypted_bsk_ptr_increment,
                copy_encrypted_ntt_bsk_base_mod.get() + (i * coeff_count) + encrypted_bsk_ptr_increment,
                coeff_count, bsk_modulus[i],
                tmp_des_bsk_base.get() + (i * coeff_count) + (2 * encrypted_bsk_ptr_increment));
        }

        auto tmp_second_mul_coeff_base(allocate_poly(coeff_count, coeff_mod_count, pool));

        // Compute 2*c0*c1 in base q
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            dyadic_product_coeffmod(
                copy_encrypted_ntt_coeff_mod.get() + (i * coeff_count),
                copy_encrypted_ntt_coeff_mod.get() + (i * coeff_count) + encrypted_ptr_increment,
                coeff_count, coeff_modulus[i],
                tmp_second_mul_coeff_base.get() + (i * coeff_count));
            add_poly_poly_coeffmod(
                tmp_second_mul_coeff_base.get() + (i * coeff_count),
                tmp_second_mul_coeff_base.get() + (i * coeff_count),
                coeff_count, coeff_modulus[i],
                tmp_des_coeff_base.get() + (i * coeff_count) + encrypted_ptr_increment);
        }

        auto tmp_second_mul_bsk_base(allocate_poly(coeff_count, bsk_base_mod_count, pool));

        // Compute 2*c0*c1 in base bsk
        for (size_t i = 0; i < bsk_base_mod_count; i++)
        {
            dyadic_product_coeffmod(
                copy_encrypted_ntt_bsk_base_mod.get() + (i * coeff_count),
                copy_encrypted_ntt_bsk_base_mod.get() + (i * coeff_count) + encrypted_bsk_ptr_increment,
                coeff_count, bsk_modulus[i],
                tmp_second_mul_bsk_base.get() + (i * coeff_count));
            add_poly_poly_coeffmod(
                tmp_second_mul_bsk_base.get() + (i * coeff_count),
                tmp_second_mul_bsk_base.get() + (i * coeff_count),
                coeff_count, bsk_modulus[i],
                tmp_des_bsk_base.get() + (i * coeff_count) + encrypted_bsk_ptr_increment);
        }

        // Convert back outputs from NTT form
        for (size_t i = 0; i < dest_count; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                inverse_ntt_negacyclic_harvey_lazy(
                    tmp_des_coeff_base.get() + (i * (encrypted_ptr_increment)) + (j * coeff_count),
                    coeff_small_ntt_tables[j]);
            }
            for (size_t j = 0; j < bsk_base_mod_count; j++)
            {
                inverse_ntt_negacyclic_harvey_lazy(
                    tmp_des_bsk_base.get() + (i * (encrypted_bsk_ptr_increment)) +
                    (j * coeff_count), bsk_small_ntt_tables[j]);
            }
        }

        // Now we multiply plain modulus to both results in base q and Bsk and
        // allocate them together in one container as (te0)q(te'0)Bsk | ... |te count)q (te' count)Bsk
        // to make it ready for fast_floor
        auto tmp_coeff_bsk_together(allocate_poly(
            coeff_count, dest_count * (coeff_mod_count + bsk_base_mod_count), pool));
        uint64_t *tmp_coeff_bsk_together_ptr = tmp_coeff_bsk_together.get();

        // Base q
        for (size_t i = 0; i < dest_count; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                multiply_poly_scalar_coeffmod(
                    tmp_des_coeff_base.get() + (j * coeff_count) + (i * encrypted_ptr_increment),
                    coeff_count, plain_modulus, coeff_modulus[j],
                    tmp_coeff_bsk_together_ptr + (j * coeff_count));
            }
            tmp_coeff_bsk_together_ptr += encrypted_ptr_increment;

            for (size_t k = 0; k < bsk_base_mod_count; k++)
            {
                multiply_poly_scalar_coeffmod(
                    tmp_des_bsk_base.get() + (k * coeff_count) + (i * encrypted_bsk_ptr_increment),
                    coeff_count, plain_modulus, bsk_modulus[k],
                    tmp_coeff_bsk_together_ptr + (k * coeff_count));
            }
            tmp_coeff_bsk_together_ptr += encrypted_bsk_ptr_increment;
        }

        // Allocate a new poly for fast floor result in Bsk
        auto tmp_result_bsk(allocate_poly(coeff_count, dest_count * bsk_base_mod_count, pool));
        for (size_t i = 0; i < dest_count; i++)
        {
            // Step 3: fast floor from q U {Bsk} to Bsk
            base_converter->fast_floor(
                tmp_coeff_bsk_together.get() + (i * (encrypted_ptr_increment + encrypted_bsk_ptr_increment)),
                tmp_result_bsk.get() + (i * encrypted_bsk_ptr_increment), pool);

            // Step 4: fast base convert from Bsk to q
            base_converter->fastbconv_sk(
                tmp_result_bsk.get() + (i * encrypted_bsk_ptr_increment), encrypted.data(i), pool);
        }
    }

    void Evaluator::ckks_square(Ciphertext &encrypted, MemoryPoolHandle pool)
    {
        if (!encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();

        double new_scale = encrypted.scale() * encrypted.scale();

        // Check that scale is positive and not too large
        if (new_scale <= 0 || (static_cast<int>(log2(new_scale)) >=
            context_data.total_coeff_modulus_bit_count()))
        {
            throw invalid_argument("scale out of bounds");
        }

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_count = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_count, coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // Prepare destination
        encrypted.resize(context_, parms.parms_id(), dest_count);

        //pointer increment to switch to a next polynomial
        size_t encrypted_ptr_increment = coeff_count * coeff_mod_count;

        //Step 1: naive multiplication modulo the coefficient modulus
        //First allocate two temp polys :
        //one for results in base q. This need to be zero
        //for the arbitrary size multiplication; not for 2x2 though
        auto tmp_des(allocate_zero_poly(
            coeff_count * dest_count, coeff_mod_count, pool));

        //Allocate tmp polys for NTT multiplication results in base q
        auto tmp1_poly(allocate_poly(coeff_count, coeff_mod_count, pool));
        auto tmp2_poly(allocate_poly(coeff_count, coeff_mod_count, pool));

        // First convert all the inputs into NTT form
        auto copy_encrypted_ntt(allocate_poly(
            coeff_count * encrypted_size, coeff_mod_count, pool));
        set_poly_poly(encrypted.data(), coeff_count * encrypted_size,
            coeff_mod_count, copy_encrypted_ntt.get());

        // The simplest case when the ciphertext dimension is 2
        if (encrypted_size == 2)
        {
            //Compute c0^2, 2*c0 + c1 and c1^2 modulo q
            //tmp poly to keep 2 * c0 * c1
            auto tmp_second_mul(allocate_poly(coeff_count, coeff_mod_count, pool));

            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                //Des[0] = c0^2 in NTT
                dyadic_product_coeffmod(
                    copy_encrypted_ntt.get() + (i * coeff_count),
                    copy_encrypted_ntt.get() + (i * coeff_count),
                    coeff_count, coeff_modulus[i],
                    tmp_des.get() + (i * coeff_count));

                //Des[1] = 2 * c0 * c1
                dyadic_product_coeffmod(
                    copy_encrypted_ntt.get() + (i * coeff_count),
                    copy_encrypted_ntt.get() + (i * coeff_count) + encrypted_ptr_increment,
                    coeff_count, coeff_modulus[i],
                    tmp_second_mul.get() + (i * coeff_count));
                add_poly_poly_coeffmod(
                    tmp_second_mul.get() + (i * coeff_count),
                    tmp_second_mul.get() + (i * coeff_count),
                    coeff_count, coeff_modulus[i],
                    tmp_des.get() + (i * coeff_count) + encrypted_ptr_increment);

                //Des[2] = c1^2 in NTT
                dyadic_product_coeffmod(
                    copy_encrypted_ntt.get() + (i * coeff_count) + encrypted_ptr_increment,
                    copy_encrypted_ntt.get() + (i * coeff_count) + encrypted_ptr_increment,
                    coeff_count, coeff_modulus[i],
                    tmp_des.get() + (i * coeff_count) + (2 * encrypted_ptr_increment));
            }
        }
        else
        {
            // Perform multiplication on arbitrary size ciphertexts

            // Loop over encrypted1 components [i], seeing if a match exists with an encrypted2
            // component [j] such that [i+j]=[secret_power_index]
            // Only need to check encrypted1 components up to and including [secret_power_index],
            // and strictly less than [encrypted_array.size()]

            // Number of encrypted1 components to check
            size_t current_encrypted_limit = 0;

            for (size_t secret_power_index = 0; secret_power_index < dest_count; secret_power_index++)
            {
                current_encrypted_limit = min(encrypted_size, secret_power_index + 1);

                for (size_t encrypted1_index = 0; encrypted1_index < current_encrypted_limit;
                    encrypted1_index++)
                {
                    // check if a corresponding component in encrypted2 exists
                    if (encrypted_size > secret_power_index - encrypted1_index)
                    {
                        size_t encrypted2_index = secret_power_index - encrypted1_index;

                        // NTT Multiplication and addition for results in q
                        for (size_t i = 0; i < coeff_mod_count; i++)
                        {
                            // ci * dj
                            dyadic_product_coeffmod(
                                copy_encrypted_ntt.get() + (i * coeff_count) +
                                (encrypted_ptr_increment * encrypted1_index),
                                copy_encrypted_ntt.get() + (i * coeff_count) +
                                (encrypted_ptr_increment * encrypted2_index),
                                coeff_count, coeff_modulus[i],
                                tmp1_poly.get() + (i * coeff_count));
                            // Dest[i+j]
                            add_poly_poly_coeffmod(
                                tmp1_poly.get() + (i * coeff_count),
                                tmp_des.get() + (i * coeff_count) +
                                (secret_power_index * coeff_count * coeff_mod_count),
                                coeff_count, coeff_modulus[i],
                                tmp_des.get() + (i * coeff_count) +
                                (secret_power_index * coeff_count * coeff_mod_count));
                        }
                    }
                }
            }
        }

        // Set the final result
        set_poly_poly(tmp_des.get(), coeff_count * dest_count, coeff_mod_count, encrypted.data());

        // Set the scale
        encrypted.scale() = new_scale;
    }

    void Evaluator::relinearize_internal(Ciphertext &encrypted, 
        const RelinKeys &relin_keys, size_t destination_size, 
        MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!relin_keys.is_metadata_valid_for(context_))
        {
            throw invalid_argument("relin_keys is not valid for encryption parameters");
        }
        if (relin_keys.parms_id() != context_->first_parms_id())
        {
            throw invalid_argument("parameter mismatch");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        size_t encrypted_size = encrypted.size();

        // Verify parameters.
        if (destination_size < 2 || destination_size > encrypted_size)
        {
            throw invalid_argument("destination_size must be at least 2 and less than or equal to current count");
        }
        if (relin_keys.size() < sub_safe(encrypted_size, size_t(2)))
        {
            throw invalid_argument("not enough relinearization keys");
        }

        // If encrypted is already at the desired level, return
        if (destination_size == encrypted_size)
        {
            return;
        }

        // Calculate number of relinearize_one_step calls needed
        size_t relins_needed = encrypted_size - destination_size;

        // Update temp to store the current result after relinearization
        switch (context_data.parms().scheme())
        {
            case scheme_type::BFV:
            {
                if (encrypted.is_ntt_form())
                {
                    throw invalid_argument("BFV encrypted cannot be in NTT form");
                }
                for (size_t i = 0; i < relins_needed; i++)
                {
                    bfv_relinearize_one_step(encrypted.data(), encrypted_size,
                        context_data, relin_keys, pool);
                    encrypted_size--;
                }
                break;
            }

            case scheme_type::CKKS:
            {
                if (!encrypted.is_ntt_form())
                {
                    throw invalid_argument("CKKS encrypted must be in NTT form");
                }
                for (size_t i = 0; i < relins_needed; i++)
                {
                    ckks_relinearize_one_step(encrypted.data(), encrypted_size,
                        context_data, relin_keys, pool);
                    encrypted_size--;
                }
                break;
            }

            default:
                throw invalid_argument("unsupported scheme");
        }

        // Put the output of final relinearization into destination.
        // Prepare destination only at this point because we are resizing down
        encrypted.resize(context_, parms.parms_id(), destination_size);
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::bfv_relinearize_one_step(uint64_t *encrypted, 
        size_t encrypted_size, const SEALContext::ContextData &context_data,
        const RelinKeys &relin_keys, MemoryPool &pool)
    {
        // Extract encryption parameters.
        // Parameters corresponding to the ciphertext level
        auto &parms = context_data.parms();

        // q_l corresponding to the ciphertext level
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();

        // number of factors in q_l
        size_t coeff_mod_count = coeff_modulus.size();

        // Size test
        if (!product_fits_in(encrypted_size, coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // n * number of factors in q_l
        size_t rns_poly_uint64_count = coeff_count * coeff_mod_count;
#ifdef SEAL_DEBUG
        if (encrypted == nullptr)
        {
            throw invalid_argument("encrypted cannot be null");
        }
        if (encrypted_size <= 2)
        {
            throw invalid_argument("encrypted_size must be at least 3");
        }
        if (relin_keys.size() < sub_safe(encrypted_size, size_t(2)))
        {
            throw invalid_argument("not enough relinearization keys");
        }
#endif
        // q/qi mod qi
        auto &first_context_data = *context_->context_data();
        auto &coeff_small_ntt_tables = first_context_data.small_ntt_tables();

        // Decompose encrypted_array[count-1] into base w
        // Want to create an array of polys, each of whose components i is
        // (encrypted_array[count-1])^(i) - in the notation of FV paper.
        // This allocation stores one of the decomposed factors modulo one of the primes.
        auto decomp_encrypted_last(allocate_uint(coeff_count, pool));

        // Lazy reduction
        auto wide_innerresult0(allocate_zero_poly(coeff_count, 2 * coeff_mod_count, pool));
        auto wide_innerresult1(allocate_zero_poly(coeff_count, 2 * coeff_mod_count, pool));
        auto innerresult(allocate_poly(coeff_count, coeff_mod_count, pool));
        auto temp_decomp_coeff(allocate_uint(coeff_count, pool));

        /*
        For lazy reduction to work here, we need to ensure that the 128-bit accumulators
        (wide_innerresult0 and wide_innerresult1) do not overflow. Since the modulus primes
        are at most 60 bits, if the total number of summands is K, then the size of the
        total sum of products (without reduction) is at most 62 + 60 + bit_length(K).
        We need this to be at most 128, thus we need bit_length(K) <= 6. Thus, we need K <= 63.
        In this case, this means sum_i relin_keys.data()[encrypted_size - 3][i].size() / 2 <= 63.
        */
        const uint64_t *encrypted_coeff = encrypted + (encrypted_size - 1) * rns_poly_uint64_count;

        for (size_t i = 0; i < coeff_mod_count; i++, encrypted_coeff += coeff_count)
        {
            // We use HPS improvement to Bajard's RNS key switching so scaling by q_i/q not needed
            // multiply_poly_scalar_coeffmod(
            //     encrypted_coeff, coeff_count,
            //     inv_coeff_products_mod_coeff_array[i], coeff_modulus[i],
            //     encrypted_coeff_prod_inv_coeff.get());

            int shift = 0;
            auto &key_component_ref = relin_keys.data()[encrypted_size - 3][i];
            size_t keys_size = key_component_ref.size();
            for (size_t k = 0; k < keys_size; k += 2)
            {
                const uint64_t *key_ptr_0 = key_component_ref.data(k);
                const uint64_t *key_ptr_1 = key_component_ref.data(k + 1);

                // Decompose here
                int decomposition_bit_count = relin_keys.decomposition_bit_count();
                for (size_t coeff_index = 0; coeff_index < coeff_count; coeff_index++)
                {
                    decomp_encrypted_last[coeff_index] =
                        encrypted_coeff[coeff_index] >> shift;
                    decomp_encrypted_last[coeff_index] &= 
                        (uint64_t(1) << decomposition_bit_count) - 1;
                }

                uint64_t *wide_innerresult0_ptr = wide_innerresult0.get();
                uint64_t *wide_innerresult1_ptr = wide_innerresult1.get();
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    uint64_t *temp_decomp_coeff_ptr = temp_decomp_coeff.get();
                    set_uint_uint(decomp_encrypted_last.get(), coeff_count, temp_decomp_coeff_ptr);

                    // We don't reduce here, so might get up to two extra bits. Thus 62 bits at most.
                    ntt_negacyclic_harvey_lazy(temp_decomp_coeff_ptr, coeff_small_ntt_tables[j]);

                    // Lazy reduction
                    unsigned long long wide_innerproduct[2];
                    unsigned long long temp;
                    for (size_t m = 0; m < coeff_count; m++, wide_innerresult0_ptr += 2)
                    {
                        multiply_uint64(*temp_decomp_coeff_ptr++, *key_ptr_0++, wide_innerproduct);
                        unsigned char carry = add_uint64(wide_innerresult0_ptr[0],
                            wide_innerproduct[0], &temp);
                        wide_innerresult0_ptr[0] = temp;
                        wide_innerresult0_ptr[1] += wide_innerproduct[1] + carry;
                    }

                    temp_decomp_coeff_ptr = temp_decomp_coeff.get();
                    for (size_t m = 0; m < coeff_count; m++, wide_innerresult1_ptr += 2)
                    {
                        multiply_uint64(*temp_decomp_coeff_ptr++, *key_ptr_1++, wide_innerproduct);
                        unsigned char carry = add_uint64(wide_innerresult1_ptr[0],
                            wide_innerproduct[0], &temp);
                        wide_innerresult1_ptr[0] = temp;
                        wide_innerresult1_ptr[1] += wide_innerproduct[1] + carry;
                    }
                }
                shift += decomposition_bit_count;
            }
        }

        uint64_t *innerresult_poly_ptr = innerresult.get();
        uint64_t *wide_innerresult_poly_ptr = wide_innerresult0.get();
        uint64_t *encrypted_ptr = encrypted;
        uint64_t *innerresult_coeff_ptr = innerresult_poly_ptr;
        uint64_t *wide_innerresult_coeff_ptr = wide_innerresult_poly_ptr;
        for (size_t i = 0; i < coeff_mod_count; i++, innerresult_poly_ptr += coeff_count,
            wide_innerresult_poly_ptr += 2 * coeff_count, encrypted_ptr += coeff_count)
        {
            for (size_t m = 0; m < coeff_count; m++, wide_innerresult_coeff_ptr += 2)
            {
                *innerresult_coeff_ptr++ = barrett_reduce_128(
                    wide_innerresult_coeff_ptr, coeff_modulus[i]);
            }
            inverse_ntt_negacyclic_harvey(innerresult_poly_ptr, coeff_small_ntt_tables[i]);
            add_poly_poly_coeffmod(encrypted_ptr, innerresult_poly_ptr, coeff_count,
                coeff_modulus[i], encrypted_ptr);
        }

        innerresult_poly_ptr = innerresult.get();
        wide_innerresult_poly_ptr = wide_innerresult1.get();
        encrypted_ptr = encrypted + rns_poly_uint64_count;
        innerresult_coeff_ptr = innerresult_poly_ptr;
        wide_innerresult_coeff_ptr = wide_innerresult_poly_ptr;
        for (size_t i = 0; i < coeff_mod_count; i++, innerresult_poly_ptr += coeff_count,
            wide_innerresult_poly_ptr += 2 * coeff_count, encrypted_ptr += coeff_count)
        {
            for (size_t m = 0; m < coeff_count; m++, wide_innerresult_coeff_ptr += 2)
            {
                *innerresult_coeff_ptr++ = barrett_reduce_128(
                    wide_innerresult_coeff_ptr, coeff_modulus[i]);
            }
            inverse_ntt_negacyclic_harvey(innerresult_poly_ptr, coeff_small_ntt_tables[i]);
            add_poly_poly_coeffmod(encrypted_ptr, innerresult_poly_ptr, coeff_count,
                coeff_modulus[i], encrypted_ptr);
        }
    }

    void Evaluator::ckks_relinearize_one_step(uint64_t *encrypted, 
        size_t encrypted_size, const SEALContext::ContextData &context_data,
        const RelinKeys &relin_keys, MemoryPool &pool)
    {
        // Extract encryption parameters.
        // Parameters corresponding to the ciphertext level
        auto &parms = context_data.parms();

        // q_l corresponding to the ciphertext level
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();

        // number of factors in q_l
        size_t coeff_mod_count = coeff_modulus.size();

        // Size test
        if (!product_fits_in(encrypted_size, coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // n * number of factors in q_l
        size_t rns_poly_uint64_count = coeff_count * coeff_mod_count;
#ifdef SEAL_DEBUG
        if (encrypted == nullptr)
        {
            throw invalid_argument("encrypted cannot be null");
        }
        if (encrypted_size <= 2)
        {
            throw invalid_argument("encrypted_size must be at least 3");
        }
        if (relin_keys.size() < sub_safe(encrypted_size, size_t(2)))
        {
            throw invalid_argument("not enough evaluation keys");
        }
#endif
        // q/qi mod qi
        auto &first_context_data = *context_->context_data();
        auto &coeff_small_ntt_tables = first_context_data.small_ntt_tables();

        // Decompose encrypted_array[count-1] into base w
        // Want to create an array of polys, each of whose components i is
        // (encrypted_array[count-1])^(i) - in the notation of FV paper.
        // This allocation stores one of the decomposed factors modulo one of the primes.
        auto decomp_encrypted_last(allocate_uint(coeff_count, pool));

        // Lazy reduction
        auto wide_innerresult0(allocate_zero_poly(coeff_count, 2 * coeff_mod_count, pool));
        auto wide_innerresult1(allocate_zero_poly(coeff_count, 2 * coeff_mod_count, pool));
        auto innerresult(allocate_poly(coeff_count, coeff_mod_count, pool));
        auto temp_decomp_coeff(allocate_uint(coeff_count, pool));

        /*
        For lazy reduction to work here, we need to ensure that the 128-bit accumulators
        (wide_innerresult0 and wide_innerresult1) do not overflow. Since the modulus primes
        are at most 60 bits, if the total number of summands is K, then the size of the
        total sum of products (without reduction) is at most 62 + 60 + bit_length(K).
        We need this to be at most 128, thus we need bit_length(K) <= 6. Thus, we need K <= 63.
        In this case, this means sum_i evaluation_keys.data()[encrypted_size - 3][i].size() / 2 <= 63.
        */
        uint64_t *encrypted_coeff = encrypted + (encrypted_size - 1) * rns_poly_uint64_count;

        // inner product of evaluation keys and the bit-decomposition of the last ciphertext polynomial
        for (size_t i = 0; i < coeff_mod_count; i++, encrypted_coeff += coeff_count)
        {
            // Convert the last polynomial of encrypted from NTT to create a bit-decomposition
            inverse_ntt_negacyclic_harvey(encrypted_coeff, coeff_small_ntt_tables[i]);

            // We use HPS improvement to Bajard's RNS key switching so scaling by q_i/q not needed
            // multiply_poly_scalar_coeffmod(
            //     encrypted_coeff, coeff_count,
            //     inv_coeff_products_mod_coeff_array[i], coeff_modulus[i],
            //     encrypted_coeff_prod_inv_coeff.get());

            int shift = 0;
            auto &key_component_ref = relin_keys.data()[encrypted_size - 3][i];
            size_t keys_size = key_component_ref.size();
            for (size_t k = 0; k < keys_size; k += 2)
            {
                const uint64_t *key_ptr_0 = key_component_ref.data(k);
                const uint64_t *key_ptr_1 = key_component_ref.data(k + 1);

                // Decompose here
                int decomposition_bit_count = relin_keys.decomposition_bit_count();
                for (size_t coeff_index = 0; coeff_index < coeff_count; coeff_index++)
                {
                    decomp_encrypted_last[coeff_index] =
                        encrypted_coeff[coeff_index] >> shift;
                    decomp_encrypted_last[coeff_index] &= 
                        (uint64_t(1) << decomposition_bit_count) - 1;
                }

                uint64_t *wide_innerresult0_ptr = wide_innerresult0.get();
                uint64_t *wide_innerresult1_ptr = wide_innerresult1.get();
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    uint64_t *temp_decomp_coeff_ptr = temp_decomp_coeff.get();
                    set_uint_uint(decomp_encrypted_last.get(), coeff_count, temp_decomp_coeff_ptr);

                    // We don't reduce here, so might get up to two extra bits. Thus 62 bits at most.
                    ntt_negacyclic_harvey_lazy(temp_decomp_coeff_ptr, coeff_small_ntt_tables[j]);

                    // Lazy reduction
                    unsigned long long wide_innerproduct[2];
                    unsigned long long temp;
                    for (size_t m = 0; m < coeff_count; m++, wide_innerresult0_ptr += 2)
                    {
                        multiply_uint64(*temp_decomp_coeff_ptr++, *key_ptr_0++, wide_innerproduct);
                        unsigned char carry = add_uint64(wide_innerresult0_ptr[0],
                            wide_innerproduct[0], &temp);
                        wide_innerresult0_ptr[0] = temp;
                        wide_innerresult0_ptr[1] += wide_innerproduct[1] + carry;
                    }

                    temp_decomp_coeff_ptr = temp_decomp_coeff.get();
                    for (size_t m = 0; m < coeff_count; m++, wide_innerresult1_ptr += 2)
                    {
                        multiply_uint64(*temp_decomp_coeff_ptr++, *key_ptr_1++, wide_innerproduct);
                        unsigned char carry = add_uint64(wide_innerresult1_ptr[0],
                            wide_innerproduct[0], &temp);
                        wide_innerresult1_ptr[0] = temp;
                        wide_innerresult1_ptr[1] += wide_innerproduct[1] + carry;
                    }
                }
                shift += decomposition_bit_count;
            }
        }

        uint64_t *innerresult_poly_ptr = innerresult.get();
        uint64_t *wide_innerresult_poly_ptr = wide_innerresult0.get();
        uint64_t *encrypted_ptr = encrypted;
        uint64_t *innerresult_coeff_ptr = innerresult_poly_ptr;
        uint64_t *wide_innerresult_coeff_ptr = wide_innerresult_poly_ptr;
        for (size_t i = 0; i < coeff_mod_count; i++, innerresult_poly_ptr += coeff_count,
            wide_innerresult_poly_ptr += 2 * coeff_count, encrypted_ptr += coeff_count)
        {
            for (size_t m = 0; m < coeff_count; m++, wide_innerresult_coeff_ptr += 2)
            {
                *innerresult_coeff_ptr++ = barrett_reduce_128(
                    wide_innerresult_coeff_ptr, coeff_modulus[i]);
            }
            add_poly_poly_coeffmod(encrypted_ptr, innerresult_poly_ptr, coeff_count,
                coeff_modulus[i], encrypted_ptr);
        }

        innerresult_poly_ptr = innerresult.get();
        wide_innerresult_poly_ptr = wide_innerresult1.get();
        encrypted_ptr = encrypted + rns_poly_uint64_count;
        innerresult_coeff_ptr = innerresult_poly_ptr;
        wide_innerresult_coeff_ptr = wide_innerresult_poly_ptr;
        for (size_t i = 0; i < coeff_mod_count; i++, innerresult_poly_ptr += coeff_count,
            wide_innerresult_poly_ptr += 2 * coeff_count, encrypted_ptr += coeff_count)
        {
            for (size_t m = 0; m < coeff_count; m++, wide_innerresult_coeff_ptr += 2)
            {
                *innerresult_coeff_ptr++ = barrett_reduce_128(
                    wide_innerresult_coeff_ptr, coeff_modulus[i]);
            }
            add_poly_poly_coeffmod(encrypted_ptr, innerresult_poly_ptr, coeff_count,
                coeff_modulus[i], encrypted_ptr);
        }
    }

    void Evaluator::mod_switch_scale_to_next(const Ciphertext &encrypted, 
        Ciphertext &destination, MemoryPoolHandle pool)
    {
        auto context_data_ptr = context_->context_data(encrypted.parms_id());
        if (context_data_ptr->parms().scheme() == scheme_type::BFV &&
            encrypted.is_ntt_form())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == scheme_type::CKKS &&
            !encrypted.is_ntt_form())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &next_parms = context_data.next_context_data()->parms();

        // q_1,...,q_{k-1}
        auto &next_coeff_modulus = next_parms.coeff_modulus();
        size_t next_coeff_mod_count = next_coeff_modulus.size();
        size_t coeff_count = next_parms.poly_modulus_degree();
        size_t encrypted_size = encrypted.size();
        auto &inv_last_coeff_mod_array =
            context_data.base_converter()->get_inv_last_coeff_mod_array();

        // Size test
        if (!product_fits_in(coeff_count, encrypted_size, next_coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // In CKKS need to transform away from NTT form
        Ciphertext encrypted_copy(pool);
        encrypted_copy = encrypted;
        if (next_parms.scheme() == scheme_type::CKKS)
        {
            transform_from_ntt_inplace(encrypted_copy);
        }

        auto temp1(allocate_uint(coeff_count, pool));

        // Allocate enough room for the result
        auto temp2(allocate_poly(coeff_count * encrypted_size, next_coeff_mod_count, pool));
        auto temp2_ptr = temp2.get();

        for (size_t poly_index = 0; poly_index < encrypted_size; poly_index++)
        {
            // Set temp1 to ct mod qk
            set_uint_uint(encrypted_copy.data(poly_index) + next_coeff_mod_count * coeff_count,
                coeff_count, temp1.get());
            for (size_t mod_index = 0; mod_index < next_coeff_mod_count; mod_index++,
                temp2_ptr += coeff_count)
            {
                // (ct mod qk) mod qi
                modulo_poly_coeffs(temp1.get(), coeff_count,
                    next_coeff_modulus[mod_index], temp2_ptr);
                // (-(ct mod qk)) mod qi
                negate_poly_coeffmod(temp2_ptr, coeff_count,
                    next_coeff_modulus[mod_index], temp2_ptr);
                // ((ct mod qi) - (ct mod qk)) mod qi
                add_poly_poly_coeffmod(
                    encrypted_copy.data(poly_index) + mod_index * coeff_count, temp2_ptr,
                    coeff_count, next_coeff_modulus[mod_index], temp2_ptr);
                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(temp2_ptr, coeff_count,
                    inv_last_coeff_mod_array[mod_index],
                    next_coeff_modulus[mod_index], temp2_ptr);
            }
        }

        // Resize destination
        destination.resize(context_, next_parms.parms_id(), encrypted_size);
        destination.is_ntt_form() = false;

        set_poly_poly(temp2.get(), coeff_count * encrypted_size, next_coeff_mod_count,
            destination.data());

        // In CKKS need to transform back to NTT form
        if (next_parms.scheme() == scheme_type::CKKS)
        {
            transform_to_ntt_inplace(destination);

            // Also change the scale
            destination.scale() = encrypted.scale() /
                static_cast<double>(context_data.parms().coeff_modulus().back().value());
        }
    }

    void Evaluator::mod_switch_drop_to_next(const Ciphertext &encrypted, 
        Ciphertext &destination, MemoryPoolHandle pool)
    {
        auto context_data_ptr = context_->context_data(encrypted.parms_id());
        if (context_data_ptr->parms().scheme() == scheme_type::CKKS && 
            !encrypted.is_ntt_form())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &next_context_data = *context_data_ptr->next_context_data();
        auto &next_parms = next_context_data.parms();

        // Check that scale is positive and not too large
        if (encrypted.scale() <= 0 || (static_cast<int>(log2(encrypted.scale())) >=
            next_context_data.total_coeff_modulus_bit_count()))
        {
            throw invalid_argument("scale out of bounds");
        }

        // q_1,...,q_{k-1}
        size_t next_coeff_mod_count = next_parms.coeff_modulus().size();
        size_t coeff_count = next_parms.poly_modulus_degree();
        size_t encrypted_size = encrypted.size();

        // Size check
        if (!product_fits_in(encrypted_size, coeff_count, next_coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        size_t rns_poly_total_count = next_coeff_mod_count * coeff_count;

        if (&encrypted == &destination)
        {
            // Switching in-place so need temporary space
            auto temp(allocate_uint(rns_poly_total_count * encrypted_size, pool));

            // Copy data over to temp
            for (size_t i = 0; i < encrypted_size; i++)
            {
                for (size_t j = 0; j < next_coeff_mod_count; j++)
                {
                    set_uint_uint(encrypted.data(i) + (j * coeff_count), coeff_count,
                        temp.get() + (i * rns_poly_total_count) + (j * coeff_count));
                }
            }

            // Resize destination before writing
            destination.resize(context_, next_parms.parms_id(), encrypted_size);
            destination.is_ntt_form() = true;
            destination.scale() = encrypted.scale();

            // Copy data to destination
            set_uint_uint(temp.get(), rns_poly_total_count * encrypted_size, 
                destination.data());
        }
        else
        {
            // Resize destination before writing
            destination.resize(context_, next_parms.parms_id(), encrypted_size);
            destination.is_ntt_form() = true;
            destination.scale() = encrypted.scale();

            // Copy data directly to new destination
            for (size_t i = 0; i < encrypted_size; i++)
            {
                for (size_t j = 0; j < next_coeff_mod_count; j++)
                {
                    set_uint_uint(encrypted.data(i) + (j * coeff_count), coeff_count,
                        destination.data() + (i * rns_poly_total_count) + (j * coeff_count));
                }
            }
        }
    }

    void Evaluator::mod_switch_drop_to_next(Plaintext &plain)
    {
        auto context_data_ptr = context_->context_data(plain.parms_id());
        if (!plain.is_ntt_form())
        {
            throw invalid_argument("plain is not in NTT form");
        }
        if (!context_data_ptr->next_context_data())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }

        // Extract encryption parameters.
        auto &next_context_data = *context_data_ptr->next_context_data();
        auto &next_parms = context_data_ptr->next_context_data()->parms();

        // Check that scale is positive and not too large
        if (plain.scale() <= 0 || (static_cast<int>(log2(plain.scale())) >=
            next_context_data.total_coeff_modulus_bit_count()))
        {
            throw invalid_argument("scale out of bounds");
        }

        // q_1,...,q_{k-1}
        auto &next_coeff_modulus = next_parms.coeff_modulus();
        size_t next_coeff_mod_count = next_coeff_modulus.size();
        size_t coeff_count = next_parms.poly_modulus_degree();

        // Compute destination size first for exception safety
        auto dest_size = mul_safe(next_coeff_mod_count, coeff_count); 

        plain.parms_id() = parms_id_zero;
        plain.resize(dest_size);
        plain.parms_id() = next_parms.parms_id();
    }

    void Evaluator::mod_switch_to_next(const Ciphertext &encrypted, 
        Ciphertext &destination, MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_->context_data(encrypted.parms_id());
        if (context_->last_parms_id() == encrypted.parms_id())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        if (encrypted.size() > 2)
        {
            throw invalid_argument("encrypted size must be 2");
        }

        switch (context_->context_data()->parms().scheme())
        {
        case scheme_type::BFV:
            // Modulus switching with scaling
            mod_switch_scale_to_next(encrypted, destination, move(pool));
            break;

        case scheme_type::CKKS:
            // Modulus switching without scaling
            mod_switch_drop_to_next(encrypted, destination, move(pool));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (destination.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::mod_switch_to_inplace(Ciphertext &encrypted, 
        parms_id_type parms_id, MemoryPoolHandle pool)
    {
        // Verify parameters.
        auto context_data_ptr = context_->context_data(encrypted.parms_id());
        auto target_context_data_ptr = context_->context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!target_context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (encrypted.parms_id() != parms_id)
        {
            mod_switch_to_next_inplace(encrypted, pool);
        }
    }

    void Evaluator::mod_switch_to_inplace(Plaintext &plain, parms_id_type parms_id)
    {
        // Verify parameters.
        auto context_data_ptr = context_->context_data(plain.parms_id());
        auto target_context_data_ptr = context_->context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (!context_->context_data(parms_id))
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!plain.is_ntt_form())
        {
            throw invalid_argument("plain is not in NTT form");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (plain.parms_id() != parms_id)
        {
            mod_switch_to_next_inplace(plain);
        }
    }

    void Evaluator::rescale_to_next(const Ciphertext &encrypted, Ciphertext &destination,
        MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_->context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (context_->last_parms_id() == encrypted.parms_id())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        if (encrypted.size() > 2)
        {
            throw invalid_argument("encrypted size must be 2");
        }

        switch (context_->context_data()->parms().scheme())
        {
        case scheme_type::BFV:
            throw invalid_argument("unsupported operation for scheme type");

        case scheme_type::CKKS:
            // Modulus switching with scaling
            mod_switch_scale_to_next(encrypted, destination, move(pool));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (destination.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::rescale_to_inplace(Ciphertext &encrypted, parms_id_type parms_id,
        MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_->context_data(encrypted.parms_id());
        auto target_context_data_ptr = context_->context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!target_context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        switch (context_data_ptr->parms().scheme())
        {
        case scheme_type::BFV:
            throw invalid_argument("unsupported operation for scheme type");

        case scheme_type::CKKS:
            while (encrypted.parms_id() != parms_id)
            {
                // Modulus switching with scaling
                mod_switch_scale_to_next(encrypted, encrypted, pool);
            }
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::multiply_many(vector<Ciphertext> &encrypteds,
        const RelinKeys &relin_keys, Ciphertext &destination,
        MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (encrypteds.size() == 0)
        {
            throw invalid_argument("encrypteds vector must not be empty");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        for (size_t i = 0; i < encrypteds.size(); i++)
        {
            if (&encrypteds[i] == &destination)
            {
                throw invalid_argument("encrypteds must be different from destination");
            }
        }

        // There is at least one ciphertext
        auto context_data_ptr = context_->context_data(encrypteds[0].parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypteds is not valid for encryption parameters");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();

        if (parms.scheme() != scheme_type::BFV)
        {
            throw logic_error("unsupported scheme");
        }

        // If there is only one ciphertext, return it.
        if (encrypteds.size() == 1)
        {
            destination = encrypteds[0];
            return;
        }

        // Repeatedly multiply and add to the back of the vector until the end is reached
        Ciphertext product(context_, parms.parms_id(), pool);
        for (size_t i = 0; i < encrypteds.size() - 1; i += 2)
        {
            // We only compare pointers to determine if a faster path can be taken.
            // This is under the assumption that if the two pointers are the same and
            // the parameter sets match, then it makes no sense for one of the ciphertexts
            // to be of different size than the other. More generally, it seems like
            // a reasonable assumption that if the pointers are the same, then the
            // ciphertexts are the same.
            if (encrypteds[i].data() == encrypteds[i + 1].data())
            {
                square(encrypteds[i], product);
            }
            else
            {
                multiply(encrypteds[i], encrypteds[i + 1], product);
            }
            relinearize_inplace(product, relin_keys, pool);
            encrypteds.emplace_back(product);
        }

        destination = encrypteds[encrypteds.size() - 1];
    }

    void Evaluator::exponentiate_inplace(Ciphertext &encrypted, uint64_t exponent,
        const RelinKeys &relin_keys, MemoryPoolHandle pool)
    {
        // Verify parameters.
        auto context_data_ptr = context_->context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_->context_data(relin_keys.parms_id()))
        {
            throw invalid_argument("relin_keys is not valid for encryption parameters");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        if (exponent == 0)
        {
            throw invalid_argument("exponent cannot be 0");
        }

        // Fast case
        if (exponent == 1)
        {
            return;
        }

        // Create a vector of copies of encrypted
        vector<Ciphertext> exp_vector(exponent, encrypted);
        multiply_many(exp_vector, relin_keys, encrypted, move(pool));
    }

    void Evaluator::add_plain_inplace(Ciphertext &encrypted, const Plaintext &plain)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!plain.is_valid_for(context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto &context_data = *context_->context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        if (parms.scheme() == scheme_type::BFV && encrypted.is_ntt_form())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (parms.scheme() == scheme_type::CKKS && !encrypted.is_ntt_form())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (plain.is_ntt_form() != encrypted.is_ntt_form())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (encrypted.is_ntt_form() &&
            (encrypted.parms_id() != plain.parms_id()))
        {
            throw invalid_argument("encrypted and plain parameter mismatch");
        }
        if (!are_same_scale(encrypted, plain))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        switch (parms.scheme())
        {
        case scheme_type::BFV:
        {
            auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
            auto plain_upper_half_threshold = context_data.plain_upper_half_threshold();
            auto upper_half_increment = context_data.upper_half_increment();

            for (size_t i = 0; i < plain.coeff_count(); i++)
            {
                // This is Encryptor::preencrypt
                // Multiply plain by scalar coeff_div_plain_modulus and reposition 
                // if in upper-half.
                if (plain[i] >= plain_upper_half_threshold)
                {
                    // Loop over primes
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        unsigned long long temp[2]{ 0, 0 };
                        multiply_uint64(coeff_div_plain_modulus[j], plain[i], temp);
                        temp[1] += add_uint64(temp[0], upper_half_increment[j], temp);
                        uint64_t scaled_plain_coeff = barrett_reduce_128(temp, coeff_modulus[j]);
                        *(encrypted.data() + i + (j * coeff_count)) = add_uint_uint_mod(
                            *(encrypted.data() + i + (j * coeff_count)),
                            scaled_plain_coeff, coeff_modulus[j]);
                    }
                }
                else
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        uint64_t scaled_plain_coeff = multiply_uint_uint_mod(
                            coeff_div_plain_modulus[j], plain[i], coeff_modulus[j]);
                        *(encrypted.data() + i + (j * coeff_count)) = add_uint_uint_mod(
                            *(encrypted.data() + i + (j * coeff_count)),
                            scaled_plain_coeff, coeff_modulus[j]);
                    }
                }
            }
            break;
        }

        case scheme_type::CKKS:
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                add_poly_poly_coeffmod(encrypted.data() + (j * coeff_count), 
                    plain.data() + (j*coeff_count), coeff_count, 
                    coeff_modulus[j], encrypted.data() + (j * coeff_count));
            }
            break;
        }

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::sub_plain_inplace(Ciphertext &encrypted, const Plaintext &plain)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!plain.is_valid_for(context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto &context_data = *context_->context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        if (parms.scheme() == scheme_type::BFV && encrypted.is_ntt_form())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (parms.scheme() == scheme_type::CKKS && !encrypted.is_ntt_form())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (plain.is_ntt_form() != encrypted.is_ntt_form())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (encrypted.is_ntt_form() &&
            (encrypted.parms_id() != plain.parms_id()))
        {
            throw invalid_argument("encrypted and plain parameter mismatch");
        }
        if (!are_same_scale(encrypted, plain))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        switch (parms.scheme())
        {
        case scheme_type::BFV:
        {
            auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
            auto plain_upper_half_threshold = context_data.plain_upper_half_threshold();
            auto upper_half_increment = context_data.upper_half_increment();

            for (size_t i = 0; i < plain.coeff_count(); i++)
            {
                // This is Encryptor::preencrypt changed to subtract instead
                // Multiply plain by scalar coeff_div_plain_modulus and reposition 
                // if in upper-half.
                if (plain[i] >= plain_upper_half_threshold)
                {
                    // Loop over primes
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        unsigned long long temp[2]{ 0, 0 };
                        multiply_uint64(coeff_div_plain_modulus[j], plain[i], temp);
                        temp[1] += add_uint64(temp[0], upper_half_increment[j], temp);
                        uint64_t scaled_plain_coeff = barrett_reduce_128(temp, coeff_modulus[j]);
                        *(encrypted.data() + i + (j * coeff_count)) = sub_uint_uint_mod(
                            *(encrypted.data() + i + (j * coeff_count)),
                            scaled_plain_coeff, coeff_modulus[j]);
                    }
                }
                else
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        uint64_t scaled_plain_coeff = multiply_uint_uint_mod(
                            coeff_div_plain_modulus[j], plain[i], coeff_modulus[j]);
                        *(encrypted.data() + i + (j * coeff_count)) = sub_uint_uint_mod(
                            *(encrypted.data() + i + (j * coeff_count)),
                            scaled_plain_coeff, coeff_modulus[j]);
                    }
                }
            }
            break;
        }

        case scheme_type::CKKS:
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                sub_poly_poly_coeffmod(encrypted.data() + (j * coeff_count), 
                    plain.data() + (j * coeff_count), coeff_count, 
                    coeff_modulus[j], encrypted.data() + (j * coeff_count));
            }
            break;
        }

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::multiply_plain_inplace(Ciphertext &encrypted, 
        const Plaintext &plain, MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!plain.is_valid_for(context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (!context_->context_data(encrypted.parms_id()))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (encrypted.is_ntt_form() != plain.is_ntt_form())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        if (encrypted.is_ntt_form())
        {
            multiply_plain_ntt(encrypted, plain);
        }
        else
        {
            multiply_plain_normal(encrypted, plain, move(pool));
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::multiply_plain_normal(Ciphertext &encrypted, 
        const Plaintext &plain, MemoryPool &pool)
    {
        // Extract encryption parameters.
        auto &context_data = *context_->context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        auto plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data.plain_upper_half_increment();
        auto &coeff_small_ntt_tables = context_data.small_ntt_tables();

        size_t encrypted_size = encrypted.size();
        size_t plain_coeff_count = plain.coeff_count();

        // Size check
        if (!product_fits_in(encrypted_size, coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        double new_scale = encrypted.scale() * plain.scale();

        // Check that scale is positive and not too large
        if (new_scale <= 0 || (static_cast<int>(log2(new_scale)) >=
            context_data.total_coeff_modulus_bit_count()))
        {
            throw invalid_argument("scale out of bounds");
        }

        // Set the scale
        encrypted.scale() = new_scale;

        // Multiplying just by a constant?
        if (plain_coeff_count == 1)
        {
            if (!context_data.qualifiers().using_fast_plain_lift)
            {
                auto adjusted_coeff(allocate_uint(coeff_mod_count, pool));
                if (plain[0] >= plain_upper_half_threshold)
                {
                    auto decomposed_coeff(allocate_uint(coeff_mod_count, pool));
                    add_uint_uint64(plain_upper_half_increment, plain[0],
                        coeff_mod_count, adjusted_coeff.get());
                    decompose_single_coeff(context_data, adjusted_coeff.get(), 
                        decomposed_coeff.get(), pool);

                    for (size_t i = 0; i < encrypted_size; i++)
                    {
                        for (size_t j = 0; j < coeff_mod_count; j++)
                        {
                            multiply_poly_scalar_coeffmod(
                                encrypted.data(i) + (j * coeff_count), coeff_count,
                                decomposed_coeff[j], coeff_modulus[j],
                                encrypted.data(i) + (j * coeff_count));
                        }
                    }
                }
                else
                {
                    for (size_t i = 0; i < encrypted_size; i++)
                    {
                        for (size_t j = 0; j < coeff_mod_count; j++)
                        {
                            multiply_poly_scalar_coeffmod(
                                encrypted.data(i) + (j * coeff_count), coeff_count,
                                plain[0], coeff_modulus[j],
                                encrypted.data(i) + (j * coeff_count));
                        }
                    }
                }
                return;
            }
            else
            {
                // Need for lift plain coefficient in RNS form regarding to each qi
                if (plain[0] >= plain_upper_half_threshold)
                {
                    for (size_t i = 0; i < encrypted_size; i++)
                    {
                        for (size_t j = 0; j < coeff_mod_count; j++)
                        {
                            multiply_poly_scalar_coeffmod(
                                encrypted.data(i) + (j * coeff_count), coeff_count,
                                plain[0] + plain_upper_half_increment[j],
                                coeff_modulus[j], encrypted.data(i) + (j * coeff_count));
                        }
                    }
                }
                // No need for lifting
                else
                {
                    for (size_t i = 0; i < encrypted_size; i++)
                    {
                        for (size_t j = 0; j < coeff_mod_count; j++)
                        {
                            multiply_poly_scalar_coeffmod(
                                encrypted.data(i) + (j * coeff_count), coeff_count,
                                plain[0], coeff_modulus[j],
                                encrypted.data(i) + (j * coeff_count));
                        }
                    }
                }
                return;
            }
        }

        // Generic plain case
        auto adjusted_poly(allocate_zero_uint(coeff_count * coeff_mod_count, pool));
        auto decomposed_poly(allocate_uint(coeff_count * coeff_mod_count, pool));
        uint64_t *poly_to_transform = nullptr;
        if (!context_data.qualifiers().using_fast_plain_lift)
        {
            // Reposition coefficients.
            const uint64_t *plain_ptr = plain.data();
            uint64_t *adjusted_poly_ptr = adjusted_poly.get();
            for (size_t i = 0; i < plain_coeff_count; i++, plain_ptr++,
                adjusted_poly_ptr += coeff_mod_count)
            {
                if (*plain_ptr >= plain_upper_half_threshold)
                {
                    add_uint_uint64(plain_upper_half_increment,
                        *plain_ptr, coeff_mod_count, adjusted_poly_ptr);
                }
                else
                {
                    *adjusted_poly_ptr = *plain_ptr;
                }
            }
            decompose(context_data, adjusted_poly.get(), decomposed_poly.get(), pool);
            poly_to_transform = decomposed_poly.get();
        }
        else
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                const uint64_t *plain_ptr = plain.data();
                uint64_t *adjusted_poly_ptr = adjusted_poly.get() + (j * coeff_count);
                uint64_t current_plain_upper_half_increment = plain_upper_half_increment[j];
                for (size_t i = 0; i < plain_coeff_count; i++, plain_ptr++, adjusted_poly_ptr++)
                {
                    // Need to lift the coefficient in each qi
                    if (*plain_ptr >= plain_upper_half_threshold)
                    {
                        *adjusted_poly_ptr = *plain_ptr + current_plain_upper_half_increment;
                    }
                    // No need for lifting
                    else
                    {
                        *adjusted_poly_ptr = *plain_ptr;
                    }
                }
            }
            poly_to_transform = adjusted_poly.get();
        }

        // Need to multiply each component in encrypted with decomposed_poly (plain poly)
        // Transform plain poly only once
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            ntt_negacyclic_harvey(
                poly_to_transform + (i * coeff_count), coeff_small_ntt_tables[i]);
        }

        for (size_t i = 0; i < encrypted_size; i++)
        {
            uint64_t *encrypted_ptr = encrypted.data(i);
            for (size_t j = 0; j < coeff_mod_count; j++, encrypted_ptr += coeff_count)
            {
                // Explicit inline to avoid unnecessary copy
                //ntt_multiply_poly_nttpoly(encrypted.data(i) + (j * coeff_count),
                //poly_to_transform + (j * coeff_count),
                //    coeff_small_ntt_tables_[j], encrypted.data(i) + (j * coeff_count), pool);

                // Lazy reduction
                ntt_negacyclic_harvey_lazy(encrypted_ptr, coeff_small_ntt_tables[j]);
                dyadic_product_coeffmod(encrypted_ptr, poly_to_transform + (j * coeff_count),
                    coeff_count, coeff_modulus[j], encrypted_ptr);
                inverse_ntt_negacyclic_harvey(encrypted_ptr, coeff_small_ntt_tables[j]);
            }
        }
    }

    void Evaluator::multiply_plain_ntt(Ciphertext &encrypted_ntt, 
        const Plaintext &plain_ntt)
    {
        // Verify parameters.
        if (!plain_ntt.is_ntt_form())
        {
            throw invalid_argument("plain_ntt is not in NTT form");
        }
        if (encrypted_ntt.parms_id() != plain_ntt.parms_id())
        {
            throw invalid_argument("encrypted_ntt and plain_ntt parameter mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data(encrypted_ntt.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        // Size check
        if (!product_fits_in(encrypted_ntt_size, coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        double new_scale = encrypted_ntt.scale() * plain_ntt.scale();

        // Check that scale is positive and not too large
        if (new_scale <= 0 || (static_cast<int>(log2(new_scale)) >=
            context_data.total_coeff_modulus_bit_count()))
        {
            throw invalid_argument("scale out of bounds");
        }

        for (size_t i = 0; i < encrypted_ntt_size; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                dyadic_product_coeffmod(
                    encrypted_ntt.data(i) + (j * coeff_count),
                    plain_ntt.data() + (j * coeff_count),
                    coeff_count, coeff_modulus[j],
                    encrypted_ntt.data(i) + (j * coeff_count));
            }
        }

        // Set the scale
        encrypted_ntt.scale() = new_scale;
    }

    void Evaluator::transform_to_ntt_inplace(Plaintext &plain, 
        parms_id_type parms_id, MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!plain.is_valid_for(context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto context_data_ptr = context_->context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for the current context");
        }
        if (plain.is_ntt_form())
        {
            throw invalid_argument("plain is already in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t plain_coeff_count = plain.coeff_count();

        auto plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data.plain_upper_half_increment();

        auto &coeff_small_ntt_tables = context_data.small_ntt_tables();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // Resize to fit the entire NTT transformed (ciphertext size) polynomial
        // Note that the new coefficients are automatically set to 0
        plain.resize(coeff_count * coeff_mod_count);

        // Verify if plain lift is needed
        if (!context_data.qualifiers().using_fast_plain_lift)
        {
            auto adjusted_poly(allocate_zero_uint(coeff_count * coeff_mod_count, pool));
            for (size_t i = 0; i < plain_coeff_count; i++)
            {
                if (plain[i] >= plain_upper_half_threshold)
                {
                    add_uint_uint64(plain_upper_half_increment, plain[i],
                        coeff_mod_count, adjusted_poly.get() + (i * coeff_mod_count));
                }
                else
                {
                    adjusted_poly[i * coeff_mod_count] = plain[i];
                }
            }
            decompose(context_data, adjusted_poly.get(), plain.data(), pool);
        }
        // No need for composed plain lift and decomposition
        else
        {
            for (size_t j = coeff_mod_count; j--; )
            {
                const uint64_t *plain_ptr = plain.data();
                uint64_t *adjusted_poly_ptr = plain.data() + (j * coeff_count);
                uint64_t current_plain_upper_half_increment = plain_upper_half_increment[j];
                for (size_t i = 0; i < plain_coeff_count; i++, plain_ptr++, adjusted_poly_ptr++)
                {
                    // Need to lift the coefficient in each qi
                    if (*plain_ptr >= plain_upper_half_threshold)
                    {
                        *adjusted_poly_ptr = *plain_ptr + current_plain_upper_half_increment;
                    }
                    // No need for lifting
                    else
                    {
                        *adjusted_poly_ptr = *plain_ptr;
                    }
                }
            }
        }

        // Transform to NTT domain
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            ntt_negacyclic_harvey(
                plain.data() + (i * coeff_count), coeff_small_ntt_tables[i]);
        }

        plain.parms_id() = parms_id;
    }

    void Evaluator::transform_to_ntt_inplace(Ciphertext &encrypted)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_->context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted is already in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();

        auto &coeff_small_ntt_tables = context_data.small_ntt_tables();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // Transform each polynomial to NTT domain
        for (size_t i = 0; i < encrypted_size; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                ntt_negacyclic_harvey(
                    encrypted.data(i) + (j * coeff_count), coeff_small_ntt_tables[j]);
            }
        }

        // Finally change the is_ntt_transformed flag
        encrypted.is_ntt_form() = true;
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::transform_from_ntt_inplace(Ciphertext &encrypted_ntt)
    {
        // Verify parameters.
        if (!encrypted_ntt.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_->context_data(encrypted_ntt.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted_ntt is not valid for encryption parameters");
        }
        if (!encrypted_ntt.is_ntt_form())
        {
            throw invalid_argument("encrypted_ntt is not in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = parms.coeff_modulus().size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        auto &coeff_small_ntt_tables = context_data.small_ntt_tables();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // Transform each polynomial from NTT domain
        for (size_t i = 0; i < encrypted_ntt_size; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                inverse_ntt_negacyclic_harvey(
                    encrypted_ntt.data(i) + (j * coeff_count), coeff_small_ntt_tables[j]);
            }
        }

        // Finally change the is_ntt_transformed flag
        encrypted_ntt.is_ntt_form() = false;
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted_ntt.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::apply_galois_inplace(Ciphertext &encrypted, uint64_t galois_elt,
        const GaloisKeys &galois_keys, MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        // Checking Galois keys for validity can be slow so we postpone it and check only 
        // those keys that are actually used.

        auto &context_data = *context_->context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        if (galois_keys.parms_id() != context_->first_parms_id())
        {
            throw invalid_argument("parameter mismatch");
        }
        if (parms.scheme() == scheme_type::BFV && encrypted.is_ntt_form())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (parms.scheme() == scheme_type::CKKS && !encrypted.is_ntt_form())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        // Extract encryption parameters.
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        uint64_t m = mul_safe(static_cast<uint64_t>(coeff_count), uint64_t(2));
        uint64_t subgroup_size = static_cast<uint64_t>(coeff_count >> 1);
        int n_power_of_two = get_power_of_two(static_cast<uint64_t>(coeff_count));

        // Verify parameters
        if (!(galois_elt & 1) || unsigned_geq(galois_elt, m))
        {
            throw invalid_argument("galois element is not valid");
        }
        if (encrypted_size > 2)
        {
            throw invalid_argument("encrypted size must be 2");
        }

        auto &first_context_data = *context_->context_data();
        auto &coeff_small_ntt_tables = first_context_data.small_ntt_tables();

        // Check if Galois key is generated or not.
        // If not, attempt a bit decomposition; maybe we have log(n) many keys
        if (!galois_keys.has_key(galois_elt))
        {
            // galois_elt = 3^order1 * (-1)^order2
            uint64_t order1 = Zmstar_to_generator_.at(galois_elt).first;
            uint64_t order2 = Zmstar_to_generator_.at(galois_elt).second;

            // We use either 3 or -3 as our generator, depending on which gives smaller HW
            uint64_t two_power_of_gen = 3;

            // Does order1 or n/2-order1 have smaller Hamming weight?
            if (hamming_weight(subgroup_size - order1) < hamming_weight(order1))
            {
                order1 = subgroup_size - order1;
                try_mod_inverse(3, m, two_power_of_gen);
            }

            while(order1)
            {
                if (order1 & 1)
                {
                    if (!galois_keys.has_key(two_power_of_gen))
                    {
                        throw invalid_argument("galois key not present");
                    }
                    apply_galois_inplace(encrypted, two_power_of_gen, galois_keys, pool);
                }
                two_power_of_gen = mul_safe(two_power_of_gen, two_power_of_gen);
                two_power_of_gen &= (m - 1);
                order1 >>= 1;
            }
            if (order2)
            {
                if (!galois_keys.has_key(m - 1))
                {
                    throw invalid_argument("galois key not present");
                }
                apply_galois_inplace(encrypted, m - 1, galois_keys, pool);
            }
            return;
        }

        // Check the Galois key for galois_elt at this point.
        for (auto &b : galois_keys.key(galois_elt))
        {
            if (!b.is_metadata_valid_for(context_) || !b.is_ntt_form() || 
                b.parms_id() != galois_keys.parms_id())
            {
                throw invalid_argument("galois_keys is not valid for encryption parameters");
            }
        }

        auto temp0(allocate_zero_uint(coeff_count * coeff_mod_count, pool));
        auto temp1(allocate_zero_uint(coeff_count * coeff_mod_count, pool));

        if (parms.scheme() == scheme_type::BFV)
        {
            // Apply Galois for each ciphertext
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                util::apply_galois(encrypted.data() + (i * coeff_count), n_power_of_two,
                    galois_elt, coeff_modulus[i], temp0.get() + (i * coeff_count));
            }
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                util::apply_galois(encrypted.data(1) + (i * coeff_count), n_power_of_two,
                    galois_elt, coeff_modulus[i], temp1.get() + (i * coeff_count));
            }
        }
        else if (parms.scheme() == scheme_type::CKKS)
        {
            // Apply Galois for each ciphertext
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                util::apply_galois_ntt(encrypted.data() + (i * coeff_count), n_power_of_two,
                    galois_elt, temp0.get() + (i * coeff_count));
            }
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                util::apply_galois_ntt(encrypted.data(1) + (i * coeff_count), n_power_of_two,
                    galois_elt, temp1.get() + (i * coeff_count));
            }

            // Transform ct[1] from NTT
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                inverse_ntt_negacyclic_harvey(temp1.get() + (i * coeff_count),
                    coeff_small_ntt_tables[i]);
            }
        }
        else
        {
            throw logic_error("scheme not implemented");
        }

        // Calculate (temp1 * galois_key.first, temp1 * galois_key.second) + (temp0, 0)
        const uint64_t *encrypted_coeff = temp1.get();

        // decompose encrypted_array[count-1] into base w
        // want to create an array of polys, each of whose components i is
        // (encrypted_array[count-1])^(i) - in the notation of FV paper.
        // This allocation stores one of the decomposed factors modulo one of the primes.
        auto decomp_encrypted_last(allocate_uint(coeff_count, pool));

        // Lazy reduction
        auto wide_innerresult0(allocate_zero_poly(coeff_count, 2 * coeff_mod_count, pool));
        auto wide_innerresult1(allocate_zero_poly(coeff_count, 2 * coeff_mod_count, pool));
        auto innerresult(allocate_poly(coeff_count, coeff_mod_count, pool));
        auto temp_decomp_coeff(allocate_uint(coeff_count, pool));

        /*
        For lazy reduction to work here, we need to ensure that the 128-bit accumulators
        (wide_innerresult0 and wide_innerresult1) do not overflow. Since the modulus primes
        are at most 60 bits, if the total number of summands is K, then the size of the
        total sum of products (without reduction) is at most 62 + 60 + bit_length(K).
        We need this to be at most 128, thus we need bit_length(K) <= 6. Thus, we need K <= 63.
        In this case, this means sum_i galois_keys.key(galois_elt)[i].size() / 2 <= 63.
        */
        for (size_t i = 0; i < coeff_mod_count; i++, encrypted_coeff += coeff_count)
        {
            // We use HPS improvement to Bajard's RNS key switching so scaling by q_i/q not needed
            // multiply_poly_scalar_coeffmod(
            //     encrypted_coeff, coeff_count,
            //     inv_coeff_products_mod_coeff_array[i], coeff_modulus[i],
            //     encrypted_coeff_prod_inv_coeff.get());

            int shift = 0;
            auto &key_component_ref = galois_keys.key(galois_elt)[i];
            size_t keys_size = key_component_ref.size();
            for (size_t k = 0; k < keys_size; k += 2)
            {
                const uint64_t *key_ptr_0 = key_component_ref.data(k);
                const uint64_t *key_ptr_1 = key_component_ref.data(k + 1);

                // Decompose here
                int decomposition_bit_count = galois_keys.decomposition_bit_count();
                for (size_t coeff_index = 0; coeff_index < coeff_count; coeff_index++)
                {
                    decomp_encrypted_last[coeff_index] = 
                        encrypted_coeff[coeff_index] >> shift;
                    decomp_encrypted_last[coeff_index] &= 
                        (uint64_t(1) << decomposition_bit_count) - 1;
                }

                uint64_t *wide_innerresult0_ptr = wide_innerresult0.get();
                uint64_t *wide_innerresult1_ptr = wide_innerresult1.get();
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    uint64_t *temp_decomp_coeff_ptr = temp_decomp_coeff.get();
                    set_uint_uint(decomp_encrypted_last.get(), coeff_count, temp_decomp_coeff_ptr);

                    // We don't reduce here, so might get up to two extra bits. Thus 62 bits at most.
                    ntt_negacyclic_harvey_lazy(temp_decomp_coeff_ptr, coeff_small_ntt_tables[j]);

                    // Lazy reduction
                    unsigned long long wide_innerproduct[2];
                    unsigned long long temp;
                    for (size_t l = 0; l < coeff_count; l++, wide_innerresult0_ptr += 2)
                    {
                        multiply_uint64(*temp_decomp_coeff_ptr++, *key_ptr_0++, wide_innerproduct);
                        unsigned char carry = add_uint64(wide_innerresult0_ptr[0],
                            wide_innerproduct[0], &temp);
                        wide_innerresult0_ptr[0] = temp;
                        wide_innerresult0_ptr[1] += wide_innerproduct[1] + carry;
                    }

                    temp_decomp_coeff_ptr = temp_decomp_coeff.get();
                    for (size_t l = 0; l < coeff_count; l++, wide_innerresult1_ptr += 2)
                    {
                        multiply_uint64(*temp_decomp_coeff_ptr++, *key_ptr_1++, wide_innerproduct);
                        unsigned char carry = add_uint64(wide_innerresult1_ptr[0],
                            wide_innerproduct[0], &temp);
                        wide_innerresult1_ptr[0] = temp;
                        wide_innerresult1_ptr[1] += wide_innerproduct[1] + carry;
                    }
                }
                shift += decomposition_bit_count;
            }
        }

        uint64_t *temp_ptr = temp0.get();
        uint64_t *innerresult_poly_ptr = innerresult.get();
        uint64_t *wide_innerresult_poly_ptr = wide_innerresult0.get();
        uint64_t *encrypted_ptr = encrypted.data();
        uint64_t *innerresult_coeff_ptr = innerresult_poly_ptr;
        uint64_t *wide_innerresult_coeff_ptr = wide_innerresult_poly_ptr;
        for (size_t i = 0; i < coeff_mod_count; i++, innerresult_poly_ptr += coeff_count,
            wide_innerresult_poly_ptr += 2 * coeff_count, encrypted_ptr += coeff_count,
            temp_ptr += coeff_count)
        {
            for (size_t k = 0; k < coeff_count; 
                k++, wide_innerresult_coeff_ptr += 2, innerresult_coeff_ptr++)
            {
                *innerresult_coeff_ptr = barrett_reduce_128(
                    wide_innerresult_coeff_ptr, coeff_modulus[i]);
            }
            if (parms.scheme() == scheme_type::BFV)
            {
                inverse_ntt_negacyclic_harvey(innerresult_poly_ptr, 
                    coeff_small_ntt_tables[i]);
            }
            add_poly_poly_coeffmod(temp_ptr, innerresult_poly_ptr, coeff_count,
                coeff_modulus[i], encrypted_ptr);
        }

        innerresult_poly_ptr = innerresult.get();
        wide_innerresult_poly_ptr = wide_innerresult1.get();
        encrypted_ptr = encrypted.data(1);
        wide_innerresult_coeff_ptr = wide_innerresult_poly_ptr;
        for (size_t i = 0; i < coeff_mod_count; i++, innerresult_poly_ptr += coeff_count,
            wide_innerresult_poly_ptr += 2 * coeff_count, encrypted_ptr += coeff_count)
        {
            innerresult_coeff_ptr = encrypted_ptr;
            for (size_t k = 0; k < coeff_count; 
                k++, wide_innerresult_coeff_ptr += 2, innerresult_coeff_ptr++)
            {
                *innerresult_coeff_ptr = barrett_reduce_128(
                    wide_innerresult_coeff_ptr, coeff_modulus[i]);
            }
            if (parms.scheme() == scheme_type::BFV)
            {
                inverse_ntt_negacyclic_harvey(encrypted_ptr, coeff_small_ntt_tables[i]);
            }
        }

        // If CKKS, mark encrypted as NTT form
        if (parms.scheme() == scheme_type::CKKS)
        {
            encrypted.is_ntt_form() = true;
        }
#ifndef SEAL_ALLOW_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::rotate_internal(Ciphertext &encrypted, int steps,
        const GaloisKeys &galois_keys, MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!encrypted.is_metadata_valid_for(context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto &context_data = *context_->context_data(encrypted.parms_id());
        if (!context_data.qualifiers().using_batching)
        {
            throw logic_error("encryption parameters do not support batching");
        }

        // Is there anything to do?
        if (steps == 0)
        {
            return;
        }

        size_t coeff_count = context_data.parms().poly_modulus_degree();

        // Perform rotation and key switching
        apply_galois_inplace(encrypted, 
            steps_to_galois_elt(steps, coeff_count), 
            galois_keys, move(pool));
    }
}
