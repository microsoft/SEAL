// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/context.h"
#include "seal/util/pointer.h"
#include "seal/util/polycore.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/numth.h"
#include <utility>
#include <stdexcept>

using namespace std;
using namespace seal::util;

namespace seal
{
    SEALContext::ContextData SEALContext::validate(EncryptionParameters parms)
    {
        ContextData context_data(parms, pool_);
        context_data.qualifiers_.parameters_set = true;

        auto &coeff_modulus = parms.coeff_modulus();
        auto &plain_modulus = parms.plain_modulus();

        // The number of coeff moduli is restricted to 62 for lazy reductions
        // in baseconverter.cpp to work
        if (coeff_modulus.size() > SEAL_COEFF_MOD_COUNT_MAX ||
            coeff_modulus.size() < SEAL_COEFF_MOD_COUNT_MIN)
        {
            context_data.qualifiers_.parameters_set = false;
            return context_data;
        }

        size_t coeff_mod_count = coeff_modulus.size();
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // Check coefficient moduli bounds
            if (coeff_modulus[i].value() >> SEAL_USER_MOD_BIT_COUNT_MAX ||
                !(coeff_modulus[i].value() >> (SEAL_USER_MOD_BIT_COUNT_MIN - 1)))
            {
                context_data.qualifiers_.parameters_set = false;
                return context_data;
            }

            // Check that all coeff moduli are pairwise relatively prime
            for (size_t j = 0; j < i; j++)
            {
                if (gcd(coeff_modulus[i].value(), coeff_modulus[j].value()) > 1)
                {
                    context_data.qualifiers_.parameters_set = false;
                    return context_data;
                }
            }
        }

        // Compute the product of all coeff moduli
        context_data.total_coeff_modulus_ = allocate_uint(coeff_mod_count, pool_);
        auto temp(allocate_uint(coeff_mod_count, pool_));
        set_uint(1, coeff_mod_count, context_data.total_coeff_modulus_.get());
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            multiply_uint_uint64(context_data.total_coeff_modulus_.get(),
                coeff_mod_count, coeff_modulus[i].value(), coeff_mod_count,
                temp.get());
            set_uint_uint(temp.get(), coeff_mod_count,
                context_data.total_coeff_modulus_.get());
        }
        context_data.total_coeff_modulus_bit_count_ = get_significant_bit_count_uint(
            context_data.total_coeff_modulus_.get(), coeff_mod_count);

        // Check polynomial modulus degree and create poly_modulus
        size_t poly_modulus_degree = parms.poly_modulus_degree();
        int coeff_count_power = get_power_of_two(poly_modulus_degree);
        if (poly_modulus_degree < SEAL_POLY_MOD_DEGREE_MIN ||
            poly_modulus_degree > SEAL_POLY_MOD_DEGREE_MAX ||
            coeff_count_power < 0)
        {
            // Parameters are not valid
            context_data.qualifiers_.parameters_set = false;
            return context_data;
        }

        // Quick sanity check
        if (!product_fits_in(coeff_mod_count, poly_modulus_degree))
        {
            throw logic_error("invalid parameters");
        }

        // Polynomial modulus X^(2^k) + 1 is guaranteed at this point
        context_data.qualifiers_.using_fft = true;

        // Assume parameters satisfy desired security level
        context_data.qualifiers_.sec_level = sec_level_;

        // Check if the parameters are secure according to HomomorphicEncryption.org
        // security standard
        if (context_data.total_coeff_modulus_bit_count_ >
            CoeffModulus::MaxBitCount(poly_modulus_degree, sec_level_))
        {
            // Not secure according to HomomorphicEncryption.org security standard
            context_data.qualifiers_.sec_level = sec_level_type::none;
            if (sec_level_ != sec_level_type::none)
            {
                // Parameters are not valid
                context_data.qualifiers_.parameters_set = false;
                return context_data;
            }
        }

        // Can we use NTT with coeff_modulus?
        context_data.qualifiers_.using_ntt = true;
        context_data.small_ntt_tables_ =
            allocate<SmallNTTTables>(coeff_mod_count, pool_, pool_);
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            if (!context_data.small_ntt_tables_[i].generate(coeff_count_power,
                coeff_modulus[i]))
            {
                // Parameters are not valid
                context_data.qualifiers_.using_ntt = false;
                context_data.qualifiers_.parameters_set = false;
                return context_data;
            }
        }

        if (parms.scheme() == scheme_type::BFV)
        {
            // Plain modulus must be at least 2 and at most 60 bits
            if (plain_modulus.value() >> SEAL_PLAIN_MOD_MAX ||
                !(plain_modulus.value() >> (SEAL_PLAIN_MOD_MIN - 1)))
            {
                context_data.qualifiers_.parameters_set = false;
                return context_data;
            }

            // Check that all coeff moduli are relatively prime to plain_modulus
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                if (gcd(coeff_modulus[i].value(), plain_modulus.value()) > 1)
                {
                    context_data.qualifiers_.parameters_set = false;
                    return context_data;
                }
            }

            // Check that plain_modulus is smaller than total coeff modulus
            if (!is_less_than_uint_uint(plain_modulus.data(), plain_modulus.uint64_count(),
                context_data.total_coeff_modulus_.get(), coeff_mod_count))
            {
                // Parameters are not valid
                context_data.qualifiers_.parameters_set = false;
                return context_data;
            }

            // Can we use batching? (NTT with plain_modulus)
            context_data.qualifiers_.using_batching = false;
            context_data.plain_ntt_tables_ = allocate<SmallNTTTables>(pool_);
            if (context_data.plain_ntt_tables_->generate(coeff_count_power, plain_modulus))
            {
                context_data.qualifiers_.using_batching = true;
            }

            // Check for plain_lift
            // If all the small coefficient moduli are larger than plain modulus,
            // we can quickly lift plain coefficients to RNS form
            context_data.qualifiers_.using_fast_plain_lift = true;
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                context_data.qualifiers_.using_fast_plain_lift &=
                    (coeff_modulus[i].value() > plain_modulus.value());
            }

            // Calculate coeff_div_plain_modulus (BFV-"Delta") and the remainder
            // upper_half_increment
            context_data.coeff_div_plain_modulus_ = allocate_uint(coeff_mod_count, pool_);
            context_data.upper_half_increment_ = allocate_uint(coeff_mod_count, pool_);
            auto wide_plain_modulus(duplicate_uint_if_needed(plain_modulus.data(),
                plain_modulus.uint64_count(), coeff_mod_count, false, pool_));
            divide_uint_uint(context_data.total_coeff_modulus_.get(),
                wide_plain_modulus.get(), coeff_mod_count,
                context_data.coeff_div_plain_modulus_.get(),
                context_data.upper_half_increment_.get(), pool_);

            // Decompose coeff_div_plain_modulus into RNS factors
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                temp[i] = modulo_uint(context_data.coeff_div_plain_modulus_.get(),
                    coeff_mod_count, coeff_modulus[i], pool_);
            }
            set_uint_uint(temp.get(), coeff_mod_count,
                context_data.coeff_div_plain_modulus_.get());

            // Decompose upper_half_increment into RNS factors
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                temp[i] = modulo_uint(context_data.upper_half_increment_.get(),
                    coeff_mod_count, coeff_modulus[i], pool_);
            }
            set_uint_uint(temp.get(), coeff_mod_count,
                context_data.upper_half_increment_.get());

            // Calculate (plain_modulus + 1) / 2.
            context_data.plain_upper_half_threshold_ = (plain_modulus.value() + 1) >> 1;

            // Calculate coeff_modulus - plain_modulus.
            context_data.plain_upper_half_increment_ =
                allocate_uint(coeff_mod_count, pool_);
            if (context_data.qualifiers_.using_fast_plain_lift)
            {
                // Calculate coeff_modulus[i] - plain_modulus if using_fast_plain_lift
                for (size_t i = 0; i < coeff_mod_count; i++)
                {
                    context_data.plain_upper_half_increment_[i] =
                        coeff_modulus[i].value() - plain_modulus.value();
                }
            }
            else
            {
                sub_uint_uint(context_data.total_coeff_modulus(),
                    wide_plain_modulus.get(), coeff_mod_count,
                    context_data.plain_upper_half_increment_.get());
            }
        }
        else if (parms.scheme() == scheme_type::CKKS)
        {
            // Check that plain_modulus is set to zero
            if (!plain_modulus.is_zero())
            {
                // Parameters are not valid
                context_data.qualifiers_.parameters_set = false;
                return context_data;
            }

            // When using CKKS batching (BatchEncoder) is always enabled
            context_data.qualifiers_.using_batching = true;

            // Cannot use fast_plain_lift for CKKS since the plaintext coefficients
            // can easily be larger than coefficient moduli
            context_data.qualifiers_.using_fast_plain_lift = false;

            // Calculate 2^64 / 2 (most negative plaintext coefficient value)
            context_data.plain_upper_half_threshold_ = uint64_t(1) << 63;

            // Calculate plain_upper_half_increment = 2^64 mod coeff_modulus for CKKS plaintexts
            context_data.plain_upper_half_increment_ = allocate_uint(coeff_mod_count, pool_);
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                uint64_t tmp = (uint64_t(1) << 63) % coeff_modulus[i].value();
                context_data.plain_upper_half_increment_[i] = multiply_uint_uint_mod(
                    tmp,
                    sub_safe(coeff_modulus[i].value(), uint64_t(2)),
                    coeff_modulus[i]);
            }

            // Compute the upper_half_threshold for this modulus.
            context_data.upper_half_threshold_ = allocate_uint(
                coeff_mod_count, pool_);
            increment_uint(context_data.total_coeff_modulus(),
                coeff_mod_count, context_data.upper_half_threshold_.get());
            right_shift_uint(context_data.upper_half_threshold_.get(), 1,
                coeff_mod_count, context_data.upper_half_threshold_.get());
        }
        else
        {
            throw invalid_argument("unsupported scheme");
        }

        // Create BaseConverter
        context_data.base_converter_ = allocate<BaseConverter>(pool_, pool_);
        context_data.base_converter_->generate(coeff_modulus, poly_modulus_degree,
            plain_modulus);
        if (!context_data.base_converter_->is_generated())
        {
            // Parameters are not valid
            context_data.qualifiers_.parameters_set = false;
            return context_data;
        }

        // Check whether the coefficient modulus consists of a set of primes that
        // are in decreasing order
        context_data.qualifiers_.using_descending_modulus_chain = true;
        for (size_t i = 0; i < coeff_mod_count - 1; i++)
        {
            context_data.qualifiers_.using_descending_modulus_chain
                &= (coeff_modulus[i].value() > coeff_modulus[i + 1].value());
        }

        // Done with validation and pre-computations
        return context_data;
    }

    parms_id_type SEALContext::create_next_context_data(
        const parms_id_type &prev_parms_id)
    {
        // Create the next set of parameters by removing last modulus
        auto next_parms = context_data_map_.at(prev_parms_id)->parms_;
        auto next_coeff_modulus = next_parms.coeff_modulus();
        next_coeff_modulus.pop_back();
        next_parms.set_coeff_modulus(next_coeff_modulus);
        auto next_parms_id = next_parms.parms_id();

        // Validate next parameters and create next context_data
        auto next_context_data = validate(next_parms);

        // If not valid then return zero parms_id
        if (!next_context_data.qualifiers_.parameters_set)
        {
            return parms_id_zero;
        }

        // Add them to the context_data_map_
        context_data_map_.emplace(make_pair(next_parms_id,
            make_shared<const ContextData>(move(next_context_data))));

        // Add pointer to next context_data to the previous one (linked list)
        // Add pointer to previous context_data to the next one (doubly linked list)
        // We need to remove constness first to modify this
        const_pointer_cast<ContextData>(
            context_data_map_.at(prev_parms_id))->next_context_data_ =
                context_data_map_.at(next_parms_id);
        const_pointer_cast<ContextData>(
            context_data_map_.at(next_parms_id))->prev_context_data_ =
                context_data_map_.at(prev_parms_id);

        return next_parms_id;
    }

    SEALContext::SEALContext(EncryptionParameters parms, bool expand_mod_chain,
        sec_level_type sec_level, MemoryPoolHandle pool)
        : pool_(move(pool)), sec_level_(sec_level)
    {
        if (!pool_)
        {
            throw invalid_argument("pool is uninitialized");
        }

        // Set random generator
        if (!parms.random_generator())
        {
            parms.set_random_generator(
                UniformRandomGeneratorFactory::default_factory());
        }

        // Validate parameters and add new ContextData to the map
        // Note that this happens even if parameters are not valid

        // First create key_parms_id_.
        context_data_map_.emplace(make_pair(parms.parms_id(),
            make_shared<const ContextData>(validate(parms))));
        key_parms_id_ = parms.parms_id();

        // Then create first_parms_id_ if the parameters are valid and there is
        // more than one modulus in coeff_modulus. This is equivalent to expanding
        // the chain by one step. Otherwise, we set first_parms_id_ to equal
        // key_parms_id_.
        if (!context_data_map_.at(key_parms_id_)->qualifiers_.parameters_set ||
            parms.coeff_modulus().size() == 1)
        {
            first_parms_id_ = key_parms_id_;
        }
        else
        {
            auto next_parms_id = create_next_context_data(key_parms_id_);
            first_parms_id_ = (next_parms_id == parms_id_zero) ?
                key_parms_id_ : next_parms_id;
        }

        // Set last_parms_id_ to point to first_parms_id_
        last_parms_id_ = first_parms_id_;

        // Check if keyswitching is available
        using_keyswitching_ = (first_parms_id_ != key_parms_id_);

        // If modulus switching chain is to be created, compute the remaining
        // parameter sets as long as they are valid to use (parameters_set == true)
        if (expand_mod_chain &&
            context_data_map_.at(first_parms_id_)->qualifiers_.parameters_set)
        {
            auto prev_parms_id = first_parms_id_;
            while (context_data_map_.at(prev_parms_id)->parms().coeff_modulus().size() > 1)
            {
                auto next_parms_id = create_next_context_data(prev_parms_id);
                if (next_parms_id == parms_id_zero)
                {
                    break;
                }
                prev_parms_id = next_parms_id;
                last_parms_id_ = next_parms_id;
            }
        }

        // Set the chain_index for each context_data
        size_t parms_count = context_data_map_.size();
        auto context_data_ptr = context_data_map_.at(key_parms_id_);
        while (context_data_ptr)
        {
            // We need to remove constness first to modify this
            const_pointer_cast<ContextData>(
                context_data_ptr)->chain_index_ = --parms_count;
            context_data_ptr = context_data_ptr->next_context_data_;
        }
    }
}
