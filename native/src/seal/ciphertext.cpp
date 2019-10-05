// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ciphertext.h"
#include "seal/randomgen.h"
#include "seal/util/defines.h"
#include "seal/util/polyarithsmallmod.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    Ciphertext &Ciphertext::operator =(const Ciphertext &assign)
    {
        // Check for self-assignment
        if (this == &assign)
        {
            return *this;
        }

        // Copy over fields
        parms_id_ = assign.parms_id_;
        is_ntt_form_ = assign.is_ntt_form_;
        scale_ = assign.scale_;

        // Then resize
        resize_internal(assign.size_, assign.poly_modulus_degree_,
            assign.coeff_mod_count_);

        // Size is guaranteed to be OK now so copy over
        copy(assign.data_.cbegin(), assign.data_.cend(), data_.begin());

        return *this;
    }

    void Ciphertext::reserve(shared_ptr<SEALContext> context,
        parms_id_type parms_id, size_t size_capacity)
    {
        // Verify parameters
        if (!context)
        {
            throw invalid_argument("invalid context");
        }
        if (!context->parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        auto context_data_ptr = context->get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        // Need to set parms_id first
        auto &parms = context_data_ptr->parms();
        parms_id_ = context_data_ptr->parms_id();

        reserve_internal(size_capacity,
            parms.poly_modulus_degree(), parms.coeff_modulus().size());
    }

    void Ciphertext::reserve_internal(size_t size_capacity,
        size_t poly_modulus_degree, size_t coeff_mod_count)
    {
        if (size_capacity < SEAL_CIPHERTEXT_SIZE_MIN ||
            size_capacity > SEAL_CIPHERTEXT_SIZE_MAX)
        {
            throw invalid_argument("invalid size_capacity");
        }

        size_t new_data_capacity =
            mul_safe(size_capacity, poly_modulus_degree, coeff_mod_count);
        size_t new_data_size = min<size_t>(new_data_capacity, data_.size());

        // First reserve, then resize
        data_.reserve(new_data_capacity);
        data_.resize(new_data_size);

        // Set the size
        size_ = min<size_t>(size_capacity, size_);
        poly_modulus_degree_ = poly_modulus_degree;
        coeff_mod_count_ = coeff_mod_count;
    }

    void Ciphertext::resize(shared_ptr<SEALContext> context,
        parms_id_type parms_id, size_t size)
    {
        // Verify parameters
        if (!context)
        {
            throw invalid_argument("invalid context");
        }
        if (!context->parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        auto context_data_ptr = context->get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        // Need to set parms_id first
        auto &parms = context_data_ptr->parms();
        parms_id_ = context_data_ptr->parms_id();

        resize_internal(size,
            parms.poly_modulus_degree(), parms.coeff_modulus().size());
    }

    void Ciphertext::resize_internal(size_t size,
        size_t poly_modulus_degree, size_t coeff_mod_count)
    {
        if ((size < SEAL_CIPHERTEXT_SIZE_MIN && size != 0) ||
            size > SEAL_CIPHERTEXT_SIZE_MAX)
        {
            throw invalid_argument("invalid size");
        }

        // Resize the data
        size_t new_data_size =
            mul_safe(size, poly_modulus_degree, coeff_mod_count);
        data_.resize(new_data_size);

        // Set the size parameters
        size_ = size;
        poly_modulus_degree_ = poly_modulus_degree;
        coeff_mod_count_ = coeff_mod_count;
    }

    void Ciphertext::expand_seed(
        shared_ptr<SEALContext> context,
        const random_seed_type &seed)
    {
        auto context_data_ptr = context->get_context_data(parms_id_);
        auto &coeff_modulus = context_data_ptr->parms().coeff_modulus();

        // Set up the BlakePRNG with appropriate non-default buffer size
        // and given seed.
        BlakePRNG rg(seed);

        // Flood the entire ciphertext polynomial with random data
        rg.generate(
            mul_safe(data_.size(), sizeof(ct_coeff_type)),
            reinterpret_cast<SEAL_BYTE*>(data_.begin()));

        // Finally reduce each polynomial appropriately
        auto data_ptr = data_.begin();
        for (size_t poly_index = 0; poly_index < size_; poly_index++)
        {
            for (size_t rns_index = 0; rns_index < coeff_mod_count_; rns_index++)
            {
                // Clear top bits from each coefficient
                transform(data_ptr, data_ptr + poly_modulus_degree_, data_ptr,
                    [](auto in) {
                        return in & static_cast<ct_coeff_type>(0x7FFFFFFFFFFFFFFFULL);
                    });

                // Then reduce; unfortunately we do two passes over the data here
                modulo_poly_coeffs_63(
                    data_ptr,
                    poly_modulus_degree_,
                    coeff_modulus[rns_index],
                    data_ptr); 
            }
        }
    }

    void Ciphertext::save_members(ostream &stream) const
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            stream.write(reinterpret_cast<const char*>(&parms_id_), sizeof(parms_id_type));
            SEAL_BYTE is_ntt_form_byte = static_cast<SEAL_BYTE>(is_ntt_form_);
            stream.write(reinterpret_cast<const char*>(&is_ntt_form_byte), sizeof(SEAL_BYTE));
            uint64_t size64 = safe_cast<uint64_t>(size_);
            stream.write(reinterpret_cast<const char*>(&size64), sizeof(uint64_t));
            uint64_t poly_modulus_degree64 = safe_cast<uint64_t>(poly_modulus_degree_);
            stream.write(reinterpret_cast<const char*>(&poly_modulus_degree64), sizeof(uint64_t));
            uint64_t coeff_mod_count64 = safe_cast<uint64_t>(coeff_mod_count_);
            stream.write(reinterpret_cast<const char*>(&coeff_mod_count64), sizeof(uint64_t));
            stream.write(reinterpret_cast<const char*>(&scale_), sizeof(double));

            // Save the IntArray
            data_.save(stream, compr_mode_type::none);
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);
    }

    void Ciphertext::load_members(shared_ptr<SEALContext> context, istream &stream)
    {
        // Verify parameters
        if (!context)
        {
            throw invalid_argument("invalid context");
        }
        if (!context->parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        Ciphertext new_data(data_.pool());

        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            parms_id_type parms_id{};
            stream.read(reinterpret_cast<char*>(&parms_id), sizeof(parms_id_type));
            SEAL_BYTE is_ntt_form_byte;
            stream.read(reinterpret_cast<char*>(&is_ntt_form_byte), sizeof(SEAL_BYTE));
            uint64_t size64 = 0;
            stream.read(reinterpret_cast<char*>(&size64), sizeof(uint64_t));
            uint64_t poly_modulus_degree64 = 0;
            stream.read(reinterpret_cast<char*>(&poly_modulus_degree64), sizeof(uint64_t));
            uint64_t coeff_mod_count64 = 0;
            stream.read(reinterpret_cast<char*>(&coeff_mod_count64), sizeof(uint64_t));
            double scale = 0;
            stream.read(reinterpret_cast<char*>(&scale), sizeof(double));

            // Set values already at this point for the metadata validity check
            new_data.parms_id_ = parms_id;
            new_data.is_ntt_form_ = (is_ntt_form_byte == SEAL_BYTE(0)) ? false : true;
            new_data.size_ = safe_cast<size_t>(size64);
            new_data.poly_modulus_degree_ = safe_cast<size_t>(poly_modulus_degree64);
            new_data.coeff_mod_count_ = safe_cast<size_t>(coeff_mod_count64);
            new_data.scale_ = scale;

            // Checking the validity of loaded metadata
            // Note: We allow pure key levels here! This is to allow load_members
            // to be used also when loading derived objects like PublicKey. This
            // further means that functions reading in Ciphertext objects must check
            // that for those use-cases the Ciphertext truly is at the data level
            // if it is supposed to be. In other words, one cannot assume simply
            // based on load_members succeeding that the Ciphertext is valid for
            // computations.
            if (!is_metadata_valid_for(new_data, context, true))
            {
                throw logic_error("ciphertext data is invalid");
            }

            // Compute the total uint64 count required and reserve memory.
            // Note that this must be done after the metadata is checked for validity.
            auto total_uint64_count = mul_safe(
                new_data.size_,
                new_data.poly_modulus_degree_,
                new_data.coeff_mod_count_);

            // Reserve memory for the entire (expected) ciphertext data
            new_data.data_.reserve(total_uint64_count);

            // Load the data. Note that we are supplying also the expected maximum
            // size of the loaded IntArray. This is an important security measure to
            // prevent a malformed IntArray from causing arbitrarily large memory
            // allocations.
            new_data.data_.load(stream, total_uint64_count);

            // Expected buffer size in the seeded case
            auto seeded_uint64_count = poly_modulus_degree64 * coeff_mod_count64;

            // This is the case where we need to expand a seed, otherwise full
            // ciphertext data was (possibly) loaded and do nothing
            if (unsigned_eq(new_data.data_.size(), seeded_uint64_count))
            {
                // Single polynomial size data was loaded, so we are in the
                // seeded ciphertext case. Next load the seed.
                random_seed_type seed;
                stream.read(reinterpret_cast<char*>(&seed), sizeof(random_seed_type));
                new_data.expand_seed(move(context), seed);
            }

            // Verify that the buffer is correct
            if (!is_buffer_valid(new_data))
            {
                throw logic_error("ciphertext data is invalid");
            }
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);

        swap(*this, new_data);
    }
}
