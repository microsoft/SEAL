// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ciphertext.h"
#include "seal/util/polycore.h"

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
        parms_id_type parms_id, size_type size_capacity)
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

        reserve_internal(size_capacity, parms.poly_modulus_degree(),
            safe_cast<size_type>(parms.coeff_modulus().size()));
    }

    void Ciphertext::reserve_internal(size_type size_capacity,
        size_type poly_modulus_degree, size_type coeff_mod_count)
    {
        if (size_capacity < SEAL_CIPHERTEXT_SIZE_MIN ||
            size_capacity > SEAL_CIPHERTEXT_SIZE_MAX)
        {
            throw invalid_argument("invalid size_capacity");
        }

        size_type new_data_capacity =
            mul_safe(size_capacity, poly_modulus_degree, coeff_mod_count);
        size_type new_data_size = min<size_type>(new_data_capacity, data_.size());

        // First reserve, then resize
        data_.reserve(new_data_capacity);
        data_.resize(new_data_size);

        // Set the size
        size_ = min<size_type>(size_capacity, size_);
        poly_modulus_degree_ = poly_modulus_degree;
        coeff_mod_count_ = coeff_mod_count;
    }

    void Ciphertext::resize(shared_ptr<SEALContext> context,
        parms_id_type parms_id, size_type size)
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

        resize_internal(size, parms.poly_modulus_degree(),
            safe_cast<size_type>(parms.coeff_modulus().size()));
    }

    void Ciphertext::resize_internal(size_type size,
        size_type poly_modulus_degree, size_type coeff_mod_count)
    {
        if ((size < SEAL_CIPHERTEXT_SIZE_MIN && size != 0) ||
            size > SEAL_CIPHERTEXT_SIZE_MAX)
        {
            throw invalid_argument("invalid size");
        }

        // Resize the data
        size_type new_data_size =
            mul_safe(size, poly_modulus_degree, coeff_mod_count);
        data_.resize(new_data_size);

        // Set the size parameters
        size_ = size;
        poly_modulus_degree_ = poly_modulus_degree;
        coeff_mod_count_ = coeff_mod_count;
    }

    void Ciphertext::save(ostream &stream) const
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

            // Save the data
            data_.save(stream);
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }

        stream.exceptions(old_except_mask);
    }

    void Ciphertext::unsafe_load(istream &stream)
    {
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

            // Load the data
            new_data.data_.load(stream);
            if (unsigned_neq(new_data.data_.size(),
                mul_safe(size64, poly_modulus_degree64, coeff_mod_count64)))
            {
                throw invalid_argument("ciphertext data is invalid");
            }

            // Set values
            new_data.parms_id_ = parms_id;
            new_data.is_ntt_form_ = (is_ntt_form_byte == SEAL_BYTE(0)) ? false : true;
            new_data.size_ = safe_cast<size_type>(size64);
            new_data.poly_modulus_degree_ = safe_cast<size_type>(poly_modulus_degree64);
            new_data.coeff_mod_count_ = safe_cast<size_type>(coeff_mod_count64);
            new_data.scale_ = scale;
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);

        swap(*this, new_data);
    }
}