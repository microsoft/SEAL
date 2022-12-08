// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ciphertext.h"
#include "seal/util/defines.h"
#include "seal/util/pointer.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/rlwe.h"
#include <algorithm>

using namespace std;
using namespace seal::util;

namespace seal
{
    Ciphertext &Ciphertext::operator=(const Ciphertext &assign)
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
        correction_factor_ = assign.correction_factor_;

        // Then resize
        resize_internal(assign.size_, assign.poly_modulus_degree_, assign.coeff_modulus_size_);

        // Size is guaranteed to be OK now so copy over
        copy(assign.data_.cbegin(), assign.data_.cend(), data_.begin());

        return *this;
    }

    void Ciphertext::reserve(const SEALContext &context, parms_id_type parms_id, size_t size_capacity)
    {
        // Verify parameters
        if (!context.parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        auto context_data_ptr = context.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        // Need to set parms_id first
        auto &parms = context_data_ptr->parms();
        parms_id_ = context_data_ptr->parms_id();

        reserve_internal(size_capacity, parms.poly_modulus_degree(), parms.coeff_modulus().size());
    }

    void Ciphertext::reserve_internal(size_t size_capacity, size_t poly_modulus_degree, size_t coeff_modulus_size)
    {
        if (size_capacity < SEAL_CIPHERTEXT_SIZE_MIN || size_capacity > SEAL_CIPHERTEXT_SIZE_MAX)
        {
            throw invalid_argument("invalid size_capacity");
        }

        size_t new_data_capacity = mul_safe(size_capacity, poly_modulus_degree, coeff_modulus_size);
        size_t new_data_size = min<size_t>(new_data_capacity, data_.size());

        // First reserve, then resize
        data_.reserve(new_data_capacity);
        data_.resize(new_data_size);

        // Set the size
        size_ = min<size_t>(size_capacity, size_);
        poly_modulus_degree_ = poly_modulus_degree;
        coeff_modulus_size_ = coeff_modulus_size;
    }

    void Ciphertext::resize(const SEALContext &context, parms_id_type parms_id, size_t size)
    {
        // Verify parameters
        if (!context.parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        auto context_data_ptr = context.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        // Need to set parms_id first
        auto &parms = context_data_ptr->parms();
        parms_id_ = context_data_ptr->parms_id();

        resize_internal(size, parms.poly_modulus_degree(), parms.coeff_modulus().size());
    }

    void Ciphertext::resize_internal(size_t size, size_t poly_modulus_degree, size_t coeff_modulus_size)
    {
        if ((size < SEAL_CIPHERTEXT_SIZE_MIN && size != 0) || size > SEAL_CIPHERTEXT_SIZE_MAX)
        {
            throw invalid_argument("invalid size");
        }

        // Resize the data
        size_t new_data_size = mul_safe(size, poly_modulus_degree, coeff_modulus_size);
        data_.resize(new_data_size);

        // Set the size parameters
        size_ = size;
        poly_modulus_degree_ = poly_modulus_degree;
        coeff_modulus_size_ = coeff_modulus_size;
    }

    void Ciphertext::expand_seed(
        const SEALContext &context, const UniformRandomGeneratorInfo &prng_info, SEALVersion version)
    {
        auto context_data_ptr = context.get_context_data(parms_id_);

        // Set up a PRNG from the given info and sample the second polynomial
        auto prng = prng_info.make_prng();
        if (!prng)
        {
            throw logic_error("unsupported prng_type");
        }

        if (version.major == 4)
        {
            sample_poly_uniform(prng, context_data_ptr->parms(), data(1));
        }
        else if (version.major == 3 && version.minor >= 6)
        {
            sample_poly_uniform(prng, context_data_ptr->parms(), data(1));
        }
        else if (version.major == 3 && version.minor == 4)
        {
            sample_poly_uniform_seal_3_4(prng, context_data_ptr->parms(), data(1));
        }
        else if (version.major == 3 && version.minor == 5)
        {
            sample_poly_uniform_seal_3_5(prng, context_data_ptr->parms(), data(1));
        }
        else
        {
            // prior to v3.4, AES-128 was used, which is not compatible with later versions
            throw logic_error("incompatible version");
        }
    }

    streamoff Ciphertext::save_size(compr_mode_type compr_mode) const
    {
        // We need to consider two cases: seeded and unseeded; these have very
        // different size characteristics and we need the exact size when
        // compr_mode is compr_mode_type::none.
        size_t data_size;
        if (has_seed_marker())
        {
            // Create a temporary aliased DynArray of smaller size
            DynArray<ct_coeff_type> alias_data(
                Pointer<ct_coeff_type>::Aliasing(const_cast<ct_coeff_type *>(data_.cbegin())), data_.size() / 2, false,
                data_.pool());

            data_size = add_safe(
                safe_cast<size_t>(alias_data.save_size(compr_mode_type::none)), // data_(0)
                static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none))); // seed
        }
        else
        {
            data_size = safe_cast<size_t>(data_.save_size(compr_mode_type::none)); // data_
        }

        size_t members_size = Serialization::ComprSizeEstimate(
            add_safe(
                sizeof(parms_id_type), // parms_id_
                sizeof(seal_byte), // is_ntt_form_
                sizeof(uint64_t), // size_
                sizeof(uint64_t), // poly_modulus_degree_
                sizeof(uint64_t), // coeff_modulus_size_
                sizeof(double), // scale_
                sizeof(uint64_t), // correction_factor_
                data_size),
            compr_mode);

        return safe_cast<streamoff>(add_safe(sizeof(Serialization::SEALHeader), members_size));
    }

    void Ciphertext::save_members(ostream &stream) const
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            stream.write(reinterpret_cast<const char *>(&parms_id_), sizeof(parms_id_type));
            seal_byte is_ntt_form_byte = static_cast<seal_byte>(is_ntt_form_);
            stream.write(reinterpret_cast<const char *>(&is_ntt_form_byte), sizeof(seal_byte));
            uint64_t size64 = safe_cast<uint64_t>(size_);
            stream.write(reinterpret_cast<const char *>(&size64), sizeof(uint64_t));
            uint64_t poly_modulus_degree64 = safe_cast<uint64_t>(poly_modulus_degree_);
            stream.write(reinterpret_cast<const char *>(&poly_modulus_degree64), sizeof(uint64_t));
            uint64_t coeff_modulus_size64 = safe_cast<uint64_t>(coeff_modulus_size_);
            stream.write(reinterpret_cast<const char *>(&coeff_modulus_size64), sizeof(uint64_t));
            stream.write(reinterpret_cast<const char *>(&scale_), sizeof(double));
            stream.write(reinterpret_cast<const char *>(&correction_factor_), sizeof(uint64_t));

            if (has_seed_marker())
            {
                UniformRandomGeneratorInfo info;
                size_t info_size = static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
                info.load(reinterpret_cast<const seal_byte *>(data(1) + 1), info_size);

                size_t data_size = data_.size();
                size_t half_size = data_size / 2;
                // Save_members must be a const method.
                // Create an alias of data_; must be handled with care.
                DynArray<ct_coeff_type> alias_data(data_.pool_);
                alias_data.size_ = half_size;
                alias_data.capacity_ = half_size;
                auto alias_ptr = util::Pointer<ct_coeff_type>::Aliasing(const_cast<ct_coeff_type *>(data_.cbegin()));
                swap(alias_data.data_, alias_ptr);
                alias_data.save(stream, compr_mode_type::none);

                // Save the UniformRandomGeneratorInfo
                info.save(stream, compr_mode_type::none);
            }
            else
            {
                // Save the DynArray
                data_.save(stream, compr_mode_type::none);
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
    }

    void Ciphertext::load_members(const SEALContext &context, istream &stream, SEAL_MAYBE_UNUSED SEALVersion version)
    {
        // Verify parameters
        if (!context.parameters_set())
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
            stream.read(reinterpret_cast<char *>(&parms_id), sizeof(parms_id_type));
            seal_byte is_ntt_form_byte;
            stream.read(reinterpret_cast<char *>(&is_ntt_form_byte), sizeof(seal_byte));
            uint64_t size64 = 0;
            stream.read(reinterpret_cast<char *>(&size64), sizeof(uint64_t));
            uint64_t poly_modulus_degree64 = 0;
            stream.read(reinterpret_cast<char *>(&poly_modulus_degree64), sizeof(uint64_t));
            uint64_t coeff_modulus_size64 = 0;
            stream.read(reinterpret_cast<char *>(&coeff_modulus_size64), sizeof(uint64_t));
            double scale = 0;
            stream.read(reinterpret_cast<char *>(&scale), sizeof(double));
            uint64_t correction_factor = 1;
            if (version.major == 4)
            {
                stream.read(reinterpret_cast<char *>(&correction_factor), sizeof(uint64_t));
            }

            // Set values already at this point for the metadata validity check
            new_data.parms_id_ = parms_id;
            new_data.is_ntt_form_ = (is_ntt_form_byte == seal_byte{}) ? false : true;
            new_data.size_ = safe_cast<size_t>(size64);
            new_data.poly_modulus_degree_ = safe_cast<size_t>(poly_modulus_degree64);
            new_data.coeff_modulus_size_ = safe_cast<size_t>(coeff_modulus_size64);
            new_data.scale_ = scale;
            new_data.correction_factor_ = correction_factor;

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
            auto total_uint64_count =
                mul_safe(new_data.size_, new_data.poly_modulus_degree_, new_data.coeff_modulus_size_);

            // Reserve memory for the entire (expected) ciphertext data
            new_data.data_.reserve(total_uint64_count);

            // Load the data. Note that we are supplying also the expected maximum
            // size of the loaded DynArray. This is an important security measure to
            // prevent a malformed DynArray from causing arbitrarily large memory
            // allocations.
            new_data.data_.load(stream, total_uint64_count);

            // Expected buffer size in the seeded case
            auto seeded_uint64_count = poly_modulus_degree64 * coeff_modulus_size64;

            // This is the case where we need to expand a seed, otherwise full
            // ciphertext data was already (possibly) loaded and we are done
            if (unsigned_eq(new_data.data_.size(), seeded_uint64_count))
            {
                // Single polynomial size data was loaded, so we are in the seeded
                // ciphertext case. Next load the UniformRandomGeneratorInfo.
                UniformRandomGeneratorInfo prng_info;

                if (version.major == 4)
                {
                    prng_info.load(stream);
                }
                else if (version.major == 3 && version.minor >= 6)
                {
                    prng_info.load(stream);
                }
                else if (version.major == 3 && version.minor >= 4)
                {
                    // We only need to load the hash value; only Blake2xb is supported
                    prng_info.type() = prng_type::blake2xb;
                    stream.read(reinterpret_cast<char *>(&prng_info.seed()), prng_seed_byte_count);
                }
                else
                {
                    // seeded ciphertexts were not implemented before 3.4
                    throw logic_error("incompatible version");
                }

                // Set up a UniformRandomGenerator and expand
                new_data.data_.resize(total_uint64_count);
                new_data.expand_seed(context, prng_info, version);
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

        // BGV Ciphertext are converted to NTT form.
        if (context.key_context_data()->parms().scheme() == scheme_type::bgv && !this->is_ntt_form() && this->data())
        {
            ntt_negacyclic_harvey(*this, this->size(), context.get_context_data(this->parms_id())->small_ntt_tables());
            this->is_ntt_form() = true;
        }
    }
} // namespace seal
