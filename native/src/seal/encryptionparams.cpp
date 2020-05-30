// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/encryptionparams.h"
#include "seal/util/uintcore.h"
#include <limits>

using namespace std;
using namespace seal::util;

namespace seal
{
    const parms_id_type parms_id_zero = util::HashFunction::hash_zero_block;

    void EncryptionParameters::save_members(ostream &stream) const
    {
        // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
        auto old_except_mask = stream.exceptions();
        try
        {
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            uint64_t poly_modulus_degree64 = static_cast<uint64_t>(poly_modulus_degree_);
            uint64_t coeff_modulus_size64 = static_cast<uint64_t>(coeff_modulus_.size());
            uint8_t scheme = static_cast<uint8_t>(scheme_);

            stream.write(reinterpret_cast<const char *>(&scheme), sizeof(uint8_t));
            stream.write(reinterpret_cast<const char *>(&poly_modulus_degree64), sizeof(uint64_t));
            stream.write(reinterpret_cast<const char *>(&coeff_modulus_size64), sizeof(uint64_t));
            for (const auto &mod : coeff_modulus_)
            {
                mod.save(stream, compr_mode_type::none);
            }

            // Only BFV uses plain_modulus but save it in any case for simplicity
            plain_modulus_.save(stream, compr_mode_type::none);
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

    void EncryptionParameters::load_members(istream &stream)
    {
        // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
        auto old_except_mask = stream.exceptions();
        try
        {
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            // Read the scheme identifier
            uint8_t scheme;
            stream.read(reinterpret_cast<char *>(&scheme), sizeof(uint8_t));

            // This constructor will throw if scheme is invalid
            EncryptionParameters parms(scheme);

            // Read the poly_modulus_degree
            uint64_t poly_modulus_degree64 = 0;
            stream.read(reinterpret_cast<char *>(&poly_modulus_degree64), sizeof(uint64_t));

            // Only check for upper bound; lower bound is zero for scheme_type::none
            if (poly_modulus_degree64 > SEAL_POLY_MOD_DEGREE_MAX)
            {
                throw logic_error("poly_modulus_degree is invalid");
            }

            // Read the coeff_modulus size
            uint64_t coeff_modulus_size64 = 0;
            stream.read(reinterpret_cast<char *>(&coeff_modulus_size64), sizeof(uint64_t));

            // Only check for upper bound; lower bound is zero for scheme_type::none
            if (coeff_modulus_size64 > SEAL_COEFF_MOD_COUNT_MAX)
            {
                throw logic_error("coeff_modulus is invalid");
            }

            // Read the coeff_modulus
            vector<Modulus> coeff_modulus;
            for (uint64_t i = 0; i < coeff_modulus_size64; i++)
            {
                coeff_modulus.emplace_back();
                coeff_modulus.back().load(stream);
            }

            // Read the plain_modulus
            Modulus plain_modulus;
            plain_modulus.load(stream);

            // Supposedly everything worked so set the values of member variables
            parms.set_poly_modulus_degree(safe_cast<size_t>(poly_modulus_degree64));
            parms.set_coeff_modulus(coeff_modulus);

            // Only BFV uses plain_modulus; set_plain_modulus checks that for
            // other schemes it is zero
            parms.set_plain_modulus(plain_modulus);

            // Set the loaded parameters
            swap(*this, parms);

            stream.exceptions(old_except_mask);
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

    void EncryptionParameters::compute_parms_id()
    {
        size_t coeff_modulus_size = coeff_modulus_.size();

        size_t total_uint64_count = add_safe(
            size_t(1), // scheme
            size_t(1), // poly_modulus_degree
            coeff_modulus_size, plain_modulus_.uint64_count());

        auto param_data(allocate_uint(total_uint64_count, pool_));
        uint64_t *param_data_ptr = param_data.get();

        // Write the scheme identifier
        *param_data_ptr++ = static_cast<uint64_t>(scheme_);

        // Write the poly_modulus_degree. Note that it will always be positive.
        *param_data_ptr++ = static_cast<uint64_t>(poly_modulus_degree_);

        for (const auto &mod : coeff_modulus_)
        {
            *param_data_ptr++ = mod.value();
        }

        set_uint(plain_modulus_.data(), plain_modulus_.uint64_count(), param_data_ptr);
        param_data_ptr += plain_modulus_.uint64_count();

        HashFunction::hash(param_data.get(), total_uint64_count, parms_id_);

        // Did we somehow manage to get a zero block as result? This is reserved for
        // plaintexts to indicate non-NTT-transformed form.
        if (parms_id_ == parms_id_zero)
        {
            throw logic_error("parms_id cannot be zero");
        }
    }
} // namespace seal
