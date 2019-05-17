// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/encryptionparams.h"
#include "seal/util/uintcore.h"
#include <limits>

using namespace std;
using namespace seal::util;

namespace seal
{
    void EncryptionParameters::Save(const EncryptionParameters &parms, ostream &stream)
    {
        // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
        auto old_except_mask = stream.exceptions();
        try
        {
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            uint64_t poly_modulus_degree64 = static_cast<uint64_t>(parms.poly_modulus_degree());
            uint64_t coeff_mod_count64 = static_cast<uint64_t>(parms.coeff_modulus().size());
            uint8_t scheme = static_cast<uint8_t>(parms.scheme());

            stream.write(reinterpret_cast<const char*>(&scheme), sizeof(uint8_t));
            stream.write(reinterpret_cast<const char*>(&poly_modulus_degree64), sizeof(uint64_t));
            stream.write(reinterpret_cast<const char*>(&coeff_mod_count64), sizeof(uint64_t));
            for (const auto &mod : parms.coeff_modulus())
            {
                mod.save(stream);
            }
            // CKKS does not use plain_modulus
            if (parms.scheme() == scheme_type::BFV)
            {
                parms.plain_modulus().save(stream);
            }
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
    }

    EncryptionParameters EncryptionParameters::Load(istream &stream)
    {
        // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
        auto old_except_mask = stream.exceptions();
        try
        {
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            // Read the scheme identifier
            uint8_t scheme;
            stream.read(reinterpret_cast<char*>(&scheme), sizeof(uint8_t));

            // This constructor will throw if scheme is invalid
            EncryptionParameters parms(scheme);

            // Read the poly_modulus_degree
            uint64_t poly_modulus_degree64 = 0;
            stream.read(reinterpret_cast<char*>(&poly_modulus_degree64), sizeof(uint64_t));
            if (poly_modulus_degree64 < SEAL_POLY_MOD_DEGREE_MIN ||
                poly_modulus_degree64 > SEAL_POLY_MOD_DEGREE_MAX)
            {
                throw invalid_argument("poly_modulus_degree is invalid");
            }

            // Read the coeff_modulus size
            uint64_t coeff_mod_count64 = 0;
            stream.read(reinterpret_cast<char*>(&coeff_mod_count64), sizeof(uint64_t));
            if (coeff_mod_count64 > SEAL_COEFF_MOD_COUNT_MAX ||
                coeff_mod_count64 < SEAL_COEFF_MOD_COUNT_MIN)
            {
                throw invalid_argument("coeff_modulus is invalid");
            }

            // Read the coeff_modulus
            vector<SmallModulus> coeff_modulus(coeff_mod_count64);
            for (auto &mod : coeff_modulus)
            {
                mod.load(stream);
            }

            // Read the plain_modulus
            SmallModulus plain_modulus;
            // CKKS does not use plain_modulus
            if (parms.scheme() == scheme_type::BFV)
            {
                plain_modulus.load(stream);
            }

            // Supposedly everything worked so set the values of member variables
            parms.set_poly_modulus_degree(safe_cast<size_t>(poly_modulus_degree64));
            parms.set_coeff_modulus(coeff_modulus);
            // CKKS does not use plain_modulus
            if (parms.scheme() == scheme_type::BFV)
            {
                parms.set_plain_modulus(plain_modulus);
            }

            stream.exceptions(old_except_mask);
            return parms;
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
    }

    void EncryptionParameters::compute_parms_id()
    {
        size_t coeff_mod_count = coeff_modulus_.size();

        size_t total_uint64_count = add_safe(
            size_t(1),  // scheme
            size_t(1),  // poly_modulus_degree
            coeff_mod_count,
            plain_modulus_.uint64_count()
        );

        auto param_data(allocate_uint(total_uint64_count, pool_));
        uint64_t *param_data_ptr = param_data.get();

        // Write the scheme identifier
        *param_data_ptr++ = static_cast<uint64_t>(scheme_);

        // Write the poly_modulus_degree. Note that it will always be positive.
        *param_data_ptr++ = static_cast<uint64_t>(poly_modulus_degree_);

        for(const auto &mod : coeff_modulus_)
        {
            *param_data_ptr++ = mod.value();
        }

        set_uint_uint(plain_modulus_.data(), plain_modulus_.uint64_count(), param_data_ptr);
        param_data_ptr += plain_modulus_.uint64_count();

        HashFunction::sha3_hash(param_data.get(), total_uint64_count, parms_id_);

        // Did we somehow manage to get a zero block as result? This is reserved for
        // plaintexts to indicate non-NTT-transformed form.
        if (parms_id_ == parms_id_zero)
        {
            throw logic_error("parms_id cannot be zero");
        }
    }
}
