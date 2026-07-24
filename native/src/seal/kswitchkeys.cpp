// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/kswitchkeys.h"
#include <stdexcept>

using namespace std;
using namespace seal::util;

namespace seal
{
    KSwitchKeys &KSwitchKeys::operator=(const KSwitchKeys &assign)
    {
        // Check for self-assignment
        if (this == &assign)
        {
            return *this;
        }

        // Copy over fields
        parms_id_ = assign.parms_id_;

        // Then copy over keys
        keys_.clear();
        size_t keys_dim1 = assign.keys_.size();
        keys_.reserve(keys_dim1);
        for (size_t i = 0; i < keys_dim1; i++)
        {
            size_t keys_dim2 = assign.keys_[i].size();
            keys_.emplace_back();
            keys_[i].reserve(keys_dim2);
            for (size_t j = 0; j < keys_dim2; j++)
            {
                keys_[i].emplace_back(PublicKey(pool_));
                keys_[i][j] = assign.keys_[i][j];
            }
        }

        return *this;
    }

    void KSwitchKeys::save_members(ostream &stream) const
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            uint64_t keys_dim1 = static_cast<uint64_t>(keys_.size());

            // Save the parms_id
            stream.write(reinterpret_cast<const char *>(&parms_id_), sizeof(parms_id_type));

            // Save the size of keys_
            stream.write(reinterpret_cast<const char *>(&keys_dim1), sizeof(uint64_t));

            // Now loop again over keys_dim1
            for (size_t index = 0; index < keys_dim1; index++)
            {
                // Save second dimension of keys_
                uint64_t keys_dim2 = static_cast<uint64_t>(keys_[index].size());
                stream.write(reinterpret_cast<const char *>(&keys_dim2), sizeof(uint64_t));

                // Loop over keys_dim2 and save all (or none)
                for (size_t j = 0; j < keys_dim2; j++)
                {
                    // Save the key
                    keys_[index][j].save(stream, compr_mode_type::none);
                }
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

    void KSwitchKeys::load_members(const SEALContext &context, istream &stream, SEAL_MAYBE_UNUSED SEALVersion version)
    {
        // Verify parameters
        if (!context.parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        // Create new keys
        vector<vector<PublicKey>> new_keys;

        // Stage parms_id locally so a throw mid-load cannot leave this object with
        // a new parms_id paired with its old keys_. It is committed next to the
        // swap below, matching the atomic staging used by the other loaders.
        parms_id_type new_parms_id{};

        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            // Read the parms_id
            stream.read(reinterpret_cast<char *>(&new_parms_id), sizeof(parms_id_type));

            // Read in the size of keys_
            uint64_t keys_dim1 = 0;
            stream.read(reinterpret_cast<char *>(&keys_dim1), sizeof(uint64_t));

            // Bound keys_dim1 by the number of key-switching keys this context can
            // legitimately require, not the compile-time maximum. For Galois keys
            // that is at most poly_modulus_degree (one key per coefficient slot); for
            // relinearization keys it is far smaller. Using the context-derived bound
            // prevents a hostile stream from claiming a huge key count and driving a
            // large allocation in reserve() below before any key is validated.
            size_t max_keys_dim1 = context.key_context_data()->parms().poly_modulus_degree();
            if (keys_dim1 > max_keys_dim1)
            {
                throw logic_error("KSwitchKeys outer dimension is invalid");
            }

            // The inner dimension is the RNS decomposition count, which equals the
            // number of primes in the first (data-level) coeff_modulus.
            size_t max_keys_dim2 = context.first_context_data()->parms().coeff_modulus().size();

            // Reserve first for dimension of keys_
            new_keys.reserve(safe_cast<size_t>(keys_dim1));

            // Loop over the first dimension of keys_
            for (size_t index = 0; index < keys_dim1; index++)
            {
                // Read the size of the second dimension
                uint64_t keys_dim2 = 0;
                stream.read(reinterpret_cast<char *>(&keys_dim2), sizeof(uint64_t));

                // Bound keys_dim2 by the context's RNS decomposition count rather
                // than the compile-time maximum, for the same reason as above.
                if (keys_dim2 > max_keys_dim2)
                {
                    throw logic_error("KSwitchKeys inner dimension is invalid");
                }

                // Don't resize; only reserve
                new_keys.emplace_back();
                new_keys.back().reserve(safe_cast<size_t>(keys_dim2));
                for (size_t j = 0; j < keys_dim2; j++)
                {
                    PublicKey key(pool_);
                    key.unsafe_load(context, stream);
                    new_keys[index].emplace_back(std::move(key));
                }
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

        parms_id_ = new_parms_id;
        swap(keys_, new_keys);
    }
} // namespace seal
