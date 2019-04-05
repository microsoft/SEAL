// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/kswitchkeys.h"
#include "seal/util/defines.h"
#include <stdexcept>

using namespace std;
using namespace seal::util;

namespace seal
{
    KSwitchKeys &KSwitchKeys::operator =(const KSwitchKeys &assign)
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

    void KSwitchKeys::save(ostream &stream) const
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            uint64_t keys_dim1 = static_cast<uint64_t>(keys_.size());

            // Save the parms_id
            stream.write(reinterpret_cast<const char*>(&parms_id_),
                sizeof(parms_id_type));

            // Save the size of keys_
            stream.write(reinterpret_cast<const char*>(&keys_dim1), sizeof(uint64_t));

            // Now loop again over keys_dim1
            for (size_t index = 0; index < keys_dim1; index++)
            {
                // Save second dimension of keys_
                uint64_t keys_dim2 = static_cast<uint64_t>(keys_[index].size());
                stream.write(reinterpret_cast<const char*>(&keys_dim2), sizeof(uint64_t));

                // Loop over keys_dim2 and save all (or none)
                for (size_t j = 0; j < keys_dim2; j++)
                {
                    // Save the key
                    keys_[index][j].save(stream);
                }
            }
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }

        stream.exceptions(old_except_mask);
    }

    void KSwitchKeys::unsafe_load(istream &stream)
    {
        // Create new keys
        vector<vector<PublicKey>> new_keys;

        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            // Read the parms_id
            stream.read(reinterpret_cast<char*>(&parms_id_),
                sizeof(parms_id_type));

            // Read in the size of keys_
            uint64_t keys_dim1 = 0;
            stream.read(reinterpret_cast<char*>(&keys_dim1), sizeof(uint64_t));

            // Reserve first for dimension of keys_
            new_keys.reserve(safe_cast<size_t>(keys_dim1));

            // Loop over the first dimension of keys_
            for (size_t index = 0; index < keys_dim1; index++)
            {
                // Read the size of the second dimension
                uint64_t keys_dim2 = 0;
                stream.read(reinterpret_cast<char*>(&keys_dim2), sizeof(uint64_t));

                // Don't resize; only reserve
                new_keys.emplace_back();
                new_keys.back().reserve(safe_cast<size_t>(keys_dim2));
                for (size_t j = 0; j < keys_dim2; j++)
                {
                    PublicKey key(pool_);
                    key.unsafe_load(stream);
                    new_keys[index].emplace_back(move(key));
                }
            }
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);

        swap(keys_, new_keys);
    }
}
