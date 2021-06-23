// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/defines.h"

#ifdef SEAL_USE_INTEL_HEXL
#include "seal/memorymanager.h"
#include "seal/util/intel_seal_ext.h"
#include "seal/util/locks.h"
#include <unordered_map>
#include "hexl/hexl.hpp"

using namespace std;
using namespace seal;
namespace intel
{
    namespace seal_ext
    {
        hexl::NTT get_ntt(size_t N, uint64_t modulus, uint64_t root)
        {
            static unordered_map<pair<uint64_t, uint64_t>, hexl::NTT, HashPair> ntt_cache_;

            static util::ReaderWriterLocker ntt_cache_locker_;

            pair<uint64_t, uint64_t> key{ N, modulus };

            // Enable shared access to NTT already present
            {
                util::ReaderLock reader_lock(ntt_cache_locker_.acquire_read());
                auto ntt_it = ntt_cache_.find(key);
                if (ntt_it != ntt_cache_.end())
                {
                    return ntt_it->second;
                }
            }

            // Deal with NTT not yet present
            util::WriterLock write_lock(ntt_cache_locker_.acquire_write());

            // Check ntt_cache for value (may be added by another thread)
            auto ntt_it = ntt_cache_.find(key);
            if (ntt_it == ntt_cache_.end())
            {
                hexl::NTT ntt(N, modulus, root, MemoryManager::GetPool(), hexl::SimpleThreadSafePolicy{});
                ntt_it = ntt_cache_.emplace(move(key), move(ntt)).first;
            }
            return ntt_it->second;
        }
    } // namespace seal_ext
} // namespace intel

#endif
