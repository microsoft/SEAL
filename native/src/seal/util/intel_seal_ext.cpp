// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/defines.h"

#ifdef SEAL_USE_INTEL_HEXL
#include "seal/memorymanager.h"
#include "seal/util/intel_seal_ext.h"
#include "seal/util/locks.h"
#include <unordered_map>
#include "hexl/hexl.hpp"

namespace intel
{
    namespace seal_ext
    {
        intel::hexl::NTT get_ntt(size_t N, uint64_t modulus, uint64_t root)
        {
            static std::unordered_map<std::pair<uint64_t, uint64_t>, intel::hexl::NTT, seal_ext::HashPair> ntt_cache_;

            static seal::util::ReaderWriterLocker ntt_cache_locker_;

            std::pair<uint64_t, uint64_t> key{ N, modulus };

            // Enable shared access of NTT already present
            {
                seal::util::ReaderLock reader_lock(ntt_cache_locker_.acquire_read());
                auto ntt_it = ntt_cache_.find(key);
                if (ntt_it != ntt_cache_.end())
                {
                    return ntt_it->second;
                }
            }

            // Deal with NTT not yet present
            seal::util::WriterLock write_lock(ntt_cache_locker_.acquire_write());

            // Check ntt_cache for value (maybe added by another thread)
            auto ntt_it = ntt_cache_.find(key);
            if (ntt_it == ntt_cache_.end())
            {
                intel::hexl::NTT ntt(
                    N, modulus, root, seal::MemoryManager::GetPool(), intel::hexl::SimpleThreadSafePolicy{});
                ntt_it = ntt_cache_.emplace(std::move(key), std::move(ntt)).first;
            }
            return ntt_it->second;
        }
    } // namespace seal_ext
} // namespace intel

#endif
