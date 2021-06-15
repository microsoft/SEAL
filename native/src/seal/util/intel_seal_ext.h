// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/defines.h"

#ifdef SEAL_USE_INTEL_HEXL
#include "seal/memorymanager.h"
#include "seal/util/iterator.h"
#include "seal/util/locks.h"
#include "seal/util/pointer.h"
#include <unordered_map>
#include "hexl/hexl.hpp"

namespace intel
{
    namespace hexl
    {
        // Single threaded SEAL allocator adapter
        template <>
        struct NTT::AllocatorAdapter<seal::MemoryPoolHandle>
            : public AllocatorInterface<NTT::AllocatorAdapter<seal::MemoryPoolHandle>>
        {
            AllocatorAdapter(seal::MemoryPoolHandle handle) : handle_(std::move(handle))
            {}

            ~AllocatorAdapter()
            {}

            // interface implementations
            void *allocate_impl(std::size_t bytes_count)
            {
                cache_.push_back(static_cast<seal::util::MemoryPool &>(handle_).get_for_byte_count(bytes_count));
                return cache_.back().get();
            }

            void deallocate_impl(void *p, std::size_t n)
            {
                (void)n;
                auto it = std::remove_if(
                    cache_.begin(), cache_.end(),
                    [p](const seal::util::Pointer<seal::seal_byte> &seal_pointer) { return p == seal_pointer.get(); });

#ifdef SEAL_DEBUG
                if (it == cache_.end())
                {
                    throw std::logic_error("Inconsistent single-threaded allocator cache");
                }
#endif
                cache_.erase(it, cache_.end());
            }

        private:
            seal::MemoryPoolHandle handle_;
            std::vector<seal::util::Pointer<seal::seal_byte>> cache_;
        };

        // Thread safe policy
        struct SimpleThreadSafePolicy
        {
            SimpleThreadSafePolicy() : m_ptr(std::make_unique<std::mutex>())
            {}

            std::unique_lock<std::mutex> locker()
            {
                if (!m_ptr)
                {
                    throw std::logic_error("accessing a moved object");
                }
                return std::unique_lock<std::mutex>{ *m_ptr };
            };

        private:
            std::unique_ptr<std::mutex> m_ptr;
        };

        // Multithreaded SEAL allocator adapter
        template <>
        struct NTT::AllocatorAdapter<seal::MemoryPoolHandle, SimpleThreadSafePolicy>
            : public AllocatorInterface<NTT::AllocatorAdapter<seal::MemoryPoolHandle, SimpleThreadSafePolicy>>
        {
            AllocatorAdapter(seal::MemoryPoolHandle handle, SimpleThreadSafePolicy &&policy)
                : handle_(std::move(handle)), policy_(std::move(policy))
            {}

            ~AllocatorAdapter()
            {}
            // interface implementations
            void *allocate_impl(std::size_t bytes_count)
            {
                {
                    // to prevent inline optimization with deadlock
                    auto accessor = policy_.locker();
                    cache_.push_back(static_cast<seal::util::MemoryPool &>(handle_).get_for_byte_count(bytes_count));
                    return cache_.back().get();
                }
            }

            void deallocate_impl(void *p, std::size_t n)
            {
                (void)n;
                {
                    // to prevent inline optimization with deadlock
                    auto accessor = policy_.locker();
                    auto it = std::remove_if(
                        cache_.begin(), cache_.end(), [p](const seal::util::Pointer<seal::seal_byte> &seal_pointer) {
                            return p == seal_pointer.get();
                        });

#ifdef SEAL_DEBUG
                    if (it == cache_.end())
                    {
                        throw std::logic_error("Inconsistent multi-threaded allocator cache");
                    }
#endif
                    cache_.erase(it, cache_.end());
                }
            }

        private:
            seal::MemoryPoolHandle handle_;
            SimpleThreadSafePolicy policy_;
            std::vector<seal::util::Pointer<seal::seal_byte>> cache_;
        };
    } // namespace hexl

    namespace seal_ext
    {
        struct HashPair
        {
            template <class T1, class T2>
            std::size_t operator()(const std::pair<T1, T2> &p) const
            {
                auto hash1 = std::hash<T1>{}(std::get<0>(p));
                auto hash2 = std::hash<T2>{}(std::get<1>(p));
                return hash_combine(hash1, hash2);
            }

            static std::size_t hash_combine(std::size_t lhs, std::size_t rhs)
            {
                lhs ^= rhs + 0x9e3779b9 + (lhs << 6) + (lhs >> 2);
                return lhs;
            }
        };

        /**
        Returns a HEXL NTT object corresponding to the given parameters.

        @param[in] N The polynomial modulus degree
        @param[in] modulus The modulus
        @param[in] root The root of unity
        */
        hexl::NTT get_ntt(std::size_t N, std::uint64_t modulus, std::uint64_t root);

        /**
        Computes the forward negacyclic NTT from the given parameters.

        @param[in,out] operand The data on which to compute the NTT.
        @param[in] N The polynomial modulus degree
        @param[in] modulus The modulus
        @param[in] root The root of unity
        @param[in] input_mod_factor Bounds the input data to the range [0, input_mod_factor * modulus)
        @param[in] output_mod_factor Bounds the output data to the range [0, output_mod_factor * modulus)
        */
        inline void compute_forward_ntt(
            seal::util::CoeffIter operand, std::size_t N, std::uint64_t modulus, std::uint64_t root,
            std::uint64_t input_mod_factor, std::uint64_t output_mod_factor)
        {
            get_ntt(N, modulus, root).ComputeForward(operand, operand, input_mod_factor, output_mod_factor);
        }

        /**
        Computes the inverse negacyclic NTT from the given parameters.

        @param[in,out] operand The data on which to compute the NTT.
        @param[in] N The polynomial modulus degree
        @param[in] modulus The modulus
        @param[in] root The root of unity
        @param[in] input_mod_factor Bounds the input data to the range [0, input_mod_factor * modulus)
        @param[in] output_mod_factor Bounds the output data to the range [0, output_mod_factor * modulus)
        */
        inline void compute_inverse_ntt(
            seal::util::CoeffIter operand, std::size_t N, std::uint64_t modulus, std::uint64_t root,
            std::uint64_t input_mod_factor, std::uint64_t output_mod_factor)
        {
            get_ntt(N, modulus, root).ComputeInverse(operand, operand, input_mod_factor, output_mod_factor);
        }

    } // namespace seal_ext
} // namespace intel

#endif
