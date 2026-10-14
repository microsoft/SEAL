// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include <algorithm>
#if !defined(SEAL_USE_INTEL_HEXL) && defined(SEAL_USE_INTRIN) && defined(__aarch64__) && defined(__ARM_NEON) && \
    !defined(_MSC_VER)
#define SEAL_NTT_USE_NEON
#include <arm_neon.h>
#endif
#ifdef SEAL_USE_INTEL_HEXL
#include "seal/memorymanager.h"
#include "seal/util/iterator.h"
#include "seal/util/locks.h"
#include "seal/util/pointer.h"
#include <unordered_map>
#include "hexl/hexl.hpp"
#endif

using namespace std;

#ifdef SEAL_USE_INTEL_HEXL
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

            void deallocate_impl(void *p, SEAL_MAYBE_UNUSED std::size_t n)
            {
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

            void deallocate_impl(void *p, SEAL_MAYBE_UNUSED std::size_t n)
            {
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
        static intel::hexl::NTT &get_ntt(size_t N, uint64_t modulus, uint64_t root)
        {
            static unordered_map<pair<uint64_t, uint64_t>, hexl::NTT, HashPair> ntt_cache_;

            static seal::util::ReaderWriterLocker ntt_cache_locker_;

            pair<uint64_t, uint64_t> key{ N, modulus };

            // Enable shared access to NTT already present
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

            // Check ntt_cache for value (may be added by another thread)
            auto ntt_it = ntt_cache_.find(key);
            if (ntt_it == ntt_cache_.end())
            {
                hexl::NTT ntt(N, modulus, root, seal::MemoryManager::GetPool(), hexl::SimpleThreadSafePolicy{});
                ntt_it = ntt_cache_.emplace(std::move(key), std::move(ntt)).first;
            }
            return ntt_it->second;
        }

        /**
        Computes the forward negacyclic NTT from the given parameters.

        @param[in,out] operand The data on which to compute the NTT.
        @param[in] N The polynomial modulus degree
        @param[in] modulus The modulus
        @param[in] root The root of unity
        @param[in] input_mod_factor Bounds the input data to the range [0, input_mod_factor * modulus)
        @param[in] output_mod_factor Bounds the output data to the range [0, output_mod_factor * modulus)
        */
        static void compute_forward_ntt(
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
        static void compute_inverse_ntt(
            seal::util::CoeffIter operand, std::size_t N, std::uint64_t modulus, std::uint64_t root,
            std::uint64_t input_mod_factor, std::uint64_t output_mod_factor)
        {
            get_ntt(N, modulus, root).ComputeInverse(operand, operand, input_mod_factor, output_mod_factor);
        }

    } // namespace seal_ext
} // namespace intel
#endif

namespace seal
{
    namespace util
    {
#ifndef SEAL_USE_INTEL_HEXL
        namespace
        {
            // For inputs in range, the lazy outputs of these kernels match NTTTables::ntt_handler() bit for bit

            // multiply_uint_mod_lazy with p by value
            SEAL_FORCE_INLINE uint64_t ntt_mul_root(uint64_t y, const MultiplyUIntModOperand &w, uint64_t p)
            {
                unsigned long long hw;
                multiply_uint64_hw64(y, w.quotient, &hw);
                return y * w.operand - hw * p;
            }

            // Inputs and outputs in [0, 4p)
            SEAL_FORCE_INLINE void ntt_fwd_bf(
                uint64_t &x, uint64_t &y, const MultiplyUIntModOperand &w, uint64_t p, uint64_t two_p)
            {
                uint64_t u = sub_if_ge_uint64(x, two_p);
                uint64_t v = ntt_mul_root(y, w, p);
                x = u + v;
                y = u + two_p - v;
            }

            // Inputs and outputs in [0, 2p)
            SEAL_FORCE_INLINE void ntt_inv_bf(
                uint64_t &x, uint64_t &y, const MultiplyUIntModOperand &w, uint64_t p, uint64_t two_p)
            {
                uint64_t u = x;
                uint64_t v = y;
                x = sub_if_ge_uint64(u + v, two_p);
                y = ntt_mul_root(u + two_p - v, w, p);
            }

            // ntt_inv_bf times s, with ws = root * s
            SEAL_FORCE_INLINE void ntt_inv_bf_scaled(
                uint64_t &x, uint64_t &y, const MultiplyUIntModOperand &s, const MultiplyUIntModOperand &ws, uint64_t p,
                uint64_t two_p)
            {
                uint64_t u = x;
                uint64_t v = y;
                uint64_t t = sub_if_ge_uint64(u + v, two_p);
                x = ntt_mul_root(t, s, p);
                y = ntt_mul_root(u + two_p - v, ws, p);
            }

            // ratio is floor(2^64 / p)
            template <bool Reduce>
            SEAL_FORCE_INLINE uint64_t ntt_load(const uint64_t *src, size_t index, uint64_t p, uint64_t ratio)
            {
                uint64_t x = src[index];
                SEAL_IF_CONSTEXPR(Reduce)
                {
                    unsigned long long q;
                    multiply_uint64_hw64(x, ratio, &q);
                    x = sub_if_ge_uint64(x - q * p, p);
                }
                return x;
            }

            // Reduces x from [0, 4p) to [0, p) if FullReduce
            template <bool FullReduce>
            SEAL_FORCE_INLINE uint64_t ntt_fwd_store_value(uint64_t x, uint64_t p, uint64_t two_p)
            {
                return FullReduce ? sub_if_ge_uint64(sub_if_ge_uint64(x, two_p), p) : x;
            }

            // Reduces x from [0, 2p) to [0, p) if FullReduce
            template <bool FullReduce>
            SEAL_FORCE_INLINE uint64_t ntt_inv_store_value(uint64_t x, uint64_t p)
            {
                return FullReduce ? sub_if_ge_uint64(x, p) : x;
            }

            template <bool Reduce, bool FullReduce>
            SEAL_FORCE_INLINE void ntt_fwd_radix4_bf(
                const uint64_t *src, uint64_t *dst, size_t o, size_t h, const MultiplyUIntModOperand &r1,
                const MultiplyUIntModOperand &r2a, const MultiplyUIntModOperand &r2b, uint64_t p, uint64_t two_p,
                uint64_t ratio)
            {
                uint64_t x0 = ntt_load<Reduce>(src, o, p, ratio);
                uint64_t x1 = ntt_load<Reduce>(src, o + h, p, ratio);
                uint64_t x2 = ntt_load<Reduce>(src, o + 2 * h, p, ratio);
                uint64_t x3 = ntt_load<Reduce>(src, o + 3 * h, p, ratio);

                ntt_fwd_bf(x0, x2, r1, p, two_p);
                ntt_fwd_bf(x1, x3, r1, p, two_p);
                ntt_fwd_bf(x0, x1, r2a, p, two_p);
                ntt_fwd_bf(x2, x3, r2b, p, two_p);

                dst[o] = ntt_fwd_store_value<FullReduce>(x0, p, two_p);
                dst[o + h] = ntt_fwd_store_value<FullReduce>(x1, p, two_p);
                dst[o + 2 * h] = ntt_fwd_store_value<FullReduce>(x2, p, two_p);
                dst[o + 3 * h] = ntt_fwd_store_value<FullReduce>(x3, p, two_p);
            }

            SEAL_FORCE_INLINE void ntt_inv_radix4_bf(
                const uint64_t *src, uint64_t *dst, size_t o, size_t g, const MultiplyUIntModOperand &ra0,
                const MultiplyUIntModOperand &ra1, const MultiplyUIntModOperand &rb, uint64_t p, uint64_t two_p)
            {
                uint64_t x0 = src[o];
                uint64_t x1 = src[o + g];
                uint64_t x2 = src[o + 2 * g];
                uint64_t x3 = src[o + 3 * g];

                ntt_inv_bf(x0, x1, ra0, p, two_p);
                ntt_inv_bf(x2, x3, ra1, p, two_p);
                ntt_inv_bf(x0, x2, rb, p, two_p);
                ntt_inv_bf(x1, x3, rb, p, two_p);

                dst[o] = x0;
                dst[o + g] = x1;
                dst[o + 2 * g] = x2;
                dst[o + 3 * g] = x3;
            }

#ifdef SEAL_NTT_USE_NEON
            SEAL_FORCE_INLINE uint64x2_t ntt_vsub_if_ge(uint64x2_t x, uint64x2_t m)
            {
                return vsubq_u64(x, vandq_u64(vcgeq_u64(x, m), m));
            }

            // Root w0 for lane 0, w1 for lane 1; scalar code, as NEON has no 64 x 64 -> 128-bit multiply
            SEAL_FORCE_INLINE uint64x2_t
            ntt_vmul_root(uint64x2_t y, const MultiplyUIntModOperand &w0, const MultiplyUIntModOperand &w1, uint64_t p)
            {
                uint64_t r0 = ntt_mul_root(vgetq_lane_u64(y, 0), w0, p);
                uint64_t r1 = ntt_mul_root(vgetq_lane_u64(y, 1), w1, p);
                return vsetq_lane_u64(r1, vdupq_n_u64(r0), 1);
            }

            SEAL_FORCE_INLINE void ntt_vfwd_bf(
                uint64x2_t &x, uint64x2_t &y, const MultiplyUIntModOperand &w, uint64_t p, uint64x2_t vtwo_p)
            {
                uint64x2_t u = ntt_vsub_if_ge(x, vtwo_p);
                uint64x2_t v = ntt_vmul_root(y, w, w, p);
                x = vaddq_u64(u, v);
                y = vsubq_u64(vaddq_u64(u, vtwo_p), v);
            }

            SEAL_FORCE_INLINE void ntt_vinv_bf(
                uint64x2_t &x, uint64x2_t &y, const MultiplyUIntModOperand &w0, const MultiplyUIntModOperand &w1,
                uint64_t p, uint64x2_t vtwo_p)
            {
                uint64x2_t u = x;
                uint64x2_t v = y;
                x = ntt_vsub_if_ge(vaddq_u64(u, v), vtwo_p);
                y = ntt_vmul_root(vsubq_u64(vaddq_u64(u, vtwo_p), v), w0, w1, p);
            }

            SEAL_FORCE_INLINE void ntt_vinv_bf_scaled(
                uint64x2_t &x, uint64x2_t &y, const MultiplyUIntModOperand &s, const MultiplyUIntModOperand &ws,
                uint64_t p, uint64x2_t vtwo_p)
            {
                uint64x2_t u = x;
                uint64x2_t v = y;
                uint64x2_t t = ntt_vsub_if_ge(vaddq_u64(u, v), vtwo_p);
                x = ntt_vmul_root(t, s, s, p);
                y = ntt_vmul_root(vsubq_u64(vaddq_u64(u, vtwo_p), v), ws, ws, p);
            }

            template <bool FullReduce>
            SEAL_FORCE_INLINE uint64x2_t ntt_vfwd_store_value(uint64x2_t x, uint64x2_t vp, uint64x2_t vtwo_p)
            {
                return FullReduce ? ntt_vsub_if_ge(ntt_vsub_if_ge(x, vtwo_p), vp) : x;
            }

            template <bool FullReduce>
            SEAL_FORCE_INLINE uint64x2_t ntt_vinv_store_value(uint64x2_t x, uint64x2_t vp)
            {
                return FullReduce ? ntt_vsub_if_ge(x, vp) : x;
            }

            // Requires g >= 2
            template <bool FullReduce>
            void ntt_fwd_layer_radix2_neon(
                const uint64_t *src, uint64_t *dst, size_t m, size_t g, const MultiplyUIntModOperand *roots, uint64_t p)
            {
                const uint64x2_t vp = vdupq_n_u64(p);
                const uint64x2_t vtwo_p = vdupq_n_u64(p << 1);
                for (size_t i = 0; i < m; i++)
                {
                    const MultiplyUIntModOperand r = roots[m + i];
                    const size_t offset = 2 * g * i;
                    for (size_t j = 0; j < g; j += 2)
                    {
                        uint64x2_t a = vld1q_u64(src + offset + j);
                        uint64x2_t b = vld1q_u64(src + offset + g + j);
                        ntt_vfwd_bf(a, b, r, p, vtwo_p);
                        vst1q_u64(dst + offset + j, ntt_vfwd_store_value<FullReduce>(a, vp, vtwo_p));
                        vst1q_u64(dst + offset + g + j, ntt_vfwd_store_value<FullReduce>(b, vp, vtwo_p));
                    }
                }
            }

            // Requires h >= 2
            template <bool FullReduce>
            void ntt_fwd_layer_radix4_neon(
                const uint64_t *src, uint64_t *dst, size_t m, size_t h, const MultiplyUIntModOperand *roots, uint64_t p)
            {
                const uint64_t two_p = p << 1;
                const uint64x2_t vp = vdupq_n_u64(p);
                const uint64x2_t vtwo_p = vdupq_n_u64(two_p);
                for (size_t i = 0; i < m; i++)
                {
                    const MultiplyUIntModOperand r1 = roots[m + i];
                    const MultiplyUIntModOperand r2a = roots[2 * m + 2 * i];
                    const MultiplyUIntModOperand r2b = roots[2 * m + 2 * i + 1];
                    const size_t o0 = 4 * h * i;
                    const size_t o1 = o0 + h;
                    const size_t o2 = o1 + h;
                    const size_t o3 = o2 + h;
                    for (size_t j = 0; j < h; j += 2)
                    {
                        // x1 and x3 stay scalar: their layer-1 outputs only feed multiplications
                        const uint64_t x1a = src[o1 + j], x1b = src[o1 + j + 1];
                        const uint64_t u1a = sub_if_ge_uint64(x1a, two_p), u1b = sub_if_ge_uint64(x1b, two_p);
                        const uint64_t v3a = ntt_mul_root(src[o3 + j], r1, p);
                        const uint64_t v3b = ntt_mul_root(src[o3 + j + 1], r1, p);
                        const uint64_t w1a = ntt_mul_root(u1a + v3a, r2a, p);
                        const uint64_t w1b = ntt_mul_root(u1b + v3b, r2a, p);
                        const uint64_t w3a = ntt_mul_root(u1a + two_p - v3a, r2b, p);
                        const uint64_t w3b = ntt_mul_root(u1b + two_p - v3b, r2b, p);

                        const uint64_t v2a = ntt_mul_root(src[o2 + j], r1, p);
                        const uint64_t v2b = ntt_mul_root(src[o2 + j + 1], r1, p);

                        const uint64x2_t v2 = vsetq_lane_u64(v2b, vdupq_n_u64(v2a), 1);
                        const uint64x2_t w1 = vsetq_lane_u64(w1b, vdupq_n_u64(w1a), 1);
                        const uint64x2_t w3 = vsetq_lane_u64(w3b, vdupq_n_u64(w3a), 1);

                        // Layer 1 on x0 and x2, reduced to [0, 2p) for layer 2
                        const uint64x2_t u0 = ntt_vsub_if_ge(vld1q_u64(src + o0 + j), vtwo_p);
                        const uint64x2_t g0 = ntt_vsub_if_ge(vaddq_u64(u0, v2), vtwo_p);
                        const uint64x2_t g2 = ntt_vsub_if_ge(vsubq_u64(vaddq_u64(u0, vtwo_p), v2), vtwo_p);

                        const uint64x2_t y0 = vaddq_u64(g0, w1);
                        const uint64x2_t y1 = vsubq_u64(vaddq_u64(g0, vtwo_p), w1);
                        const uint64x2_t y2 = vaddq_u64(g2, w3);
                        const uint64x2_t y3 = vsubq_u64(vaddq_u64(g2, vtwo_p), w3);

                        vst1q_u64(dst + o0 + j, ntt_vfwd_store_value<FullReduce>(y0, vp, vtwo_p));
                        vst1q_u64(dst + o1 + j, ntt_vfwd_store_value<FullReduce>(y1, vp, vtwo_p));
                        vst1q_u64(dst + o2 + j, ntt_vfwd_store_value<FullReduce>(y2, vp, vtwo_p));
                        vst1q_u64(dst + o3 + j, ntt_vfwd_store_value<FullReduce>(y3, vp, vtwo_p));
                    }
                }
            }

            // Requires g >= 2, or g == 1 with m even
            void ntt_inv_layer_radix2_neon(
                const uint64_t *src, uint64_t *dst, size_t m, size_t g, const MultiplyUIntModOperand *roots, uint64_t p)
            {
                const uint64x2_t vtwo_p = vdupq_n_u64(p << 1);
                if (g == 1)
                {
                    // Groups i and i + 1 in the two lanes
                    for (size_t i = 0; i < m; i += 2)
                    {
                        uint64x2x2_t v = vld2q_u64(src + 2 * i);
                        ntt_vinv_bf(v.val[0], v.val[1], roots[i], roots[i + 1], p, vtwo_p);
                        vst2q_u64(dst + 2 * i, v);
                    }
                    return;
                }
                for (size_t i = 0; i < m; i++)
                {
                    const MultiplyUIntModOperand r = roots[i];
                    const size_t offset = 2 * g * i;
                    for (size_t j = 0; j < g; j += 2)
                    {
                        uint64x2_t a = vld1q_u64(src + offset + j);
                        uint64x2_t b = vld1q_u64(src + offset + g + j);
                        ntt_vinv_bf(a, b, r, r, p, vtwo_p);
                        vst1q_u64(dst + offset + j, a);
                        vst1q_u64(dst + offset + g + j, b);
                    }
                }
            }

            // Requires g >= 2, or g == 1 with m / 2 even
            void ntt_inv_layer_radix4_neon(
                const uint64_t *src, uint64_t *dst, size_t m, size_t g, const MultiplyUIntModOperand *roots_a,
                const MultiplyUIntModOperand *roots_b, uint64_t p)
            {
                const uint64x2_t vtwo_p = vdupq_n_u64(p << 1);
                if (g == 1)
                {
                    // Groups k and k + 1 in the two lanes
                    for (size_t k = 0; k < (m >> 1); k += 2)
                    {
                        uint64x2x4_t v = vld4q_u64(src + 4 * k);
                        ntt_vinv_bf(v.val[0], v.val[1], roots_a[2 * k], roots_a[2 * k + 2], p, vtwo_p);
                        ntt_vinv_bf(v.val[2], v.val[3], roots_a[2 * k + 1], roots_a[2 * k + 3], p, vtwo_p);
                        ntt_vinv_bf(v.val[0], v.val[2], roots_b[k], roots_b[k + 1], p, vtwo_p);
                        ntt_vinv_bf(v.val[1], v.val[3], roots_b[k], roots_b[k + 1], p, vtwo_p);
                        vst4q_u64(dst + 4 * k, v);
                    }
                    return;
                }
                for (size_t k = 0; k < (m >> 1); k++)
                {
                    const MultiplyUIntModOperand ra0 = roots_a[2 * k];
                    const MultiplyUIntModOperand ra1 = roots_a[2 * k + 1];
                    const MultiplyUIntModOperand rb = roots_b[k];
                    const size_t o0 = 4 * g * k;
                    const size_t o1 = o0 + g;
                    const size_t o2 = o1 + g;
                    const size_t o3 = o2 + g;
                    for (size_t j = 0; j < g; j += 2)
                    {
                        uint64x2_t x0 = vld1q_u64(src + o0 + j);
                        uint64x2_t x1 = vld1q_u64(src + o1 + j);
                        uint64x2_t x2 = vld1q_u64(src + o2 + j);
                        uint64x2_t x3 = vld1q_u64(src + o3 + j);

                        ntt_vinv_bf(x0, x1, ra0, ra0, p, vtwo_p);
                        ntt_vinv_bf(x2, x3, ra1, ra1, p, vtwo_p);
                        ntt_vinv_bf(x0, x2, rb, rb, p, vtwo_p);
                        ntt_vinv_bf(x1, x3, rb, rb, p, vtwo_p);

                        vst1q_u64(dst + o0 + j, x0);
                        vst1q_u64(dst + o1 + j, x1);
                        vst1q_u64(dst + o2 + j, x2);
                        vst1q_u64(dst + o3 + j, x3);
                    }
                }
            }

            // Requires g >= 2
            template <bool FullReduce>
            void ntt_inv_last_layers_radix4_neon(
                const uint64_t *src, uint64_t *dst, size_t g, const MultiplyUIntModOperand &ra0,
                const MultiplyUIntModOperand &ra1, const MultiplyUIntModOperand &s, const MultiplyUIntModOperand &ws,
                uint64_t p)
            {
                const uint64x2_t vp = vdupq_n_u64(p);
                const uint64x2_t vtwo_p = vdupq_n_u64(p << 1);
                for (size_t j = 0; j < g; j += 2)
                {
                    uint64x2_t x0 = vld1q_u64(src + j);
                    uint64x2_t x1 = vld1q_u64(src + g + j);
                    uint64x2_t x2 = vld1q_u64(src + 2 * g + j);
                    uint64x2_t x3 = vld1q_u64(src + 3 * g + j);

                    ntt_vinv_bf(x0, x1, ra0, ra0, p, vtwo_p);
                    ntt_vinv_bf(x2, x3, ra1, ra1, p, vtwo_p);
                    ntt_vinv_bf_scaled(x0, x2, s, ws, p, vtwo_p);
                    ntt_vinv_bf_scaled(x1, x3, s, ws, p, vtwo_p);

                    vst1q_u64(dst + j, ntt_vinv_store_value<FullReduce>(x0, vp));
                    vst1q_u64(dst + g + j, ntt_vinv_store_value<FullReduce>(x1, vp));
                    vst1q_u64(dst + 2 * g + j, ntt_vinv_store_value<FullReduce>(x2, vp));
                    vst1q_u64(dst + 3 * g + j, ntt_vinv_store_value<FullReduce>(x3, vp));
                }
            }
#endif

            // m groups of gap g; group i uses roots[m + i]
            template <bool Reduce, bool FullReduce>
            void ntt_fwd_layer_radix2(
                const uint64_t *src, uint64_t *dst, size_t m, size_t g, const MultiplyUIntModOperand *roots, uint64_t p,
                uint64_t ratio)
            {
#ifdef SEAL_NTT_USE_NEON
                if (!Reduce && g >= 2)
                {
                    ntt_fwd_layer_radix2_neon<FullReduce>(src, dst, m, g, roots, p);
                    return;
                }
#endif
                const uint64_t two_p = p << 1;
                for (size_t i = 0; i < m; i++)
                {
                    const MultiplyUIntModOperand r = roots[m + i];
                    const size_t offset = 2 * g * i;
                    for (size_t j = 0; j < g; j++)
                    {
                        uint64_t a = ntt_load<Reduce>(src, offset + j, p, ratio);
                        uint64_t b = ntt_load<Reduce>(src, offset + g + j, p, ratio);
                        ntt_fwd_bf(a, b, r, p, two_p);
                        dst[offset + j] = ntt_fwd_store_value<FullReduce>(a, p, two_p);
                        dst[offset + g + j] = ntt_fwd_store_value<FullReduce>(b, p, two_p);
                    }
                }
            }

            // m groups of gap 2h, then 2m groups of gap h
            template <bool Reduce, bool FullReduce>
            void ntt_fwd_layer_radix4(
                const uint64_t *src, uint64_t *dst, size_t m, size_t h, const MultiplyUIntModOperand *roots, uint64_t p,
                uint64_t ratio)
            {
#ifdef SEAL_NTT_USE_NEON
                if (!Reduce && h >= 2)
                {
                    ntt_fwd_layer_radix4_neon<FullReduce>(src, dst, m, h, roots, p);
                    return;
                }
#endif
                const uint64_t two_p = p << 1;
                if (h == 1)
                {
                    for (size_t i = 0; i < m; i++)
                    {
                        const MultiplyUIntModOperand r1 = roots[m + i];
                        const MultiplyUIntModOperand r2a = roots[2 * m + 2 * i];
                        const MultiplyUIntModOperand r2b = roots[2 * m + 2 * i + 1];
                        ntt_fwd_radix4_bf<Reduce, FullReduce>(src, dst, 4 * i, 1, r1, r2a, r2b, p, two_p, ratio);
                    }
                    return;
                }
                for (size_t i = 0; i < m; i++)
                {
                    const MultiplyUIntModOperand r1 = roots[m + i];
                    const MultiplyUIntModOperand r2a = roots[2 * m + 2 * i];
                    const MultiplyUIntModOperand r2b = roots[2 * m + 2 * i + 1];
                    const size_t offset = 4 * h * i;
                    for (size_t j = 0; j < h; j++)
                    {
                        ntt_fwd_radix4_bf<Reduce, FullReduce>(src, dst, offset + j, h, r1, r2a, r2b, p, two_p, ratio);
                    }
                }
            }

            // Forward NTT of src into dst (bit-reversed order); src may equal dst. Input in [0, 4p) (any 64-bit values
            // if Reduce), output in [0, 4p) ([0, p) if FullReduce). roots: NTTTables::get_from_root_powers().
            template <bool Reduce, bool FullReduce>
            void ntt_forward_kernel(
                const uint64_t *src, uint64_t *dst, int log_n, const MultiplyUIntModOperand *roots,
                const Modulus &modulus)
            {
                const uint64_t p = modulus.value();
                const uint64_t ratio = modulus.const_ratio()[1];
                const size_t n = size_t(1) << log_n;
                size_t m = 1;
                int layers = log_n;
                bool first = true;

                if (layers & 1)
                {
                    if (layers == 1)
                    {
                        ntt_fwd_layer_radix2<Reduce, FullReduce>(src, dst, m, n >> 1, roots, p, ratio);
                        return;
                    }
                    ntt_fwd_layer_radix2<Reduce, false>(src, dst, m, n >> 1, roots, p, ratio);
                    first = false;
                    m <<= 1;
                    layers--;
                }

                for (; layers > 0; layers -= 2)
                {
                    const size_t h = n / (4 * m);
                    if (first)
                    {
                        if (layers == 2)
                        {
                            ntt_fwd_layer_radix4<Reduce, FullReduce>(src, dst, m, h, roots, p, ratio);
                        }
                        else
                        {
                            ntt_fwd_layer_radix4<Reduce, false>(src, dst, m, h, roots, p, ratio);
                        }
                        first = false;
                    }
                    else if (layers == 2)
                    {
                        ntt_fwd_layer_radix4<false, FullReduce>(dst, dst, m, h, roots, p, ratio);
                    }
                    else
                    {
                        ntt_fwd_layer_radix4<false, false>(dst, dst, m, h, roots, p, ratio);
                    }
                    m <<= 2;
                }
            }

            // m groups of gap g; group i uses roots[i]
            void ntt_inv_layer_radix2(
                const uint64_t *src, uint64_t *dst, size_t m, size_t g, const MultiplyUIntModOperand *roots, uint64_t p)
            {
#ifdef SEAL_NTT_USE_NEON
                if (g >= 2 || !(m & 1))
                {
                    ntt_inv_layer_radix2_neon(src, dst, m, g, roots, p);
                    return;
                }
#endif
                const uint64_t two_p = p << 1;
                for (size_t i = 0; i < m; i++)
                {
                    const MultiplyUIntModOperand r = roots[i];
                    const size_t offset = 2 * g * i;
                    for (size_t j = 0; j < g; j++)
                    {
                        uint64_t a = src[offset + j];
                        uint64_t b = src[offset + g + j];
                        ntt_inv_bf(a, b, r, p, two_p);
                        dst[offset + j] = a;
                        dst[offset + g + j] = b;
                    }
                }
            }

            // m groups of gap g (roots_a), then m / 2 groups of gap 2g (roots_b)
            void ntt_inv_layer_radix4(
                const uint64_t *src, uint64_t *dst, size_t m, size_t g, const MultiplyUIntModOperand *roots_a,
                const MultiplyUIntModOperand *roots_b, uint64_t p)
            {
#ifdef SEAL_NTT_USE_NEON
                if (g >= 2 || !((m >> 1) & 1))
                {
                    ntt_inv_layer_radix4_neon(src, dst, m, g, roots_a, roots_b, p);
                    return;
                }
#endif
                const uint64_t two_p = p << 1;
                if (g == 1)
                {
                    for (size_t k = 0; k < (m >> 1); k++)
                    {
                        const MultiplyUIntModOperand ra0 = roots_a[2 * k];
                        const MultiplyUIntModOperand ra1 = roots_a[2 * k + 1];
                        const MultiplyUIntModOperand rb = roots_b[k];
                        ntt_inv_radix4_bf(src, dst, 4 * k, 1, ra0, ra1, rb, p, two_p);
                    }
                    return;
                }
                for (size_t k = 0; k < (m >> 1); k++)
                {
                    const MultiplyUIntModOperand ra0 = roots_a[2 * k];
                    const MultiplyUIntModOperand ra1 = roots_a[2 * k + 1];
                    const MultiplyUIntModOperand rb = roots_b[k];
                    const size_t offset = 4 * g * k;
                    for (size_t j = 0; j < g; j++)
                    {
                        ntt_inv_radix4_bf(src, dst, offset + j, g, ra0, ra1, rb, p, two_p);
                    }
                }
            }

            // The last two layers: 2 groups of gap g, then 1 scaled group of gap 2g
            template <bool FullReduce>
            void ntt_inv_last_layers_radix4(
                const uint64_t *src, uint64_t *dst, size_t g, const MultiplyUIntModOperand *roots_a,
                const MultiplyUIntModOperand &scalar, const MultiplyUIntModOperand &scaled_root, uint64_t p)
            {
                const MultiplyUIntModOperand s = scalar;
                const MultiplyUIntModOperand ws = scaled_root;
                const MultiplyUIntModOperand ra0 = roots_a[0];
                const MultiplyUIntModOperand ra1 = roots_a[1];
#ifdef SEAL_NTT_USE_NEON
                if (g >= 2)
                {
                    ntt_inv_last_layers_radix4_neon<FullReduce>(src, dst, g, ra0, ra1, s, ws, p);
                    return;
                }
#endif
                const uint64_t two_p = p << 1;
                for (size_t j = 0; j < g; j++)
                {
                    uint64_t x0 = src[j];
                    uint64_t x1 = src[g + j];
                    uint64_t x2 = src[2 * g + j];
                    uint64_t x3 = src[3 * g + j];

                    ntt_inv_bf(x0, x1, ra0, p, two_p);
                    ntt_inv_bf(x2, x3, ra1, p, two_p);
                    ntt_inv_bf_scaled(x0, x2, s, ws, p, two_p);
                    ntt_inv_bf_scaled(x1, x3, s, ws, p, two_p);

                    dst[j] = ntt_inv_store_value<FullReduce>(x0, p);
                    dst[g + j] = ntt_inv_store_value<FullReduce>(x1, p);
                    dst[2 * g + j] = ntt_inv_store_value<FullReduce>(x2, p);
                    dst[3 * g + j] = ntt_inv_store_value<FullReduce>(x3, p);
                }
            }

            // Inverse NTT of src (bit-reversed order) into dst, times scalar instead of n^(-1); src may equal dst.
            // Input in [0, 2p), output in [0, 2p) ([0, p) if FullReduce). roots: NTTTables::get_from_inv_root_powers().
            template <bool FullReduce>
            void ntt_inverse_kernel(
                const uint64_t *src, uint64_t *dst, int log_n, const MultiplyUIntModOperand *roots,
                const MultiplyUIntModOperand &scalar, const Modulus &modulus)
            {
                const uint64_t p = modulus.value();
                const size_t n = size_t(1) << log_n;

                const MultiplyUIntModOperand last_root = roots[n - 1];
                MultiplyUIntModOperand scaled_root;
                scaled_root.set(multiply_uint_mod(last_root.operand, scalar, modulus), modulus);

                if (log_n == 1)
                {
                    uint64_t x = src[0];
                    uint64_t y = src[1];
                    ntt_inv_bf_scaled(x, y, scalar, scaled_root, p, p << 1);
                    dst[0] = ntt_inv_store_value<FullReduce>(x, p);
                    dst[1] = ntt_inv_store_value<FullReduce>(y, p);
                    return;
                }

                // Layer with m groups uses roots[n - 2m + 1 .. n - m]
                size_t m = n >> 1;
                size_t g = 1;
                int layers = log_n;
                const uint64_t *in = src;

                if (layers & 1)
                {
                    ntt_inv_layer_radix2(in, dst, m, g, roots + (n - 2 * m + 1), p);
                    in = dst;
                    m >>= 1;
                    g <<= 1;
                    layers--;
                }

                for (; layers > 2; layers -= 2)
                {
                    ntt_inv_layer_radix4(in, dst, m, g, roots + (n - 2 * m + 1), roots + (n - m + 1), p);
                    in = dst;
                    m >>= 2;
                    g <<= 2;
                }

                // Here m == 2
                ntt_inv_last_layers_radix4<FullReduce>(in, dst, g, roots + (n - 3), scalar, scaled_root, p);
            }
        } // namespace
#endif

        NTTTables::NTTTables(int coeff_count_power, const Modulus &modulus, MemoryPoolHandle pool)
            : pool_(std::move(pool))
        {
#ifdef SEAL_DEBUG
            if (!pool_)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            initialize(coeff_count_power, modulus);
        }

        void NTTTables::initialize(int coeff_count_power, const Modulus &modulus)
        {
            if ((coeff_count_power < get_power_of_two(SEAL_POLY_MOD_DEGREE_MIN)) ||
                coeff_count_power > get_power_of_two(SEAL_POLY_MOD_DEGREE_MAX))
            {
                throw invalid_argument("coeff_count_power out of range");
            }
            coeff_count_power_ = coeff_count_power;
            coeff_count_ = size_t(1) << coeff_count_power_;
            modulus_ = modulus;
            // We defer parameter checking to try_minimal_primitive_root(...)
            if (!try_minimal_primitive_root(2 * coeff_count_, modulus_, root_))
            {
                throw invalid_argument("invalid modulus");
            }
            if (!try_invert_uint_mod(root_, modulus_, inv_root_))
            {
                throw invalid_argument("invalid modulus");
            }

#ifdef SEAL_USE_INTEL_HEXL
            // Pre-compute HEXL NTT object
            intel::seal_ext::get_ntt(coeff_count_, modulus.value(), root_);
#endif

            // Populate tables with powers of root in specific orders.
            root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);
            MultiplyUIntModOperand root;
            root.set(root_, modulus_);
            uint64_t power = root_;
            for (size_t i = 1; i < coeff_count_; i++)
            {
                root_powers_[reverse_bits(i, coeff_count_power_)].set(power, modulus_);
                power = multiply_uint_mod(power, root, modulus_);
            }
            root_powers_[0].set(static_cast<uint64_t>(1), modulus_);

            inv_root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);
            root.set(inv_root_, modulus_);
            power = inv_root_;
            for (size_t i = 1; i < coeff_count_; i++)
            {
                inv_root_powers_[reverse_bits(i - 1, coeff_count_power_) + 1].set(power, modulus_);
                power = multiply_uint_mod(power, root, modulus_);
            }
            inv_root_powers_[0].set(static_cast<uint64_t>(1), modulus_);

            // Compute n^(-1) modulo q.
            uint64_t degree_uint = static_cast<uint64_t>(coeff_count_);
            if (!try_invert_uint_mod(degree_uint, modulus_, inv_degree_modulo_.operand))
            {
                throw invalid_argument("invalid modulus");
            }
            inv_degree_modulo_.set_quotient(modulus_);

            mod_arith_lazy_ = ModArithLazy(modulus_);
            ntt_handler_ = NTTHandler(mod_arith_lazy_);
        }

        class NTTTablesCreateIter
        {
        public:
            using value_type = NTTTables;
            using pointer = void;
            using reference = value_type;
            using difference_type = ptrdiff_t;

            // LegacyInputIterator allows reference to be equal to value_type so we can construct
            // the return objects on the fly and return by value.
            using iterator_category = input_iterator_tag;

            // Require default constructor
            NTTTablesCreateIter()
            {}

            // Other constructors
            NTTTablesCreateIter(int coeff_count_power, vector<Modulus> modulus, MemoryPoolHandle pool)
                : coeff_count_power_(coeff_count_power), modulus_(modulus), pool_(std::move(pool))
            {}

            // Require copy and move constructors and assignments
            NTTTablesCreateIter(const NTTTablesCreateIter &copy) = default;

            NTTTablesCreateIter(NTTTablesCreateIter &&source) = default;

            NTTTablesCreateIter &operator=(const NTTTablesCreateIter &assign) = default;

            NTTTablesCreateIter &operator=(NTTTablesCreateIter &&assign) = default;

            // Dereferencing creates NTTTables and returns by value
            inline value_type operator*() const
            {
                return { coeff_count_power_, modulus_[index_], pool_ };
            }

            // Pre-increment
            inline NTTTablesCreateIter &operator++() noexcept
            {
                index_++;
                return *this;
            }

            // Post-increment
            inline NTTTablesCreateIter operator++(int) noexcept
            {
                NTTTablesCreateIter result(*this);
                index_++;
                return result;
            }

            // Must be EqualityComparable
            inline bool operator==(const NTTTablesCreateIter &compare) const noexcept
            {
                return (compare.index_ == index_) && (coeff_count_power_ == compare.coeff_count_power_);
            }

            inline bool operator!=(const NTTTablesCreateIter &compare) const noexcept
            {
                return !operator==(compare);
            }

            // Arrow operator must be defined
            value_type operator->() const
            {
                return **this;
            }

        private:
            size_t index_ = 0;
            int coeff_count_power_ = 0;
            vector<Modulus> modulus_;
            MemoryPoolHandle pool_;
        };

        void CreateNTTTables(
            int coeff_count_power, const vector<Modulus> &modulus, Pointer<NTTTables> &tables, MemoryPoolHandle pool)
        {
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
            if (!modulus.size())
            {
                throw invalid_argument("invalid modulus");
            }
            // coeff_count_power and modulus will be validated by "allocate"

            NTTTablesCreateIter iter(coeff_count_power, modulus, pool);
            tables = allocate(iter, modulus.size(), pool);
        }

        void ntt_negacyclic_harvey_lazy(CoeffIter operand, const NTTTables &tables)
        {
#ifdef SEAL_USE_INTEL_HEXL
            size_t N = size_t(1) << tables.coeff_count_power();
            uint64_t p = tables.modulus().value();
            uint64_t root = tables.get_root();

            intel::seal_ext::compute_forward_ntt(operand, N, p, root, 4, 4);
#else
            ntt_forward_kernel<false, false>(
                operand.ptr(), operand.ptr(), tables.coeff_count_power(), tables.get_from_root_powers(),
                tables.modulus());
#endif
        }

        void ntt_negacyclic_harvey(CoeffIter operand, const NTTTables &tables)
        {
#ifdef SEAL_USE_INTEL_HEXL
            size_t N = size_t(1) << tables.coeff_count_power();
            uint64_t p = tables.modulus().value();
            uint64_t root = tables.get_root();

            intel::seal_ext::compute_forward_ntt(operand, N, p, root, 4, 1);
#else
            ntt_forward_kernel<false, true>(
                operand.ptr(), operand.ptr(), tables.coeff_count_power(), tables.get_from_root_powers(),
                tables.modulus());
#endif
        }

        void inverse_ntt_negacyclic_harvey_lazy(CoeffIter operand, const NTTTables &tables)
        {
#ifdef SEAL_USE_INTEL_HEXL
            size_t N = size_t(1) << tables.coeff_count_power();
            uint64_t p = tables.modulus().value();
            uint64_t root = tables.get_root();
            intel::seal_ext::compute_inverse_ntt(operand, N, p, root, 2, 2);
#else
            ntt_inverse_kernel<false>(
                operand.ptr(), operand.ptr(), tables.coeff_count_power(), tables.get_from_inv_root_powers(),
                tables.inv_degree_modulo(), tables.modulus());
#endif
        }

        void inverse_ntt_negacyclic_harvey(CoeffIter operand, const NTTTables &tables)
        {
#ifdef SEAL_USE_INTEL_HEXL
            size_t N = size_t(1) << tables.coeff_count_power();
            uint64_t p = tables.modulus().value();
            uint64_t root = tables.get_root();
            intel::seal_ext::compute_inverse_ntt(operand, N, p, root, 2, 1);
#else
            ntt_inverse_kernel<true>(
                operand.ptr(), operand.ptr(), tables.coeff_count_power(), tables.get_from_inv_root_powers(),
                tables.inv_degree_modulo(), tables.modulus());
#endif
        }

        void ntt_negacyclic_harvey_lazy(
            ConstCoeffIter operand, const NTTTables &tables, bool reduce_input, CoeffIter result)
        {
#ifdef SEAL_USE_INTEL_HEXL
            size_t n = size_t(1) << tables.coeff_count_power();
            if (reduce_input)
            {
                modulo_poly_coeffs(operand, n, tables.modulus(), result);
            }
            else if (operand.ptr() != result.ptr())
            {
                copy_n(operand.ptr(), n, result.ptr());
            }
            ntt_negacyclic_harvey_lazy(result, tables);
#else
            if (reduce_input)
            {
                ntt_forward_kernel<true, false>(
                    operand.ptr(), result.ptr(), tables.coeff_count_power(), tables.get_from_root_powers(),
                    tables.modulus());
            }
            else
            {
                ntt_forward_kernel<false, false>(
                    operand.ptr(), result.ptr(), tables.coeff_count_power(), tables.get_from_root_powers(),
                    tables.modulus());
            }
#endif
        }

        void inverse_ntt_negacyclic_harvey(ConstCoeffIter operand, const NTTTables &tables, CoeffIter result)
        {
#ifdef SEAL_USE_INTEL_HEXL
            if (operand.ptr() != result.ptr())
            {
                copy_n(operand.ptr(), size_t(1) << tables.coeff_count_power(), result.ptr());
            }
            inverse_ntt_negacyclic_harvey(result, tables);
#else
            ntt_inverse_kernel<true>(
                operand.ptr(), result.ptr(), tables.coeff_count_power(), tables.get_from_inv_root_powers(),
                tables.inv_degree_modulo(), tables.modulus());
#endif
        }

        void inverse_ntt_negacyclic_harvey_scaled(
            ConstCoeffIter operand, uint64_t scalar, const NTTTables &tables, CoeffIter result)
        {
            const Modulus &modulus = tables.modulus();
#ifdef SEAL_USE_INTEL_HEXL
            inverse_ntt_negacyclic_harvey(operand, tables, result);
            MultiplyUIntModOperand s;
            s.set(barrett_reduce_64(scalar, modulus), modulus);
            multiply_poly_scalar_coeffmod(result, size_t(1) << tables.coeff_count_power(), s, modulus, result);
#else
            // Fold scalar into n^(-1)
            MultiplyUIntModOperand s;
            s.set(multiply_uint_mod(barrett_reduce_64(scalar, modulus), tables.inv_degree_modulo(), modulus), modulus);
            ntt_inverse_kernel<true>(
                operand.ptr(), result.ptr(), tables.coeff_count_power(), tables.get_from_inv_root_powers(), s, modulus);
#endif
        }
    } // namespace util
} // namespace seal
