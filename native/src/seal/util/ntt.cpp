// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/ntt.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include <algorithm>
#include <vector>
#ifdef SEAL_USE_INTEL_HEXL
#include "seal/memorymanager.h"
#include "seal/util/iterator.h"
#include "seal/util/locks.h"
#include "seal/util/pointer.h"
#include <unordered_map>
#include "hexl/hexl.hpp"
#endif
#ifdef __riscv_vector
#include <riscv_vector.h>
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

    #if defined(__riscv_v_intrinsic)
        vuint64m4_t parallel_128bit_div_4_rvv(vuint64m4_t num_hi, vuint64m4_t num_lo, vuint64m4_t den, size_t vl) {
            vuint64m4_t v_quo = __riscv_vmv_v_x_u64m4(0, vl);
            vuint64m4_t v_rem = __riscv_vmv_v_x_u64m4(0, vl);
            
            // Process upper 64 bits from num_hi
           for (int j = 0; j < 64; j++) {
                v_rem = __riscv_vsll_vx_u64m4(v_rem, 1, vl);
                vuint64m4_t next_bit = __riscv_vsrl_vx_u64m4(num_hi, 63, vl);
                num_hi = __riscv_vsll_vx_u64m4(num_hi, 1, vl);
                v_rem = __riscv_vor_vv_u64m4(v_rem, next_bit, vl);
                v_quo = __riscv_vsll_vx_u64m4(v_quo, 1, vl);
                
                vbool16_t mask = __riscv_vmsgeu_vv_u64m4_b16(v_rem, den, vl);
                v_rem = __riscv_vsub_vv_u64m4_mu(mask, v_rem, v_rem, den, vl);
                v_quo = __riscv_vor_vx_u64m4_mu(mask, v_quo, v_quo, 1, vl);
           } 
            // Process lower 64 bits from num_lo
          
            for (int j = 0; j < 64; j++) {
                v_rem = __riscv_vsll_vx_u64m4(v_rem, 1, vl);
                vuint64m4_t next_bit = __riscv_vsrl_vx_u64m4(num_lo, 63, vl);
                num_lo = __riscv_vsll_vx_u64m4(num_lo, 1, vl);
                v_rem = __riscv_vor_vv_u64m4(v_rem, next_bit, vl);
                v_quo = __riscv_vsll_vx_u64m4(v_quo, 1, vl);
                
                vbool16_t mask = __riscv_vmsgeu_vv_u64m4_b16(v_rem, den, vl);
                v_rem = __riscv_vsub_vv_u64m4_mu(mask, v_rem, v_rem, den, vl);
                v_quo = __riscv_vor_vx_u64m4_mu(mask, v_quo, v_quo, 1, vl);
            }         
            return v_quo;
        }
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
#ifdef SEAL_DEBUG
            if ((coeff_count_power < get_power_of_two(SEAL_POLY_MOD_DEGREE_MIN)) ||
                coeff_count_power > get_power_of_two(SEAL_POLY_MOD_DEGREE_MAX))
            {
                throw invalid_argument("coeff_count_power out of range");
            }
#endif
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
            
            #if defined(__riscv_v_intrinsic)
            
                // Unified function with buffer reuse - single optimization
                auto compute_powers_vectorized = [&](uint64_t initial_power, MultiplyUIntModOperand* target_array, bool is_inverse) -> void {
                    
                    // Thread-local buffers - reused across calls to avoid repeated allocation
                    static thread_local std::vector<uint64_t> num_buffer;
                    static thread_local std::vector<uint64_t> quot_buffer;
                    
                    // Resize buffers only if needed
                    if (num_buffer.size() < coeff_count_) {
                        num_buffer.resize(coeff_count_);
                        quot_buffer.resize(coeff_count_);
                    }
                    
                    // Generate powers
                    num_buffer[0] = initial_power;
                    for (size_t i = 1; i < coeff_count_; i++) {
                        num_buffer[i] = multiply_uint_mod(num_buffer[i-1], root, modulus_);
                    }
                    
                    // Vectorized division
                    uint64_t denom = modulus_.value();
                    size_t processed = 0;
                    
                    size_t vl = __riscv_vsetvl_e64m4(coeff_count_-1 - processed);
                    vuint64m4_t den_vec = __riscv_vmv_v_x_u64m4(denom, vl);
                    vuint64m4_t num_lo = __riscv_vmv_v_x_u64m4(0, vl); // low 64 bits assumed zero
                    
                    while (processed < coeff_count_-1) {
                        vl = __riscv_vsetvl_e64m4(coeff_count_-1 - processed);
                        vuint64m4_t num_hi = __riscv_vle64_v_u64m4(num_buffer.data() + processed, vl);
                        vuint64m4_t quo_vec = parallel_128bit_div_4_rvv(num_hi, num_lo, den_vec, vl);
                        __riscv_vse64_v_u64m4(quot_buffer.data() + processed, quo_vec, vl);
                        processed += vl;
                    }
                    
                    // Store results
                    if (is_inverse) {
                        for(size_t i = 1; i < coeff_count_; i++){
                            size_t rev = reverse_bits(i-1, coeff_count_power_) + 1;
                            target_array[rev].operand = num_buffer[i - 1];
                            target_array[rev].quotient = quot_buffer[i - 1];
                        }
                    } else {
                        for(size_t i = 1; i < coeff_count_; i++){
                            size_t rev = reverse_bits(i, coeff_count_power_);
                            target_array[rev].operand = num_buffer[i - 1];
                            target_array[rev].quotient = quot_buffer[i - 1];
                        }
                    }
                };
                
                // Compute root powers using unified function
                compute_powers_vectorized(power, root_powers_.get(), false);
                
            #else
            
            // Original scalar fallback
            for (size_t i = 1; i < coeff_count_; i++)
            {
                root_powers_[reverse_bits(i, coeff_count_power_)].set(power, modulus_);
                power = multiply_uint_mod(power, root, modulus_);
            }
            
            #endif
            
            root_powers_[0].set(static_cast<uint64_t>(1), modulus_);
  
            // Inverse root powers
            inv_root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);
            root.set(inv_root_, modulus_);
            power = inv_root_;
            
            #if defined(__riscv_v_intrinsic)
                // Reuse the same function and buffers for inverse powers
                compute_powers_vectorized(power, inv_root_powers_.get(), true);
            #else
            
            // Original scalar fallback for inverse
            for (size_t i = 1; i < coeff_count_; i++)
            {
                inv_root_powers_[reverse_bits(i - 1, coeff_count_power_) + 1].set(power, modulus_);
                power = multiply_uint_mod(power, root, modulus_);
            }
            
            #endif
            
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
            #if defined(__riscv_v_intrinsic)
                tables.ntt_handler().transform_to_rev_rvv(operand.ptr(), tables.coeff_count_power(), tables.get_from_root_powers());
            #else 
                tables.ntt_handler().transform_to_rev(operand.ptr(), tables.coeff_count_power(), tables.get_from_root_powers());
            #endif
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
            ntt_negacyclic_harvey_lazy(operand, tables);
            // Finally maybe we need to reduce every coefficient modulo q, but we
            // know that they are in the range [0, 4q).
            // Since word size is controlled this is fast.
            std::uint64_t modulus = tables.modulus().value();
            std::uint64_t two_times_modulus = modulus * 2;
            std::size_t n = std::size_t(1) << tables.coeff_count_power();

            SEAL_ITERATE(operand, n, [&](auto &I) {
                // Note: I must be passed to the lambda by reference.
                if (I >= two_times_modulus)
                {
                    I -= two_times_modulus;
                }
                if (I >= modulus)
                {
                    I -= modulus;
                }
            });
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
            MultiplyUIntModOperand inv_degree_modulo = tables.inv_degree_modulo();
            #if defined(__riscv_v_intrinsic)
                tables.ntt_handler().transform_from_rev_rvv(operand.ptr(), tables.coeff_count_power(), tables.get_from_inv_root_powers(), &inv_degree_modulo);
            #else
                tables.ntt_handler().transform_from_rev(operand.ptr(), tables.coeff_count_power(), tables.get_from_inv_root_powers(), &inv_degree_modulo);
            #endif
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
            inverse_ntt_negacyclic_harvey_lazy(operand, tables);
            std::uint64_t modulus = tables.modulus().value();
            std::size_t n = std::size_t(1) << tables.coeff_count_power();

            // Final adjustments; compute a[j] = a[j] * n^{-1} mod q.
            // We incorporated the final adjustment in the butterfly. Only need to reduce here.
            SEAL_ITERATE(operand, n, [&](auto &I) {
                // Note: I must be passed to the lambda by reference.
                if (I >= modulus)
                {
                    I -= modulus;
                }
            });
#endif
        }
    } // namespace util
} // namespace seal
