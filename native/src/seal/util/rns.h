// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "seal/util/iterator.h"
#include "seal/util/ntt.h"
#include "seal/util/pointer.h"
#include "seal/util/uintarithsmallmod.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <vector>

namespace seal
{
    namespace util
    {
        class RNSBase
        {
        public:
            RNSBase(const std::vector<Modulus> &rnsbase, MemoryPoolHandle pool);

            RNSBase(RNSBase &&source) = default;

            RNSBase(const RNSBase &copy, MemoryPoolHandle pool);

            RNSBase(const RNSBase &copy) : RNSBase(copy, copy.pool_)
            {}

            RNSBase &operator=(const RNSBase &assign) = delete;

            SEAL_NODISCARD inline const Modulus &operator[](std::size_t index) const
            {
                if (index >= size_)
                {
                    throw std::out_of_range("index is out of range");
                }
                return base_[index];
            }

            SEAL_NODISCARD inline std::size_t size() const noexcept
            {
                return size_;
            }

            SEAL_NODISCARD bool contains(const Modulus &value) const noexcept;

            SEAL_NODISCARD bool is_subbase_of(const RNSBase &superbase) const noexcept;

            SEAL_NODISCARD inline bool is_superbase_of(const RNSBase &subbase) const noexcept
            {
                return subbase.is_subbase_of(*this);
            }

            SEAL_NODISCARD inline bool is_proper_subbase_of(const RNSBase &superbase) const noexcept
            {
                return (size_ < superbase.size_) && is_subbase_of(superbase);
            }

            SEAL_NODISCARD inline bool is_proper_superbase_of(const RNSBase &subbase) const noexcept
            {
                return (size_ > subbase.size_) && !is_subbase_of(subbase);
            }

            SEAL_NODISCARD RNSBase extend(const Modulus &value) const;

            SEAL_NODISCARD RNSBase extend(const RNSBase &other) const;

            SEAL_NODISCARD RNSBase drop() const;

            SEAL_NODISCARD RNSBase drop(const Modulus &value) const;

            void decompose(std::uint64_t *value, MemoryPoolHandle pool) const;

            void decompose_array(std::uint64_t *value, std::size_t count, MemoryPoolHandle pool) const;

            void compose(std::uint64_t *value, MemoryPoolHandle pool) const;

            void compose_array(std::uint64_t *value, std::size_t count, MemoryPoolHandle pool) const;

            SEAL_NODISCARD inline const Modulus *base() const noexcept
            {
                return base_.get();
            }

            SEAL_NODISCARD inline const std::uint64_t *base_prod() const noexcept
            {
                return base_prod_.get();
            }

            SEAL_NODISCARD inline const std::uint64_t *punctured_prod_array() const noexcept
            {
                return punctured_prod_array_.get();
            }

            SEAL_NODISCARD inline const MultiplyUIntModOperand *inv_punctured_prod_mod_base_array() const noexcept
            {
                return inv_punctured_prod_mod_base_array_.get();
            }

        private:
            RNSBase(MemoryPoolHandle pool) : pool_(std::move(pool)), size_(0)
            {
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }
            }

            bool initialize();

            MemoryPoolHandle pool_;

            std::size_t size_;

            Pointer<Modulus> base_;

            Pointer<std::uint64_t> base_prod_;

            Pointer<std::uint64_t> punctured_prod_array_;

            Pointer<MultiplyUIntModOperand> inv_punctured_prod_mod_base_array_;
        };

        class BaseConverter
        {
        public:
            BaseConverter(const RNSBase &ibase, const RNSBase &obase, MemoryPoolHandle pool)
                : pool_(std::move(pool)), ibase_(ibase, pool_), obase_(obase, pool_)
            {
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }

                initialize(nullptr, nullptr);
            }

            /**
            Creates a BaseConverter for a scaled fast base conversion. With ibase = {q_1, ..., q_k} (with product q)
            and obase = {p_1, ..., p_l}, fast_convert and fast_convert_array compute

                out_j = [ (sum_i [in_i * a_i * (q/q_i)^(-1)]_{q_i} * (q/q_i)) * b_j ]_{p_j},

            where a_i = ibase_scale[i] and b_j = obase_scale[j]. With all factors equal to 1 this is the usual fast
            base conversion. Scaling is not supported by exact_convert_array.

            @throws std::invalid_argument if the sizes of ibase_scale or obase_scale do not match the bases
            */
            BaseConverter(
                const RNSBase &ibase, const RNSBase &obase, const std::vector<std::uint64_t> &ibase_scale,
                const std::vector<std::uint64_t> &obase_scale, MemoryPoolHandle pool)
                : pool_(std::move(pool)), ibase_(ibase, pool_), obase_(obase, pool_)
            {
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }
                if (ibase_scale.size() != ibase_.size() || obase_scale.size() != obase_.size())
                {
                    throw std::invalid_argument("scale size mismatch");
                }

                initialize(ibase_scale.data(), obase_scale.data());
            }

            SEAL_NODISCARD inline std::size_t ibase_size() const noexcept
            {
                return ibase_.size();
            }

            SEAL_NODISCARD inline std::size_t obase_size() const noexcept
            {
                return obase_.size();
            }

            SEAL_NODISCARD inline const RNSBase &ibase() const noexcept
            {
                return ibase_;
            }

            SEAL_NODISCARD inline const RNSBase &obase() const noexcept
            {
                return obase_;
            }

            void fast_convert(ConstCoeffIter in, CoeffIter out, MemoryPoolHandle pool) const;

            /**
            Converts every coefficient of in. The input coefficients may be any 64-bit values. in and out may overlap
            only at equal coefficient indices; for example, they may be identical or disjoint.
            */
            void fast_convert_array(ConstRNSIter in, RNSIter out, MemoryPoolHandle pool) const;

            // The exact base convertion function, only supports obase size of 1.
            void exact_convert_array(ConstRNSIter in, CoeffIter out, MemoryPoolHandle) const;

        private:
            friend class RNSTool;

            BaseConverter(const BaseConverter &copy) = delete;

            BaseConverter(BaseConverter &&source) = delete;

            BaseConverter &operator=(const BaseConverter &assign) = delete;

            BaseConverter &operator=(BaseConverter &&assign) = delete;

            void initialize(const std::uint64_t *ibase_scale, const std::uint64_t *obase_scale);

            /**
            Converts count coefficients, reading ibase component i from in + i * in_stride and writing obase component
            j to out + j * out_stride. The output equals the corresponding coefficients of fast_convert_array. out
            must not overlap in or temp.

            @param[in] input_reduced True if every input coefficient is already reduced modulo its ibase element
            @param[out] temp Scratch space for count * ibase_size() values. On return, row i (at temp + i * count)
            holds [in_i * a_i * (q/q_i)^(-1)]_{q_i}, unless input_reduced is true, the first step is the identity, and
            in_stride equals count.
            */
            void fast_convert_block(
                const std::uint64_t *in, std::size_t in_stride, std::size_t count, bool input_reduced,
                std::uint64_t *out, std::size_t out_stride, std::uint64_t *temp) const;

            // Number of coefficients converted at a time; a block of first-step values (ibase_size() rows) then stays
            // in cache for typical base sizes
            static constexpr std::size_t max_block_size = 512;

            MemoryPoolHandle pool_;

            RNSBase ibase_;

            RNSBase obase_;

            // Whether this converter was created with input or output scaling factors
            bool is_scaled_ = false;

            // Whether all constants of the first step (the inverse punctured products times the input scaling factors)
            // are 1
            bool unit_first_step_ = false;

            // a_i * (q/q_i)^(-1) mod q_i, where a_i are the input scaling factors (all 1 if not scaled)
            Pointer<MultiplyUIntModOperand> scaled_inv_punctured_prod_;

            // b_j * (q/q_i) mod p_j, where b_j are the output scaling factors (all 1 if not scaled)
            Pointer<Pointer<std::uint64_t>> base_change_matrix_;

            // Row-major copy of base_change_matrix_ used by fast_convert_block. Rows for odd p_j are multiplied by
            // 2^64 mod p_j, so that dot products can be reduced with a Montgomery reduction instead of a Barrett
            // reduction.
            Pointer<std::uint64_t> conv_matrix_;

            // -p_j^(-1) mod 2^64 for odd p_j, and 0 for even p_j
            Pointer<std::uint64_t> obase_neg_inv_mod_2_64_;

            // End indices of a partition of [0, ibase_size()) into chunks in which the sum of (q_i - 1) is less than
            // 2^64, so that a dot product over a chunk is less than p_j * 2^64 (the input bound of Montgomery
            // reduction)
            std::vector<std::size_t> ibase_chunk_ends_;
        };

        class RNSTool
        {
        public:
            /**
            @throws std::invalid_argument if poly_modulus_degree is out of range, coeff_modulus is not valid, or pool is
            invalid.
            @throws std::logic_error if coeff_modulus and extended bases do not support NTT or are not coprime.
            */
            RNSTool(
                std::size_t poly_modulus_degree, const RNSBase &coeff_modulus, const Modulus &plain_modulus,
                MemoryPoolHandle pool);

            /**
            @param[in] input Must be in RNS form, i.e. coefficient must be less than the associated modulus.
            */
            void divide_and_round_q_last_inplace(RNSIter input, MemoryPoolHandle pool) const;

            void divide_and_round_q_last_ntt_inplace(
                RNSIter input, ConstNTTTablesIter rns_ntt_tables, MemoryPoolHandle pool) const;

            /**
            Out-of-place versions of divide_and_round_q_last_inplace and divide_and_round_q_last_ntt_inplace: the
            result, in base q without its last modulus, is written to destination. Component i of destination may
            coincide with component j <= i of input; in particular, destination may equal input.
            */
            void divide_and_round_q_last(ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool) const;

            void divide_and_round_q_last_ntt(
                ConstRNSIter input, ConstNTTTablesIter rns_ntt_tables, RNSIter destination,
                MemoryPoolHandle pool) const;

            /**
            Removes the last modulus of q from a BGV ciphertext component x in NTT form: computes (x - delta) / q_last,
            where delta is a multiple of t congruent to x modulo q_last. The result is written to destination, with the
            same rules as for divide_and_round_q_last.
            */
            void mod_t_and_divide_q_last_ntt(
                ConstRNSIter input, ConstNTTTablesIter rns_ntt_tables, RNSIter destination,
                MemoryPoolHandle pool) const;

            /**
            Shenoy-Kumaresan conversion from Bsk to q
            */
            void fastbconv_sk(ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool) const;

            /**
            Montgomery reduction mod q; changes base from Bsk U {m_tilde} to Bsk
            */
            void sm_mrq(ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool) const;

            /**
            Divide by q and fast floor from q U Bsk to Bsk
            */
            void fast_floor(ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool) const;

            /**
            Fast base conversion from q to Bsk U {m_tilde}
            */
            void fastbconv_m_tilde(ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool) const;

            /**
            Steps (1)-(2) of BEHZ multiplication (see Evaluator::bfv_multiply): fastbconv_m_tilde followed by sm_mrq,
            from base q to base Bsk. The input may hold any 64-bit values. If lazy_output is true, each output
            coefficient is only reduced to [0, 3m) for its prime m in Bsk, which suffices as input to
            ntt_negacyclic_harvey_lazy.
            */
            void fastbconv_m_tilde_sm_mrq(
                ConstRNSIter input, bool lazy_output, RNSIter destination, MemoryPoolHandle pool) const;

            /**
            Steps (5)-(8) of BEHZ multiplication (see Evaluator::bfv_multiply): inverse NTT of the input in base
            q U Bsk, multiplication by t, fast_floor, and fastbconv_sk to base q. input_q and input_Bsk are in NTT form
            with every coefficient in [0, 2m) for its prime m, and are overwritten. If input_montgomery_form is true,
            the input holds c * 2^(-64) mod m, and the result is computed for c.
            */
            void inverse_ntt_multiply_t_fast_floor_fastbconv_sk(
                RNSIter input_q, RNSIter input_Bsk, ConstNTTTablesIter base_q_ntt_tables, bool input_montgomery_form,
                RNSIter destination, MemoryPoolHandle pool) const;

            /**
            Compute round(t/q * |input|_q) mod t exactly
            */
            void decrypt_scale_and_round(ConstRNSIter phase, CoeffIter destination, MemoryPoolHandle pool) const;

            /**
            Remove the last q for bgv ciphertext
            */
            void mod_t_and_divide_q_last_ntt_inplace(
                RNSIter input, ConstNTTTablesIter rns_ntt_tables, MemoryPoolHandle pool) const;

            /**
            Compute mod t
            */
            void decrypt_modt(RNSIter phase, CoeffIter destination, MemoryPoolHandle pool) const;

            SEAL_NODISCARD inline auto inv_q_last_mod_q() const noexcept
            {
                return inv_q_last_mod_q_.get();
            }

            SEAL_NODISCARD inline auto base_Bsk_ntt_tables() const noexcept
            {
                return base_Bsk_ntt_tables_.get();
            }

            SEAL_NODISCARD inline auto base_q() const noexcept
            {
                return base_q_.get();
            }

            SEAL_NODISCARD inline auto base_B() const noexcept
            {
                return base_B_.get();
            }

            SEAL_NODISCARD inline auto base_Bsk() const noexcept
            {
                return base_Bsk_.get();
            }

            SEAL_NODISCARD inline auto base_Bsk_m_tilde() const noexcept
            {
                return base_Bsk_m_tilde_.get();
            }

            SEAL_NODISCARD inline auto base_t_gamma() const noexcept
            {
                return base_t_gamma_.get();
            }

            SEAL_NODISCARD inline auto &m_tilde() const noexcept
            {
                return m_tilde_;
            }

            SEAL_NODISCARD inline auto &m_sk() const noexcept
            {
                return m_sk_;
            }

            SEAL_NODISCARD inline auto &t() const noexcept
            {
                return t_;
            }

            SEAL_NODISCARD inline auto &gamma() const noexcept
            {
                return gamma_;
            }

            SEAL_NODISCARD inline auto &inv_q_last_mod_t() const noexcept
            {
                return inv_q_last_mod_t_;
            }

            SEAL_NODISCARD inline const uint64_t &q_last_mod_t() const noexcept
            {
                return q_last_mod_t_;
            }

        private:
            RNSTool(const RNSTool &copy) = delete;

            RNSTool(RNSTool &&source) = delete;

            RNSTool &operator=(const RNSTool &assign) = delete;

            RNSTool &operator=(RNSTool &&assign) = delete;

            /**
            Generates the pre-computations for the given parameters.
            */
            void initialize(std::size_t poly_modulus_degree, const RNSBase &q, const Modulus &t);

            // Precomputation for fastbconv_m_tilde, sm_mrq, and fastbconv_m_tilde_sm_mrq
            void initialize_behz_extension();

            // Precomputation for fast_floor, fastbconv_sk, and inverse_ntt_multiply_t_fast_floor_fastbconv_sk
            void initialize_behz_floor();

            // Precomputation for decrypt_scale_and_round and decrypt_modt
            void initialize_decryption();

            // Precomputation for divide_and_round_q_last, divide_and_round_q_last_ntt, and mod_t_and_divide_q_last_ntt
            void initialize_mod_switch();

            /**
            Final step of the Shenoy-Kumaresan conversion from Bsk to q, for count coefficients: given the fast base
            conversion of the B part of the input to q U {m_sk} (component i at conv_q_m_sk + i * conv_stride, fully
            reduced) and the m_sk part of the input (input_m_sk), writes component i of the output to
            destination + i * destination_stride. scratch must hold 2 * count values.
            */
            void fastbconv_sk_finish(
                const std::uint64_t *conv_q_m_sk, std::size_t conv_stride, const std::uint64_t *input_m_sk,
                std::uint64_t *destination, std::size_t destination_stride, std::size_t count,
                std::uint64_t *scratch) const;

            MemoryPoolHandle pool_;

            std::size_t coeff_count_ = 0;

            Pointer<RNSBase> base_q_;

            Pointer<RNSBase> base_B_;

            Pointer<RNSBase> base_Bsk_;

            Pointer<RNSBase> base_Bsk_m_tilde_;

            Pointer<RNSBase> base_t_gamma_;

            // NTTTables for Bsk
            Pointer<NTTTables> base_Bsk_ntt_tables_;

            Modulus m_tilde_;

            Modulus m_sk_;

            Modulus t_;

            Modulus gamma_;

            // Precomputation for fastbconv_m_tilde, sm_mrq, and fastbconv_m_tilde_sm_mrq

            // Base converter: q --> Bsk U {m_tilde}, with the input scaled by m_tilde
            Pointer<BaseConverter> base_q_to_Bsk_m_tilde_conv_;

            // Base converter: q --> Bsk, with the input scaled by m_tilde and the output by m_tilde^(-1)
            Pointer<BaseConverter> base_q_to_Bsk_mont_conv_;

            // (q/q_i) * (-prod(q)^(-1)) mod m_tilde
            Pointer<std::uint64_t> m_tilde_row_neg_inv_prod_q_;

            // -prod(q)^(-1) mod m_tilde
            MultiplyUIntModOperand neg_inv_prod_q_mod_m_tilde_;

            // m_tilde^(-1) mod Bsk
            Pointer<MultiplyUIntModOperand> inv_m_tilde_mod_Bsk_;

            // prod(q) * m_tilde^(-1) mod Bsk
            Pointer<MultiplyUIntModOperand> prod_q_inv_m_tilde_mod_Bsk_;

            // Precomputation for fast_floor, fastbconv_sk, and inverse_ntt_multiply_t_fast_floor_fastbconv_sk

            // Base converter: q --> Bsk
            Pointer<BaseConverter> base_q_to_Bsk_conv_;

            // Base converter: B --> q U {m_sk}
            Pointer<BaseConverter> base_B_to_q_m_sk_conv_;

            // Base converter: q --> Bsk, with the input scaled by (q/q_i) and the output by
            // prod(q)^(-1) * (prod(B)/b_j)^(-1) for b_j in B and by prod(q)^(-1) for m_sk (only if t is non-zero)
            Pointer<BaseConverter> base_q_to_Bsk_floor_conv_;

            // Base converter: B --> q U {m_sk}, with the input scaled by (prod(B)/b_j) (only if t is non-zero)
            Pointer<BaseConverter> base_B_to_q_m_sk_unit_conv_;

            // Inverse NTT scalars in base q and in base Bsk; the second half of each array includes the factor 2^64 for
            // input in Montgomery form (only if t is non-zero)
            Pointer<std::uint64_t> intt_scalar_q_;

            Pointer<std::uint64_t> intt_scalar_Bsk_;

            // prod(q)^(-1) mod Bsk
            Pointer<MultiplyUIntModOperand> inv_prod_q_mod_Bsk_;

            // prod(B)^(-1) mod m_sk
            MultiplyUIntModOperand inv_prod_B_mod_m_sk_;

            // prod(B) mod q
            Pointer<MultiplyUIntModOperand> prod_B_mod_q_;

            // Precomputation for decrypt_scale_and_round and decrypt_modt (only if t is non-zero)

            // Base converter: q --> {t, gamma}
            Pointer<BaseConverter> base_q_to_t_gamma_conv_;

            // Base converter: q --> t
            Pointer<BaseConverter> base_q_to_t_conv_;

            // gamma^(-1) mod t
            MultiplyUIntModOperand inv_gamma_mod_t_;

            // -prod(q)^(-1) mod {t, gamma}
            Pointer<MultiplyUIntModOperand> neg_inv_q_mod_t_gamma_;

            // prod({t, gamma}) mod q
            Pointer<MultiplyUIntModOperand> prod_t_gamma_mod_q_;

            // Precomputation for divide_and_round_q_last, divide_and_round_q_last_ntt, and mod_t_and_divide_q_last_ntt

            // q[last]^(-1) mod q[i] for i = 0..last-1
            Pointer<MultiplyUIntModOperand> inv_q_last_mod_q_;

            std::uint64_t inv_q_last_mod_t_ = 1;

            std::uint64_t q_last_mod_t_ = 1;
        };

#ifdef SEAL_USE_INTEL_HEXL
        // With Intel HEXL, behz_tensor_product uses HEXL's dyadic products and outputs standard representatives
        constexpr bool behz_tensor_product_montgomery_form = false;
#else
        // behz_tensor_product outputs c * 2^(-64) mod p (Montgomery form); the factor 2^64 is folded into the scalar of
        // the subsequent inverse NTT (see RNSTool::inverse_ntt_multiply_t_fast_floor_fastbconv_sk)
        constexpr bool behz_tensor_product_montgomery_form = true;
#endif

        /**
        Computes the BEHZ ciphertext tensor product for one RNS base, with all polynomials in NTT form:

            out[k] = sum_{i + j = k} in1[i] * in2[j],  k = 0, ..., in1_size + in2_size - 2.

        The input coefficients can be lazily reduced to [0, 4 * modulus) (as output by ntt_negacyclic_harvey_lazy),
        and every modulus must have at most SEAL_MOD_BIT_COUNT_MAX bits. Every output coefficient is written exactly
        once and is fully reduced, so the output does not need to be initialized. If
        behz_tensor_product_montgomery_form is true, the output is out[k] * 2^(-64) instead (fully reduced). Passing
        the same iterators for in1 and in2 computes a square with about half of the products.
        */
        void behz_tensor_product(
            ConstPolyIter in1, std::size_t in1_size, ConstPolyIter in2, std::size_t in2_size, ConstModulusIter base,
            std::size_t base_size, std::size_t coeff_count, PolyIter out, MemoryPoolHandle pool);
    } // namespace util
} // namespace seal
