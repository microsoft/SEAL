// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/smallmodulus.h"
#include "seal/util/numth.h"
#include "seal/util/pointer.h"
#include "seal/util/smallntt.h"
#include <memory>
#include <stdexcept>
#include <vector>

namespace seal
{
    namespace util
    {
        class BaseConverter
        {
        public:
            BaseConverter(MemoryPoolHandle pool)
                : pool_(std::move(pool)), base_q_crt_(pool_), base_B_crt_(pool_), base_q_to_Bsk_conv_(pool_),
                  base_q_to_m_tilde_conv_(pool_), base_B_to_q_conv_(pool_), base_B_to_m_sk_conv_(pool_),
                  base_q_to_t_gamma_conv_(pool_)
            {
#ifdef SEAL_DEBUG
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }
#endif
            }

            BaseConverter(
                std::size_t poly_modulus_degree, const std::vector<SmallModulus> &coeff_modulus,
                const SmallModulus &plain_modulus, MemoryPoolHandle pool);

            /**
            Generates the pre-computations for the given parameters.
            */
            bool initialize(
                std::size_t poly_modulus_degree, const std::vector<SmallModulus> &coeff_modulus,
                const SmallModulus &plain_modulus);

            void divide_and_round_q_last_inplace(std::uint64_t *input, MemoryPoolHandle pool) const;

            void divide_and_round_q_last_ntt_inplace(
                std::uint64_t *input, const Pointer<SmallNTTTables> &rns_ntt_tables, MemoryPoolHandle pool) const;

            /**
            Shenoy-Kumaresan conversion from Bsk to q
            */
            void fastbconv_sk(const std::uint64_t *input, std::uint64_t *destination, MemoryPoolHandle pool) const;

            /**
            Montgomery reduction from Bsk U {m_tilde} to Bsk
            */
            void montgomery_reduction(
                const std::uint64_t *input, std::uint64_t *destination, MemoryPoolHandle pool) const;

            /**
            Divide by q and fast floor from q U Bsk to Bsk
            */
            void fast_floor(const std::uint64_t *input, std::uint64_t *destination, MemoryPoolHandle pool) const;

            /**
            Fast base conversion from q to Bsk U {m_tilde}
            */
            void fastbconv_m_tilde(const std::uint64_t *input, std::uint64_t *destination, MemoryPoolHandle pool) const;

            /**
            Compute round(t/q * |input|_q) mod t exactly
            */
            void exact_scale_and_round(const uint64_t *phase, uint64_t *destination, MemoryPoolHandle pool) const;

            void reset() noexcept;

            SEAL_NODISCARD inline bool is_initialized() const noexcept
            {
                return is_initialized_;
            }

            SEAL_NODISCARD inline operator bool() const noexcept
            {
                return is_initialized();
            }

            SEAL_NODISCARD inline auto &inv_q_last_mod_q() const noexcept
            {
                return inv_q_last_mod_q_;
            }

            SEAL_NODISCARD inline auto &base_Bsk_small_ntt_tables() const noexcept
            {
                return base_Bsk_small_ntt_tables_;
            }

            SEAL_NODISCARD inline auto base_q_size() const noexcept
            {
                return base_q_size_;
            }

            SEAL_NODISCARD inline auto &base_q() const noexcept
            {
                return base_q_;
            }

            SEAL_NODISCARD inline auto base_B_size() const noexcept
            {
                return base_q_size_;
            }

            SEAL_NODISCARD inline auto &base_B() const noexcept
            {
                return base_B_;
            }

            SEAL_NODISCARD inline auto base_Bsk_size() const noexcept
            {
                return base_Bsk_size_;
            }

            SEAL_NODISCARD inline auto &base_Bsk() const noexcept
            {
                return base_Bsk_;
            }

            SEAL_NODISCARD inline auto base_Bsk_m_tilde_size() const noexcept
            {
                return base_Bsk_m_tilde_size_;
            }

            SEAL_NODISCARD inline auto &base_Bsk_m_tilde() const noexcept
            {
                return base_Bsk_m_tilde_;
            }

            SEAL_NODISCARD inline auto base_t_gamma_size() const noexcept
            {
                return base_t_gamma_size_;
            }

            SEAL_NODISCARD inline auto &base_t_gamma() const noexcept
            {
                return base_t_gamma_;
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

        private:
            BaseConverter(const BaseConverter &copy) = delete;

            BaseConverter(BaseConverter &&source) = delete;

            BaseConverter &operator=(const BaseConverter &assign) = delete;

            BaseConverter &operator=(BaseConverter &&assign) = delete;

            MemoryPoolHandle pool_;

            bool is_initialized_ = false;

            std::size_t coeff_count_ = 0;

            std::size_t base_q_size_ = 0;

            Pointer<SmallModulus> base_q_;

            std::size_t base_B_size_ = 0;

            Pointer<SmallModulus> base_B_;

            std::size_t base_Bsk_size_ = 0;

            Pointer<SmallModulus> base_Bsk_;

            std::size_t base_Bsk_m_tilde_size_ = 0;

            Pointer<SmallModulus> base_Bsk_m_tilde_;

            std::size_t base_t_gamma_size_ = 0;

            Pointer<SmallModulus> base_t_gamma_;

            // CRT tool for the initial coeff_modulus base q
            CRTTool base_q_crt_;

            // CRT tool for the extended (auxiliary) base B
            CRTTool base_B_crt_;

            // Base converter: q --> B_sk
            BaseConvTool base_q_to_Bsk_conv_;

            // Base converter: q --> {m_tilde}
            BaseConvTool base_q_to_m_tilde_conv_;

            // Base converter: B --> q
            BaseConvTool base_B_to_q_conv_;

            // Base converter: B --> {m_sk}
            BaseConvTool base_B_to_m_sk_conv_;

            // Base converter: q --> {t, gamma}
            BaseConvTool base_q_to_t_gamma_conv_;

            // prod(q)^(-1) mod Bsk
            Pointer<std::uint64_t> inv_prod_q_mod_Bsk_;

            // prod(q)^(-1) mod m_tilde
            std::uint64_t inv_prod_q_mod_m_tilde_ = 0;

            // prod(B)^(-1) mod m_sk
            std::uint64_t inv_prod_B_mod_m_sk_ = 0;

            // gamma^(-1) mod t
            std::uint64_t inv_gamma_mod_t_ = 0;

            // prod(B) mod q
            Pointer<std::uint64_t> prod_B_mod_q_;

            // m_tilde^(-1) mod Bsk
            Pointer<std::uint64_t> inv_m_tilde_mod_Bsk_;

            // prod(q) mod Bsk
            Pointer<std::uint64_t> prod_q_mod_Bsk_;

            // -prod(q)^(-1) mod {t, gamma}
            Pointer<std::uint64_t> neg_inv_q_mod_t_gamma_;

            // prod({t, gamma}) mod q
            Pointer<std::uint64_t> prod_t_gamma_mod_q_;

            // q[last]^(-1) mod q[i] for i = 0..last-1
            Pointer<std::uint64_t> inv_q_last_mod_q_;

            // SmallNTTTables for Bsk
            Pointer<SmallNTTTables> base_Bsk_small_ntt_tables_;

            SmallModulus m_tilde_;

            SmallModulus m_sk_;

            SmallModulus t_;

            SmallModulus gamma_;
        };
    } // namespace util
} // namespace seal
