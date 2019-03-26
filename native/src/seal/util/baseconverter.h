// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <stdexcept>
#include <vector>
#include <memory>
#include "seal/util/pointer.h"
#include "seal/memorymanager.h"
#include "seal/smallmodulus.h"
#include "seal/util/smallntt.h"
#include "seal/biguint.h"

namespace seal
{
    namespace util
    {
        class BaseConverter
        {
        public:
            BaseConverter(MemoryPoolHandle pool) : pool_(std::move(pool))
            {
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }
            }

            BaseConverter(const std::vector<SmallModulus> &coeff_base,
                std::size_t coeff_count, const SmallModulus &small_plain_mod,
                MemoryPoolHandle pool);

            /**
            Generates the pre-computations for the given parameters.
            */
            void generate(const std::vector<SmallModulus> &coeff_base,
                std::size_t coeff_count, const SmallModulus &small_plain_mod);

            void floor_last_coeff_modulus_inplace(
                std::uint64_t *rns_poly,
                MemoryPoolHandle pool) const;

            void floor_last_coeff_modulus_ntt_inplace(
                std::uint64_t *rns_poly,
                const Pointer<SmallNTTTables> &rns_ntt_tables,
                MemoryPoolHandle pool) const;

            /**
            Fast base converter from q to Bsk
            */
            void fastbconv(const std::uint64_t *input,
                std::uint64_t *destination, MemoryPoolHandle pool) const;

            /**
            Fast base converter from Bsk to q
            */
            void fastbconv_sk(const std::uint64_t *input,
                std::uint64_t *destination, MemoryPoolHandle pool) const;

            /**
            Reduction from Bsk U {m_tilde} to Bsk
            */
            void mont_rq(const std::uint64_t *input,
                std::uint64_t *destination) const;

            /**
            Fast base converter from q U Bsk to Bsk
            */
            void fast_floor(const std::uint64_t *input,
                std::uint64_t *destination, MemoryPoolHandle pool) const;

            /**
            Fast base converter from q to Bsk U {m_tilde}
            */
            void fastbconv_mtilde(const std::uint64_t *input,
                std::uint64_t *destination, MemoryPoolHandle pool) const;

            /**
            Fast base converter from q to plain_modulus U {gamma}
            */
            void fastbconv_plain_gamma(const std::uint64_t *input,
                std::uint64_t *destination, MemoryPoolHandle pool) const;

            void reset() noexcept;

            inline auto is_generated() const noexcept
            {
                return generated_;
            }

            inline auto coeff_base_mod_count() const noexcept
            {
                return coeff_base_mod_count_;
            }

            inline auto aux_base_mod_count() const noexcept
            {
                return aux_base_mod_count_;
            }

            inline auto &get_plain_gamma_product() const noexcept
            {
                return plain_gamma_product_mod_coeff_array_;
            }

            inline auto &get_neg_inv_coeff() const noexcept
            {
                return neg_inv_coeff_products_all_mod_plain_gamma_array_;
            }

            inline auto &get_plain_gamma_array() const noexcept
            {
                return plain_gamma_array_;
            }

            inline const std::uint64_t *get_coeff_products_array() const noexcept
            {
                return coeff_products_array_.get();
            }

            inline std::uint64_t get_inv_gamma() const noexcept
            {
                return inv_gamma_mod_plain_;
            }

            inline auto &get_bsk_small_ntt_tables() const noexcept
            {
                return bsk_small_ntt_tables_;
            }

            inline auto bsk_base_mod_count() const noexcept
            {
                return bsk_base_mod_count_;
            }

            inline auto &get_bsk_mod_array() const noexcept
            {
                return bsk_base_array_;
            }

            inline auto &get_msk() const noexcept
            {
                return m_sk_;
            }

            inline auto &get_m_tilde() const noexcept
            {
                return m_tilde_;
            }

            inline auto &get_mtilde_inv_coeff_products_mod_coeff() const noexcept
            {
                return mtilde_inv_coeff_base_products_mod_coeff_array_;
            }

            inline auto &get_inv_coeff_mod_mtilde() const noexcept
            {
                return inv_coeff_products_mod_mtilde_;
            }

            inline auto &get_inv_coeff_mod_coeff_array() const noexcept
            {
                return inv_coeff_base_products_mod_coeff_array_;
            }

            inline auto &get_inv_last_coeff_mod_array() const noexcept
            {
                return inv_last_coeff_mod_array_;
            }

            inline auto &get_coeff_base_products_mod_msk() const noexcept
            {
                return coeff_base_products_mod_aux_bsk_array_[bsk_base_mod_count_ - 1];
            }

        private:
            BaseConverter(const BaseConverter &copy) = delete;

            BaseConverter(BaseConverter &&source) = delete;

            BaseConverter &operator =(const BaseConverter &assign) = delete;

            BaseConverter &operator =(BaseConverter &&assign) = delete;

            MemoryPoolHandle pool_;

            bool generated_ = false;

            std::size_t coeff_count_ = 0;

            std::size_t coeff_base_mod_count_ = 0;

            std::size_t aux_base_mod_count_ = 0;

            std::size_t bsk_base_mod_count_ = 0;

            std::size_t plain_gamma_count_ = 0;

            // Array of coefficient small moduli
            Pointer<SmallModulus> coeff_base_array_;

            // Array of auxiliary moduli
            Pointer<SmallModulus> aux_base_array_;

            // Array of auxiliary U {m_sk_} moduli
            Pointer<SmallModulus> bsk_base_array_;

            // Array of plain modulus U gamma
            Pointer<SmallModulus> plain_gamma_array_;

            // Punctured products of the coeff moduli
            Pointer<std::uint64_t> coeff_products_array_;

            // Matrix which contains the products of coeff moduli mod aux
            Pointer<Pointer<std::uint64_t>> coeff_base_products_mod_aux_bsk_array_;

            // Array of inverse coeff modulus products mod each small coeff mods
            Pointer<std::uint64_t> inv_coeff_base_products_mod_coeff_array_;

            // Array of coeff moduli products mod m_tilde
            Pointer<std::uint64_t> coeff_base_products_mod_mtilde_array_;

            // Array of coeff modulus products times m_tilda mod each coeff modulus
            Pointer<std::uint64_t> mtilde_inv_coeff_base_products_mod_coeff_array_;

            // Matrix of the inversion of coeff modulus products mod each auxiliary mods
            Pointer<std::uint64_t> inv_coeff_products_all_mod_aux_bsk_array_;

            // Matrix of auxiliary mods products mod each coeff modulus
            Pointer<Pointer<std::uint64_t>> aux_base_products_mod_coeff_array_;

            // Array of inverse auxiliary mod products mod each auxiliary mods
            Pointer<std::uint64_t> inv_aux_base_products_mod_aux_array_;

            // Array of auxiliary bases products mod m_sk_
            Pointer<std::uint64_t> aux_base_products_mod_msk_array_;

            // Coeff moduli products inverse mod m_tilde
            std::uint64_t inv_coeff_products_mod_mtilde_ = 0;

            // Auxiliary base products mod m_sk_ (m1*m2*...*ml)-1 mod m_sk
            std::uint64_t inv_aux_products_mod_msk_ = 0;

            // Gamma inverse mod plain modulus
            std::uint64_t inv_gamma_mod_plain_ = 0;

            // Auxiliary base products mod coeff moduli (m1*m2*...*ml) mod qi
            Pointer<std::uint64_t> aux_products_all_mod_coeff_array_;

            // Array of m_tilde inverse mod Bsk = m U {msk}
            Pointer<std::uint64_t> inv_mtilde_mod_bsk_array_;

            // Array of all coeff base products mod Bsk
            Pointer<std::uint64_t> coeff_products_all_mod_bsk_array_;

            // Matrix of coeff base product mod plain modulus and gamma
            Pointer<Pointer<std::uint64_t>> coeff_products_mod_plain_gamma_array_;

            // Array of negative inverse all coeff base product mod plain modulus and gamma
            Pointer<std::uint64_t> neg_inv_coeff_products_all_mod_plain_gamma_array_;

            // Array of plain_gamma_product mod coeff base moduli
            Pointer<std::uint64_t> plain_gamma_product_mod_coeff_array_;

            // Array of small NTT tables for moduli in Bsk
            Pointer<SmallNTTTables> bsk_small_ntt_tables_;

            // For modulus switching: inverses of the last coeff base modulus
            Pointer<std::uint64_t> inv_last_coeff_mod_array_;

            SmallModulus m_tilde_;

            SmallModulus m_sk_;

            SmallModulus small_plain_mod_;

            SmallModulus gamma_;
        };
    }
}
