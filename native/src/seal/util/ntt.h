// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "seal/util/pointer.h"
#include "seal/util/uintcore.h"
#include <stdexcept>

namespace seal
{
    namespace util
    {
        class NTTTables
        {
        public:
            NTTTables(NTTTables &&source) = default;

            NTTTables(NTTTables &copy)
                : pool_(copy.pool_), root_(copy.root_), coeff_count_power_(copy.coeff_count_power_),
                  coeff_count_(copy.coeff_count_), modulus_(copy.modulus_), inv_degree_modulo_(copy.inv_degree_modulo_)
            {
                root_powers_ = allocate_uint(coeff_count_, pool_);
                inv_root_powers_ = allocate_uint(coeff_count_, pool_);
                scaled_root_powers_ = allocate_uint(coeff_count_, pool_);
                scaled_inv_root_powers_ = allocate_uint(coeff_count_, pool_);

                set_uint_uint(copy.root_powers_.get(), coeff_count_, root_powers_.get());
                set_uint_uint(copy.inv_root_powers_.get(), coeff_count_, inv_root_powers_.get());
                set_uint_uint(copy.scaled_root_powers_.get(), coeff_count_, scaled_root_powers_.get());
                set_uint_uint(copy.scaled_inv_root_powers_.get(), coeff_count_, scaled_inv_root_powers_.get());
            }

            NTTTables(int coeff_count_power, const Modulus &modulus, MemoryPoolHandle pool = MemoryManager::GetPool());

            SEAL_NODISCARD inline std::uint64_t get_root() const
            {
                return root_;
            }

            SEAL_NODISCARD inline auto get_from_root_powers(std::size_t index) const -> std::uint64_t
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
#endif
                return root_powers_[index];
            }

            SEAL_NODISCARD inline auto get_from_scaled_root_powers(std::size_t index) const -> std::uint64_t
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
#endif
                return scaled_root_powers_[index];
            }

            SEAL_NODISCARD inline auto get_from_inv_root_powers(std::size_t index) const -> std::uint64_t
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
#endif
                return inv_root_powers_[index];
            }

            SEAL_NODISCARD inline auto get_from_scaled_inv_root_powers(std::size_t index) const -> std::uint64_t
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
#endif
                return scaled_inv_root_powers_[index];
            }

            SEAL_NODISCARD inline auto get_inv_degree_modulo() const -> const std::uint64_t *
            {
                return &inv_degree_modulo_;
            }

            SEAL_NODISCARD inline const Modulus &modulus() const
            {
                return modulus_;
            }

            SEAL_NODISCARD inline int coeff_count_power() const
            {
                return coeff_count_power_;
            }

            SEAL_NODISCARD inline std::size_t coeff_count() const
            {
                return coeff_count_;
            }

        private:
            NTTTables &operator=(const NTTTables &assign) = delete;

            NTTTables &operator=(NTTTables &&assign) = delete;

            void initialize(int coeff_count_power, const Modulus &modulus);

            // Computed bit-scrambled vector of first 1 << coeff_count_power powers
            // of a primitive root.
            void ntt_powers_of_primitive_root(std::uint64_t root, std::uint64_t *destination) const;

            // Scales the elements of a vector returned by powers_of_primitive_root(...)
            // by word_size/modulus and rounds down.
            void ntt_scale_powers_of_primitive_root(const std::uint64_t *input, std::uint64_t *destination) const;

            MemoryPoolHandle pool_;

            std::uint64_t root_ = 0;

            // Size coeff_count_
            Pointer<std::uint64_t> root_powers_;

            // Size coeff_count_
            Pointer<std::uint64_t> scaled_root_powers_;

            int coeff_count_power_ = 0;

            std::size_t coeff_count_ = 0;

            Modulus modulus_;

            // Size coeff_count_
            Pointer<std::uint64_t> inv_root_powers_;

            // Size coeff_count_
            Pointer<std::uint64_t> scaled_inv_root_powers_;

            std::uint64_t inv_degree_modulo_ = 0;
        };

        /**
        Allocate and construct an array of NTTTables each with different a modulus.

        @throws std::invalid_argument if modulus is empty, modulus does not support NTT, coeff_count_power is invalid,
        or pool is uninitialized.
        */
        void CreateNTTTables(
            int coeff_count_power, const std::vector<Modulus> &modulus, Pointer<NTTTables> &tables,
            MemoryPoolHandle pool);

        void ntt_negacyclic_harvey_lazy(std::uint64_t *operand, const NTTTables &tables);

        inline void ntt_negacyclic_harvey(std::uint64_t *operand, const NTTTables &tables)
        {
            ntt_negacyclic_harvey_lazy(operand, tables);

            // Finally maybe we need to reduce every coefficient modulo q, but we
            // know that they are in the range [0, 4q).
            // Since word size is controlled this is fast.
            std::uint64_t modulus = tables.modulus().value();
            std::uint64_t two_times_modulus = modulus * 2;
            std::size_t n = std::size_t(1) << tables.coeff_count_power();

            for (; n--; operand++)
            {
                if (*operand >= two_times_modulus)
                {
                    *operand -= two_times_modulus;
                }
                if (*operand >= modulus)
                {
                    *operand -= modulus;
                }
            }
        }

        void inverse_ntt_negacyclic_harvey_lazy(std::uint64_t *operand, const NTTTables &tables);

        inline void inverse_ntt_negacyclic_harvey(std::uint64_t *operand, const NTTTables &tables)
        {
            inverse_ntt_negacyclic_harvey_lazy(operand, tables);

            std::uint64_t modulus = tables.modulus().value();
            std::size_t n = std::size_t(1) << tables.coeff_count_power();

            // Final adjustments; compute a[j] = a[j] * n^{-1} mod q.
            // We incorporated the final adjustment in the butterfly. Only need
            // to reduce here.
            for (; n--; operand++)
            {
                if (*operand >= modulus)
                {
                    *operand -= modulus;
                }
            }
        }
    } // namespace util
} // namespace seal
