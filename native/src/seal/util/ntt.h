// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "seal/util/defines.h"
#include "seal/util/iterator.h"
#include "seal/util/pointer.h"
#include "seal/util/uintarithsmallmod.h"
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
                root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);
                inv_root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);

                std::copy_n(copy.root_powers_.get(), coeff_count_, root_powers_.get());
                std::copy_n(copy.inv_root_powers_.get(), coeff_count_, inv_root_powers_.get());
            }

            NTTTables(int coeff_count_power, const Modulus &modulus, MemoryPoolHandle pool = MemoryManager::GetPool());

            SEAL_NODISCARD inline std::uint64_t get_root() const
            {
                return root_;
            }

            SEAL_NODISCARD inline MultiplyUIntModOperand get_from_root_powers(std::size_t index) const
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
#endif
                return root_powers_[index];
            }

            SEAL_NODISCARD inline MultiplyUIntModOperand get_from_inv_root_powers(std::size_t index) const
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
#endif
                return inv_root_powers_[index];
            }

            SEAL_NODISCARD inline const MultiplyUIntModOperand &inv_degree_modulo() const
            {
                return inv_degree_modulo_;
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
            void ntt_powers_of_primitive_root(std::uint64_t root, MultiplyUIntModOperand *destination) const;

            MemoryPoolHandle pool_;

            std::uint64_t root_ = 0;

            int coeff_count_power_ = 0;

            std::size_t coeff_count_ = 0;

            Modulus modulus_;

            MultiplyUIntModOperand inv_degree_modulo_;

            // Size coeff_count_
            Pointer<MultiplyUIntModOperand> root_powers_;

            // Size coeff_count_
            Pointer<MultiplyUIntModOperand> inv_root_powers_;
        };

        /**
        Allocate and construct an array of NTTTables each with different a modulus.

        @throws std::invalid_argument if modulus is empty, modulus does not support NTT, coeff_count_power is invalid,
        or pool is uninitialized.
        */
        void CreateNTTTables(
            int coeff_count_power, const std::vector<Modulus> &modulus, Pointer<NTTTables> &tables,
            MemoryPoolHandle pool);

        void ntt_negacyclic_harvey_lazy(CoeffIter operand, const NTTTables &tables);

        inline void ntt_negacyclic_harvey_lazy(
            RNSIter operand, std::size_t coeff_modulus_size, ConstNTTTablesIter tables)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!tables)
            {
                throw std::invalid_argument("tables");
            }
#endif
            SEAL_ITERATE(iter(operand, tables), coeff_modulus_size, [&](auto I) {
                ntt_negacyclic_harvey_lazy(get<0>(I), get<1>(I));
            });
        }

        inline void ntt_negacyclic_harvey_lazy(PolyIter operand, std::size_t size, ConstNTTTablesIter tables)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!tables)
            {
                throw std::invalid_argument("tables");
            }
#endif
            SEAL_ITERATE(
                operand, size, [&](auto I) { ntt_negacyclic_harvey_lazy(I, operand.coeff_modulus_size(), tables); });
        }

        inline void ntt_negacyclic_harvey(CoeffIter operand, const NTTTables &tables)
        {
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
        }

        inline void ntt_negacyclic_harvey(RNSIter operand, std::size_t coeff_modulus_size, ConstNTTTablesIter tables)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!tables)
            {
                throw std::invalid_argument("tables");
            }
#endif
            SEAL_ITERATE(iter(operand, tables), coeff_modulus_size, [&](auto I) {
                ntt_negacyclic_harvey(get<0>(I), get<1>(I));
            });
        }

        inline void ntt_negacyclic_harvey(PolyIter operand, std::size_t size, ConstNTTTablesIter tables)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!tables)
            {
                throw std::invalid_argument("tables");
            }
#endif
            SEAL_ITERATE(
                operand, size, [&](auto I) { ntt_negacyclic_harvey(I, operand.coeff_modulus_size(), tables); });
        }

        void inverse_ntt_negacyclic_harvey_lazy(CoeffIter operand, const NTTTables &tables);

        inline void inverse_ntt_negacyclic_harvey_lazy(
            RNSIter operand, std::size_t coeff_modulus_size, ConstNTTTablesIter tables)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!tables)
            {
                throw std::invalid_argument("tables");
            }
#endif
            SEAL_ITERATE(iter(operand, tables), coeff_modulus_size, [&](auto I) {
                inverse_ntt_negacyclic_harvey_lazy(get<0>(I), get<1>(I));
            });
        }

        inline void inverse_ntt_negacyclic_harvey_lazy(PolyIter operand, std::size_t size, ConstNTTTablesIter tables)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!tables)
            {
                throw std::invalid_argument("tables");
            }
#endif
            SEAL_ITERATE(operand, size, [&](auto I) {
                inverse_ntt_negacyclic_harvey_lazy(I, operand.coeff_modulus_size(), tables);
            });
        }

        inline void inverse_ntt_negacyclic_harvey(CoeffIter operand, const NTTTables &tables)
        {
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
        }

        inline void inverse_ntt_negacyclic_harvey(
            RNSIter operand, std::size_t coeff_modulus_size, ConstNTTTablesIter tables)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!tables)
            {
                throw std::invalid_argument("tables");
            }
#endif
            SEAL_ITERATE(iter(operand, tables), coeff_modulus_size, [&](auto I) {
                inverse_ntt_negacyclic_harvey(get<0>(I), get<1>(I));
            });
        }

        inline void inverse_ntt_negacyclic_harvey(PolyIter operand, std::size_t size, ConstNTTTablesIter tables)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!tables)
            {
                throw std::invalid_argument("tables");
            }
#endif
            SEAL_ITERATE(
                operand, size, [&](auto I) { inverse_ntt_negacyclic_harvey(I, operand.coeff_modulus_size(), tables); });
        }
    } // namespace util
} // namespace seal
