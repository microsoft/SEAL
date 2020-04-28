// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/util/pointer.h"
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace seal
{
    namespace util
    {
        class GaloisTool
        {
        public:
            GaloisTool(int coeff_count_power, MemoryPoolHandle pool) : pool_(std::move(pool))
            {
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }

                initialize(coeff_count_power);
            }

            void apply_galois(
                const std::uint64_t *operand, std::uint32_t galois_elt, const Modulus &modulus,
                std::uint64_t *result) const;

            void apply_galois_ntt(const std::uint64_t *operand, std::uint32_t galois_elt, std::uint64_t *result);

            /**
            Compute the Galois element corresponding to a given rotation step.
            */
            SEAL_NODISCARD std::uint32_t get_elt_from_step(int step) const;

            /**
            Compute the Galois elements corresponding to a vector of given rotation steps.
            */
            SEAL_NODISCARD std::vector<std::uint32_t> get_elts_from_steps(const std::vector<int> &steps) const;

            /**
            Compute a vector of all necessary galois_elts.
            */
            SEAL_NODISCARD std::vector<std::uint32_t> get_elts_all() const noexcept;

            /**
            Compute the index in the range of 0 to (coeff_count_ - 1) of a given Galois element.
            */
            SEAL_NODISCARD static inline std::size_t GetIndexFromElt(std::uint32_t galois_elt)
            {
#ifdef SEAL_DEBUG
                if (!(galois_elt & 1))
                {
                    throw std::invalid_argument("galois_elt is not valid");
                }
#endif
                return util::safe_cast<std::size_t>((galois_elt - 1) >> 1);
            }

        private:
            GaloisTool(const GaloisTool &copy) = delete;

            GaloisTool(GaloisTool &&source) = delete;

            GaloisTool &operator=(const GaloisTool &assign) = delete;

            GaloisTool &operator=(GaloisTool &&assign) = delete;

            void initialize(int coeff_count_power);

            void generate_table_ntt(std::uint32_t galois_elt, Pointer<std::uint32_t> &result);

            MemoryPoolHandle pool_;

            int coeff_count_power_ = 0;

            std::size_t coeff_count_ = 0;

            static constexpr std::uint32_t generator_ = 3;

            Pointer<Pointer<std::uint32_t>> permutation_tables_;

            mutable util::ReaderWriterLocker permutation_tables_locker_;
        };
    } // namespace util
} // namespace seal
