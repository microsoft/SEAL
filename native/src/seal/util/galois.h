// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/util/pointer.h"
#include <stdexcept>

namespace seal
{
    namespace util
    {

        class GaloisPermutationTables
        {
        public:

            static void generate_table_ntt(int coeff_count_power, std::uint32_t galois_elt, std::uint32_t *result);

            GaloisPermutationTables(int coeff_count_power, std::uint32_t generator, MemoryPoolHandle pool)
                : pool_(std::move(pool))
            {
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }

                initialize(coeff_count_power, generator);
            }

            SEAL_NODISCARD const std::uint32_t *get_table(std::uint32_t galois_elt) const;

        private:
            GaloisPermutationTables(const GaloisPermutationTables &copy) = delete;

            GaloisPermutationTables(GaloisPermutationTables &&source) = delete;

            GaloisPermutationTables &operator=(const GaloisPermutationTables &assign) = delete;

            GaloisPermutationTables &operator=(GaloisPermutationTables &&assign) = delete;

            void initialize(int coeff_count_power, std::uint32_t generator);

            MemoryPoolHandle pool_;

            int coeff_count_power_ = 0;

            std::size_t coeff_count_ = 0;

            std::size_t elt_count_ = 0;

            std::uint32_t generator_ = 0;

            std::vector<Pointer<std::uint32_t>> tables_;
        };

        class GaloisTool
        {
        public:

            GaloisTool(int coeff_count_power, MemoryPoolHandle pool) : pool_(std::move(pool)) {
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }

                initialize(coeff_count_power, std::uint32_t(3));
            }

            GaloisTool(int coeff_count_power, std::uint32_t generator, MemoryPoolHandle pool) : pool_(std::move(pool)) {
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }

                initialize(coeff_count_power, generator);
            }

            void apply_galois(const std::uint64_t *operand, std::uint32_t galois_elt, const SmallModulus &modulus, std::uint64_t *result) const;

            void apply_galois_ntt(const std::uint64_t *operand, std::uint32_t galois_elt, std::uint64_t *result) const;

            SEAL_NODISCARD std::uint32_t get_elt_from_step(int step) const;

            SEAL_NODISCARD static inline std::size_t get_index_from_elt(std::uint32_t galois_elt)
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

            void initialize(int coeff_count_power, std::uint32_t generator);

            MemoryPoolHandle pool_;

            int coeff_count_power_ = 0;

            std::size_t coeff_count_ = 0;

            std::uint32_t generator_ = 0;

            Pointer<GaloisPermutationTables> permutation_tables_;
        };
    } // namespace util
} // namespace seal
