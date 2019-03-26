// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <stdexcept>
#include "seal/util/pointer.h"
#include "seal/memorymanager.h"
#include "seal/smallmodulus.h"

namespace seal
{
    namespace util
    {
        class SmallNTTTables
        {
        public:
            SmallNTTTables(MemoryPoolHandle pool = MemoryManager::GetPool()) :
                pool_(std::move(pool))
            {
#ifdef SEAL_DEBUG
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }
#endif
            }

            SmallNTTTables(int coeff_count_power, const SmallModulus &modulus,
                MemoryPoolHandle pool = MemoryManager::GetPool());

            inline bool is_generated() const
            {
                return generated_;
            }

            bool generate(int coeff_count_power, const SmallModulus &modulus);

            void reset();

            inline std::uint64_t get_root() const
            {
#ifdef SEAL_DEBUG
                if (!generated_)
                {
                    throw std::logic_error("tables are not generated");
                }
#endif
                return root_;
            }

            inline std::uint64_t get_from_root_powers(std::size_t index) const
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
                if (!generated_)
                {
                    throw std::logic_error("tables are not generated");
                }
#endif
                return root_powers_[index];
            }

            inline std::uint64_t get_from_scaled_root_powers(std::size_t index) const
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
                if (!generated_)
                {
                    throw std::logic_error("tables are not generated");
                }
#endif
                return scaled_root_powers_[index];
            }

            inline std::uint64_t get_from_inv_root_powers(std::size_t index) const
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
                if (!generated_)
                {
                    throw std::logic_error("tables are not generated");
                }
#endif
                return inv_root_powers_[index];
            }

            inline std::uint64_t get_from_scaled_inv_root_powers(std::size_t index) const
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
                if (!generated_)
                {
                    throw std::logic_error("tables are not generated");
                }
#endif
                return scaled_inv_root_powers_[index];
            }

            inline std::uint64_t get_from_inv_root_powers_div_two(
                std::size_t index) const
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
                if (!generated_)
                {
                    throw std::logic_error("tables are not generated");
                }
#endif
                return inv_root_powers_div_two_[index];
            }

            inline std::uint64_t get_from_scaled_inv_root_powers_div_two(
                std::size_t index) const
            {
#ifdef SEAL_DEBUG
                if (index >= coeff_count_)
                {
                    throw std::out_of_range("index");
                }
                if (!generated_)
                {
                    throw std::logic_error("tables are not generated");
                }
#endif
                return scaled_inv_root_powers_div_two_[index];
            }

            inline const std::uint64_t *get_inv_degree_modulo() const
            {
#ifdef SEAL_DEBUG
                if (!generated_)
                {
                    throw std::logic_error("tables are not generated");
                }
#endif
                return &inv_degree_modulo_;
            }

            inline const SmallModulus &modulus() const
            {
                return modulus_;
            }

            inline int coeff_count_power() const
            {
                return coeff_count_power_;
            }

            inline std::size_t coeff_count() const
            {
                return coeff_count_;
            }

        private:
            SmallNTTTables(const SmallNTTTables &copy) = delete;

            SmallNTTTables(SmallNTTTables &&source) = delete;

            SmallNTTTables &operator =(const SmallNTTTables &assign) = delete;

            SmallNTTTables &operator =(SmallNTTTables &&assign) = delete;

            // Computed bit-scrambled vector of first 1 << coeff_count_power powers
            // of a primitive root.
            void ntt_powers_of_primitive_root(std::uint64_t root,
                std::uint64_t *destination) const;

            // Scales the elements of a vector returned by powers_of_primitive_root(...)
            // by word_size/modulus and rounds down.
            void ntt_scale_powers_of_primitive_root(const std::uint64_t *input,
                std::uint64_t *destination) const;

            MemoryPoolHandle pool_;

            bool generated_ = false;

            std::uint64_t root_ = 0;

            // Size coeff_count_
            Pointer<decltype(root_)> root_powers_;

            // Size coeff_count_
            Pointer<decltype(root_)> scaled_root_powers_;

            // Size coeff_count_
            Pointer<decltype(root_)> inv_root_powers_div_two_;

            // Size coeff_count_
            Pointer<decltype(root_)> scaled_inv_root_powers_div_two_;

            int coeff_count_power_ = 0;

            std::size_t coeff_count_ = 0;

            SmallModulus modulus_;

            // Size coeff_count_
            Pointer<decltype(root_)> inv_root_powers_;

            // Size coeff_count_
            Pointer<decltype(root_)> scaled_inv_root_powers_;

            std::uint64_t inv_degree_modulo_ = 0;

        };

        void ntt_negacyclic_harvey_lazy(std::uint64_t *operand,
            const SmallNTTTables &tables);

        inline void ntt_negacyclic_harvey(std::uint64_t *operand,
            const SmallNTTTables &tables)
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

        void inverse_ntt_negacyclic_harvey_lazy(std::uint64_t *operand,
            const SmallNTTTables &tables);

        inline void inverse_ntt_negacyclic_harvey(std::uint64_t *operand,
            const SmallNTTTables &tables)
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
    }
}
