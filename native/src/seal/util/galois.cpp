// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/galois.h"
#include "seal/util/numth.h"
#include "seal/util/uintcore.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void GaloisTool::generate_table_ntt(uint32_t galois_elt, Pointer<uint32_t> &result)
        {
#ifdef SEAL_DEBUG
            if (!(galois_elt & 1) || (galois_elt >= 2 * (uint64_t(1) << coeff_count_power_)))
            {
                throw std::invalid_argument("Galois element is not valid");
            }
#endif
            ReaderLock reader_lock(permutation_tables_locker_.acquire_read());
            if (result)
            {
                return;
            }
            reader_lock.unlock();

            WriterLock writer_lock(permutation_tables_locker_.acquire_write());
            result = allocate<uint32_t>(coeff_count_, pool_);
            auto result_ptr = result.get();

            uint32_t coeff_count_minus_one = safe_cast<uint32_t>(coeff_count_) - 1;
            for (size_t i = coeff_count_; i < coeff_count_ << 1; i++)
            {
                uint32_t reversed = reverse_bits<uint32_t>(safe_cast<uint32_t>(i), coeff_count_power_ + 1);
                uint64_t index_raw = (static_cast<uint64_t>(galois_elt) * static_cast<uint64_t>(reversed)) >> 1;
                index_raw &= static_cast<uint64_t>(coeff_count_minus_one);
                *result_ptr++ = reverse_bits<uint32_t>(static_cast<uint32_t>(index_raw), coeff_count_power_);
            }
            writer_lock.unlock();
            return;
        }

        uint32_t GaloisTool::get_elt_from_step(int step) const
        {
            uint32_t n = safe_cast<uint32_t>(coeff_count_);
            uint32_t m32 = mul_safe(n, uint32_t(2));
            uint64_t m = static_cast<uint64_t>(m32);

            if (step == 0)
            {
                return static_cast<uint32_t>(m - 1);
            }
            else
            {
                // Extract sign of steps. When steps is positive, the rotation
                // is to the left; when steps is negative, it is to the right.
                bool sign = step < 0;
                uint32_t pos_step = safe_cast<uint32_t>(abs(step));

                if (pos_step >= (n >> 1))
                {
                    throw invalid_argument("step count too large");
                }

                pos_step &= m32 - 1;
                if (sign)
                {
                    step = safe_cast<int>(n >> 1) - safe_cast<int>(pos_step);
                }
                else
                {
                    step = safe_cast<int>(pos_step);
                }

                // Construct Galois element for row rotation
                uint64_t gen = static_cast<uint64_t>(generator_);
                uint64_t galois_elt = 1;
                while (step--)
                {
                    galois_elt *= gen;
                    galois_elt &= m - 1;
                }
                return static_cast<uint32_t>(galois_elt);
            }
        }

        vector<uint32_t> GaloisTool::get_elts_from_steps(const vector<int> &steps) const
        {
            vector<uint32_t> galois_elts;
            transform(steps.begin(), steps.end(), back_inserter(galois_elts), [&](auto s) {
                return get_elt_from_step(s);
            });
            return galois_elts;
        }

        vector<uint32_t> GaloisTool::get_elts_all() const
        {
            uint32_t m = safe_cast<uint32_t>(static_cast<uint64_t>(coeff_count_) << 1);
            vector<uint32_t> galois_elts{};

            // Generate Galois keys for m - 1 (X -> X^{m-1})
            galois_elts.push_back(m - 1);

            // Generate Galois key for power of 3 mod m (X -> X^{3^k}) and
            // for negative power of 3 mod m (X -> X^{-3^k})
            uint64_t two_power_of_three = 3;
            uint64_t neg_two_power_of_three = 0;
            try_invert_uint_mod(3, m, neg_two_power_of_three);
            for (int i = 0; i < coeff_count_power_ - 1; i++)
            {
                galois_elts.push_back(static_cast<uint32_t>(two_power_of_three));
                two_power_of_three *= two_power_of_three;
                two_power_of_three &= (m - 1);

                galois_elts.push_back(static_cast<uint32_t>(neg_two_power_of_three));
                neg_two_power_of_three *= neg_two_power_of_three;
                neg_two_power_of_three &= (m - 1);
            }

            return galois_elts;
        }

        void GaloisTool::initialize(int coeff_count_power, uint32_t generator)
        {
#ifdef SEAL_DEBUG
            if ((coeff_count_power < get_power_of_two(SEAL_POLY_MOD_DEGREE_MIN)) ||
                coeff_count_power > get_power_of_two(SEAL_POLY_MOD_DEGREE_MAX))
            {
                throw invalid_argument("coeff_count_power out of range");
            }
#endif
            if (!(generator & 1) || (generator >= 2 * (uint64_t(1) << coeff_count_power)))
            {
                throw invalid_argument("generator is not valid");
            }

            coeff_count_power_ = coeff_count_power;
            coeff_count_ = size_t(1) << coeff_count_power_;
            generator_ = generator;

            // Capacity for coeff_count_ number of tables
            permutation_tables_.resize(coeff_count_);
        }

        void GaloisTool::apply_galois(const uint64_t *operand, uint32_t galois_elt, const SmallModulus &modulus, uint64_t *result) const
        {
#ifdef SEAL_DEBUG
            if (operand == nullptr)
            {
                throw std::invalid_argument("operand");
            }
            if (result == nullptr)
            {
                throw std::invalid_argument("result");
            }
            if (operand == result)
            {
                throw std::invalid_argument("result cannot point to the same value as operand");
            }
            // Verify coprime conditions.
            if (!(galois_elt & 1) || (galois_elt >= 2 * (uint64_t(1) << coeff_count_power_)))
            {
                throw std::invalid_argument("Galois element is not valid");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
#endif
            const uint64_t modulus_value = modulus.value();
            uint64_t coeff_count_minus_one = (uint64_t(1) << coeff_count_power_) - 1;
            for (uint64_t i = 0; i <= coeff_count_minus_one; i++)
            {
                uint64_t index_raw = i * galois_elt;
                uint64_t index = index_raw & coeff_count_minus_one;
                uint64_t result_value = *operand++;
                if ((index_raw >> coeff_count_power_) & 1)
                {
                    // Explicit inline
                    // result[index] = negate_uint_mod(result[index], modulus);
                    int64_t non_zero = (result_value != 0);
                    result_value = (modulus_value - result_value) & static_cast<uint64_t>(-non_zero);
                }
                result[index] = result_value;
            }
        }

        void GaloisTool::apply_galois_ntt(const uint64_t *operand, uint32_t galois_elt, uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (operand == nullptr)
            {
                throw std::invalid_argument("operand");
            }
            if (result == nullptr)
            {
                throw std::invalid_argument("result");
            }
            if (operand == result)
            {
                throw std::invalid_argument("result cannot point to the same value as operand");
            }
            // Verify coprime conditions.
            if (!(galois_elt & 1) || (galois_elt >= 2 * (uint64_t(1) << coeff_count_power_)))
            {
                throw std::invalid_argument("Galois element is not valid");
            }
#endif

            generate_table_ntt(galois_elt, permutation_tables_.at(get_index_from_elt(galois_elt)));

            auto &table = permutation_tables_.at(get_index_from_elt(galois_elt));
            // Perform permutation.
            for (size_t i = 0; i < coeff_count_; i++)
            {
                result[i] = operand[table[i]];
            }
        }
    } // namespace util
} // namespace seal