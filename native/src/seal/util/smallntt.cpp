// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/smallntt.h"
#include "seal/util/polyarith.h"
#include "seal/util/uintarith.h"
#include "seal/smallmodulus.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/defines.h"
#include <algorithm>

using namespace std;

namespace seal
{
    namespace util
    {
        SmallNTTTables::SmallNTTTables(int coeff_count_power,
            const SmallModulus &modulus, MemoryPoolHandle pool) :
            pool_(move(pool))
        {
#ifdef SEAL_DEBUG
            if (!pool_)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            if (!generate(coeff_count_power, modulus))
            {
                // Generation failed; probably modulus wasn't prime.
                // It is necessary to check generated() after creating
                // this class.
            }
        }

        void SmallNTTTables::reset()
        {
            generated_ = false;
            modulus_ = SmallModulus();
            root_ = 0;
            root_powers_.release();
            scaled_root_powers_.release();
            inv_root_powers_.release();
            scaled_inv_root_powers_.release();
            inv_degree_modulo_ = 0;
            coeff_count_power_ = 0;
            coeff_count_ = 0;
        }

        bool SmallNTTTables::generate(int coeff_count_power,
            const SmallModulus &modulus)
        {
            reset();

            if ((coeff_count_power < get_power_of_two(SEAL_POLY_MOD_DEGREE_MIN)) ||
                coeff_count_power > get_power_of_two(SEAL_POLY_MOD_DEGREE_MAX))
            {
                throw invalid_argument("coeff_count_power out of range");
            }

            coeff_count_power_ = coeff_count_power;
            coeff_count_ = size_t(1) << coeff_count_power_;

            // Allocate memory for the tables
            root_powers_ = allocate_uint(coeff_count_, pool_);
            inv_root_powers_ = allocate_uint(coeff_count_, pool_);
            scaled_root_powers_ = allocate_uint(coeff_count_, pool_);
            scaled_inv_root_powers_ = allocate_uint(coeff_count_, pool_);
            modulus_ = modulus;

            // We defer parameter checking to try_minimal_primitive_root(...)
            if (!try_minimal_primitive_root(2 * coeff_count_, modulus_, root_))
            {
                reset();
                return false;
            }

            uint64_t inverse_root;
            if (!try_invert_uint_mod(root_, modulus_, inverse_root))
            {
                reset();
                return false;
            }

            // Populate the tables storing (scaled version of) powers of root
            // mod q in bit-scrambled order.
            ntt_powers_of_primitive_root(root_, root_powers_.get());
            ntt_scale_powers_of_primitive_root(root_powers_.get(),
                scaled_root_powers_.get());

            // Populate the tables storing (scaled version of) powers of
            // (root)^{-1} mod q in bit-scrambled order.
            ntt_powers_of_primitive_root(inverse_root, inv_root_powers_.get());
            ntt_scale_powers_of_primitive_root(inv_root_powers_.get(),
                scaled_inv_root_powers_.get());

            // Reordering inv_root_powers_ so that the access pattern at inverse NTT is sequential.
            std::vector<uint64_t> tmp(coeff_count_);
            uint64_t *ptr = tmp.data() + 1;
            for (size_t i = coeff_count_ / 2; i > 0; i /= 2) {
                for (size_t j = i; j < i * 2; ++j)
                    *ptr++ = inv_root_powers_[j];
            }
            std::copy(tmp.cbegin(), tmp.cend(), inv_root_powers_.get());

            ptr = tmp.data() + 1;
            for (size_t i = coeff_count_ / 2; i > 0; i /= 2) {
                for (size_t j = i; j < i * 2; ++j)
                    *ptr++ = scaled_inv_root_powers_[j];
            }
            std::copy(tmp.cbegin(), tmp.cend(), scaled_inv_root_powers_.get());

            // Last compute n^(-1) modulo q.
            uint64_t degree_uint = static_cast<uint64_t>(coeff_count_);
            generated_ = try_invert_uint_mod(degree_uint, modulus_, inv_degree_modulo_);

            if (!generated_)
            {
                reset();
                return false;
            }
            return true;
        }

        void SmallNTTTables::ntt_powers_of_primitive_root(uint64_t root,
            uint64_t *destination) const
        {
            uint64_t *destination_start = destination;
            *destination_start = 1;
            for (size_t i = 1; i < coeff_count_; i++)
            {
                uint64_t *next_destination =
                    destination_start + reverse_bits(i, coeff_count_power_);
                *next_destination =
                    multiply_uint_uint_mod(*destination, root, modulus_);
                destination = next_destination;
            }
        }

        // compute floor ( input * beta /q ), where beta is a 64k power of 2
        // and  0 < q < beta.
        static inline uint64_t precompute_mulmod(uint64_t y, uint64_t p) {
            uint64_t wide_quotient[2]{ 0, 0 };
            uint64_t wide_coeff[2]{ 0, y };
            divide_uint128_uint64_inplace(wide_coeff, p, wide_quotient);
            return wide_quotient[0];
        }

        void SmallNTTTables::ntt_scale_powers_of_primitive_root(
            const uint64_t *input, uint64_t *destination) const
        {
            for (size_t i = 0; i < coeff_count_; i++, input++, destination++)
            {
                *destination = precompute_mulmod(*input, modulus_.value());
            }
        }

        struct ntt_body {
            const uint64_t modulus, two_times_modulus;
            ntt_body(uint64_t modulus) : modulus(modulus), two_times_modulus(modulus << 1) {}

            // x0' <- x0 + w * x1
            // x1' <- x0 - w * x1
            inline void forward(uint64_t *x0, uint64_t *x1, uint64_t W, uint64_t Wprime) const {
                uint64_t u = *x0;
                uint64_t v = mulmod_lazy(*x1, W, Wprime);

                u -= select(two_times_modulus, u < two_times_modulus);
                *x0 = u + v;
                *x1 = u - v + two_times_modulus;
            }

            // x0' <- x0 + x1
            // x1' <- x0 - w * x1
            inline void backward(uint64_t *x0, uint64_t *x1, uint64_t W, uint64_t Wprime) const {
                uint64_t u = *x0;
                uint64_t v = *x1;
                uint64_t t = u + v;
                t -= select(two_times_modulus, t < two_times_modulus);

                *x0 = t;
                *x1 = mulmod_lazy(u - v + two_times_modulus, W, Wprime);
            }

            inline void backward_last(uint64_t *x0, uint64_t *x1, uint64_t inv_N, uint64_t inv_Nprime, uint64_t inv_N_W, uint64_t inv_N_Wprime) const {
                uint64_t u = *x0;
                uint64_t v = *x1;
                uint64_t t = u + v;
                t -= select(two_times_modulus, t < two_times_modulus);

                *x0 = mulmod_lazy(t, inv_N, inv_Nprime);
                *x1 = mulmod_lazy(u - v + two_times_modulus, inv_N_W, inv_N_Wprime);
            }

            // x * y mod p using Shoup's trick, i.e., yprime = floor(2^64 * y / p)
            inline uint64_t mulmod_lazy(uint64_t x, uint64_t y, uint64_t yprime) const {
                unsigned long long q;
                multiply_uint64_hw64(x, yprime, &q);
                return x * y - q * modulus;
            }

            // return 0 if cond = true, else return b if cond = false
            inline uint64_t select(uint64_t b, bool cond) const {
                return (b & -(uint64_t) cond) ^ b;
            }
        };

        /**
        This function computes in-place the negacyclic NTT. The input is
        a polynomial a of degree n in R_q, where n is assumed to be a power of
        2 and q is a prime such that q = 1 (mod 2n).

        The output is a vector A such that the following hold:
        A[j] =  a(psi**(2*bit_reverse(j) + 1)), 0 <= j < n.

        For details, see Michael Naehrig and Patrick Longa.
        */
        void ntt_negacyclic_harvey_lazy(uint64_t *operand,
            const SmallNTTTables &tables)
        {
            ntt_body ntt(tables.modulus().value());

            size_t n = size_t(1) << tables.coeff_count_power();
            size_t t = n >> 1;
            for (size_t m = 1; m < n; m <<= 1)
            {
                if (t >= 4)
                {
                    for (size_t i = 0; i < m; i++)
                    {
                        size_t j1 = 2 * i * t;
                        size_t j2 = j1 + t;
                        const uint64_t W = tables.get_from_root_powers(m + i);
                        const uint64_t Wprime = tables.get_from_scaled_root_powers(m + i);

                        uint64_t *X = operand + j1;
                        uint64_t *Y = X + t;
                        for (size_t j = j1; j < j2; j += 4)
                        {
                            ntt.forward(X++, Y++, W, Wprime);
                            ntt.forward(X++, Y++, W, Wprime);
                            ntt.forward(X++, Y++, W, Wprime);
                            ntt.forward(X++, Y++, W, Wprime);
                        }
                    }
                }
                else
                {
                    for (size_t i = 0; i < m; i++)
                    {
                        size_t j1 = 2 * i * t;
                        size_t j2 = j1 + t;
                        const uint64_t W = tables.get_from_root_powers(m + i);
                        const uint64_t Wprime = tables.get_from_scaled_root_powers(m + i);

                        uint64_t *X = operand + j1;
                        uint64_t *Y = X + t;
                        for (size_t j = j1; j < j2; j++)
                        {
                            ntt.forward(X++, Y++, W, Wprime);
                        }
                    }
                }
                t >>= 1;
            }
        }

        // Inverse negacyclic NTT using Harvey's butterfly. (See Patrick Longa and Michael Naehrig).
        void inverse_ntt_negacyclic_harvey_lazy(uint64_t *operand, const SmallNTTTables &tables)
        {
            ntt_body ntt(tables.modulus().value());

            const size_t n = size_t(1) << tables.coeff_count_power();
            size_t t = 1;
            size_t inv_root_index = 1;
            // m > 2 to skip the last layer
            for (size_t m = n; m > 2; m >>= 1)
            {
                size_t j1 = 0;
                size_t h = m >> 1;
                if (t >= 4)
                {
                    for (size_t i = 0; i < h; i++, ++inv_root_index)
                    {
                        size_t j2 = j1 + t;
                        // Need the powers of phi^{-1} in bit-reversed order
                        const uint64_t W = tables.get_from_inv_root_powers(inv_root_index);
                        const uint64_t Wprime = tables.get_from_scaled_inv_root_powers(inv_root_index);

                        uint64_t *U = operand + j1;
                        uint64_t *V = U + t;
                        for (size_t j = j1; j < j2; j += 4)
                        {
                            ntt.backward(U++, V++, W, Wprime);
                            ntt.backward(U++, V++, W, Wprime);
                            ntt.backward(U++, V++, W, Wprime);
                            ntt.backward(U++, V++, W, Wprime);
                        }
                        j1 += (t << 1);
                    }
                }
                else
                {
                    for (size_t i = 0; i < h; i++, ++inv_root_index)
                    {
                        size_t j2 = j1 + t;
                        // Need the powers of  phi^{-1} in bit-reversed order
                        const uint64_t W = tables.get_from_inv_root_powers(inv_root_index);
                        const uint64_t Wprime = tables.get_from_scaled_inv_root_powers(inv_root_index);

                        uint64_t *U = operand + j1;
                        uint64_t *V = U + t;
                        for (size_t j = j1; j < j2; j++)
                        {
                            ntt.backward(U++, V++, W, Wprime);
                        }
                        j1 += (t << 1);
                    }
                }
                t <<= 1;
            }

            // merge n^{-1} with the last layer of invNTT
            const uint64_t W = tables.get_from_inv_root_powers(inv_root_index);
            const uint64_t inv_N = *(tables.get_inv_degree_modulo());
            const uint64_t inv_N_W = multiply_uint_uint_mod(inv_N, W, tables.modulus());
            const uint64_t inv_Nprime = precompute_mulmod(inv_N, tables.modulus().value());
            const uint64_t inv_N_Wprime = precompute_mulmod(inv_N_W, tables.modulus().value());

            uint64_t *U = operand;
            uint64_t *V = U + (n / 2);
            for (size_t j = n / 2; j < n; j++)
            {
                ntt.backward_last(U++, V++, inv_N, inv_Nprime, inv_N_W, inv_N_Wprime);
            }
        }
    }
}
