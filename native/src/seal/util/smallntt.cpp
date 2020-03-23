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
        // floor(y * 2^64 / p) which is used to accelerate f(x) = x * y mod p
        static inline uint64_t shoupify(uint64_t y, uint64_t p) {
            uint64_t cnst_128[2]{0, y};
            uint64_t shoup[2];
            seal::util::divide_uint128_uint64_inplace(cnst_128, p, shoup);
            return shoup[0];
        }

        // Workhorse for NTT & iNTT for a prime p.
        struct SlothfulNTT {
        public:
            const uint64_t p, Lp; // prime p, and Lp = 2*p for now.
            const uint64_t rdp; // floor(2^64 / p)
            explicit SlothfulNTT(uint64_t p, uint64_t Lp, uint64_t rdp = 0) : p(p), Lp(Lp), rdp(rdp) {
              if (p >= (1L << 59)) 
              {
                  throw std::logic_error("SlothfulNTT requires 59-bit modulus most, but got " + std::to_string(p));
              }
            }

            // x0' <- x0 + w * x1 mod p
            // x1' <- x0 - w * x1 mod p
            inline void forward_lazy(uint64_t *x0, uint64_t *x1, uint64_t w, uint64_t wshoup) const {
                uint64_t u, v;
                u = *x0;
                v = mulmod_lazy(*x1, w, wshoup);

                *x0 = u + v;
                *x1 = u - v + Lp;
            }

            inline void forward_last_lazy(uint64_t *x0, uint64_t *x1, uint64_t w, uint64_t wshoup) const {
                uint64_t u, v;
                u = reduce_barrett_lazy(*x0);
                v = mulmod_lazy(*x1, w, wshoup);

                *x0 = u + v;
                *x1 = u - v + Lp;
            }

            // x0' <- x0 + x1 mod p
            // x1' <- x0 - w * x1 mod p
            inline void backward_lazy(uint64_t *x0, uint64_t *x1, uint64_t w, uint64_t wshoup) const {
                uint64_t u = *x0;
                uint64_t v = *x1;
                uint64_t t = u + v;
                t -= select(Lp, t < Lp);
                *x0 = t;
                *x1 = mulmod_lazy(u - v + Lp, w, wshoup);
            }

            inline void backward_last_lazy(uint64_t *x0, uint64_t *x1, uint64_t inv_n, uint64_t inv_n_shoup, uint64_t inv_n_w, uint64_t inv_n_w_shoup) const {
                uint64_t u = *x0;
                uint64_t v = *x1;
                uint64_t t = u + v;
                t -= select(Lp, t < Lp);
                *x0 = mulmod_lazy(t, inv_n, inv_n_shoup);
                *x1 = mulmod_lazy(u - v + Lp, inv_n_w, inv_n_w_shoup);
            }
        private:
            // return 0 if cond = true, else return b if cond = false
            inline uint64_t select(uint64_t b, bool cond) const {
                return (b & -(uint64_t) cond) ^ b;
            }

            // x * y mod p using Shoup's trick, i.e., yshoup = floor(2^64 * y / p)
            inline uint64_t mulmod_lazy(uint64_t x, uint64_t y, uint64_t yshoup) const {
                unsigned long long q;
                multiply_uint64_hw64(x, yshoup, &q);
                return x * y - q * p;
            }

            inline uint64_t mulmod(uint64_t x, uint64_t y, uint64_t yshoup) const {
                x = mulmod_lazy(x, y, yshoup);
                return x - select(p, x < p);
            }

            // Basically mulmod_lazy(x, 1, shoup(1))
            inline uint64_t reduce_barrett_lazy(uint64_t x) const {
#ifdef SEAL_DEBUG
                if (rdp == 0)
                {
                    throw invalid_argument("reduce_barrett_lazy: invalid parameter");
                }
#endif
                unsigned long long q;
                multiply_uint64_hw64(x, rdp, &q);
                return x - q * p;
            }
        };

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
        void SmallNTTTables::ntt_scale_powers_of_primitive_root(
            const uint64_t *input, uint64_t *destination) const
        {
            for (size_t i = 0; i < coeff_count_; i++)
            {
                *destination++ = shoupify(*input++, modulus_.value());
            }
        }

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
          const uint64_t p = tables.modulus().value();
          SlothfulNTT ntt_body(p, p << 1, shoupify(1, p));

          const size_t n = size_t(1) << tables.coeff_count_power();
          size_t m = 1;
          size_t h = n >> 1;

          const uint64_t *w = tables.get_root_powers() + 1;
          const uint64_t *wshoup = tables.get_scaled_root_powers() + 1;

          { // main loop: for h >= 4
            for (; h > 2; m <<= 1, h >>= 1) {
              auto x0 = operand;
              auto x1 = x0 + h; 
              for (size_t r = 0; r < m; ++r, ++w, ++wshoup) {
                // buttefly group that use the same twiddle factor, i.e., w[r].
                for (size_t i = 0; i < h; i += 4) { // unrolling
                  ntt_body.forward_lazy(x0++, x1++, *w, *wshoup);
                  ntt_body.forward_lazy(x0++, x1++, *w, *wshoup);
                  ntt_body.forward_lazy(x0++, x1++, *w, *wshoup);
                  ntt_body.forward_lazy(x0++, x1++, *w, *wshoup);
                }
                x0 += h;
                x1 += h;
              }
            }
          }

          { // m = degree / 4, h = 2
            auto x0 = operand;
            auto x1 = x0 + 2;
            for (size_t r = 0; r < m; ++r, ++w, ++wshoup) { // unrolling
              ntt_body.forward_lazy(x0++, x1++, *w, *wshoup);
              ntt_body.forward_lazy(x0, x1, *w, *wshoup); // combine the incr to following steps
              x0 += 3;
              x1 += 3;
            }
            m <<= 1;
          }

          { // m = degree / 2, h = 1
            auto x0 = operand;
            auto x1 = x0 + 1;
            for (size_t r = 0; r < m; ++r, ++w, ++wshoup) {
              ntt_body.forward_last_lazy(x0, x1, *w, *wshoup);
              x0 += 2;
              x1 += 2;
            }
          }
          // At the end operand[0 .. n) stay in [0, 4p).
        }

        // Inverse negacyclic NTT using Harvey's butterfly. (See Patrick Longa and Michael Naehrig).
        void inverse_ntt_negacyclic_harvey_lazy(uint64_t *operand, const SmallNTTTables &tables)
        {
          const uint64_t p = tables.modulus().value();
          const uint64_t n = 1L << tables.coeff_count_power();
          const uint64_t *w = tables.get_inv_root_powers() + 1;
          const uint64_t *wshoup = tables.get_scaled_inv_root_powers() + 1;

          SlothfulNTT intt_body(p, 2 * p);
          { // first loop: m = degree / 2, h = 1
            const size_t m = n >> 1;
            auto x0 = operand;
            auto x1 = x0 + 1; // invariant: x1 = x0 + h during the iteration
            for (size_t r = 0; r < m; ++r, ++w, ++wshoup) {
              intt_body.backward_lazy(x0, x1, *w, *wshoup);
              x0 += 2;
              x1 += 2;
            }
          }

          { // second loop: m = degree / 4, h = 2
            const size_t m = n / 4;
            auto x0 = operand;
            auto x1 = x0 + 2;
            for (size_t r = 0; r < m; ++r, ++w, ++wshoup) {
              intt_body.backward_lazy(x0++, x1++, *w, *wshoup);
              intt_body.backward_lazy(x0, x1, *w, *wshoup);
              x0 += 3;
              x1 += 3;
            }
          }

          { // main loop: for h >= 4
            size_t m = n / 8;
            size_t h = 4;
            // m > 1 to skip the last layer
            for (; m > 1; m >>= 1, h <<= 1) {
              auto x0 = operand;
              auto x1 = x0 + h;
              for (size_t r = 0; r < m; ++r, ++w, ++wshoup) {
                for (size_t i = 0; i < h; i += 4) { // unrolling
                  intt_body.backward_lazy(x0++, x1++, *w, *wshoup);
                  intt_body.backward_lazy(x0++, x1++, *w, *wshoup);
                  intt_body.backward_lazy(x0++, x1++, *w, *wshoup);
                  intt_body.backward_lazy(x0++, x1++, *w, *wshoup);
                }
                x0 += h;
                x1 += h;
              }
            }
          }

          // Multiply n^{-1} merged with the last layer of butterfly.
          const uint64_t inv_n = *(tables.get_inv_degree_modulo());
          const uint64_t inv_n_shoup = shoupify(inv_n, p);
          const uint64_t inv_n_w = multiply_uint_uint_mod(inv_n, *w, tables.modulus());
          const uint64_t inv_n_w_shoup = shoupify(inv_n_w, p);

          uint64_t *x0 = operand;
          uint64_t *x1 = x0 + n / 2;
          for (size_t i = n / 2; i < n; ++i) {
            intt_body.backward_last_lazy(x0++, x1++, inv_n, inv_n_shoup, inv_n_w, inv_n_w_shoup);
          }
          // At the end operand[0 .. n) stay in [0, 2p).
        }
    }
}
