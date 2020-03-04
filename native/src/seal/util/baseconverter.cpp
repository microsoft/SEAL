// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/smallmodulus.h"
#include "seal/util/baseconverter.h"
#include "seal/util/defines.h"
#include "seal/util/globals.h"
#include "seal/util/numth.h"
#include "seal/util/pointer.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/smallntt.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <algorithm>
#include <iterator>
#include <numeric>
#include <stdexcept>

using namespace std;

namespace seal
{
    namespace util
    {
        BaseConverter::BaseConverter(
            size_t poly_modulus_degree, const vector<SmallModulus> &coeff_modulus, const SmallModulus &plain_modulus,
            MemoryPoolHandle pool)
            : pool_(move(pool))
        {
#ifdef SEAL_DEBUG
            if (!pool_)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            initialize(poly_modulus_degree, coeff_modulus, plain_modulus);
        }

        bool BaseConverter::initialize(
            size_t poly_modulus_degree, const vector<SmallModulus> &coeff_modulus, const SmallModulus &plain_modulus)
        {
            // Reset all data
            reset();

            // Return if coeff_modulus is out of bounds
            if (coeff_modulus.size() < SEAL_COEFF_MOD_COUNT_MIN || coeff_modulus.size() > SEAL_COEFF_MOD_COUNT_MAX)
            {
                return is_initialized_;
            }

            // Return if coeff_count is not a power of two or out of bounds
            int coeff_count_power = get_power_of_two(poly_modulus_degree);
            if (coeff_count_power < 0 || poly_modulus_degree > SEAL_POLY_MOD_DEGREE_MAX ||
                poly_modulus_degree < SEAL_POLY_MOD_DEGREE_MIN)
            {
                return is_initialized_;
            }

            t_ = plain_modulus;
            coeff_count_ = poly_modulus_degree;

            // Allocate memory for the bases q, B, Bsk, Bsk U m_tilde, t_gamma
            base_q_size_ = coeff_modulus.size();
            base_q_ = allocate<SmallModulus>(base_q_size_, pool_);

            // In some cases we might need to increase the size of the base B by one, namely
            // we require K * n * t * q^2 < q * prod(B) * m_sk, where K takes into account
            // cross terms when larger size ciphertexts are used, and n is the "delta factor"
            // for the ring. We reserve 32 bits for K * n. Here the coeff modulus primes q_i
            // are bounded to be 60 bits, and all primes in B and m_sk are 61 bits.
            int total_coeff_bit_count =
                accumulate(coeff_modulus.cbegin(), coeff_modulus.cend(), 0, [](int result, auto &mod) {
                    return result + mod.bit_count();
                });

            base_B_size_ = base_q_size_;
            if (32 + t_.bit_count() + total_coeff_bit_count >= 61 * safe_cast<int>(base_q_size_) + 61)
            {
                base_B_size_++;
            }
            base_B_ = allocate<SmallModulus>(base_B_size_, pool_);

            base_Bsk_size_ = base_B_size_ + 1;
            base_Bsk_ = allocate<SmallModulus>(base_Bsk_size_, pool_);

            base_Bsk_m_tilde_size_ = base_Bsk_size_ + 1;
            base_Bsk_m_tilde_ = allocate<SmallModulus>(base_Bsk_m_tilde_size_, pool_);

            // If plain_modulus is non-zero, then set up also base_t_gamma_
            if (!t_.is_zero())
            {
                base_t_gamma_size_ = 2;
                base_t_gamma_ = allocate<SmallModulus>(base_t_gamma_size_, pool_);
            }
#ifdef SEAL_DEBUG
            // Size check
            if (!product_fits_in(coeff_count_, base_Bsk_m_tilde_size_))
            {
                throw logic_error("invalid parameters");
            }
#endif
            // Sample primes for B and two more primes: m_sk and gamma
            auto baseconv_primes = get_primes(coeff_count_, SEAL_USER_MOD_BIT_COUNT_MAX + 1, base_Bsk_m_tilde_size_);

            auto baseconv_primes_iter = baseconv_primes.cbegin();
            m_sk_ = *baseconv_primes_iter++;
            gamma_ = *baseconv_primes_iter++;

            // Set m_tilde_ to a non-prime value
            m_tilde_ = uint64_t(1) << 32;

            // Populate the base arrays
            copy(coeff_modulus.cbegin(), coeff_modulus.cend(), base_q_.get());
            copy_n(baseconv_primes_iter, base_B_size_, base_B_.get());
            copy_n(base_B_.get(), base_B_size_, base_Bsk_.get());
            base_Bsk_[base_Bsk_size_ - 1] = m_sk_;
            copy_n(base_Bsk_.get(), base_Bsk_size_, base_Bsk_m_tilde_.get());
            base_Bsk_m_tilde_[base_Bsk_m_tilde_size_ - 1] = m_tilde_;

            // If base_t_gamma_ is initialized then set the moduli to t_ and gamma_
            if (base_t_gamma_)
            {
                base_t_gamma_[0] = t_;
                base_t_gamma_[1] = gamma_;
            }

            // Generate the Bsk SmallNTTTables; these are used for NTT after base extension to Bsk
            base_Bsk_small_ntt_tables_ = allocate<SmallNTTTables>(base_Bsk_size_, pool_);
            for (size_t i = 0; i < base_Bsk_size_; i++)
            {
                if (!base_Bsk_small_ntt_tables_[i].initialize(coeff_count_power, base_Bsk_[i]))
                {
                    reset();
                    return is_initialized_;
                }
            }

            // Set up CRTTool for q
            if (!base_q_crt_.initialize(base_q_.get(), base_q_size_))
            {
                reset();
                return is_initialized_;
            }

            // Set up CRTTool for B
            if (!base_B_crt_.initialize(base_B_.get(), base_B_size_))
            {
                reset();
                return is_initialized_;
            }

            // Set up BaseConvTool for q --> Bsk
            if (!base_q_to_Bsk_conv_.initialize(base_q_.get(), base_q_size_, base_Bsk_.get(), base_Bsk_size_))
            {
                reset();
                return is_initialized_;
            }

            // Set up BaseConvTool for q --> {m_tilde}
            if (!base_q_to_m_tilde_conv_.initialize(base_q_.get(), base_q_size_, &m_tilde_, 1))
            {
                reset();
                return is_initialized_;
            }

            // Set up BaseConvTool for B --> q
            if (!base_B_to_q_conv_.initialize(base_B_.get(), base_B_size_, base_q_.get(), base_q_size_))
            {
                reset();
                return is_initialized_;
            }

            // Set up BaseConvTool for B --> {m_sk}
            if (!base_B_to_m_sk_conv_.initialize(base_B_.get(), base_B_size_, &m_sk_, 1))
            {
                reset();
                return is_initialized_;
            }

            if (base_t_gamma_)
            {
                // Set up BaseConvTool for q --> {t, gamma}
                if (!base_q_to_t_gamma_conv_.initialize(
                        base_q_.get(), base_q_size_, base_t_gamma_.get(), base_t_gamma_size_))
                {
                    reset();
                    return is_initialized_;
                }
            }

            // Compute prod(q)
            auto prod_q(allocate_uint(base_q_size_, pool_));
            auto base_q_values(allocate_uint(base_q_size_, pool_));
            for (size_t i = 0; i < base_q_size_; i++)
            {
                base_q_values[i] = base_q_[i].value();
            }
            multiply_many_uint64(base_q_values.get(), base_q_size_, prod_q.get(), pool_);

            // Compute prod(B)
            auto base_B_product(allocate_uint(base_B_size_, pool_));
            auto base_B_values(allocate_uint(base_B_size_, pool_));
            for (size_t i = 0; i < base_B_size_; i++)
            {
                base_B_values[i] = base_B_[i].value();
            }
            multiply_many_uint64(base_B_values.get(), base_B_size_, base_B_product.get(), pool_);

            // Compute prod(B) mod q
            prod_B_mod_q_ = allocate_uint(base_q_size_, pool_);
            for (size_t i = 0; i < base_q_size_; i++)
            {
                prod_B_mod_q_[i] = modulo_uint(base_B_product.get(), base_B_size_, base_q_[i], pool_);
            }

            // Compute prod(q)^(-1) mod Bsk
            inv_prod_q_mod_Bsk_ = allocate_uint(base_Bsk_size_, pool_);
            for (size_t i = 0; i < base_Bsk_size_; i++)
            {
                inv_prod_q_mod_Bsk_[i] = modulo_uint(prod_q.get(), base_q_size_, base_Bsk_[i], pool_);
                if (!try_invert_uint_mod(inv_prod_q_mod_Bsk_[i], base_Bsk_[i], inv_prod_q_mod_Bsk_[i]))
                {
                    reset();
                    return is_initialized_;
                }
            }

            // Compute prod(B)^(-1) mod m_sk
            inv_prod_B_mod_m_sk_ = modulo_uint(base_B_product.get(), base_B_size_, m_sk_, pool_);
            if (!try_invert_uint_mod(inv_prod_B_mod_m_sk_, m_sk_, inv_prod_B_mod_m_sk_))
            {
                reset();
                return is_initialized_;
            }

            // Compute m_tilde^(-1) mod Bsk
            inv_m_tilde_mod_Bsk_ = allocate_uint(base_Bsk_size_, pool_);
            for (size_t i = 0; i < base_Bsk_size_; i++)
            {
                if (!try_invert_uint_mod(
                        m_tilde_.value() % base_Bsk_[i].value(), base_Bsk_[i], inv_m_tilde_mod_Bsk_[i]))
                {
                    reset();
                    return is_initialized_;
                }
            }

            // Compute prod(q)^(-1) mod m_tilde
            inv_prod_q_mod_m_tilde_ = modulo_uint(prod_q.get(), base_q_size_, m_tilde_, pool_);
            if (!try_invert_uint_mod(inv_prod_q_mod_m_tilde_, m_tilde_, inv_prod_q_mod_m_tilde_))
            {
                reset();
                return is_initialized_;
            }

            // Compute prod(q) mod Bsk
            prod_q_mod_Bsk_ = allocate_uint(base_Bsk_size_, pool_);
            for (size_t i = 0; i < base_Bsk_size_; i++)
            {
                prod_q_mod_Bsk_[i] = modulo_uint(prod_q.get(), base_q_size_, base_Bsk_[i], pool_);
            }

            if (base_t_gamma_)
            {
                // Compute gamma^(-1) mod t
                if (!try_invert_uint_mod(gamma_.value() % t_.value(), t_, inv_gamma_mod_t_))
                {
                    reset();
                    return is_initialized_;
                }

                // Compute prod({t, gamma}) mod q
                prod_t_gamma_mod_q_ = allocate_uint(base_q_size_, pool_);
                for (size_t i = 0; i < base_q_size_; i++)
                {
                    prod_t_gamma_mod_q_[i] =
                        multiply_uint_uint_mod(base_t_gamma_[0].value(), base_t_gamma_[1].value(), base_q_[i]);
                }

                // Compute -prod(q)^(-1) mod {t, gamma}
                neg_inv_q_mod_t_gamma_ = allocate_uint(base_t_gamma_size_, pool_);
                for (size_t i = 0; i < base_t_gamma_size_; i++)
                {
                    neg_inv_q_mod_t_gamma_[i] = modulo_uint(prod_q.get(), base_q_size_, base_t_gamma_[i], pool_);
                    if (!try_invert_uint_mod(neg_inv_q_mod_t_gamma_[i], base_t_gamma_[i], neg_inv_q_mod_t_gamma_[i]))
                    {
                        reset();
                        return is_initialized_;
                    }
                    neg_inv_q_mod_t_gamma_[i] = negate_uint_mod(neg_inv_q_mod_t_gamma_[i], base_t_gamma_[i]);
                }
            }

            // Compute q[last]^(-1) mod q[i] for i = 0..last-1
            // This is used by modulus switching and rescaling
            inv_q_last_mod_q_ = allocate_uint(base_q_size_ - 1, pool_);
            for (size_t i = 0; i < base_q_size_ - 1; i++)
            {
                if (!try_invert_uint_mod(base_q_[base_q_size_ - 1].value(), base_q_[i], inv_q_last_mod_q_[i]))
                {
                    reset();
                    return is_initialized_;
                }
            }

            // Everything went well
            is_initialized_ = true;

            return is_initialized_;
        }

        void BaseConverter::reset() noexcept
        {
            is_initialized_ = false;

            coeff_count_ = 0;

            base_q_size_ = 0;
            base_q_.release();
            base_B_size_ = 0;
            base_B_.release();
            base_Bsk_size_ = 0;
            base_Bsk_.release();
            base_Bsk_m_tilde_size_ = 0;
            base_Bsk_m_tilde_.release();
            base_t_gamma_size_ = 0;
            base_t_gamma_.release();

            base_q_crt_.reset();
            base_B_crt_.reset();
            base_q_to_Bsk_conv_.reset();
            base_q_to_m_tilde_conv_.reset();
            base_B_to_q_conv_.reset();
            base_B_to_m_sk_conv_.reset();
            base_q_to_t_gamma_conv_.reset();

            inv_prod_q_mod_Bsk_.release();
            inv_prod_q_mod_m_tilde_ = 0;
            inv_prod_B_mod_m_sk_ = 0;
            inv_gamma_mod_t_ = 0;
            prod_B_mod_q_.release();
            inv_m_tilde_mod_Bsk_.release();
            prod_q_mod_Bsk_.release();
            neg_inv_q_mod_t_gamma_.release();
            prod_t_gamma_mod_q_.release();
            inv_q_last_mod_q_.release();

            base_Bsk_small_ntt_tables_.release();

            m_tilde_ = 0;
            m_sk_ = 0;
            t_ = 0;
            gamma_ = 0;
            coeff_count_ = 0;
        }

        void BaseConverter::divide_and_floor_q_last_inplace(uint64_t *input, MemoryPoolHandle pool) const
        {
            if (!is_initialized_)
            {
                throw logic_error("BaseConverter is uninitialized");
            }
#ifdef SEAL_DEBUG
            if (!input)
            {
                throw invalid_argument("input cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            auto temp(allocate_uint(coeff_count_, pool));
            for (size_t i = 0; i < base_q_size_ - 1; i++)
            {
                // (ct mod qk) mod qi
                modulo_poly_coeffs_63(input + (base_q_size_ - 1) * coeff_count_, coeff_count_, base_q_[i], temp.get());

                // ((ct mod qi) - (ct mod qk)) mod qi
                sub_poly_poly_coeffmod(
                    input + (i * coeff_count_), temp.get(), coeff_count_, base_q_[i], input + (i * coeff_count_));

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(
                    input + i * coeff_count_, coeff_count_, inv_q_last_mod_q_[i], base_q_[i],
                    input + (i * coeff_count_));
            }
        }

        void BaseConverter::divide_and_floor_q_last_ntt_inplace(
            uint64_t *input, const Pointer<SmallNTTTables> &rns_ntt_tables, MemoryPoolHandle pool) const
        {
            if (!is_initialized_)
            {
                throw logic_error("BaseConverter is uninitialized");
            }
#ifdef SEAL_DEBUG
            if (!input)
            {
                throw invalid_argument("input cannot be null");
            }
            if (!rns_ntt_tables)
            {
                throw invalid_argument("rns_ntt_tables cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            // Convert to non-NTT form
            inverse_ntt_negacyclic_harvey(input + (base_q_size_ - 1) * coeff_count_, rns_ntt_tables[base_q_size_ - 1]);

            auto temp(allocate_uint(coeff_count_, pool));
            for (size_t i = 0; i < base_q_size_ - 1; i++)
            {
                // (ct mod qk) mod qi
                modulo_poly_coeffs_63(input + (base_q_size_ - 1) * coeff_count_, coeff_count_, base_q_[i], temp.get());

                // Convert to NTT form
                ntt_negacyclic_harvey(temp.get(), rns_ntt_tables[i]);

                // ((ct mod qi) - (ct mod qk)) mod qi
                sub_poly_poly_coeffmod(
                    input + (i * coeff_count_), temp.get(), coeff_count_, base_q_[i], input + (i * coeff_count_));

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(
                    input + (i * coeff_count_), coeff_count_, inv_q_last_mod_q_[i], base_q_[i],
                    input + (i * coeff_count_));
            }
        }

        void BaseConverter::divide_and_round_q_last_inplace(uint64_t *input, MemoryPoolHandle pool) const
        {
            if (!is_initialized_)
            {
                throw logic_error("BaseConverter is uninitialized");
            }
#ifdef SEAL_DEBUG
            if (!input)
            {
                throw invalid_argument("input cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            uint64_t *last_ptr = input + (base_q_size_ - 1) * coeff_count_;

            // Add (qi-1)/2 to change from flooring to rounding.
            SmallModulus last_modulus = base_q_[base_q_size_ - 1];
            uint64_t half = last_modulus.value() >> 1;
            for (size_t j = 0; j < coeff_count_; j++)
            {
                last_ptr[j] = barrett_reduce_63(last_ptr[j] + half, last_modulus);
            }

            auto temp(allocate_uint(coeff_count_, pool));
            uint64_t *temp_ptr = temp.get();
            for (size_t i = 0; i < base_q_size_ - 1; i++)
            {
                // (ct mod qk) mod qi
                modulo_poly_coeffs_63(last_ptr, coeff_count_, base_q_[i], temp_ptr);

                uint64_t half_mod = barrett_reduce_63(half, base_q_[i]);
                for (size_t j = 0; j < coeff_count_; j++)
                {
                    temp_ptr[j] = sub_uint_uint_mod(temp_ptr[j], half_mod, base_q_[i]);
                }

                sub_poly_poly_coeffmod(
                    input + (i * coeff_count_), temp_ptr, coeff_count_, base_q_[i], input + (i * coeff_count_));

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(
                    input + (i * coeff_count_), coeff_count_, inv_q_last_mod_q_[i], base_q_[i],
                    input + (i * coeff_count_));
            }
        }

        void BaseConverter::divide_and_round_q_last_ntt_inplace(
            uint64_t *input, const Pointer<SmallNTTTables> &rns_ntt_tables, MemoryPoolHandle pool) const
        {
            if (!is_initialized_)
            {
                throw logic_error("BaseConverter is uninitialized");
            }
#ifdef SEAL_DEBUG
            if (!input)
            {
                throw invalid_argument("input cannot be null");
            }
            if (!rns_ntt_tables)
            {
                throw invalid_argument("rns_ntt_tables cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            uint64_t *last_ptr = input + (base_q_size_ - 1) * coeff_count_;

            // Convert to non-NTT form
            inverse_ntt_negacyclic_harvey(last_ptr, rns_ntt_tables[base_q_size_ - 1]);

            // Add (qi-1)/2 to change from flooring to rounding.
            SmallModulus last_modulus = base_q_[base_q_size_ - 1];
            uint64_t half = last_modulus.value() >> 1;
            for (size_t j = 0; j < coeff_count_; j++)
            {
                last_ptr[j] = barrett_reduce_63(last_ptr[j] + half, last_modulus);
            }

            auto temp(allocate_uint(coeff_count_, pool));
            uint64_t *temp_ptr = temp.get();
            for (size_t i = 0; i < base_q_size_ - 1; i++)
            {
                // (ct mod qk) mod qi
                modulo_poly_coeffs_63(last_ptr, coeff_count_, base_q_[i], temp_ptr);

                uint64_t half_mod = barrett_reduce_63(half, base_q_[i]);
                for (size_t j = 0; j < coeff_count_; j++)
                {
                    temp_ptr[j] = sub_uint_uint_mod(temp_ptr[j], half_mod, base_q_[i]);
                }

                ntt_negacyclic_harvey(temp_ptr, rns_ntt_tables[i]);

                sub_poly_poly_coeffmod(
                    input + (i * coeff_count_), temp_ptr, coeff_count_, base_q_[i], input + (i * coeff_count_));

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(
                    input + (i * coeff_count_), coeff_count_, inv_q_last_mod_q_[i], base_q_[i],
                    input + (i * coeff_count_));
            }
        }

        void BaseConverter::fastbconv_sk(const uint64_t *input, uint64_t *destination, MemoryPoolHandle pool) const
        {
            if (!is_initialized_)
            {
                throw logic_error("BaseConverter is uninitialized");
            }
#ifdef SEAL_DEBUG
            if (!input)
            {
                throw invalid_argument("input cannot be null");
            }
            if (!destination)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            /*
            Require: Input in base Bsk
            Ensure: Output in base q
            */

            // Fast convert B -> q; input is in Bsk but we only use B
            base_B_to_q_conv_.fast_convert_array(input, coeff_count_, destination, pool);

            // Compute alpha_sk
            // Fast convert B -> {m_sk}; input is in Bsk but we only use B
            auto temp(allocate_uint(coeff_count_, pool));
            base_B_to_m_sk_conv_.fast_convert_array(input, coeff_count_, temp.get(), pool);

            // Take the m_sk part of input, subtract from temp, and multiply by inv_prod_B_mod_m_sk_
            // input_sk is allocated in input + (base_B_size_ * coeff_count_)
            const uint64_t *input_ptr = input + (base_B_size_ * coeff_count_);
            auto alpha_sk(allocate_uint(coeff_count_, pool));
            uint64_t *alpha_sk_ptr = alpha_sk.get();
            uint64_t *temp_ptr = temp.get();
            const uint64_t m_sk_value = m_sk_.value();
            for (size_t i = 0; i < coeff_count_; i++)
            {
                // It is not necessary for the negation to be reduced modulo the small prime
                alpha_sk_ptr[i] =
                    multiply_uint_uint_mod(temp_ptr[i] + (m_sk_value - input_ptr[i]), inv_prod_B_mod_m_sk_, m_sk_);
            }

            // alpha_sk is now ready for the Shenoy-Kumaresan conversion; however, note that our
            // alpha_sk here is not a centered reduction, so we need to apply a correction below.
            const uint64_t m_sk_div_2 = m_sk_value >> 1;
            for (size_t i = 0; i < base_q_size_; i++)
            {
                SmallModulus base_q_elt = base_q_[i];
                uint64_t prod_B_mod_q_elt = prod_B_mod_q_[i];
                for (size_t k = 0; k < coeff_count_; k++, destination++)
                {
                    // Correcting alpha_sk since it represents a negative value
                    if (alpha_sk_ptr[k] > m_sk_div_2)
                    {
                        *destination = multiply_add_uint_mod(
                            prod_B_mod_q_elt, m_sk_value - alpha_sk_ptr[k], *destination, base_q_elt);
                    }
                    // No correction needed
                    else
                    {
                        // It is not necessary for the negation to be reduced modulo the small prime
                        *destination = multiply_add_uint_mod(
                            base_q_elt.value() - prod_B_mod_q_[i], alpha_sk_ptr[k], *destination, base_q_elt);
                    }
                }
            }
        }

        void BaseConverter::montgomery_reduction(const uint64_t *input, uint64_t *destination) const
        {
            if (!is_initialized_)
            {
                throw logic_error("BaseConverter is uninitialized");
            }
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (destination == nullptr)
            {
                throw invalid_argument("destination cannot be null");
            }
#endif
            /*
            Require: Input in base Bsk U {m_tilde}
            Ensure: Output in base Bsk
            */

            for (size_t k = 0; k < base_Bsk_size_; k++)
            {
                // The last component of the input is mod m_tilde
                const uint64_t *input_m_tilde_ptr = input + (coeff_count_ * base_Bsk_size_);

                SmallModulus base_Bsk_elt = base_Bsk_[k];
                uint64_t inv_m_tilde_mod_Bsk_elt = inv_m_tilde_mod_Bsk_[k];
                uint64_t prod_q_mod_Bsk_elt = prod_q_mod_Bsk_[k];
                for (size_t i = 0; i < coeff_count_; i++, destination++, input++)
                {
                    // Compute r_m_tilde
                    // Duplicate work: This needs to be computed only once per coefficient, not per Bsk modulus
                    uint64_t r_m_tilde =
                        multiply_uint_uint_mod(input_m_tilde_ptr[i], inv_prod_q_mod_m_tilde_, m_tilde_);
                    r_m_tilde = negate_uint_mod(r_m_tilde, m_tilde_);

                    // Compute (input + q*r_m_tilde)*m_tilde^(-1) mod Bsk
                    *destination = multiply_uint_uint_mod(
                        multiply_add_uint_mod(prod_q_mod_Bsk_elt, r_m_tilde, *input, base_Bsk_elt),
                        inv_m_tilde_mod_Bsk_elt, base_Bsk_elt);
                }
            }
        }

        void BaseConverter::fast_floor(const uint64_t *input, uint64_t *destination, MemoryPoolHandle pool) const
        {
            if (!is_initialized_)
            {
                throw logic_error("BaseConverter is uninitialized");
            }
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (destination == nullptr)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            /*
            Require: Input in base q U Bsk
            Ensure: Output in base Bsk
            */

            // Convert q -> Bsk
            base_q_to_Bsk_conv_.fast_convert_array(input, coeff_count_, destination, pool);

            // Move input pointer to past the base q components
            input += base_q_size_ * coeff_count_;
            for (size_t i = 0; i < base_Bsk_size_; i++)
            {
                SmallModulus base_Bsk_elt = base_Bsk_[i];
                uint64_t inv_prod_q_mod_Bsk_elt = inv_prod_q_mod_Bsk_[i];
                for (size_t k = 0; k < coeff_count_; k++, input++, destination++)
                {
                    // It is not necessary for the negation to be reduced modulo base_Bsk_elt
                    *destination = multiply_uint_uint_mod(
                        *input + (base_Bsk_elt.value() - *destination), inv_prod_q_mod_Bsk_elt, base_Bsk_elt);
                }
            }
        }

        void BaseConverter::fastbconv_m_tilde(const uint64_t *input, uint64_t *destination, MemoryPoolHandle pool) const
        {
            if (!is_initialized_)
            {
                throw logic_error("BaseConverter is uninitialized");
            }
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (destination == nullptr)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            /*
            Require: Input in q
            Ensure: Output in Bsk U {m_tilde}
            */

            // We need to multiply first the input with m_tilde mod q
            // This is to facilitate Montgomery reduction in the next step of multiplication
            // This is NOT an ideal approach: as mentioned in Bajard et al., multiplication by
            // m_tilde can be easily merge into the base conversion operation; however, then
            // we could not use the BaseConvTool as below without modifications.
            auto temp(allocate_poly(coeff_count_, base_q_size_, pool));
            for (size_t i = 0; i < base_q_size_; i++)
            {
                multiply_poly_scalar_coeffmod(
                    input + (i * coeff_count_), coeff_count_, m_tilde_.value(), base_q_[i],
                    temp.get() + (i * coeff_count_));
            }

            // Now convert to Bsk
            base_q_to_Bsk_conv_.fast_convert_array(temp.get(), coeff_count_, destination, pool);

            // Finally convert to {m_tilde}
            base_q_to_m_tilde_conv_.fast_convert_array(
                temp.get(), coeff_count_, destination + (base_Bsk_size_ * coeff_count_), pool);
        }

        void BaseConverter::exact_scale_and_round(
            const uint64_t *input, uint64_t *destination, MemoryPoolHandle pool) const
        {
            // Compute |gamma * plain|qi * ct(s)
            auto temp(allocate_poly(coeff_count_, base_q_size_, pool));
            for (size_t i = 0; i < base_q_size_; i++)
            {
                multiply_poly_scalar_coeffmod(
                    input + (i * coeff_count_), coeff_count_, prod_t_gamma_mod_q_[i], base_q_[i],
                    temp.get() + (i * coeff_count_));
            }

            // Make another temp destination to get the poly in mod {t, gamma}
            auto temp_t_gamma(allocate_poly(coeff_count_, base_t_gamma_size_, pool));

            // Convert from q to {t, gamma}
            base_q_to_t_gamma_conv_.fast_convert_array(temp.get(), coeff_count_, temp_t_gamma.get(), pool);

            // Multiply by -prod(q)^(-1) mod {t, gamma}
            for (size_t i = 0; i < base_t_gamma_size_; i++)
            {
                multiply_poly_scalar_coeffmod(
                    temp_t_gamma.get() + (i * coeff_count_), coeff_count_, neg_inv_q_mod_t_gamma_[i], base_t_gamma_[i],
                    temp_t_gamma.get() + (i * coeff_count_));
            }

            // Need to correct values in temp_t_gamma (gamma component only) which are
            // larger than floor(gamma/2)
            uint64_t gamma_div_2 = base_t_gamma_[1].value() >> 1;

            // Now compute the subtraction to remove error and perform final multiplication by
            // gamma inverse mod plain_modulus
            for (size_t i = 0; i < coeff_count_; i++)
            {
                // Need correction because of centered mod
                if (temp_t_gamma[i + coeff_count_] > gamma_div_2)
                {
                    // Compute -(gamma - a) instead of (a - gamma)
                    destination[i] = add_uint_uint_mod(
                        temp_t_gamma[i], (gamma_.value() - temp_t_gamma[i + coeff_count_]) % t_.value(), t_);
                }
                // No correction needed
                else
                {
                    destination[i] =
                        sub_uint_uint_mod(temp_t_gamma[i], temp_t_gamma[i + coeff_count_] % t_.value(), t_);
                }
                if (0 != destination[i])
                {
                    // Perform final multiplication by gamma inverse mod plain_modulus
                    destination[i] = multiply_uint_uint_mod(destination[i], inv_gamma_mod_t_, t_);
                }
            }
        }
    } // namespace util
} // namespace seal
