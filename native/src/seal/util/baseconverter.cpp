// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdexcept>
#include <algorithm>
#include <numeric>
#include "seal/util/defines.h"
#include "seal/util/pointer.h"
#include "seal/util/uintcore.h"
#include "seal/util/polycore.h"
#include "seal/util/baseconverter.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/smallntt.h"
#include "seal/util/globals.h"
#include "seal/smallmodulus.h"

using namespace std;

namespace seal
{
    namespace util
    {
        BaseConverter::BaseConverter(const std::vector<SmallModulus> &coeff_base,
            size_t coeff_count, const SmallModulus &small_plain_mod,
            MemoryPoolHandle pool) : pool_(move(pool))
        {
#ifdef SEAL_DEBUG
            if (!pool)
            {
                throw std::invalid_argument("pool is uninitialized");
            }
#endif
            generate(coeff_base, coeff_count, small_plain_mod);
        }

        void BaseConverter::generate(const std::vector<SmallModulus> &coeff_base,
            size_t coeff_count, const SmallModulus &small_plain_mod)
        {
#ifdef SEAL_DEBUG
            if (get_power_of_two(coeff_count) < 0)
            {
                throw invalid_argument("coeff_count must be a power of 2");
            }
            if (coeff_base.size() < SEAL_COEFF_MOD_COUNT_MIN ||
                coeff_base.size() > SEAL_COEFF_MOD_COUNT_MAX)
            {
                throw invalid_argument("coeff_base has invalid size");
            }
#endif
            int coeff_count_power = get_power_of_two(coeff_count);

            /**
            Perform all the required pre-computations and populate the tables
            */
            reset();

            m_sk_ = global_variables::internal_mods::m_sk;
            m_tilde_ = global_variables::internal_mods::m_tilde;
            gamma_ = global_variables::internal_mods::gamma;
            small_plain_mod_ = small_plain_mod;
            coeff_count_ = coeff_count;
            coeff_base_mod_count_ = coeff_base.size();
            aux_base_mod_count_ = coeff_base.size();

            // In some cases we might need to increase the size of the aux base by one, namely
            // we require K * n * t * q^2 < q * prod_i m_i * m_sk, where K takes into account
            // cross terms when larger size ciphertexts are used, and n is the "delta factor"
            // for the ring. We reserve 32 bits for K * n. Here the coeff modulus primes q_i
            // are bounded to be 60 bits, and all m_i, m_sk are 61 bits.
            int total_coeff_bit_count = accumulate(coeff_base.cbegin(), coeff_base.cend(), 0,
                [](int result, auto &mod) { return result + mod.bit_count(); });

            if (32 + small_plain_mod_.bit_count() + total_coeff_bit_count >=
                61 * safe_cast<int>(coeff_base_mod_count_) + 61)
            {
                aux_base_mod_count_++;
            }

            // Base sizes
            bsk_base_mod_count_ = aux_base_mod_count_ + 1;
            plain_gamma_count_ = 2;

            // Size check; should always pass
            if (!product_fits_in(coeff_count_, coeff_base_mod_count_))
            {
                throw logic_error("invalid parameters");
            }
            if (!product_fits_in(coeff_count_, aux_base_mod_count_))
            {
                throw logic_error("invalid parameters");
            }
            if (!product_fits_in(coeff_count_, bsk_base_mod_count_))
            {
                throw logic_error("invalid parameters");
            }

            // We use a reversed order here for performance reasons
            coeff_base_products_mod_aux_bsk_array_ =
                allocate<Pointer<std::uint64_t>>(bsk_base_mod_count_, pool_);
            generate_n(
                coeff_base_products_mod_aux_bsk_array_.get(),
                bsk_base_mod_count_,
                [&]() { return allocate_uint(coeff_base_mod_count_, pool_); });

            // We use a reversed order here for performance reasons
            aux_base_products_mod_coeff_array_ =
                allocate<Pointer<std::uint64_t>>(coeff_base_mod_count_, pool_);
            generate_n(
                aux_base_products_mod_coeff_array_.get(),
                coeff_base_mod_count_,
                [&]() { return allocate_uint(aux_base_mod_count_, pool_); });

            coeff_products_mod_plain_gamma_array_ =
                allocate<Pointer<std::uint64_t>>(plain_gamma_count_, pool_);
            generate_n(
                coeff_products_mod_plain_gamma_array_.get(),
                plain_gamma_count_,
                [&]() { return allocate_uint(coeff_base_mod_count_, pool_); });

            // Create moduli arrays
            coeff_base_array_ = allocate<SmallModulus>(coeff_base_mod_count_, pool_);
            aux_base_array_ = allocate<SmallModulus>(aux_base_mod_count_, pool_);
            bsk_base_array_ = allocate<SmallModulus>(bsk_base_mod_count_, pool_);

            copy(coeff_base.cbegin(), coeff_base.cend(), coeff_base_array_.get());
            copy_n(global_variables::internal_mods::aux_small_mods.cbegin(),
                aux_base_mod_count_, aux_base_array_.get());
            copy_n(aux_base_array_.get(), aux_base_mod_count_, bsk_base_array_.get());
            bsk_base_array_[bsk_base_mod_count_ - 1] = m_sk_;

            // Generate Bsk U {mtilde} small ntt tables which is used in Evaluator
            bsk_small_ntt_tables_ = allocate<SmallNTTTables>(bsk_base_mod_count_, pool_);
            for (size_t i = 0; i < bsk_base_mod_count_; i++)
            {
                if (!bsk_small_ntt_tables_[i].generate(coeff_count_power, bsk_base_array_[i]))
                {
                    reset();
                    return;
                }
            }

            size_t coeff_products_uint64_count = coeff_base_mod_count_;
            size_t aux_products_uint64_count = aux_base_mod_count_;

            // Generate punctured products of coeff moduli
            coeff_products_array_ = allocate_zero_uint(
                coeff_products_uint64_count * coeff_base_mod_count_, pool_);
            auto tmp_coeff(allocate_uint(coeff_products_uint64_count, pool_));

            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                coeff_products_array_[i * coeff_products_uint64_count] = 1;
                for (size_t j = 0; j < coeff_base_mod_count_; j++)
                {
                    if (i != j)
                    {
                        multiply_uint_uint64(coeff_products_array_.get() +
                            (i * coeff_products_uint64_count), coeff_products_uint64_count,
                            coeff_base_array_[j].value(), coeff_products_uint64_count,
                            tmp_coeff.get());
                        set_uint_uint(tmp_coeff.get(), coeff_products_uint64_count,
                            coeff_products_array_.get() + (i * coeff_products_uint64_count));
                    }
                }
            }

            // Generate punctured products of aux moduli
            auto aux_products_array(allocate_zero_uint(
                aux_products_uint64_count * aux_base_mod_count_, pool_));
            auto tmp_aux(allocate_uint(aux_products_uint64_count, pool_));

            for (size_t i = 0; i < aux_base_mod_count_; i++)
            {
                aux_products_array[i * aux_products_uint64_count] = 1;
                for (size_t j = 0; j < aux_base_mod_count_; j++)
                {
                    if (i != j)
                    {
                        multiply_uint_uint64(aux_products_array.get() +
                            (i * aux_products_uint64_count), aux_products_uint64_count,
                            aux_base_array_[j].value(), aux_products_uint64_count,
                            tmp_aux.get());
                        set_uint_uint(tmp_aux.get(), aux_products_uint64_count,
                            aux_products_array.get() + (i * aux_products_uint64_count));
                    }
                }
            }

            // Compute auxiliary base products mod m_sk
            aux_base_products_mod_msk_array_ = allocate_uint(aux_base_mod_count_, pool_);
            for (size_t i = 0; i < aux_base_mod_count_; i++)
            {
                aux_base_products_mod_msk_array_[i] =
                    modulo_uint(aux_products_array.get() + (i * aux_products_uint64_count),
                        aux_products_uint64_count, m_sk_, pool_);
            }

            // Compute inverse coeff base mod coeff base array (qi^(-1)) mod qi and
            // mtilde inv coeff products mod auxiliary moduli  (m_tilda*qi^(-1)) mod qi
            inv_coeff_base_products_mod_coeff_array_ =
                allocate_uint(coeff_base_mod_count_, pool_);
            mtilde_inv_coeff_base_products_mod_coeff_array_ =
                allocate_uint(coeff_base_mod_count_, pool_);
            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                inv_coeff_base_products_mod_coeff_array_[i] =
                    modulo_uint(coeff_products_array_.get() + (i * coeff_products_uint64_count),
                    coeff_products_uint64_count, coeff_base_array_[i], pool_);
                if (!try_invert_uint_mod(inv_coeff_base_products_mod_coeff_array_[i],
                    coeff_base_array_[i], inv_coeff_base_products_mod_coeff_array_[i]))
                {
                    reset();
                    return;
                }
                mtilde_inv_coeff_base_products_mod_coeff_array_[i] =
                    multiply_uint_uint_mod(inv_coeff_base_products_mod_coeff_array_[i],
                    m_tilde_.value(), coeff_base_array_[i]);
            }

            // Compute inverse auxiliary moduli mod auxiliary moduli (mi^(-1)) mod mi
            inv_aux_base_products_mod_aux_array_ = allocate_uint(aux_base_mod_count_, pool_);
            for (size_t i = 0; i < aux_base_mod_count_; i++)
            {
                inv_aux_base_products_mod_aux_array_[i] =
                    modulo_uint(aux_products_array.get() + (i * aux_products_uint64_count),
                        aux_products_uint64_count, aux_base_array_[i], pool_);
                if (!try_invert_uint_mod(inv_aux_base_products_mod_aux_array_[i],
                    aux_base_array_[i], inv_aux_base_products_mod_aux_array_[i]))
                {
                    reset();
                    return;
                }
            }

            // Compute coeff modulus products mod mtilde (qi) mod m_tilde_
            coeff_base_products_mod_mtilde_array_ = allocate_uint(coeff_base_mod_count_, pool_);
            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                coeff_base_products_mod_mtilde_array_[i] =
                    modulo_uint(coeff_products_array_.get() + (i * coeff_products_uint64_count),
                        coeff_products_uint64_count, m_tilde_, pool_);
            }

            // Compute coeff modulus products mod auxiliary moduli (qi) mod mj U {msk}
            coeff_base_products_mod_aux_bsk_array_ =
                allocate<Pointer<std::uint64_t>>(bsk_base_mod_count_, pool_);
            for (size_t i = 0; i < aux_base_mod_count_; i++)
            {
                coeff_base_products_mod_aux_bsk_array_[i] =
                    allocate_uint(coeff_base_mod_count_, pool_);
                for (size_t j = 0; j < coeff_base_mod_count_; j++)
                {
                    coeff_base_products_mod_aux_bsk_array_[i][j] =
                        modulo_uint(coeff_products_array_.get() + (j * coeff_products_uint64_count),
                            coeff_products_uint64_count, aux_base_array_[i], pool_);
                }
            }

            // Add qi mod msk at the end of the array
            coeff_base_products_mod_aux_bsk_array_[bsk_base_mod_count_ - 1] =
                allocate_uint(coeff_base_mod_count_, pool_);
            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                coeff_base_products_mod_aux_bsk_array_[bsk_base_mod_count_ - 1][i] =
                    modulo_uint(coeff_products_array_.get() + (i * coeff_products_uint64_count),
                        coeff_products_uint64_count, m_sk_, pool_);
            }

            // Compute auxiliary moduli products mod coeff moduli (mj) mod qi
            aux_base_products_mod_coeff_array_ =
                allocate<Pointer<std::uint64_t>>(coeff_base_mod_count_, pool_);
            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                aux_base_products_mod_coeff_array_[i] = allocate_uint(aux_base_mod_count_, pool_);
                for (size_t j = 0; j < aux_base_mod_count_; j++)
                {
                    aux_base_products_mod_coeff_array_[i][j] =
                        modulo_uint(aux_products_array.get() + (j * aux_products_uint64_count),
                            aux_products_uint64_count, coeff_base_array_[i], pool_);
                }
            }

            // Compute coeff moduli products inverse mod auxiliary mods  (qi^(-1)) mod mj U {msk}
            auto coeff_products_all(allocate_uint(coeff_base_mod_count_, pool_));
            auto tmp_products_all(allocate_uint(coeff_base_mod_count_, pool_));
            set_uint(1, coeff_base_mod_count_, coeff_products_all.get());

            // Compute the product of all coeff moduli
            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                multiply_uint_uint64(coeff_products_all.get(), coeff_base_mod_count_,
                    coeff_base_array_[i].value(), coeff_base_mod_count_, tmp_products_all.get());
                set_uint_uint(tmp_products_all.get(), coeff_base_mod_count_,
                    coeff_products_all.get());
            }

            // Compute inverses of coeff_products_all modulo aux moduli
            inv_coeff_products_all_mod_aux_bsk_array_ = allocate_uint(bsk_base_mod_count_, pool_);
            for (size_t i = 0; i < aux_base_mod_count_; i++)
            {
                inv_coeff_products_all_mod_aux_bsk_array_[i] = modulo_uint(coeff_products_all.get(),
                    coeff_base_mod_count_, aux_base_array_[i], pool_);
                if (!try_invert_uint_mod(inv_coeff_products_all_mod_aux_bsk_array_[i],
                    aux_base_array_[i], inv_coeff_products_all_mod_aux_bsk_array_[i]))
                {
                    reset();
                    return;
                }
            }

            // Add product of all coeffs mod msk at the end of the array
            inv_coeff_products_all_mod_aux_bsk_array_[bsk_base_mod_count_ - 1] =
                modulo_uint(coeff_products_all.get(), coeff_base_mod_count_, m_sk_, pool_);
            if (!try_invert_uint_mod(inv_coeff_products_all_mod_aux_bsk_array_[bsk_base_mod_count_ - 1],
                m_sk_, inv_coeff_products_all_mod_aux_bsk_array_[bsk_base_mod_count_ - 1]))
            {
                reset();
                return;
            }

            // Compute the products of all aux moduli
            auto aux_products_all(allocate_uint(aux_base_mod_count_, pool_));
            auto tmp_aux_products_all(allocate_uint(aux_base_mod_count_, pool_));
            set_uint(1, aux_base_mod_count_, aux_products_all.get());

            for (size_t i = 0; i < aux_base_mod_count_; i++)
            {
                multiply_uint_uint64(aux_products_all.get(), aux_base_mod_count_,
                    aux_base_array_[i].value(), aux_base_mod_count_, tmp_aux_products_all.get());
                set_uint_uint(tmp_aux_products_all.get(), aux_base_mod_count_,
                    aux_products_all.get());
            }

            // Compute the auxiliary products inverse mod m_sk_ (M-1) mod m_sk_
            inv_aux_products_mod_msk_ = modulo_uint(aux_products_all.get(),
                aux_base_mod_count_, m_sk_, pool_);
            if (!try_invert_uint_mod(inv_aux_products_mod_msk_, m_sk_,
                inv_aux_products_mod_msk_))
            {
                reset();
                return;
            }

            // Compute auxiliary products all mod coefficient moduli
            aux_products_all_mod_coeff_array_ = allocate_uint(coeff_base_mod_count_, pool_);
            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                aux_products_all_mod_coeff_array_[i] = modulo_uint(aux_products_all.get(),
                    aux_base_mod_count_, coeff_base_array_[i], pool_);
            }

            // Compute m_tilde inverse mod bsk base
            inv_mtilde_mod_bsk_array_ = allocate_uint(bsk_base_mod_count_, pool_);
            for (size_t i = 0; i < aux_base_mod_count_; i++)
            {
                if (!try_invert_uint_mod(m_tilde_.value() % aux_base_array_[i].value(),
                    aux_base_array_[i], inv_mtilde_mod_bsk_array_[i]))
                {
                    reset();
                    return;
                }
            }

            // Add m_tilde inverse mod msk at the end of the array
            if (!try_invert_uint_mod(m_tilde_.value() % m_sk_.value(), m_sk_,
                inv_mtilde_mod_bsk_array_[bsk_base_mod_count_ - 1]))
            {
                reset();
                return;
            }

            // Compute coeff moduli products inverse mod m_tilde
            inv_coeff_products_mod_mtilde_ = modulo_uint(coeff_products_all.get(),
                coeff_base_mod_count_, m_tilde_, pool_);
            if (!try_invert_uint_mod(inv_coeff_products_mod_mtilde_, m_tilde_,
                inv_coeff_products_mod_mtilde_))
            {
                reset();
                return;
            }

            // Compute coeff base products all mod Bsk
            coeff_products_all_mod_bsk_array_ = allocate_uint(bsk_base_mod_count_, pool_);
            for (size_t i = 0; i < aux_base_mod_count_; i++)
            {
                coeff_products_all_mod_bsk_array_[i] =
                    modulo_uint(coeff_products_all.get(), coeff_base_mod_count_,
                        aux_base_array_[i], pool_);
            }

            // Add coeff base products all mod m_sk_ at the end of the array
            coeff_products_all_mod_bsk_array_[bsk_base_mod_count_ - 1] =
                modulo_uint(coeff_products_all.get(), coeff_base_mod_count_, m_sk_, pool_);

            // Compute inverses of last coeff base modulus modulo the first ones for
            // modulus switching/rescaling.
            inv_last_coeff_mod_array_ = allocate_uint(coeff_base_mod_count_ - 1, pool_);
            for (size_t i = 0; i < coeff_base_mod_count_ - 1; i++)
            {
                if (!try_mod_inverse(coeff_base_array_[coeff_base_mod_count_ - 1].value(),
                    coeff_base_array_[i].value(), inv_last_coeff_mod_array_[i]))
                {
                    reset();
                    return;
                }
            }

            // Generate plain gamma array of small_plain_mod_ is set to non-zero.
            // Otherwise assume we use CKKS and no plain_modulus is needed.
            if (!small_plain_mod_.is_zero())
            {
                plain_gamma_array_ = allocate<SmallModulus>(plain_gamma_count_, pool_);
                plain_gamma_array_[0] = small_plain_mod_;
                plain_gamma_array_[1] = gamma_;

                // Compute coeff moduli products mod plain gamma
                coeff_products_mod_plain_gamma_array_ =
                    allocate<Pointer<std::uint64_t>>(plain_gamma_count_, pool_);
                for (size_t i = 0; i < plain_gamma_count_; i++)
                {
                    coeff_products_mod_plain_gamma_array_[i] =
                        allocate_uint(coeff_base_mod_count_, pool_);
                    for (size_t j = 0; j < coeff_base_mod_count_; j++)
                    {
                        coeff_products_mod_plain_gamma_array_[i][j] =
                            modulo_uint(
                                coeff_products_array_.get() + (j * coeff_products_uint64_count),
                                coeff_products_uint64_count, plain_gamma_array_[i], pool_
                            );
                    }
                }

                // Compute inverse of all coeff moduli products mod plain gamma
                neg_inv_coeff_products_all_mod_plain_gamma_array_ =
                    allocate_uint(plain_gamma_count_, pool_);
                for (size_t i = 0; i < plain_gamma_count_; i++)
                {
                    uint64_t temp = modulo_uint(coeff_products_all.get(),
                        coeff_base_mod_count_, plain_gamma_array_[i], pool_);
                    neg_inv_coeff_products_all_mod_plain_gamma_array_[i] =
                        negate_uint_mod(temp, plain_gamma_array_[i]);
                    if (!try_invert_uint_mod(neg_inv_coeff_products_all_mod_plain_gamma_array_[i],
                        plain_gamma_array_[i], neg_inv_coeff_products_all_mod_plain_gamma_array_[i]))
                    {
                        reset();
                        return;
                    }
                }

                // Compute inverse of gamma mod plain modulus
                inv_gamma_mod_plain_ = modulo_uint(gamma_.data(), gamma_.uint64_count(),
                    small_plain_mod_, pool_);
                if (!try_invert_uint_mod(
                    inv_gamma_mod_plain_, small_plain_mod_, inv_gamma_mod_plain_))
                {
                    reset();
                    return;
                }

                // Compute plain_gamma product mod coeff base moduli
                plain_gamma_product_mod_coeff_array_ =
                    allocate_uint(coeff_base_mod_count_, pool_);
                for (size_t i = 0; i < coeff_base_mod_count_; i++)
                {
                    plain_gamma_product_mod_coeff_array_[i] =
                        multiply_uint_uint_mod(small_plain_mod_.value(), gamma_.value(),
                            coeff_base_array_[i]);
                }
            }

            // Everything went well
            generated_ = true;
        }

        void BaseConverter::reset() noexcept
        {
            generated_ = false;
            coeff_base_array_.release();
            aux_base_array_.release();
            bsk_base_array_.release();
            plain_gamma_array_.release();
            coeff_products_array_.release();
            mtilde_inv_coeff_base_products_mod_coeff_array_.release();
            inv_aux_base_products_mod_aux_array_.release();
            inv_coeff_products_all_mod_aux_bsk_array_.release();
            inv_coeff_base_products_mod_coeff_array_.release();
            aux_base_products_mod_coeff_array_.release();
            coeff_base_products_mod_aux_bsk_array_.release();
            coeff_base_products_mod_mtilde_array_.release();
            aux_base_products_mod_msk_array_.release();
            aux_products_all_mod_coeff_array_.release();
            inv_mtilde_mod_bsk_array_.release();
            coeff_products_all_mod_bsk_array_.release();
            coeff_products_mod_plain_gamma_array_.release();
            neg_inv_coeff_products_all_mod_plain_gamma_array_.release();
            plain_gamma_product_mod_coeff_array_.release();
            bsk_small_ntt_tables_.release();
            inv_last_coeff_mod_array_.release();
            inv_coeff_products_mod_mtilde_ = 0;
            m_tilde_ = 0;
            m_sk_ = 0;
            gamma_ = 0;
            coeff_count_ = 0;
            coeff_base_mod_count_ = 0;
            aux_base_mod_count_ = 0;
            plain_gamma_count_ = 0;
            inv_gamma_mod_plain_ = 0;
        }

        void BaseConverter::fastbconv(const uint64_t *input,
            uint64_t *destination, MemoryPoolHandle pool) const
        {
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
                throw invalid_argument("pool is not initialied");
            }
            if (!generated_)
            {
                throw logic_error("BaseConverter is not generated");
            }
#endif
            /**
             Require: Input in q
             Ensure: Output in Bsk = {m1,...,ml} U {msk}
            */
            auto temp_coeff_transition(allocate_uint(
                coeff_count_ * coeff_base_mod_count_, pool));
            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                uint64_t inv_coeff_base_products_mod_coeff_elt =
                    inv_coeff_base_products_mod_coeff_array_[i];
                SmallModulus coeff_base_array_elt = coeff_base_array_[i];
                for (size_t k = 0; k < coeff_count_; k++, input++)
                {
                    temp_coeff_transition[i + (k * coeff_base_mod_count_)] =
                        multiply_uint_uint_mod(
                            *input,
                            inv_coeff_base_products_mod_coeff_elt,
                            coeff_base_array_elt
                        );
                }
            }

            for (size_t j = 0; j < bsk_base_mod_count_; j++)
            {
                uint64_t *temp_coeff_transition_ptr = temp_coeff_transition.get();
                SmallModulus bsk_base_array_elt = bsk_base_array_[j];
                for (size_t k = 0; k < coeff_count_; k++, destination++)
                {
                    const uint64_t *coeff_base_products_mod_aux_bsk_array_ptr =
                        coeff_base_products_mod_aux_bsk_array_[j].get();
                    unsigned long long aux_transition[2]{ 0, 0 };
                    for (size_t i = 0; i < coeff_base_mod_count_;
                        i++, temp_coeff_transition_ptr++,
                        coeff_base_products_mod_aux_bsk_array_ptr++)
                    {
                        // Lazy reduction
                        unsigned long long temp[2];

                        // Product is 60 bit + 61 bit = 121 bit, so can sum up to 127 of them with no reduction
                        // Thus need coeff_base_mod_count_ <= 127 to guarantee success
                        multiply_uint64(*temp_coeff_transition_ptr,
                            *coeff_base_products_mod_aux_bsk_array_ptr, temp);
                        unsigned char carry = add_uint64(aux_transition[0],
                            temp[0], aux_transition);
                        aux_transition[1] += temp[1] + carry;
                    }
                    *destination = barrett_reduce_128(aux_transition, bsk_base_array_elt);
                }
            }
        }

        void BaseConverter::floor_last_coeff_modulus_inplace(
            uint64_t *rns_poly,
            MemoryPoolHandle pool) const
        {
            auto temp(allocate_uint(coeff_count_, pool));
            for (size_t i = 0; i < coeff_base_mod_count_ - 1; i++)
            {
                // (ct mod qk) mod qi
                modulo_poly_coeffs_63(
                    rns_poly + (coeff_base_mod_count_ - 1) * coeff_count_,
                    coeff_count_,
                    coeff_base_array_[i],
                    temp.get());
                sub_poly_poly_coeffmod(
                    rns_poly + i * coeff_count_,
                    temp.get(),
                    coeff_count_,
                    coeff_base_array_[i],
                    rns_poly + i * coeff_count_);
                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(
                    rns_poly + i * coeff_count_,
                    coeff_count_,
                    inv_last_coeff_mod_array_[i],
                    coeff_base_array_[i],
                    rns_poly + i * coeff_count_);
            }
        }

        void BaseConverter::floor_last_coeff_modulus_ntt_inplace(
                std::uint64_t *rns_poly,
                const Pointer<SmallNTTTables> &rns_ntt_tables,
                MemoryPoolHandle pool) const
        {
            auto temp(allocate_uint(coeff_count_, pool));
            // Convert to non-NTT form
            inverse_ntt_negacyclic_harvey(
                rns_poly + (coeff_base_mod_count_ - 1) * coeff_count_,
                rns_ntt_tables[coeff_base_mod_count_ - 1]);
            for (size_t i = 0; i < coeff_base_mod_count_ - 1; i++)
            {
                // (ct mod qk) mod qi
                modulo_poly_coeffs_63(
                    rns_poly + (coeff_base_mod_count_ - 1) * coeff_count_,
                    coeff_count_,
                    coeff_base_array_[i],
                    temp.get());
                // Convert to NTT form
                ntt_negacyclic_harvey(temp.get(), rns_ntt_tables[i]);
                // ((ct mod qi) - (ct mod qk)) mod qi
                sub_poly_poly_coeffmod(
                    rns_poly + i * coeff_count_,
                    temp.get(),
                    coeff_count_,
                    coeff_base_array_[i],
                    rns_poly + i * coeff_count_);
                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(
                    rns_poly + i * coeff_count_,
                    coeff_count_,
                    inv_last_coeff_mod_array_[i],
                    coeff_base_array_[i],
                    rns_poly + i * coeff_count_);
            }
        }

        void BaseConverter::fastbconv_sk(const uint64_t *input,
            uint64_t *destination, MemoryPoolHandle pool) const
        {
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
                throw invalid_argument("pool is not initialied");
            }
#endif
            /**
             Require: Input in base Bsk = M U {msk}
             Ensure: Output in base q
            */

            // Fast convert B -> q
            auto temp_coeff_transition(allocate_uint(
                coeff_count_ * aux_base_mod_count_, pool));
            const uint64_t *input_ptr = input;
            for (size_t i = 0; i < aux_base_mod_count_; i++)
            {
                uint64_t inv_aux_base_products_mod_aux_array_elt =
                    inv_aux_base_products_mod_aux_array_[i];
                SmallModulus aux_base_array_elt = aux_base_array_[i];
                for (size_t k = 0; k < coeff_count_; k++)
                {
                    temp_coeff_transition[i + (k * aux_base_mod_count_)] =
                        multiply_uint_uint_mod(
                            *input_ptr++,
                            inv_aux_base_products_mod_aux_array_elt,
                            aux_base_array_elt
                        );
                }
            }

            uint64_t *destination_ptr = destination;
            uint64_t *temp_ptr;
            for (size_t j = 0; j < coeff_base_mod_count_; j++)
            {
                temp_ptr = temp_coeff_transition.get();
                SmallModulus coeff_base_array_elt = coeff_base_array_[j];
                for (size_t k = 0; k < coeff_count_; k++, destination_ptr++)
                {
                    const uint64_t *aux_base_products_mod_coeff_array_ptr =
                        aux_base_products_mod_coeff_array_[j].get();
                    unsigned long long aux_transition[2]{ 0, 0 };
                    for (size_t i = 0; i < aux_base_mod_count_; i++, temp_ptr++,
                        aux_base_products_mod_coeff_array_ptr++)
                    {
                        // Lazy reduction
                        unsigned long long temp[2];

                        // Product is 61 bit + 60 bit = 121 bit, so can sum up to 127 of them with no reduction
                        // Thus need aux_base_mod_count_ <= 127, so coeff_base_mod_count_ <= 126 to guarantee success
                        multiply_uint64(*temp_ptr, *aux_base_products_mod_coeff_array_ptr, temp);
                        unsigned char carry = add_uint64(aux_transition[0], temp[0], aux_transition);
                        aux_transition[1] += temp[1] + carry;
                    }
                    *destination_ptr = barrett_reduce_128(aux_transition, coeff_base_array_elt);
                }
            }

            // Compute alpha_sk
            // Require: Input is in Bsk
            // we only use coefficient in B
            // Fast convert B -> m_sk
            auto tmp(allocate_uint(coeff_count_, pool));
            destination_ptr = tmp.get();
            temp_ptr = temp_coeff_transition.get();
            for (size_t k = 0; k < coeff_count_; k++, destination_ptr++)
            {
                unsigned long long msk_transition[2]{ 0, 0 };
                const uint64_t *aux_base_products_mod_msk_array_ptr =
                    aux_base_products_mod_msk_array_.get();
                for (size_t i = 0; i < aux_base_mod_count_; i++, temp_ptr++,
                    aux_base_products_mod_msk_array_ptr++)
                {
                    // Lazy reduction
                    unsigned long long temp[2];

                    // Product is 61 bit + 61 bit = 122 bit, so can sum up to 63 of them with no reduction
                    // Thus need aux_base_mod_count_ <= 63, so coeff_base_mod_count_ <= 62 to guarantee success
                    // This gives the strongest restriction on the number of coeff modulus primes
                    multiply_uint64(*temp_ptr, *aux_base_products_mod_msk_array_ptr, temp);
                    unsigned char carry = add_uint64(msk_transition[0], temp[0], msk_transition);
                    msk_transition[1] += temp[1] + carry;
                }
                *destination_ptr = barrett_reduce_128(msk_transition, m_sk_);
            }

            auto alpha_sk(allocate_uint(coeff_count_, pool));
            input_ptr = input + (aux_base_mod_count_ * coeff_count_);
            destination_ptr = alpha_sk.get();
            temp_ptr = tmp.get();
            const uint64_t m_sk_value = m_sk_.value();
            // x_sk is allocated in input[aux_base_mod_count_]
            for (size_t i = 0; i < coeff_count_; i++, input_ptr++, temp_ptr++, destination_ptr++)
            {
                // It is not necessary for the negation to be reduced modulo the small prime
                uint64_t negated_input = m_sk_value - *input_ptr;
                *destination_ptr = multiply_uint_uint_mod(*temp_ptr + negated_input,
                    inv_aux_products_mod_msk_, m_sk_);
            }

            const uint64_t m_sk_div_2 = m_sk_value >> 1;
            destination_ptr = destination;
            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                uint64_t aux_products_all_mod_coeff_array_elt =
                    aux_products_all_mod_coeff_array_[i];
                temp_ptr = alpha_sk.get();
                SmallModulus coeff_base_array_elt = coeff_base_array_[i];
                uint64_t coeff_base_array_elt_value = coeff_base_array_elt.value();
                for (size_t k = 0; k < coeff_count_; k++, temp_ptr++, destination_ptr++)
                {
                    unsigned long long m_alpha_sk[2];

                    // Correcting alpha_sk since it is a centered modulo
                    if (*temp_ptr > m_sk_div_2)
                    {
                        // Lazy reduction
                        multiply_uint64(aux_products_all_mod_coeff_array_elt,
                            m_sk_value - *temp_ptr, m_alpha_sk);
                        m_alpha_sk[1] += add_uint64(m_alpha_sk[0], *destination_ptr, m_alpha_sk);
                        *destination_ptr = barrett_reduce_128(m_alpha_sk, coeff_base_array_elt);
                    }
                    // No correction needed
                    else
                    {
                        // Lazy reduction
                        // It is not necessary for the negation to be reduced modulo the small prime
                        multiply_uint64(
                            coeff_base_array_elt_value - aux_products_all_mod_coeff_array_elt,
                            *temp_ptr, m_alpha_sk
                        );
                        m_alpha_sk[1] += add_uint64(*destination_ptr,
                            m_alpha_sk[0], m_alpha_sk);
                        *destination_ptr = barrett_reduce_128(m_alpha_sk, coeff_base_array_elt);
                    }
                }
            }
        }

        void BaseConverter::mont_rq(const uint64_t *input, uint64_t *destination) const
        {
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
            /**
             Require: Input should in Bsk U {m_tilde}
             Ensure: Destination array in Bsk = m U {msk}
            */
            const uint64_t *input_m_tilde_ptr =
                input + coeff_count_ * bsk_base_mod_count_;
            for (size_t k = 0; k < bsk_base_mod_count_; k++)
            {
                uint64_t coeff_products_all_mod_bsk_array_elt =
                    coeff_products_all_mod_bsk_array_[k];
                uint64_t inv_mtilde_mod_bsk_array_elt = inv_mtilde_mod_bsk_array_[k];
                SmallModulus bsk_base_array_elt = bsk_base_array_[k];
                const uint64_t *input_m_tilde_ptr_copy = input_m_tilde_ptr;

                // Compute result for aux base
                for (size_t i = 0; i < coeff_count_; i++, destination++,
                    input_m_tilde_ptr_copy++, input++)
                {
                    // Compute r_mtilde
                    // Duplicate work here:
                    // This needs to be computed only once per coefficient, not per Bsk prime.
                    uint64_t r_mtilde = multiply_uint_uint_mod(*input_m_tilde_ptr_copy,
                        inv_coeff_products_mod_mtilde_, m_tilde_);
                    r_mtilde = negate_uint_mod(r_mtilde, m_tilde_);

                    // Lazy reduction
                    unsigned long long tmp[2];
                    multiply_uint64(coeff_products_all_mod_bsk_array_elt, r_mtilde, tmp);
                    tmp[1] += add_uint64(tmp[0], *input, tmp);
                    r_mtilde = barrett_reduce_128(tmp, bsk_base_array_elt);
                    *destination = multiply_uint_uint_mod(
                        r_mtilde, inv_mtilde_mod_bsk_array_elt, bsk_base_array_elt);
                }
            }
        }

        void BaseConverter::fast_floor(const uint64_t *input,
            uint64_t *destination, MemoryPoolHandle pool) const
        {
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
                throw invalid_argument("pool is not initialied");
            }
#endif
            /**
             Require: Input in q U m U {msk}
             Ensure: Destination array in Bsk
            */
            fastbconv(input, destination, pool); //q -> Bsk

            size_t index_msk = coeff_base_mod_count_ * coeff_count_;
            input += index_msk;
            for (size_t i = 0; i < bsk_base_mod_count_; i++)
            {
                SmallModulus bsk_base_array_elt = bsk_base_array_[i];
                uint64_t bsk_base_array_value = bsk_base_array_elt.value();
                uint64_t inv_coeff_products_all_mod_aux_bsk_array_elt =
                    inv_coeff_products_all_mod_aux_bsk_array_[i];
                for (size_t k = 0; k < coeff_count_; k++, input++, destination++)
                {
                    // It is not necessary for the negation to be reduced modulo the small prime
                    //negate_uint_smallmod(base_convert_Bsk.get() + k + (i * coeff_count_),
                    // bsk_base_array_[i], &negated_base_convert_Bsk);
                    *destination = multiply_uint_uint_mod(
                        *input + bsk_base_array_value - *destination,
                        inv_coeff_products_all_mod_aux_bsk_array_elt,
                        bsk_base_array_elt
                    );
                }
            }
        }

        void BaseConverter::fastbconv_mtilde(const uint64_t *input,
            uint64_t *destination, MemoryPoolHandle pool) const
        {
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
                throw invalid_argument("pool is not initialied");
            }
#endif
            /**
             Require: Input in q
             Ensure: Output in Bsk U {m_tilde}
            */

            // Compute in Bsk first; we compute |m_tilde*q^-1i| mod qi
            auto temp_coeff_transition(allocate_uint(
                coeff_count_ * coeff_base_mod_count_, pool));
            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                SmallModulus coeff_base_array_elt = coeff_base_array_[i];
                uint64_t mtilde_inv_coeff_base_products_mod_coeff_elt =
                    mtilde_inv_coeff_base_products_mod_coeff_array_[i];
                for (size_t k = 0; k < coeff_count_; k++, input++)
                {
                    temp_coeff_transition[i + (k * coeff_base_mod_count_)] =
                        multiply_uint_uint_mod(
                            *input,
                            mtilde_inv_coeff_base_products_mod_coeff_elt,
                            coeff_base_array_elt
                        );
                }
            }

            uint64_t *destination_ptr = destination;
            for (size_t j = 0; j < bsk_base_mod_count_; j++)
            {
                const uint64_t *coeff_base_products_mod_aux_bsk_array_ptr =
                    coeff_base_products_mod_aux_bsk_array_[j].get();
                uint64_t *temp_coeff_transition_ptr = temp_coeff_transition.get();
                SmallModulus bsk_base_array_elt = bsk_base_array_[j];
                for (size_t k = 0; k < coeff_count_; k++, destination_ptr++)
                {
                    unsigned long long aux_transition[2]{ 0, 0 };
                    const uint64_t *temp_ptr = coeff_base_products_mod_aux_bsk_array_ptr;
                    for (size_t i = 0; i < coeff_base_mod_count_;
                        i++, temp_ptr++, temp_coeff_transition_ptr++)
                    {
                        // Lazy reduction
                        unsigned long long temp[2]{ 0, 0 };

                        // Product is 60 bit + 61 bit = 121 bit, so can sum up to 127 of them with no reduction
                        // Thus need coeff_base_mod_count_ <= 127
                        multiply_uint64(*temp_coeff_transition_ptr, *temp_ptr, temp);
                        unsigned char carry = add_uint64(aux_transition[0],
                            temp[0], aux_transition);
                        aux_transition[1] += temp[1] + carry;
                    }
                    *destination_ptr = barrett_reduce_128(aux_transition, bsk_base_array_elt);
                }
            }

            // Computing the last element (mod m_tilde) and add it at the end of destination array
            uint64_t *temp_coeff_transition_ptr = temp_coeff_transition.get();
            destination += bsk_base_mod_count_ * coeff_count_;
            for (size_t k = 0; k < coeff_count_; k++, destination++)
            {
                unsigned long long wide_result[2]{ 0, 0 };
                const uint64_t *coeff_base_products_mod_mtilde_array_ptr =
                    coeff_base_products_mod_mtilde_array_.get();
                for (size_t i = 0; i < coeff_base_mod_count_; i++,
                    temp_coeff_transition_ptr++,
                    coeff_base_products_mod_mtilde_array_ptr++)
                {
                    // Lazy reduction
                    unsigned long long aux_transition[2];

                    // Product is 60 bit + 33 bit = 93 bit
                    multiply_uint64(*temp_coeff_transition_ptr,
                        *coeff_base_products_mod_mtilde_array_ptr, aux_transition);
                    unsigned char carry = add_uint64(aux_transition[0],
                        wide_result[0], wide_result);
                    wide_result[1] += aux_transition[1] + carry;
                }
                *destination = barrett_reduce_128(wide_result, m_tilde_);
            }
        }

        void BaseConverter::fastbconv_plain_gamma(const uint64_t *input,
            uint64_t *destination, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (small_plain_mod_.is_zero())
            {
                throw logic_error("invalid operation");
            }
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (destination == nullptr)
            {
                throw invalid_argument("destination cannot be null");
            }
#endif
            /**
             Require: Input in q
             Ensure: Output in t (plain modulus) U gamma
            */
            auto temp_coeff_transition(allocate_uint(
                coeff_count_ * coeff_base_mod_count_, pool));
            for (size_t i = 0; i < coeff_base_mod_count_; i++)
            {
                uint64_t inv_coeff_base_products_mod_coeff_elt =
                    inv_coeff_base_products_mod_coeff_array_[i];
                SmallModulus coeff_base_array_elt = coeff_base_array_[i];
                for (size_t k = 0; k < coeff_count_; k++, input++)
                {
                    temp_coeff_transition[i + (k * coeff_base_mod_count_)] =
                        multiply_uint_uint_mod(
                            *input,
                            inv_coeff_base_products_mod_coeff_elt,
                            coeff_base_array_elt
                        );
                }
            }

            for (size_t j = 0; j < plain_gamma_count_; j++)
            {
                SmallModulus plain_gamma_array_elt = plain_gamma_array_[j];
                uint64_t *temp_coeff_transition_ptr = temp_coeff_transition.get();
                const uint64_t *coeff_products_mod_plain_gamma_array_ptr =
                    coeff_products_mod_plain_gamma_array_[j].get();
                for (size_t k = 0; k < coeff_count_; k++, destination++)
                {
                    unsigned long long wide_result[2]{ 0, 0 };
                    const uint64_t *temp_ptr = coeff_products_mod_plain_gamma_array_ptr;
                    for (size_t i = 0; i < coeff_base_mod_count_; i++,
                        temp_coeff_transition_ptr++, temp_ptr++)
                    {
                        unsigned long long plain_transition[2];

                        // Lazy reduction
                        // Product is 60 bit + 61 bit = 121 bit, so can sum up to 127 of them with no reduction
                        // Thus need coeff_base_mod_count_ <= 127
                        multiply_uint64(*temp_coeff_transition_ptr, *temp_ptr, plain_transition);
                        unsigned char carry = add_uint64(plain_transition[0],
                            wide_result[0], wide_result);
                        wide_result[1] += plain_transition[1] + carry;
                    }
                    *destination = barrett_reduce_128(wide_result, plain_gamma_array_elt);
                }
            }
        }
    }
}
