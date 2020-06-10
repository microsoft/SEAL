// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/common.h"
#include "seal/util/iterator.h"
#include "seal/util/numth.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/rns.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintarithsmallmod.h"
#include <algorithm>

using namespace std;

namespace seal
{
    namespace util
    {
        RNSBase::RNSBase(const vector<Modulus> &rnsbase, MemoryPoolHandle pool)
            : pool_(move(pool)), size_(rnsbase.size())
        {
            if (!size_)
            {
                throw invalid_argument("rnsbase cannot be empty");
            }
            if (!pool_)
            {
                throw invalid_argument("pool is uninitialized");
            }

            for (size_t i = 0; i < rnsbase.size(); i++)
            {
                // The base elements cannot be zero
                if (rnsbase[i].is_zero())
                {
                    throw invalid_argument("rnsbase is invalid");
                }

                for (size_t j = 0; j < i; j++)
                {
                    // The base must be coprime
                    if (!are_coprime(rnsbase[i].value(), rnsbase[j].value()))
                    {
                        throw invalid_argument("rnsbase is invalid");
                    }
                }
            }

            // Base is good; now copy it over to rnsbase_
            base_ = allocate<Modulus>(size_, pool_);
            copy_n(rnsbase.cbegin(), size_, base_.get());

            // Initialize CRT data
            if (!initialize())
            {
                throw invalid_argument("rnsbase is invalid");
            }
        }

        RNSBase::RNSBase(const RNSBase &copy, MemoryPoolHandle pool) : pool_(move(pool)), size_(copy.size_)
        {
            if (!pool_)
            {
                throw invalid_argument("pool is uninitialized");
            }

            // Copy over the base
            base_ = allocate<Modulus>(size_, pool_);
            copy_n(copy.base_.get(), size_, base_.get());

            // Copy over CRT data
            base_prod_ = allocate_uint(size_, pool_);
            set_uint(copy.base_prod_.get(), size_, base_prod_.get());

            punctured_prod_array_ = allocate_uint(size_ * size_, pool_);
            set_uint(copy.punctured_prod_array_.get(), size_ * size_, punctured_prod_array_.get());

            inv_punctured_prod_mod_base_array_ = allocate_uint(size_, pool_);
            set_uint(copy.inv_punctured_prod_mod_base_array_.get(), size_, inv_punctured_prod_mod_base_array_.get());
        }

        bool RNSBase::contains(const Modulus &value) const noexcept
        {
            bool result = false;
            SEAL_ITERATE(iter(base_), size_, [&](auto I) { result = result || (I == value); });
            return result;
        }

        bool RNSBase::is_subbase_of(const RNSBase &superbase) const noexcept
        {
            bool result = true;
            SEAL_ITERATE(iter(base_), size_, [&](auto I) { result = result && superbase.contains(I); });
            return result;
        }

        RNSBase RNSBase::extend(Modulus value) const
        {
            if (value.is_zero())
            {
                throw invalid_argument("value cannot be zero");
            }

            SEAL_ITERATE(iter(base_), size_, [&](auto I) {
                // The base must be coprime
                if (!are_coprime(I.value(), value.value()))
                {
                    throw logic_error("cannot extend by given value");
                }
            });

            // Copy over this base
            RNSBase newbase(pool_);
            newbase.size_ = add_safe(size_, size_t(1));
            newbase.base_ = allocate<Modulus>(newbase.size_, newbase.pool_);
            copy_n(base_.get(), size_, newbase.base_.get());

            // Extend with value
            newbase.base_[newbase.size_ - 1] = value;

            // Initialize CRT data
            if (!newbase.initialize())
            {
                throw logic_error("cannot extend by given value");
            }

            return newbase;
        }

        RNSBase RNSBase::extend(const RNSBase &other) const
        {
            // The bases must be coprime
            for (size_t i = 0; i < other.size_; i++)
            {
                for (size_t j = 0; j < i; j++)
                {
                    if (!are_coprime(other[i].value(), base_[j].value()))
                    {
                        throw invalid_argument("rnsbase is invalid");
                    }
                }
            }

            // Copy over this base
            RNSBase newbase(pool_);
            newbase.size_ = add_safe(size_, other.size_);
            newbase.base_ = allocate<Modulus>(newbase.size_, newbase.pool_);
            copy_n(base_.get(), size_, newbase.base_.get());

            // Extend with other base
            copy_n(other.base_.get(), other.size_, newbase.base_.get() + size_);

            // Initialize CRT data
            if (!newbase.initialize())
            {
                throw logic_error("cannot extend by given base");
            }

            return newbase;
        }

        RNSBase RNSBase::drop() const
        {
            if (size_ == 1)
            {
                throw std::logic_error("cannot drop from base of size 1");
            }

            // Copy over this base
            RNSBase newbase(pool_);
            newbase.size_ = size_ - 1;
            newbase.base_ = allocate<Modulus>(newbase.size_, newbase.pool_);
            copy_n(base_.get(), size_ - 1, newbase.base_.get());

            // Initialize CRT data
            newbase.initialize();

            return newbase;
        }

        RNSBase RNSBase::drop(Modulus value) const
        {
            if (size_ == 1)
            {
                throw std::logic_error("cannot drop from base of size 1");
            }
            if (!contains(value))
            {
                throw logic_error("base does not contain value");
            }

            // Copy over this base
            RNSBase newbase(pool_);
            newbase.size_ = size_ - 1;
            newbase.base_ = allocate<Modulus>(newbase.size_, newbase.pool_);
            size_t source_index = 0;
            size_t dest_index = 0;
            while (dest_index < size_ - 1)
            {
                if (base_[source_index] != value)
                {
                    newbase.base_[dest_index] = base_[source_index];
                    dest_index++;
                }
                source_index++;
            }

            // Initialize CRT data
            newbase.initialize();

            return newbase;
        }

        bool RNSBase::initialize()
        {
            // Verify that the size is not too large
            if (!product_fits_in(size_, size_))
            {
                return false;
            }

            base_prod_ = allocate_uint(size_, pool_);
            punctured_prod_array_ = allocate_zero_uint(size_ * size_, pool_);
            inv_punctured_prod_mod_base_array_ = allocate_uint(size_, pool_);

            if (size_ > 1)
            {
                auto rnsbase_values = allocate<uint64_t>(size_, pool_);
                SEAL_ITERATE(iter(base_, rnsbase_values), size_, [&](auto I) { get<1>(I) = get<0>(I).value(); });

                // Create punctured products
                // Semantic misuse of RNSIter
                RNSIter punctured_prod(punctured_prod_array_.get(), size_);
                SEAL_ITERATE(iter(punctured_prod, size_t(0)), size_, [&](auto I) {
                    multiply_many_uint64_except(rnsbase_values.get(), size_, get<1>(I), get<0>(I).ptr(), pool_);
                });

                // Compute the full product
                auto temp_mpi(allocate_uint(size_, pool_));
                multiply_uint(punctured_prod_array_.get(), size_, base_[0].value(), size_, temp_mpi.get());
                set_uint(temp_mpi.get(), size_, base_prod_.get());

                // Compute inverses of punctured products mod primes
                bool invertible = true;
                SEAL_ITERATE(iter(punctured_prod, base_, inv_punctured_prod_mod_base_array_), size_, [&](auto I) {
                    get<2>(I) = modulo_uint(get<0>(I), size_, get<1>(I));
                    invertible = invertible && try_invert_uint_mod(get<2>(I), get<1>(I), get<2>(I));
                });

                return invertible;
            }

            // Case of a single prime
            base_prod_[0] = base_[0].value();
            punctured_prod_array_[0] = 1;
            inv_punctured_prod_mod_base_array_[0] = 1;

            return true;
        }

        void RNSBase::decompose(uint64_t *value, MemoryPoolHandle pool) const
        {
            if (!value)
            {
                throw invalid_argument("value cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }

            if (size_ > 1)
            {
                // Copy the value
                auto value_copy(allocate_uint(size_, pool));
                set_uint(value, size_, value_copy.get());

                SEAL_ITERATE(iter(value, base_), size_, [&](auto I) {
                    get<0>(I) = modulo_uint(value_copy.get(), size_, get<1>(I));
                });
            }
        }

        void RNSBase::decompose_array(uint64_t *value, size_t count, MemoryPoolHandle pool) const
        {
            if (!value)
            {
                throw invalid_argument("value cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }

            if (size_ > 1)
            {
                if (!product_fits_in(count, size_))
                {
                    throw logic_error("invalid parameters");
                }

                // Decompose an array of multi-precision integers into an array of arrays, one per each base element

                // Copy the input array
                // Semantic misuse of RNSIter
                SEAL_ALLOCATE_GET_RNS_ITER(value_copy, size_, count, pool);
                set_uint(value, count * size_, value_copy);

                // Note how value_copy and value_out have size_ and count reversed
                RNSIter value_out(value, count);

                // For each output RNS array (one per base element) ...
                SEAL_ITERATE(iter(base_, value_out), size_, [&](auto I) {
                    // For each multi-precision integer in value_copy ...
                    SEAL_ITERATE(iter(get<1>(I), value_copy), count, [&](auto J) {
                        // Reduce the multi-precision integer modulo the base element and write to value_out
                        get<0>(J) = modulo_uint(get<1>(J), size_, get<0>(I));
                    });
                });
            }
        }

        void RNSBase::compose(uint64_t *value, MemoryPoolHandle pool) const
        {
            if (!value)
            {
                throw invalid_argument("value cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }

            if (size_ > 1)
            {
                // Copy the value
                auto temp_value(allocate_uint(size_, pool));
                set_uint(value, size_, temp_value.get());

                // Clear the result
                set_zero_uint(size_, value);

                // Semantic misuse of RNSIter
                RNSIter punctured_prod(punctured_prod_array_.get(), size_);

                // Compose an array of integers (one per base element) into a single multi-precision integer
                auto temp_mpi(allocate_uint(size_, pool));
                SEAL_ITERATE(
                    iter(temp_value, inv_punctured_prod_mod_base_array_, punctured_prod, base_), size_, [&](auto I) {
                        uint64_t temp_prod = multiply_uint_mod(get<0>(I), get<1>(I), get<3>(I));
                        multiply_uint(get<2>(I), size_, temp_prod, size_, temp_mpi.get());
                        add_uint_uint_mod(temp_mpi.get(), value, base_prod_.get(), size_, value);
                    });
            }
        }

        void RNSBase::compose_array(uint64_t *value, size_t count, MemoryPoolHandle pool) const
        {
            if (!value)
            {
                throw invalid_argument("value cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }

            if (size_ > 1)
            {
                if (!product_fits_in(count, size_))
                {
                    throw logic_error("invalid parameters");
                }

                // Merge the coefficients first
                auto temp_array(allocate_uint(count * size_, pool));
                for (size_t i = 0; i < count; i++)
                {
                    for (size_t j = 0; j < size_; j++)
                    {
                        temp_array[j + (i * size_)] = value[(j * count) + i];
                    }
                }

                // Clear the result
                set_zero_uint(count * size_, value);

                // Semantic misuse of RNSIter
                RNSIter temp_array_iter(temp_array.get(), size_);
                RNSIter value_iter(value, size_);
                RNSIter punctured_prod(punctured_prod_array_.get(), size_);

                // Compose an array of RNS integers into a single array of multi-precision integers
                auto temp_mpi(allocate_uint(size_, pool));
                SEAL_ITERATE(iter(temp_array_iter, value_iter), count, [&](auto I) {
                    SEAL_ITERATE(
                        iter(get<0>(I), inv_punctured_prod_mod_base_array_, punctured_prod, base_), size_, [&](auto J) {
                            uint64_t temp_prod = multiply_uint_mod(get<0>(J), get<1>(J), get<3>(J));
                            multiply_uint(get<2>(J), size_, temp_prod, size_, temp_mpi.get());
                            add_uint_uint_mod(temp_mpi.get(), get<1>(I), base_prod_.get(), size_, get<1>(I));
                        });
                });
            }
        }

        void BaseConverter::fast_convert(const uint64_t *in, uint64_t *out, MemoryPoolHandle pool) const
        {
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();

            auto temp(allocate_uint(ibase_size, pool));
            for (size_t i = 0; i < ibase_size; i++)
            {
                temp[i] = multiply_uint_mod(in[i], ibase_.inv_punctured_prod_mod_base_array()[i], ibase_[i]);
            }

            for (size_t j = 0; j < obase_size; j++)
            {
                out[j] = dot_product_mod(temp.get(), base_change_matrix_[j].get(), ibase_size, obase_[j]);
            }
        }

        void BaseConverter::fast_convert_array(
            const uint64_t *in, size_t count, uint64_t *out, MemoryPoolHandle pool) const
        {
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();

            auto temp(allocate_poly(count, ibase_size, pool));
            for (size_t i = 0; i < ibase_size; i++)
            {
                uint64_t inv_ibase_punctured_prod_mod_ibase_elt = ibase_.inv_punctured_prod_mod_base_array()[i];
                Modulus ibase_elt = ibase_[i];
                uint64_t *temp_ptr = temp.get() + i;
                for (size_t k = 0; k < count; k++, in++, temp_ptr += ibase_size)
                {
                    *temp_ptr = multiply_uint_mod(*in, inv_ibase_punctured_prod_mod_ibase_elt, ibase_elt);
                }
            }

            for (size_t j = 0; j < obase_size; j++)
            {
                uint64_t *temp_ptr = temp.get();
                Modulus obase_elt = obase_[j];
                for (size_t k = 0; k < count; k++, out++, temp_ptr += ibase_size)
                {
                    *out = dot_product_mod(temp_ptr, base_change_matrix_[j].get(), ibase_size, obase_elt);
                }
            }
        }

        void BaseConverter::initialize()
        {
            // Verify that the size is not too large
            if (!product_fits_in(ibase_.size(), obase_.size()))
            {
                throw logic_error("invalid parameters");
            }

            auto ibase_values = allocate<uint64_t>(ibase_.size(), pool_);
            for (size_t i = 0; i < ibase_.size(); i++)
            {
                ibase_values[i] = ibase_[i].value();
            }

            // Compute the base-change matrix
            base_change_matrix_ = allocate<Pointer<uint64_t>>(obase_.size(), pool_);
            for (size_t i = 0; i < obase_.size(); i++)
            {
                base_change_matrix_[i] = allocate_uint(ibase_.size(), pool_);
                for (size_t j = 0; j < ibase_.size(); j++)
                {
                    base_change_matrix_[i][j] =
                        modulo_uint(ibase_.punctured_prod_array() + (j * ibase_.size()), ibase_.size(), obase_[i]);
                }
            }
        }

        RNSTool::RNSTool(
            size_t poly_modulus_degree, const RNSBase &coeff_modulus, const Modulus &plain_modulus,
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

        void RNSTool::initialize(size_t poly_modulus_degree, const RNSBase &q, const Modulus &t)
        {
            // Return if q is out of bounds
            if (q.size() < SEAL_COEFF_MOD_COUNT_MIN || q.size() > SEAL_COEFF_MOD_COUNT_MAX)
            {
                throw invalid_argument("rnsbase is invalid");
            }

            // Return if coeff_count is not a power of two or out of bounds
            int coeff_count_power = get_power_of_two(poly_modulus_degree);
            if (coeff_count_power < 0 || poly_modulus_degree > SEAL_POLY_MOD_DEGREE_MAX ||
                poly_modulus_degree < SEAL_POLY_MOD_DEGREE_MIN)
            {
                throw invalid_argument("poly_modulus_degree is invalid");
            }

            t_ = t;
            coeff_count_ = poly_modulus_degree;

            // Allocate memory for the bases q, B, Bsk, Bsk U m_tilde, t_gamma
            size_t base_q_size = q.size();

            // In some cases we might need to increase the size of the base B by one, namely we require
            // K * n * t * q^2 < q * prod(B) * m_sk, where K takes into account cross terms when larger size ciphertexts
            // are used, and n is the "delta factor" for the ring. We reserve 32 bits for K * n. Here the coeff modulus
            // primes q_i are bounded to be SEAL_USER_MOD_BIT_COUNT_MAX (60) bits, and all primes in B and m_sk are
            // SEAL_INTERNAL_MOD_BIT_COUNT (61) bits.
            int total_coeff_bit_count = get_significant_bit_count_uint(q.base_prod(), q.size());

            size_t base_B_size = base_q_size;
            if (32 + t_.bit_count() + total_coeff_bit_count >=
                SEAL_INTERNAL_MOD_BIT_COUNT * safe_cast<int>(base_q_size) + SEAL_INTERNAL_MOD_BIT_COUNT)
            {
                base_B_size++;
            }

            size_t base_Bsk_size = add_safe(base_B_size, size_t(1));
            size_t base_Bsk_m_tilde_size = add_safe(base_Bsk_size, size_t(1));

            size_t base_t_gamma_size = 0;

            // Size check
            if (!product_fits_in(coeff_count_, base_Bsk_m_tilde_size))
            {
                throw logic_error("invalid parameters");
            }

            // Sample primes for B and two more primes: m_sk and gamma
            auto baseconv_primes = get_primes(coeff_count_, SEAL_USER_MOD_BIT_COUNT_MAX + 1, base_Bsk_m_tilde_size);
            auto baseconv_primes_iter = baseconv_primes.cbegin();
            m_sk_ = *baseconv_primes_iter++;
            gamma_ = *baseconv_primes_iter++;
            vector<Modulus> base_B_primes;
            copy_n(baseconv_primes_iter, base_B_size, back_inserter(base_B_primes));

            // Set m_tilde_ to a non-prime value
            m_tilde_ = uint64_t(1) << 32;

            // Populate the base arrays
            base_q_ = allocate<RNSBase>(pool_, q, pool_);
            base_B_ = allocate<RNSBase>(pool_, base_B_primes, pool_);
            base_Bsk_ = allocate<RNSBase>(pool_, base_B_->extend(m_sk_));
            base_Bsk_m_tilde_ = allocate<RNSBase>(pool_, base_Bsk_->extend(m_tilde_));

            // Set up t-gamma base if t_ is non-zero (using BFV)
            if (!t_.is_zero())
            {
                base_t_gamma_size = 2;
                base_t_gamma_ = allocate<RNSBase>(pool_, vector<Modulus>{ t_, gamma_ }, pool_);
            }

            // Generate the Bsk NTTTables; these are used for NTT after base extension to Bsk
            try
            {
                CreateNTTTables(
                    coeff_count_power, vector<Modulus>(base_Bsk_->base(), base_Bsk_->base() + base_Bsk_size),
                    base_Bsk_ntt_tables_, pool_);
            }
            catch (const logic_error &)
            {
                throw logic_error("invalid rns bases");
            }

            // Set up BaseConvTool for q --> Bsk
            base_q_to_Bsk_conv_ = allocate<BaseConverter>(pool_, *base_q_, *base_Bsk_, pool_);

            // Set up BaseConvTool for q --> {m_tilde}
            base_q_to_m_tilde_conv_ = allocate<BaseConverter>(pool_, *base_q_, RNSBase({ m_tilde_ }, pool_), pool_);

            // Set up BaseConvTool for B --> q
            base_B_to_q_conv_ = allocate<BaseConverter>(pool_, *base_B_, *base_q_, pool_);

            // Set up BaseConvTool for B --> {m_sk}
            base_B_to_m_sk_conv_ = allocate<BaseConverter>(pool_, *base_B_, RNSBase({ m_sk_ }, pool_), pool_);

            if (base_t_gamma_)
            {
                // Set up BaseConvTool for q --> {t, gamma}
                base_q_to_t_gamma_conv_ = allocate<BaseConverter>(pool_, *base_q_, *base_t_gamma_, pool_);
            }

            // Compute prod(B) mod q
            prod_B_mod_q_ = allocate_uint(base_q_size, pool_);
            for (size_t i = 0; i < base_q_size; i++)
            {
                prod_B_mod_q_[i] = modulo_uint(base_B_->base_prod(), base_B_size, (*base_q_)[i]);
            }

            // Compute prod(q)^(-1) mod Bsk
            inv_prod_q_mod_Bsk_ = allocate_uint(base_Bsk_size, pool_);
            for (size_t i = 0; i < base_Bsk_size; i++)
            {
                inv_prod_q_mod_Bsk_[i] = modulo_uint(base_q_->base_prod(), base_q_size, (*base_Bsk_)[i]);
                if (!try_invert_uint_mod(inv_prod_q_mod_Bsk_[i], (*base_Bsk_)[i], inv_prod_q_mod_Bsk_[i]))
                {
                    throw logic_error("invalid rns bases");
                }
            }

            // Compute prod(B)^(-1) mod m_sk
            inv_prod_B_mod_m_sk_ = modulo_uint(base_B_->base_prod(), base_B_size, m_sk_);
            if (!try_invert_uint_mod(inv_prod_B_mod_m_sk_, m_sk_, inv_prod_B_mod_m_sk_))
            {
                throw logic_error("invalid rns bases");
            }

            // Compute m_tilde^(-1) mod Bsk
            inv_m_tilde_mod_Bsk_ = allocate_uint(base_Bsk_size, pool_);
            for (size_t i = 0; i < base_Bsk_size; i++)
            {
                if (!try_invert_uint_mod(
                        m_tilde_.value() % (*base_Bsk_)[i].value(), (*base_Bsk_)[i], inv_m_tilde_mod_Bsk_[i]))
                {
                    throw logic_error("invalid rns bases");
                }
            }

            // Compute prod(q)^(-1) mod m_tilde
            inv_prod_q_mod_m_tilde_ = modulo_uint(base_q_->base_prod(), base_q_size, m_tilde_);
            if (!try_invert_uint_mod(inv_prod_q_mod_m_tilde_, m_tilde_, inv_prod_q_mod_m_tilde_))
            {
                throw logic_error("invalid rns bases");
            }

            // Compute prod(q) mod Bsk
            prod_q_mod_Bsk_ = allocate_uint(base_Bsk_size, pool_);
            for (size_t i = 0; i < base_Bsk_size; i++)
            {
                prod_q_mod_Bsk_[i] = modulo_uint(base_q_->base_prod(), base_q_size, (*base_Bsk_)[i]);
            }

            if (base_t_gamma_)
            {
                // Compute gamma^(-1) mod t
                if (!try_invert_uint_mod(gamma_.value() % t_.value(), t_, inv_gamma_mod_t_))
                {
                    throw logic_error("invalid rns bases");
                }

                // Compute prod({t, gamma}) mod q
                prod_t_gamma_mod_q_ = allocate_uint(base_q_size, pool_);
                for (size_t i = 0; i < base_q_size; i++)
                {
                    prod_t_gamma_mod_q_[i] =
                        multiply_uint_mod((*base_t_gamma_)[0].value(), (*base_t_gamma_)[1].value(), (*base_q_)[i]);
                }

                // Compute -prod(q)^(-1) mod {t, gamma}
                neg_inv_q_mod_t_gamma_ = allocate_uint(base_t_gamma_size, pool_);
                for (size_t i = 0; i < base_t_gamma_size; i++)
                {
                    neg_inv_q_mod_t_gamma_[i] = modulo_uint(base_q_->base_prod(), base_q_size, (*base_t_gamma_)[i]);
                    if (!try_invert_uint_mod(neg_inv_q_mod_t_gamma_[i], (*base_t_gamma_)[i], neg_inv_q_mod_t_gamma_[i]))
                    {
                        throw logic_error("invalid rns bases");
                    }
                    neg_inv_q_mod_t_gamma_[i] = negate_uint_mod(neg_inv_q_mod_t_gamma_[i], (*base_t_gamma_)[i]);
                }
            }

            // Compute q[last]^(-1) mod q[i] for i = 0..last-1
            // This is used by modulus switching and rescaling
            inv_q_last_mod_q_ = allocate_uint(base_q_size - 1, pool_);
            for (size_t i = 0; i < base_q_size - 1; i++)
            {
                if (!try_invert_uint_mod((*base_q_)[base_q_size - 1].value(), (*base_q_)[i], inv_q_last_mod_q_[i]))
                {
                    throw logic_error("invalid rns bases");
                }
            }
        }

        void RNSTool::divide_and_round_q_last_inplace(uint64_t *input, MemoryPoolHandle pool) const
        {
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
            auto base_q_size = base_q_->size();
            uint64_t *last_ptr = input + (base_q_size - 1) * coeff_count_;

            // Add (qi-1)/2 to change from flooring to rounding
            Modulus last_modulus = (*base_q_)[base_q_size - 1];
            uint64_t half = last_modulus.value() >> 1;
            for (size_t j = 0; j < coeff_count_; j++)
            {
                last_ptr[j] = barrett_reduce_63(last_ptr[j] + half, last_modulus);
            }

            auto temp(allocate_uint(coeff_count_, pool));
            uint64_t *temp_ptr = temp.get();
            for (size_t i = 0; i < base_q_size - 1; i++)
            {
                // (ct mod qk) mod qi
                modulo_poly_coeffs_63(last_ptr, coeff_count_, (*base_q_)[i], temp_ptr);

                uint64_t half_mod = barrett_reduce_63(half, (*base_q_)[i]);
                for (size_t j = 0; j < coeff_count_; j++)
                {
                    temp_ptr[j] = sub_uint64_mod(temp_ptr[j], half_mod, (*base_q_)[i]);
                }

                sub_poly_coeffmod(
                    input + (i * coeff_count_), temp_ptr, coeff_count_, (*base_q_)[i], input + (i * coeff_count_));

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(
                    input + (i * coeff_count_), coeff_count_, inv_q_last_mod_q_[i], (*base_q_)[i],
                    input + (i * coeff_count_));
            }
        }

        void RNSTool::divide_and_round_q_last_ntt_inplace(
            uint64_t *input, const NTTTables *rns_ntt_tables, MemoryPoolHandle pool) const
        {
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
            auto base_q_size = base_q_->size();
            uint64_t *last_ptr = input + (base_q_size - 1) * coeff_count_;

            // Convert to non-NTT form
            inverse_ntt_negacyclic_harvey(last_ptr, rns_ntt_tables[base_q_size - 1]);

            // Add (qi-1)/2 to change from flooring to rounding
            Modulus last_modulus = (*base_q_)[base_q_size - 1];
            uint64_t half = last_modulus.value() >> 1;
            for (size_t j = 0; j < coeff_count_; j++)
            {
                last_ptr[j] = barrett_reduce_63(last_ptr[j] + half, last_modulus);
            }

            auto temp(allocate_uint(coeff_count_, pool));
            uint64_t *temp_ptr = temp.get();
            for (size_t i = 0; i < base_q_size - 1; i++)
            {
                const uint64_t qi = (*base_q_)[i].value();
                // (ct mod qk) mod qi
                if (qi < last_modulus.value())
                {
                    modulo_poly_coeffs_63(last_ptr, coeff_count_, (*base_q_)[i], temp_ptr);
                }
                else
                {
                    set_uint(last_ptr, coeff_count_, temp_ptr);
                }

                // lazy subtraction here. ntt_negacyclic_harvey_lazy can take 0 < x < 4*qi input.
                const uint64_t neg_half_mod = qi - barrett_reduce_63(half, (*base_q_)[i]);
                std::transform(temp_ptr, temp_ptr + coeff_count_, temp_ptr, [neg_half_mod](uint64_t u) {
                    return u + neg_half_mod;
                });
#if SEAL_USER_MOD_BIT_COUNT_MAX <= 60
                // Since now SEAL use at most 60bit moduli, so 8*qi < 2^63.
                // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
                const uint64_t qi_lazy = qi << 2;
                ntt_negacyclic_harvey_lazy(temp_ptr, rns_ntt_tables[i]);
#else
                // 2^60 < pi < 2^62, then 4*pi < 2^64, we perfrom one reduction from [0, 4*qi) to [0, 2*qi) after ntt.
                const uint64_t qi_lazy = qi << 1;
                ntt_negacyclic_harvey_lazy(temp_ptr, rns_ntt_tables[i]);
                std::transform(temp_ptr, temp_ptr + coeff_count_, temp_ptr, [qi_lazy](uint64_t u) {
                    return u -= (qi_lazy & static_cast<uint64_t>(-static_cast<int64_t>(u >= qi_lazy)));
                });
#endif
                // Lazy subtraction again, results in [0, 2*qi_lazy),
                // The reduction [0, 2*qi_lazy) -> [0, qi) is done implicitly in multiply_poly_scalar_coeffmod.
                std::transform(input, input + coeff_count_, temp_ptr, input, [qi_lazy](uint64_t u, uint64_t v) {
                    return u + qi_lazy - v;
                });

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(input, coeff_count_, inv_q_last_mod_q_[i], (*base_q_)[i], input);
                input += coeff_count_;
            }
        }

        void RNSTool::fastbconv_sk(const uint64_t *input, uint64_t *destination, MemoryPoolHandle pool) const
        {
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

            auto base_q_size = base_q_->size();
            auto base_B_size = base_B_->size();

            // Fast convert B -> q; input is in Bsk but we only use B
            base_B_to_q_conv_->fast_convert_array(input, coeff_count_, destination, pool);

            // Compute alpha_sk
            // Fast convert B -> {m_sk}; input is in Bsk but we only use B
            auto temp(allocate_uint(coeff_count_, pool));
            base_B_to_m_sk_conv_->fast_convert_array(input, coeff_count_, temp.get(), pool);

            // Take the m_sk part of input, subtract from temp, and multiply by inv_prod_B_mod_m_sk_
            // input_sk is allocated in input + (base_B_size * coeff_count_)
            const uint64_t *input_ptr = input + (base_B_size * coeff_count_);
            auto alpha_sk(allocate_uint(coeff_count_, pool));
            uint64_t *alpha_sk_ptr = alpha_sk.get();
            uint64_t *temp_ptr = temp.get();
            const uint64_t m_sk_value = m_sk_.value();
            for (size_t i = 0; i < coeff_count_; i++)
            {
                // It is not necessary for the negation to be reduced modulo the small prime
                alpha_sk_ptr[i] =
                    multiply_uint_mod(temp_ptr[i] + (m_sk_value - input_ptr[i]), inv_prod_B_mod_m_sk_, m_sk_);
            }

            // alpha_sk is now ready for the Shenoy-Kumaresan conversion; however, note that our
            // alpha_sk here is not a centered reduction, so we need to apply a correction below.
            const uint64_t m_sk_div_2 = m_sk_value >> 1;
            for (size_t i = 0; i < base_q_size; i++)
            {
                Modulus base_q_elt = (*base_q_)[i];
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

        void RNSTool::sm_mrq(const uint64_t *input, uint64_t *destination, MemoryPoolHandle pool) const
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
                throw invalid_argument("pool is uninitialized");
            }
#endif
            /*
            Require: Input in base Bsk U {m_tilde}
            Ensure: Output in base Bsk
            */

            auto base_Bsk_size = base_Bsk_->size();

            // The last component of the input is mod m_tilde
            const uint64_t *input_m_tilde_ptr = input + (coeff_count_ * base_Bsk_size);
            const uint64_t m_tilde_div_2 = m_tilde_.value() >> 1;

            // Compute r_m_tilde
            auto r_m_tilde(allocate_uint(coeff_count_, pool));
            for (size_t i = 0; i < coeff_count_; i++)
            {
                uint64_t temp = multiply_uint_mod(input_m_tilde_ptr[i], inv_prod_q_mod_m_tilde_, m_tilde_);
                r_m_tilde[i] = negate_uint_mod(temp, m_tilde_);
            }

            for (size_t k = 0; k < base_Bsk_size; k++)
            {
                Modulus base_Bsk_elt = (*base_Bsk_)[k];
                uint64_t inv_m_tilde_mod_Bsk_elt = inv_m_tilde_mod_Bsk_[k];
                uint64_t prod_q_mod_Bsk_elt = prod_q_mod_Bsk_[k];
                for (size_t i = 0; i < coeff_count_; i++, destination++, input++)
                {
                    // We need centered reduction of r_m_tilde modulo Bsk. Note that m_tilde is chosen
                    // to be a power of two so we have '>=' below.
                    uint64_t temp = r_m_tilde[i];
                    if (temp >= m_tilde_div_2)
                    {
                        temp += base_Bsk_elt.value() - m_tilde_.value();
                    }

                    // Compute (input + q*r_m_tilde)*m_tilde^(-1) mod Bsk
                    *destination = multiply_uint_mod(
                        multiply_add_uint_mod(prod_q_mod_Bsk_elt, temp, *input, base_Bsk_elt), inv_m_tilde_mod_Bsk_elt,
                        base_Bsk_elt);
                }
            }
        }

        void RNSTool::fast_floor(const uint64_t *input, uint64_t *destination, MemoryPoolHandle pool) const
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
                throw invalid_argument("pool is uninitialized");
            }
#endif
            /*
            Require: Input in base q U Bsk
            Ensure: Output in base Bsk
            */

            auto base_q_size = base_q_->size();
            auto base_Bsk_size = base_Bsk_->size();

            // Convert q -> Bsk
            base_q_to_Bsk_conv_->fast_convert_array(input, coeff_count_, destination, pool);

            // Move input pointer to past the base q components
            input += base_q_size * coeff_count_;
            for (size_t i = 0; i < base_Bsk_size; i++)
            {
                Modulus base_Bsk_elt = (*base_Bsk_)[i];
                uint64_t inv_prod_q_mod_Bsk_elt = inv_prod_q_mod_Bsk_[i];
                for (size_t k = 0; k < coeff_count_; k++, input++, destination++)
                {
                    // It is not necessary for the negation to be reduced modulo base_Bsk_elt
                    *destination = multiply_uint_mod(
                        *input + (base_Bsk_elt.value() - *destination), inv_prod_q_mod_Bsk_elt, base_Bsk_elt);
                }
            }
        }

        void RNSTool::fastbconv_m_tilde(const uint64_t *input, uint64_t *destination, MemoryPoolHandle pool) const
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
                throw invalid_argument("pool is uninitialized");
            }
#endif
            /*
            Require: Input in q
            Ensure: Output in Bsk U {m_tilde}
            */

            auto base_q_size = base_q_->size();
            auto base_Bsk_size = base_Bsk_->size();

            // We need to multiply first the input with m_tilde mod q
            // This is to facilitate Montgomery reduction in the next step of multiplication
            // This is NOT an ideal approach: as mentioned in BEHZ16, multiplication by
            // m_tilde can be easily merge into the base conversion operation; however, then
            // we could not use the BaseConvTool as below without modifications.
            auto temp(allocate_poly(coeff_count_, base_q_size, pool));
            for (size_t i = 0; i < base_q_size; i++)
            {
                multiply_poly_scalar_coeffmod(
                    input + (i * coeff_count_), coeff_count_, m_tilde_.value(), (*base_q_)[i],
                    temp.get() + (i * coeff_count_));
            }

            // Now convert to Bsk
            base_q_to_Bsk_conv_->fast_convert_array(temp.get(), coeff_count_, destination, pool);

            // Finally convert to {m_tilde}
            base_q_to_m_tilde_conv_->fast_convert_array(
                temp.get(), coeff_count_, destination + (base_Bsk_size * coeff_count_), pool);
        }

        void RNSTool::decrypt_scale_and_round(const uint64_t *input, uint64_t *destination, MemoryPoolHandle pool) const
        {
            auto base_q_size = base_q_->size();
            auto base_t_gamma_size = base_t_gamma_->size();

            // Compute |gamma * t|_qi * ct(s)
            auto temp(allocate_poly(coeff_count_, base_q_size, pool));
            for (size_t i = 0; i < base_q_size; i++)
            {
                multiply_poly_scalar_coeffmod(
                    input + (i * coeff_count_), coeff_count_, prod_t_gamma_mod_q_[i], (*base_q_)[i],
                    temp.get() + (i * coeff_count_));
            }

            // Make another temp destination to get the poly in mod {t, gamma}
            auto temp_t_gamma(allocate_poly(coeff_count_, base_t_gamma_size, pool));

            // Convert from q to {t, gamma}
            base_q_to_t_gamma_conv_->fast_convert_array(temp.get(), coeff_count_, temp_t_gamma.get(), pool);

            // Multiply by -prod(q)^(-1) mod {t, gamma}
            for (size_t i = 0; i < base_t_gamma_size; i++)
            {
                multiply_poly_scalar_coeffmod(
                    temp_t_gamma.get() + (i * coeff_count_), coeff_count_, neg_inv_q_mod_t_gamma_[i],
                    (*base_t_gamma_)[i], temp_t_gamma.get() + (i * coeff_count_));
            }

            // Need to correct values in temp_t_gamma (gamma component only) which are
            // larger than floor(gamma/2)
            uint64_t gamma_div_2 = (*base_t_gamma_)[1].value() >> 1;

            // Now compute the subtraction to remove error and perform final multiplication by
            // gamma inverse mod t
            for (size_t i = 0; i < coeff_count_; i++)
            {
                // Need correction because of centered mod
                if (temp_t_gamma[i + coeff_count_] > gamma_div_2)
                {
                    // Compute -(gamma - a) instead of (a - gamma)
                    destination[i] = add_uint64_mod(
                        temp_t_gamma[i], (gamma_.value() - temp_t_gamma[i + coeff_count_]) % t_.value(), t_);
                }
                // No correction needed
                else
                {
                    destination[i] = sub_uint64_mod(temp_t_gamma[i], temp_t_gamma[i + coeff_count_] % t_.value(), t_);
                }

                // If this coefficient was non-zero, multiply by t^(-1)
                if (0 != destination[i])
                {
                    // Perform final multiplication by gamma inverse mod t
                    destination[i] = multiply_uint_mod(destination[i], inv_gamma_mod_t_, t_);
                }
            }
        }
    } // namespace util
} // namespace seal
