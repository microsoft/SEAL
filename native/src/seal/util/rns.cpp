// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/common.h"
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
            : pool_(std::move(pool)), size_(rnsbase.size())
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

        RNSBase::RNSBase(const RNSBase &copy, MemoryPoolHandle pool) : pool_(std::move(pool)), size_(copy.size_)
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

            inv_punctured_prod_mod_base_array_ = allocate<MultiplyUIntModOperand>(size_, pool_);
            copy_n(copy.inv_punctured_prod_mod_base_array_.get(), size_, inv_punctured_prod_mod_base_array_.get());
        }

        bool RNSBase::contains(const Modulus &value) const noexcept
        {
            bool result = false;
            SEAL_ITERATE(iter(base_), size_, [&](auto &I) { result = result || (I == value); });
            return result;
        }

        bool RNSBase::is_subbase_of(const RNSBase &superbase) const noexcept
        {
            bool result = true;
            SEAL_ITERATE(iter(base_), size_, [&](auto &I) { result = result && superbase.contains(I); });
            return result;
        }

        RNSBase RNSBase::extend(const Modulus &value) const
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
                for (size_t j = 0; j < size_; j++)
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
                throw logic_error("cannot drop from base of size 1");
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

        RNSBase RNSBase::drop(const Modulus &value) const
        {
            if (size_ == 1)
            {
                throw logic_error("cannot drop from base of size 1");
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
            inv_punctured_prod_mod_base_array_ = allocate<MultiplyUIntModOperand>(size_, pool_);

            if (size_ > 1)
            {
                auto rnsbase_values = allocate<uint64_t>(size_, pool_);
                SEAL_ITERATE(iter(base_, rnsbase_values), size_, [&](auto I) { get<1>(I) = get<0>(I).value(); });

                // Create punctured products
                StrideIter<uint64_t *> punctured_prod(punctured_prod_array_.get(), size_);
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
                    uint64_t temp = modulo_uint(get<0>(I), size_, get<1>(I));
                    invertible = invertible && try_invert_uint_mod(temp, get<1>(I), temp);
                    get<2>(I).set(temp, get<1>(I));
                });

                return invertible;
            }

            // Case of a single prime
            base_prod_[0] = base_[0].value();
            punctured_prod_array_[0] = 1;
            inv_punctured_prod_mod_base_array_[0].set(1, base_[0]);

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

                // Copy the input array into a temporary location and set a StrideIter pointing to it
                // Note that the stride size is size_
                SEAL_ALLOCATE_GET_STRIDE_ITER(value_copy, uint64_t, count, size_, pool);
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

                StrideIter<uint64_t *> punctured_prod(punctured_prod_array_.get(), size_);

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

                StrideIter<uint64_t *> temp_array_iter(temp_array.get(), size_);
                StrideIter<uint64_t *> value_iter(value, size_);
                StrideIter<uint64_t *> punctured_prod(punctured_prod_array_.get(), size_);

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

        // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to
        // ensure symbol is created.
        SEAL_CONSTEXPR_MEMBER_DEF constexpr size_t BaseConverter::max_block_size;

        void BaseConverter::fast_convert(ConstCoeffIter in, CoeffIter out, MemoryPoolHandle pool) const
        {
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();

            SEAL_ALLOCATE_GET_COEFF_ITER(temp, ibase_size, pool);
            SEAL_ITERATE(iter(temp, in, scaled_inv_punctured_prod_.get(), ibase_.base()), ibase_size, [&](auto I) {
                get<0>(I) = multiply_uint_mod(get<1>(I), get<2>(I), get<3>(I));
            });

            // for (size_t j = 0; j < obase_size; j++)
            SEAL_ITERATE(iter(out, base_change_matrix_, obase_.base()), obase_size, [&](auto I) {
                get<0>(I) = dot_product_mod(temp, get<1>(I).get(), ibase_size, get<2>(I));
            });
        }

        namespace
        {
            // Computes the first step of a fast base conversion for one input component: dst[c] = [src[c] * ipp]_{q_i}
            // for c in [0, count), with only a reduction if ipp is 1
            void base_convert_first_step(
                const uint64_t *src, size_t count, const MultiplyUIntModOperand ipp, const Modulus &qi, uint64_t *dst)
            {
                if (ipp.operand == 1)
                {
                    for (size_t c = 0; c < count; c++)
                    {
                        dst[c] = barrett_reduce_64(src[c], qi);
                    }
                }
                else
                {
                    for (size_t c = 0; c < count; c++)
                    {
                        dst[c] = multiply_uint_mod(src[c], ipp, qi);
                    }
                }
            }

            // For c in [0, count), computes sum_{i in [ib_begin, ib_end)} rows[i * stride + c] * row[i] mod p, reducing
            // the 128-bit sum with Montgomery reduction (Montgomery) or Barrett reduction, and stores it to dst[c] or,
            // if Accumulate, adds it to dst[c] modulo p. Each sum must be less than p * 2^64.
            template <bool Montgomery, bool Accumulate>
            void base_convert_block_row(
                const uint64_t *rows, size_t stride, size_t count, size_t ib_begin, size_t ib_end, const uint64_t *row,
                const Modulus &modulus, uint64_t neg_inv_p, uint64_t *dst)
            {
                const uint64_t p = modulus.value();
                auto reduce = [&](uint64_t lo, uint64_t hi) -> uint64_t {
                    SEAL_IF_CONSTEXPR(Montgomery)
                    {
                        return montgomery_reduce_128(lo, hi, p, neg_inv_p);
                    }
                    else
                    {
                        unsigned long long z[2]{ lo, hi };
                        return barrett_reduce_128(z, modulus);
                    }
                };
                auto store = [&](uint64_t *d, uint64_t value) {
                    SEAL_IF_CONSTEXPR(Accumulate)
                    {
                        *d = sub_if_ge_uint64(value + *d, p);
                    }
                    else
                    {
                        *d = value;
                    }
                };

                size_t c = 0;
#ifdef SEAL_USE___INT128
                // Independent accumulators hide the add-with-carry latency
                for (; c + 8 <= count; c += 8)
                {
                    uint128_t a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0, a7 = 0;
                    const uint64_t *t = rows + ib_begin * stride + c;
                    for (size_t i = ib_begin; i < ib_end; i++, t += stride)
                    {
                        const uint128_t w = row[i];
                        a0 += w * t[0];
                        a1 += w * t[1];
                        a2 += w * t[2];
                        a3 += w * t[3];
                        a4 += w * t[4];
                        a5 += w * t[5];
                        a6 += w * t[6];
                        a7 += w * t[7];
                    }
                    store(dst + c, reduce(static_cast<uint64_t>(a0), static_cast<uint64_t>(a0 >> 64)));
                    store(dst + c + 1, reduce(static_cast<uint64_t>(a1), static_cast<uint64_t>(a1 >> 64)));
                    store(dst + c + 2, reduce(static_cast<uint64_t>(a2), static_cast<uint64_t>(a2 >> 64)));
                    store(dst + c + 3, reduce(static_cast<uint64_t>(a3), static_cast<uint64_t>(a3 >> 64)));
                    store(dst + c + 4, reduce(static_cast<uint64_t>(a4), static_cast<uint64_t>(a4 >> 64)));
                    store(dst + c + 5, reduce(static_cast<uint64_t>(a5), static_cast<uint64_t>(a5 >> 64)));
                    store(dst + c + 6, reduce(static_cast<uint64_t>(a6), static_cast<uint64_t>(a6 >> 64)));
                    store(dst + c + 7, reduce(static_cast<uint64_t>(a7), static_cast<uint64_t>(a7 >> 64)));
                }
                for (; c + 4 <= count; c += 4)
                {
                    uint128_t a0 = 0, a1 = 0, a2 = 0, a3 = 0;
                    const uint64_t *t = rows + ib_begin * stride + c;
                    for (size_t i = ib_begin; i < ib_end; i++, t += stride)
                    {
                        const uint128_t w = row[i];
                        a0 += w * t[0];
                        a1 += w * t[1];
                        a2 += w * t[2];
                        a3 += w * t[3];
                    }
                    store(dst + c, reduce(static_cast<uint64_t>(a0), static_cast<uint64_t>(a0 >> 64)));
                    store(dst + c + 1, reduce(static_cast<uint64_t>(a1), static_cast<uint64_t>(a1 >> 64)));
                    store(dst + c + 2, reduce(static_cast<uint64_t>(a2), static_cast<uint64_t>(a2 >> 64)));
                    store(dst + c + 3, reduce(static_cast<uint64_t>(a3), static_cast<uint64_t>(a3 >> 64)));
                }
#endif
                for (; c < count; c++)
                {
                    unsigned long long acc[2]{ 0, 0 };
                    const uint64_t *t = rows + ib_begin * stride + c;
                    for (size_t i = ib_begin; i < ib_end; i++, t += stride)
                    {
                        unsigned long long prod[2];
                        multiply_uint64(*t, row[i], prod);
                        add_uint128(prod, acc, acc);
                    }
                    store(dst + c, reduce(acc[0], acc[1]));
                }
            }

            // For c in [0, count), computes dst[c] = sum_i rows[i * stride + c] * row[i] mod p, one chunk of the input
            // base at a time (chunk_ends holds the end index of each chunk). neg_inv_p is -p^(-1) mod 2^64 if row is in
            // Montgomery form, and 0 otherwise.
            void base_convert_row(
                const uint64_t *rows, size_t stride, size_t count, const vector<size_t> &chunk_ends,
                const uint64_t *row, const Modulus &p, uint64_t neg_inv_p, uint64_t *dst)
            {
                size_t ib_begin = 0;
                for (size_t chunk = 0; chunk < chunk_ends.size(); chunk++)
                {
                    const size_t ib_end = chunk_ends[chunk];
                    if (neg_inv_p)
                    {
                        if (chunk)
                        {
                            base_convert_block_row<true, true>(
                                rows, stride, count, ib_begin, ib_end, row, p, neg_inv_p, dst);
                        }
                        else
                        {
                            base_convert_block_row<true, false>(
                                rows, stride, count, ib_begin, ib_end, row, p, neg_inv_p, dst);
                        }
                    }
                    else
                    {
                        if (chunk)
                        {
                            base_convert_block_row<false, true>(
                                rows, stride, count, ib_begin, ib_end, row, p, neg_inv_p, dst);
                        }
                        else
                        {
                            base_convert_block_row<false, false>(
                                rows, stride, count, ib_begin, ib_end, row, p, neg_inv_p, dst);
                        }
                    }
                    ib_begin = ib_end;
                }
            }
        } // namespace

        void BaseConverter::fast_convert_array(ConstRNSIter in, RNSIter out, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (in.poly_modulus_degree() != out.poly_modulus_degree())
            {
                throw invalid_argument("in and out are incompatible");
            }
#endif
            const size_t ibase_size = ibase_.size();
            const size_t count = in.poly_modulus_degree();

            // Converting a block of coefficients at a time keeps the first-step values in cache
            const size_t block_size = min(max_block_size, count);
            auto temp(allocate_uint(mul_safe(block_size, ibase_size), pool));
            for (size_t block_start = 0; block_start < count; block_start += block_size)
            {
                fast_convert_block(
                    in[0].ptr() + block_start, count, min(block_size, count - block_start), false,
                    out[0].ptr() + block_start, count, temp.get());
            }
        }

        void BaseConverter::fast_convert_block(
            const uint64_t *in, size_t in_stride, size_t count, bool input_reduced, uint64_t *out, size_t out_stride,
            uint64_t *temp) const
        {
            const size_t ibase_size = ibase_.size();
            const size_t obase_size = obase_.size();

            // Step 1: row i of temp holds [in_i * a_i * (q/q_i)^(-1)]_{q_i}. If all constants are 1 and the input is
            // reduced, this is the identity: a compact input block is then used as is, and otherwise its rows are only
            // copied into temp (reading many rows that are a large power of two apart in the dot products below would
            // cause cache conflicts).
            const uint64_t *rows = temp;
            if (input_reduced && unit_first_step_)
            {
                if (in_stride == count)
                {
                    rows = in;
                }
                else
                {
                    for (size_t i = 0; i < ibase_size; i++)
                    {
                        copy_n(in + i * in_stride, count, temp + i * count);
                    }
                }
            }
            else
            {
                for (size_t i = 0; i < ibase_size; i++)
                {
                    base_convert_first_step(
                        in + i * in_stride, count, scaled_inv_punctured_prod_[i], ibase_.base()[i], temp + i * count);
                }
            }

            // Step 2: out_j = sum_i temp_i * [b_j * (q/q_i)]_{p_j} mod p_j
            for (size_t j = 0; j < obase_size; j++)
            {
                base_convert_row(
                    rows, count, count, ibase_chunk_ends_, conv_matrix_.get() + j * ibase_size, obase_.base()[j],
                    obase_neg_inv_mod_2_64_[j], out + j * out_stride);
            }
        }

        // See "An Improved RNS Variant of the BFV Homomorphic Encryption Scheme" (CT-RSA 2019) for details
        void BaseConverter::exact_convert_array(ConstRNSIter in, CoeffIter out, MemoryPoolHandle pool) const
        {
            const size_t ibase_size = ibase_.size();
            const size_t obase_size = obase_.size();
            const size_t count = in.poly_modulus_degree();

            if (obase_size != 1)
            {
                throw invalid_argument("out base in exact_convert_array must be one.");
            }
            if (is_scaled_)
            {
                throw logic_error("exact_convert_array does not support scaling");
            }

            // Blocked as in fast_convert_array. For each coefficient, v is summed over i in increasing order, so its
            // rounding does not depend on the blocking.
            const size_t block_size = min(max_block_size, count);
            auto temp(allocate_uint(mul_safe(block_size, ibase_size), pool));
            auto v_acc(allocate<double_t>(block_size, pool));

            const Modulus *ibase_mods = ibase_.base();
            const MultiplyUIntModOperand *inv_punctured_prod = ibase_.inv_punctured_prod_mod_base_array();
            const Modulus &p = obase_.base()[0];

            // [q]_p for the correction term v * [q]_p
            MultiplyUIntModOperand q_mod_p;
            q_mod_p.set(modulo_uint(ibase_.base_prod(), ibase_size, p), p);

            for (size_t block_start = 0; block_start < count; block_start += block_size)
            {
                const size_t block_count = min(block_size, count - block_start);
                double_t *acc = v_acc.get();
                for (size_t c = 0; c < block_count; c++)
                {
                    acc[c] = 0.0;
                }

                // Calculate [x_{i} * \hat{q_{i}}]_{q_{i}} and accumulate v = sum_i [x_i * \hat{q_i}]_{q_i} / q_i
                for (size_t i = 0; i < ibase_size; i++)
                {
                    uint64_t *t = temp.get() + i * block_size;
                    base_convert_first_step(
                        in[i].ptr() + block_start, block_count, inv_punctured_prod[i], ibase_mods[i], t);
                    const double_t divisor = static_cast<double_t>(ibase_mods[i].value());
                    for (size_t c = 0; c < block_count; c++)
                    {
                        const double_t dividend = static_cast<double_t>(t[c]);
                        acc[c] += dividend / divisor;
                    }
                }

                // Sum modulo p (as in fast_convert_array)
                uint64_t *dst = out.ptr() + block_start;
                base_convert_row(
                    temp.get(), block_size, block_count, ibase_chunk_ends_, conv_matrix_.get(), p,
                    obase_neg_inv_mod_2_64_[0], dst);

                // Round v and subtract v * [q]_p mod p
                for (size_t c = 0; c < block_count; c++)
                {
                    const uint64_t aggregated_rounded_v = static_cast<uint64_t>(acc[c] + 0.5);
                    const uint64_t v_q_mod_p = multiply_uint_mod(aggregated_rounded_v, q_mod_p, p);
                    dst[c] = sub_uint_mod(dst[c], v_q_mod_p, p);
                }
            }
        }

        void BaseConverter::initialize(const uint64_t *ibase_scale, const uint64_t *obase_scale)
        {
            // Verify that the size is not too large
            if (!product_fits_in(ibase_.size(), obase_.size()))
            {
                throw logic_error("invalid parameters");
            }

            is_scaled_ = ibase_scale || obase_scale;

            // Inverse punctured products of the ibase, optionally multiplied by the input scaling factors
            scaled_inv_punctured_prod_ = allocate<MultiplyUIntModOperand>(ibase_.size(), pool_);
            SEAL_ITERATE(
                iter(scaled_inv_punctured_prod_, ibase_.inv_punctured_prod_mod_base_array(), ibase_.base(), size_t(0)),
                ibase_.size(), [&](auto I) {
                    get<0>(I) = get<1>(I);
                    if (ibase_scale)
                    {
                        uint64_t scale = barrett_reduce_64(ibase_scale[get<3>(I)], get<2>(I));
                        get<0>(I).set(multiply_uint_mod(scale, get<1>(I), get<2>(I)), get<2>(I));
                    }
                });
            unit_first_step_ = all_of(
                scaled_inv_punctured_prod_.get(), scaled_inv_punctured_prod_.get() + ibase_.size(),
                [](const MultiplyUIntModOperand &op) { return op.operand == 1; });

            // Create the base-change matrix rows
            base_change_matrix_ = allocate<Pointer<uint64_t>>(obase_.size(), pool_);

            SEAL_ITERATE(iter(base_change_matrix_, obase_.base(), size_t(0)), obase_.size(), [&](auto I) {
                // Create the base-change matrix columns
                get<0>(I) = allocate_uint(ibase_.size(), pool_);

                // Output scaling factor for this row (if any)
                MultiplyUIntModOperand scale;
                if (obase_scale)
                {
                    scale.set(barrett_reduce_64(obase_scale[get<2>(I)], get<1>(I)), get<1>(I));
                }

                StrideIter<const uint64_t *> ibase_punctured_prod_array(ibase_.punctured_prod_array(), ibase_.size());
                SEAL_ITERATE(iter(get<0>(I), ibase_punctured_prod_array), ibase_.size(), [&](auto J) {
                    // Base-change matrix contains the punctured products of ibase elements modulo the obase
                    get<0>(J) = modulo_uint(get<1>(J), ibase_.size(), get<1>(I));
                    if (obase_scale)
                    {
                        get<0>(J) = multiply_uint_mod(get<0>(J), scale, get<1>(I));
                    }
                });
            });

            // Row-major copy of base_change_matrix_ for fast_convert_block, in Montgomery form for odd obase elements
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();
            conv_matrix_ = allocate_uint(mul_safe(ibase_size, obase_size), pool_);
            obase_neg_inv_mod_2_64_ = allocate_uint(obase_size, pool_);
            for (size_t j = 0; j < obase_size; j++)
            {
                const Modulus &p = obase_[j];
                uint64_t *row = conv_matrix_.get() + j * ibase_size;
                if (p.value() & 1)
                {
                    obase_neg_inv_mod_2_64_[j] = neg_inv_mod_2_64(p.value());
                    MultiplyUIntModOperand two_pow_64;
                    two_pow_64.set(two_pow_64_mod(p), p);
                    for (size_t i = 0; i < ibase_size; i++)
                    {
                        row[i] = multiply_uint_mod(base_change_matrix_[j][i], two_pow_64, p);
                    }
                }
                else
                {
                    obase_neg_inv_mod_2_64_[j] = 0;
                    copy_n(base_change_matrix_[j].get(), ibase_size, row);
                }
            }

            // Partition ibase so that the sum of (q_i - 1) over each chunk is less than 2^64. Every ibase element is
            // less than 2^61, so each chunk has at least 8 elements (except possibly the last one).
            ibase_chunk_ends_.clear();
            uint64_t chunk_sum = 0;
            for (size_t i = 0; i < ibase_size; i++)
            {
                uint64_t term = ibase_[i].value() - 1;
                unsigned long long new_sum;
                if (add_uint64(chunk_sum, term, &new_sum))
                {
                    // Overflow: close the current chunk before element i
                    ibase_chunk_ends_.push_back(i);
                    chunk_sum = term;
                }
                else
                {
                    chunk_sum = new_sum;
                }
            }
            ibase_chunk_ends_.push_back(ibase_size);
        }

        RNSTool::RNSTool(
            size_t poly_modulus_degree, const RNSBase &coeff_modulus, const Modulus &plain_modulus,
            MemoryPoolHandle pool)
            : pool_(std::move(pool))
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

            size_t base_Bsk_m_tilde_size = add_safe(base_B_size, size_t(2));

            // Size check
            if (!product_fits_in(coeff_count_, base_Bsk_m_tilde_size))
            {
                throw logic_error("invalid parameters");
            }

            // Sample primes for B and two more primes: m_sk and gamma
            auto baseconv_primes =
                get_primes(mul_safe(size_t(2), coeff_count_), SEAL_INTERNAL_MOD_BIT_COUNT, base_Bsk_m_tilde_size);
            auto baseconv_primes_iter = baseconv_primes.cbegin();
            m_sk_ = *baseconv_primes_iter++;
            gamma_ = *baseconv_primes_iter++;

            // The rule above is conservative, since it assumes that the primes in q are as large as those in B. Shrink
            // B to the shortest prefix that provably suffices. Let k be the number of primes in q, and let q also
            // denote their product. sm_mrq outputs coefficients |a| <= q * (1/2 + k / m_tilde), and an output
            // polynomial of the tensor product is a sum of at most 8 products of two such polynomials (the output size
            // is at most SEAL_CIPHERTEXT_SIZE_MAX = 16, so the smaller input size is at most 8). Its coefficients X
            // satisfy |X| <= 8 * n * q^2 * (1/2 + k / m_tilde)^2, and fast_floor outputs y = floor(t * X / q) - u with
            // 0 <= u < k, so |y| < 2.01 * t * n * q. None of this depends on B. The Shenoy-Kumaresan conversion of y
            // is exact if |y| < prod(B) * (m_sk / 2 - |B| - 2), where |B| is the number of primes in B; this holds with
            // a margin of almost a factor 8 if 32 * t * n * q <= prod(B) * m_sk, i.e., if
            //   bits(prod(B) * m_sk) - 1 >= 5 + bits(t) + log2(n) + bits(q).
            // The output of the multiplication then does not depend on B.
            static_assert(SEAL_CIPHERTEXT_SIZE_MAX <= 16, "the size of B below assumes at most 8 products");
            {
                const int required_bit_count = 5 + t_.bit_count() + coeff_count_power + total_coeff_bit_count;
                vector<uint64_t> B_m_sk_prod{ m_sk_.value() };
                auto sufficient = [&]() {
                    return get_significant_bit_count_uint(B_m_sk_prod.data(), B_m_sk_prod.size()) - 1 >=
                           required_bit_count;
                };
                size_t tight_B_size = 0;
                do
                {
                    vector<uint64_t> next(B_m_sk_prod.size() + 1);
                    multiply_uint(
                        B_m_sk_prod.data(), B_m_sk_prod.size(),
                        baseconv_primes_iter[safe_cast<ptrdiff_t>(tight_B_size)].value(), next.size(), next.data());
                    B_m_sk_prod.swap(next);
                    tight_B_size++;
                } while (tight_B_size < base_B_size && !sufficient());
                if (!sufficient())
                {
                    throw logic_error("invalid rns bases");
                }
                base_B_size = tight_B_size;
            }

            vector<Modulus> base_B_primes;
            copy_n(baseconv_primes_iter, base_B_size, back_inserter(base_B_primes));

            // m_tilde is a power of two (not a prime), so that sm_mrq and fastbconv_m_tilde_sm_mrq can reduce modulo
            // m_tilde with a mask
            m_tilde_ = uint64_t(1) << 32;

            // Populate the base arrays
            base_q_ = allocate<RNSBase>(pool_, q, pool_);
            base_B_ = allocate<RNSBase>(pool_, base_B_primes, pool_);
            base_Bsk_ = allocate<RNSBase>(pool_, base_B_->extend(m_sk_));
            base_Bsk_m_tilde_ = allocate<RNSBase>(pool_, base_Bsk_->extend(m_tilde_));

            // Set up t-gamma base if t_ is non-zero (using BFV)
            if (!t_.is_zero())
            {
                base_t_gamma_ = allocate<RNSBase>(pool_, vector<Modulus>{ t_, gamma_ }, pool_);
            }

            // Generate the Bsk NTTTables; these are used for NTT after base extension to Bsk
            try
            {
                CreateNTTTables(
                    coeff_count_power, vector<Modulus>(base_Bsk_->base(), base_Bsk_->base() + base_Bsk_->size()),
                    base_Bsk_ntt_tables_, pool_);
            }
            catch (const logic_error &)
            {
                throw logic_error("invalid rns bases");
            }

            initialize_behz_extension();
            initialize_behz_floor();
            initialize_decryption();
            initialize_mod_switch();
        }

        void RNSTool::initialize_behz_extension()
        {
            const size_t base_q_size = base_q_->size();
            const size_t base_Bsk_size = base_Bsk_->size();
            uint64_t temp;

            // Compute m_tilde^(-1) mod Bsk
            inv_m_tilde_mod_Bsk_ = allocate<MultiplyUIntModOperand>(base_Bsk_size, pool_);
            SEAL_ITERATE(iter(inv_m_tilde_mod_Bsk_, base_Bsk_->base()), base_Bsk_size, [&](auto I) {
                if (!try_invert_uint_mod(barrett_reduce_64(m_tilde_.value(), get<1>(I)), get<1>(I), temp))
                {
                    throw logic_error("invalid rns bases");
                }
                get<0>(I).set(temp, get<1>(I));
            });

            // Compute -prod(q)^(-1) mod m_tilde
            temp = modulo_uint(base_q_->base_prod(), base_q_size, m_tilde_);
            if (!try_invert_uint_mod(temp, m_tilde_, temp))
            {
                throw logic_error("invalid rns bases");
            }
            neg_inv_prod_q_mod_m_tilde_.set(negate_uint_mod(temp, m_tilde_), m_tilde_);

            // Compute prod(q) * m_tilde^(-1) mod Bsk
            prod_q_inv_m_tilde_mod_Bsk_ = allocate<MultiplyUIntModOperand>(base_Bsk_size, pool_);
            for (size_t i = 0; i < base_Bsk_size; i++)
            {
                const Modulus &m = (*base_Bsk_)[i];
                const uint64_t prod_q_mod_m = modulo_uint(base_q_->base_prod(), base_q_size, m);
                prod_q_inv_m_tilde_mod_Bsk_[i].set(multiply_uint_mod(prod_q_mod_m, inv_m_tilde_mod_Bsk_[i], m), m);
            }

            // Set up BaseConverter for q --> Bsk U {m_tilde}, with the input scaled by m_tilde. As mentioned in BEHZ16,
            // the multiplication by m_tilde (for the Montgomery reduction in sm_mrq) can be merged into the conversion.
            base_q_to_Bsk_m_tilde_conv_ = allocate<BaseConverter>(
                pool_, *base_q_, *base_Bsk_m_tilde_, vector<uint64_t>(base_q_size, m_tilde_.value()),
                vector<uint64_t>(base_Bsk_size + 1, 1), pool_);

            // For fastbconv_m_tilde_sm_mrq, the multiplication by m_tilde^(-1) is merged into the conversion to Bsk as
            // well. The output modulo m_tilde, r_m_tilde = sum_i y_i * [(q/q_i) * (-prod(q)^(-1))]_{m_tilde}, is
            // computed from the first-step values y_i of that conversion with native 64-bit arithmetic.
            vector<uint64_t> obase_scale(base_Bsk_size);
            for (size_t i = 0; i < base_Bsk_size; i++)
            {
                obase_scale[i] = inv_m_tilde_mod_Bsk_[i].operand;
            }
            base_q_to_Bsk_mont_conv_ = allocate<BaseConverter>(
                pool_, *base_q_, *base_Bsk_, vector<uint64_t>(base_q_size, m_tilde_.value()), obase_scale, pool_);
            m_tilde_row_neg_inv_prod_q_ = allocate_uint(base_q_size, pool_);
            const uint64_t m_tilde_mask = m_tilde_.value() - 1;
            for (size_t i = 0; i < base_q_size; i++)
            {
                // The low word of the punctured product (q/q_i) determines it modulo m_tilde
                const uint64_t punctured_prod_low = base_q_->punctured_prod_array()[i * base_q_size];
                m_tilde_row_neg_inv_prod_q_[i] =
                    (punctured_prod_low * neg_inv_prod_q_mod_m_tilde_.operand) & m_tilde_mask;
            }
        }

        void RNSTool::initialize_behz_floor()
        {
            const size_t base_q_size = base_q_->size();
            const size_t base_B_size = base_B_->size();
            const size_t base_Bsk_size = base_Bsk_->size();
            uint64_t temp;

            // Set up BaseConverters for q --> Bsk and B --> q U {m_sk}
            base_q_to_Bsk_conv_ = allocate<BaseConverter>(pool_, *base_q_, *base_Bsk_, pool_);
            RNSBase base_q_m_sk = base_q_->extend(m_sk_);
            base_B_to_q_m_sk_conv_ = allocate<BaseConverter>(pool_, *base_B_, base_q_m_sk, pool_);

            // Compute prod(q)^(-1) mod Bsk
            inv_prod_q_mod_Bsk_ = allocate<MultiplyUIntModOperand>(base_Bsk_size, pool_);
            for (size_t i = 0; i < base_Bsk_size; i++)
            {
                temp = modulo_uint(base_q_->base_prod(), base_q_size, (*base_Bsk_)[i]);
                if (!try_invert_uint_mod(temp, (*base_Bsk_)[i], temp))
                {
                    throw logic_error("invalid rns bases");
                }
                inv_prod_q_mod_Bsk_[i].set(temp, (*base_Bsk_)[i]);
            }

            // Compute prod(B)^(-1) mod m_sk
            temp = modulo_uint(base_B_->base_prod(), base_B_size, m_sk_);
            if (!try_invert_uint_mod(temp, m_sk_, temp))
            {
                throw logic_error("invalid rns bases");
            }
            inv_prod_B_mod_m_sk_.set(temp, m_sk_);

            // Compute prod(B) mod q
            prod_B_mod_q_ = allocate<MultiplyUIntModOperand>(base_q_size, pool_);
            for (size_t i = 0; i < base_q_size; i++)
            {
                const Modulus &qi = (*base_q_)[i];
                prod_B_mod_q_[i].set(modulo_uint(base_B_->base_prod(), base_B_size, qi), qi);
            }

            if (t_.is_zero())
            {
                return;
            }

            // For inverse_ntt_multiply_t_fast_floor_fastbconv_sk, the inverse NTT scalar in base q is
            // t * (q/q_i)^(-1) mod q_i, so the converter q --> Bsk of the fast floor is created with input scale
            // (q/q_i), making its first-step constants 1.
            intt_scalar_q_ = allocate_uint(mul_safe(size_t(2), base_q_size), pool_);
            vector<uint64_t> q_punctured_mod_q(base_q_size);
            for (size_t i = 0; i < base_q_size; i++)
            {
                const Modulus &qi = (*base_q_)[i];
                const uint64_t inv_punctured = base_q_->inv_punctured_prod_mod_base_array()[i].operand;
                if (!try_invert_uint_mod(inv_punctured, qi, q_punctured_mod_q[i]))
                {
                    throw logic_error("invalid rns bases");
                }
                const uint64_t scalar = multiply_uint_mod(barrett_reduce_64(t_.value(), qi), inv_punctured, qi);
                intt_scalar_q_[i] = scalar;
                intt_scalar_q_[base_q_size + i] = multiply_uint_mod(scalar, two_pow_64_mod(qi), qi);
            }

            // In base Bsk the inverse NTT scalar is t * prod(q)^(-1) * (prod(B)/b_j)^(-1) mod b_j for b_j in B, and
            // t * prod(q)^(-1) mod m_sk. The output of the converter q --> Bsk is scaled by the same factors without t,
            // and the converter B --> q U {m_sk} is created with input scale (prod(B)/b_j), making its first-step
            // constants 1.
            intt_scalar_Bsk_ = allocate_uint(mul_safe(size_t(2), base_Bsk_size), pool_);
            vector<uint64_t> floor_obase_scale(base_Bsk_size);
            vector<uint64_t> B_punctured_mod_B(base_B_size);
            for (size_t j = 0; j < base_Bsk_size; j++)
            {
                const Modulus &bj = (*base_Bsk_)[j];
                uint64_t scale = inv_prod_q_mod_Bsk_[j].operand;
                if (j < base_B_size)
                {
                    const uint64_t inv_punctured = base_B_->inv_punctured_prod_mod_base_array()[j].operand;
                    if (!try_invert_uint_mod(inv_punctured, bj, B_punctured_mod_B[j]))
                    {
                        throw logic_error("invalid rns bases");
                    }
                    scale = multiply_uint_mod(scale, inv_punctured, bj);
                }
                floor_obase_scale[j] = scale;
                const uint64_t scalar = multiply_uint_mod(barrett_reduce_64(t_.value(), bj), scale, bj);
                intt_scalar_Bsk_[j] = scalar;
                intt_scalar_Bsk_[base_Bsk_size + j] = multiply_uint_mod(scalar, two_pow_64_mod(bj), bj);
            }
            base_q_to_Bsk_floor_conv_ =
                allocate<BaseConverter>(pool_, *base_q_, *base_Bsk_, q_punctured_mod_q, floor_obase_scale, pool_);
            base_B_to_q_m_sk_unit_conv_ = allocate<BaseConverter>(
                pool_, *base_B_, base_q_m_sk, B_punctured_mod_B, vector<uint64_t>(base_q_size + 1, 1), pool_);
        }

        void RNSTool::initialize_decryption()
        {
            if (t_.is_zero())
            {
                return;
            }

            const size_t base_q_size = base_q_->size();
            const size_t base_t_gamma_size = base_t_gamma_->size();
            uint64_t temp;

            // Set up BaseConverter for q --> {t}
            base_q_to_t_conv_ = allocate<BaseConverter>(pool_, *base_q_, RNSBase({ t_ }, pool_), pool_);

            // Set up BaseConverter for q --> {t, gamma}
            base_q_to_t_gamma_conv_ = allocate<BaseConverter>(pool_, *base_q_, *base_t_gamma_, pool_);

            // Compute gamma^(-1) mod t
            if (!try_invert_uint_mod(barrett_reduce_64(gamma_.value(), t_), t_, temp))
            {
                throw logic_error("invalid rns bases");
            }
            inv_gamma_mod_t_.set(temp, t_);

            // Compute prod({t, gamma}) mod q
            prod_t_gamma_mod_q_ = allocate<MultiplyUIntModOperand>(base_q_size, pool_);
            SEAL_ITERATE(iter(prod_t_gamma_mod_q_, base_q_->base()), base_q_size, [&](auto I) {
                get<0>(I).set(
                    multiply_uint_mod((*base_t_gamma_)[0].value(), (*base_t_gamma_)[1].value(), get<1>(I)), get<1>(I));
            });

            // Compute -prod(q)^(-1) mod {t, gamma}
            neg_inv_q_mod_t_gamma_ = allocate<MultiplyUIntModOperand>(base_t_gamma_size, pool_);
            SEAL_ITERATE(iter(neg_inv_q_mod_t_gamma_, base_t_gamma_->base()), base_t_gamma_size, [&](auto I) {
                get<0>(I).operand = modulo_uint(base_q_->base_prod(), base_q_size, get<1>(I));
                if (!try_invert_uint_mod(get<0>(I).operand, get<1>(I), get<0>(I).operand))
                {
                    throw logic_error("invalid rns bases");
                }
                get<0>(I).set(negate_uint_mod(get<0>(I).operand, get<1>(I)), get<1>(I));
            });
        }

        void RNSTool::initialize_mod_switch()
        {
            const size_t base_q_size = base_q_->size();
            uint64_t temp;

            // Compute q[last]^(-1) mod q[i] for i = 0..last-1
            inv_q_last_mod_q_ = allocate<MultiplyUIntModOperand>(base_q_size - 1, pool_);
            SEAL_ITERATE(iter(inv_q_last_mod_q_, base_q_->base()), base_q_size - 1, [&](auto I) {
                if (!try_invert_uint_mod((*base_q_)[base_q_size - 1].value(), get<1>(I), temp))
                {
                    throw logic_error("invalid rns bases");
                }
                get<0>(I).set(temp, get<1>(I));
            });

            if (t_.value() != 0)
            {
                if (!try_invert_uint_mod(base_q_->base()[base_q_size - 1].value(), t_, inv_q_last_mod_t_))
                {
                    throw logic_error("invalid rns bases");
                }

                q_last_mod_t_ = barrett_reduce_64(base_q_->base()[base_q_size - 1].value(), t_);
            }
        }

        void RNSTool::divide_and_round_q_last_inplace(RNSIter input, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (!input)
            {
                throw invalid_argument("input cannot be null");
            }
            if (input.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("input is not valid for encryption parameters");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            size_t base_q_size = base_q_->size();
            CoeffIter last_input = input[base_q_size - 1];

            // Add (qi-1)/2 to change from flooring to rounding
            Modulus last_modulus = (*base_q_)[base_q_size - 1];
            uint64_t half = last_modulus.value() >> 1;
            add_poly_scalar_coeffmod(last_input, coeff_count_, half, last_modulus, last_input);

            SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_count_, pool);
            SEAL_ITERATE(iter(input, inv_q_last_mod_q_, base_q_->base()), base_q_size - 1, [&](auto I) {
                // (ct mod qk) mod qi
                modulo_poly_coeffs(last_input, coeff_count_, get<2>(I), temp);

                // Subtract rounding correction here; the negative sign will turn into a plus in the next subtraction
                uint64_t half_mod = barrett_reduce_64(half, get<2>(I));
                sub_poly_scalar_coeffmod(temp, coeff_count_, half_mod, get<2>(I), temp);

                // (ct mod qi) - (ct mod qk) mod qi
                sub_poly_coeffmod(get<0>(I), temp, coeff_count_, get<2>(I), get<0>(I));

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(get<0>(I), coeff_count_, get<1>(I), get<2>(I), get<0>(I));
            });
        }

        void RNSTool::divide_and_round_q_last_ntt_inplace(
            RNSIter input, ConstNTTTablesIter rns_ntt_tables, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (!input)
            {
                throw invalid_argument("input cannot be null");
            }
            if (input.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("input is not valid for encryption parameters");
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
            size_t base_q_size = base_q_->size();
            CoeffIter last_input = input[base_q_size - 1];

            // Convert to non-NTT form
            inverse_ntt_negacyclic_harvey(last_input, rns_ntt_tables[base_q_size - 1]);

            // Add (qi-1)/2 to change from flooring to rounding
            Modulus last_modulus = (*base_q_)[base_q_size - 1];
            uint64_t half = last_modulus.value() >> 1;
            add_poly_scalar_coeffmod(last_input, coeff_count_, half, last_modulus, last_input);

            SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_count_, pool);
            SEAL_ITERATE(iter(input, inv_q_last_mod_q_, base_q_->base(), rns_ntt_tables), base_q_size - 1, [&](auto I) {
                // (ct mod qk) mod qi
                if (get<2>(I).value() < last_modulus.value())
                {
                    modulo_poly_coeffs(last_input, coeff_count_, get<2>(I), temp);
                }
                else
                {
                    set_uint(last_input, coeff_count_, temp);
                }

                // Lazy subtraction here. ntt_negacyclic_harvey_lazy can take 0 < x < 4*qi input.
                uint64_t neg_half_mod = get<2>(I).value() - barrett_reduce_64(half, get<2>(I));

                // Note: lambda function parameter must be passed by reference here
                SEAL_ITERATE(temp, coeff_count_, [&](auto &J) { J += neg_half_mod; });
#if SEAL_USER_MOD_BIT_COUNT_MAX <= 60
                // Since SEAL uses at most 60-bit moduli, 8*qi < 2^63.
                // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
                uint64_t qi_lazy = get<2>(I).value() << 2;
                ntt_negacyclic_harvey_lazy(temp, get<3>(I));
#else
                // 2^60 < pi < 2^62, then 4*pi < 2^64, we perfrom one reduction from [0, 4*qi) to [0, 2*qi) after ntt.
                uint64_t qi_lazy = get<2>(I).value() << 1;
                ntt_negacyclic_harvey_lazy(temp, get<3>(I));

                // Note: lambda function parameter must be passed by reference here
                SEAL_ITERATE(temp, coeff_count_, [&](auto &J) {
                    J -= (qi_lazy & static_cast<uint64_t>(-static_cast<int64_t>(J >= qi_lazy)));
                });
#endif
                // Lazy subtraction again, results in [0, 2*qi_lazy),
                // The reduction [0, 2*qi_lazy) -> [0, qi) is done implicitly in multiply_poly_scalar_coeffmod.
                SEAL_ITERATE(iter(get<0>(I), temp), coeff_count_, [&](auto J) { get<0>(J) += qi_lazy - get<1>(J); });

                // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                multiply_poly_scalar_coeffmod(get<0>(I), coeff_count_, get<1>(I), get<2>(I), get<0>(I));
            });
        }

        void RNSTool::fastbconv_sk(ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (!input)
            {
                throw invalid_argument("input cannot be null");
            }
            if (input.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("input is not valid for encryption parameters");
            }
            if (!destination)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (destination.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("destination is not valid for encryption parameters");
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

            size_t base_q_size = base_q_->size();
            size_t base_B_size = base_B_->size();

            // Fast convert B -> q U {m_sk} in a single conversion; input is in Bsk but we only use B
            SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count_, base_q_size + 1, pool);
            base_B_to_q_m_sk_conv_->fast_convert_array(input, temp, pool);

            // Note: input_sk is allocated in input[base_B_size]
            auto scratch(allocate_uint(mul_safe(size_t(2), coeff_count_), pool));
            fastbconv_sk_finish(
                temp[0].ptr(), coeff_count_, input[base_B_size].ptr(), destination[0].ptr(), coeff_count_, coeff_count_,
                scratch.get());
        }

        void RNSTool::fastbconv_sk_finish(
            const uint64_t *conv_q_m_sk, size_t conv_stride, const uint64_t *input_m_sk, uint64_t *destination,
            size_t destination_stride, size_t count, uint64_t *scratch) const
        {
            const size_t base_q_size = base_q_->size();

            // Compute alpha_sk: take the m_sk part of input, subtract from the converted value in
            // conv_q_m_sk[base_q_size], and multiply by inv_prod_B_mod_m_sk_.
            //
            // alpha_sk is not a centered reduction, so we need to apply a correction below: if alpha_sk > m_sk / 2,
            // it represents the negative value alpha_sk - m_sk. We record the absolute value of the centered
            // representative in alpha_abs and an all-ones mask in alpha_neg for the negative case. This allows the
            // per-prime loop below to be branch-free.
            uint64_t *alpha_abs = scratch;
            uint64_t *alpha_neg = scratch + count;
            const uint64_t m_sk_value = m_sk_.value();
            const uint64_t m_sk_div_2 = m_sk_value >> 1;
            const uint64_t *conv_m_sk = conv_q_m_sk + base_q_size * conv_stride;
            const MultiplyUIntModOperand inv_prod_B_mod_m_sk = inv_prod_B_mod_m_sk_;
            for (size_t k = 0; k < count; k++)
            {
                // It is not necessary for the negation to be reduced modulo the small prime
                const uint64_t alpha =
                    multiply_uint_mod(conv_m_sk[k] + (m_sk_value - input_m_sk[k]), inv_prod_B_mod_m_sk, m_sk_);
                const uint64_t neg = less_than_mask_uint64(m_sk_div_2, alpha);
                alpha_abs[k] = alpha ^ ((alpha ^ (m_sk_value - alpha)) & neg);
                alpha_neg[k] = neg;
            }

            // For each prime q_i: output = conv + |alpha| * prod(B) if alpha was negative (corrected), and
            // conv - |alpha| * prod(B) otherwise, modulo q_i. The converted values are already reduced modulo q_i.
            for (size_t i = 0; i < base_q_size; i++)
            {
                const Modulus &qi = base_q_->base()[i];
                const MultiplyUIntModOperand prod_B_mod_qi = prod_B_mod_q_[i];
                const uint64_t *conv = conv_q_m_sk + i * conv_stride;
                uint64_t *dest = destination + i * destination_stride;
                for (size_t k = 0; k < count; k++)
                {
                    const uint64_t correction = multiply_uint_mod(alpha_abs[k], prod_B_mod_qi, qi);
                    const uint64_t sum = sub_if_ge_uint64(conv[k] + correction, qi.value());
                    const uint64_t diff = sub_uint_mod(conv[k], correction, qi);
                    dest[k] = (sum & alpha_neg[k]) | (diff & ~alpha_neg[k]);
                }
            }
        }

        void RNSTool::sm_mrq(ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (input.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("input is not valid for encryption parameters");
            }
            if (!destination)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (destination.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("destination is not valid for encryption parameters");
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

            size_t base_Bsk_size = base_Bsk_->size();

            // The last component of the input is mod m_tilde
            ConstCoeffIter input_m_tilde = input[base_Bsk_size];
            const uint64_t m_tilde_value = m_tilde_.value();
            const uint64_t m_tilde_div_2 = m_tilde_value >> 1;

            // Compute r_m_tilde; m_tilde is a power of two, so the reduction is a mask
            SEAL_ALLOCATE_GET_COEFF_ITER(r_m_tilde, coeff_count_, pool);
            const uint64_t m_tilde_mask = m_tilde_value - 1;
            const uint64_t neg_inv_prod_q = neg_inv_prod_q_mod_m_tilde_.operand;
            SEAL_ITERATE(iter(input_m_tilde, r_m_tilde), coeff_count_, [&](auto I) {
                get<1>(I) = (get<0>(I) * neg_inv_prod_q) & m_tilde_mask;
            });

            SEAL_ITERATE(
                iter(input, prod_q_inv_m_tilde_mod_Bsk_, inv_m_tilde_mod_Bsk_, base_Bsk_->base(), destination),
                base_Bsk_size, [&](auto I) {
                    const Modulus &modulus = get<3>(I);
                    const uint64_t modulus_value = modulus.value();
                    const uint64_t two_times_modulus_value = modulus_value << 1;
                    const uint64_t centering_correction = modulus_value - m_tilde_value;
                    const MultiplyUIntModOperand prod_q_inv_m_tilde_elt = get<1>(I);
                    const MultiplyUIntModOperand inv_m_tilde_elt = get<2>(I);
                    SEAL_ITERATE(iter(get<0>(I), r_m_tilde, get<4>(I)), coeff_count_, [&](auto J) {
                        // We need centered reduction of r_m_tilde modulo Bsk. Note that m_tilde is chosen
                        // to be a power of two so we have '>=' below.
                        uint64_t temp = get<1>(J);
                        temp += SEAL_COND_SELECT(temp >= m_tilde_div_2, centering_correction, uint64_t(0));

                        // Compute (input + q*r_m_tilde)*m_tilde^(-1) mod Bsk as
                        // input*m_tilde^(-1) + r_m_tilde*(q*m_tilde^(-1)) mod Bsk with two lazy Shoup multiplications;
                        // the sum is in [0, 4*modulus), which fits in 63 bits
                        uint64_t sum = multiply_uint_mod_lazy(get<0>(J), inv_m_tilde_elt, modulus) +
                                       multiply_uint_mod_lazy(temp, prod_q_inv_m_tilde_elt, modulus);
                        get<2>(J) = sub_if_ge_uint64(sub_if_ge_uint64(sum, two_times_modulus_value), modulus_value);
                    });
                });
        }

        void RNSTool::fast_floor(ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (input.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("input is not valid for encryption parameters");
            }
            if (!destination)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (destination.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("destination is not valid for encryption parameters");
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

            size_t base_q_size = base_q_->size();
            size_t base_Bsk_size = base_Bsk_->size();

            // Convert q -> Bsk
            base_q_to_Bsk_conv_->fast_convert_array(input, destination, pool);

            // Move input pointer to past the base q components
            input += base_q_size;
            SEAL_ITERATE(iter(input, inv_prod_q_mod_Bsk_, base_Bsk_->base(), destination), base_Bsk_size, [&](auto I) {
                SEAL_ITERATE(iter(get<0>(I), get<3>(I)), coeff_count_, [&](auto J) {
                    // It is not necessary for the negation to be reduced modulo base_Bsk_elt
                    get<1>(J) = multiply_uint_mod(get<0>(J) + (get<2>(I).value() - get<1>(J)), get<1>(I), get<2>(I));
                });
            });
        }

        void RNSTool::fastbconv_m_tilde(ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (input.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("input is not valid for encryption parameters");
            }
            if (!destination)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (destination.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("destination is not valid for encryption parameters");
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

            // We need to multiply the input with m_tilde mod q to facilitate Montgomery reduction in the next step of
            // multiplication. As mentioned in BEHZ16, this multiplication is merged into the base conversion: the
            // converter's constants are scaled by m_tilde. We convert to Bsk U {m_tilde} in a single conversion.
            base_q_to_Bsk_m_tilde_conv_->fast_convert_array(input, destination, pool);
        }

        void RNSTool::fastbconv_m_tilde_sm_mrq(
            ConstRNSIter input, bool lazy_output, RNSIter destination, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (input.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("input is not valid for encryption parameters");
            }
            if (!destination)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (destination.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("destination is not valid for encryption parameters");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            const size_t base_q_size = base_q_->size();
            const size_t base_Bsk_size = base_Bsk_->size();

            // The conversion and the Montgomery reduction are computed one block of coefficients at a time, so that
            // the converted values stay in cache. Scratch space for one block: the conversion's first-step values
            // (base_q_size rows) and its output in Bsk U {m_tilde} (base_Bsk_size + 1 rows).
            const size_t block_size = min(BaseConverter::max_block_size, coeff_count_);
            auto scratch(allocate_uint(mul_safe(block_size, base_q_size + base_Bsk_size + 1), pool));
            uint64_t *conv_temp = scratch.get();
            uint64_t *conv_out = conv_temp + block_size * base_q_size;

            const uint64_t m_tilde_value = m_tilde_.value();
            const uint64_t m_tilde_div_2 = m_tilde_value >> 1;
            const uint64_t m_tilde_mask = m_tilde_value - 1;
            const uint64_t *m_tilde_row = m_tilde_row_neg_inv_prod_q_.get();

            for (size_t start = 0; start < coeff_count_; start += block_size)
            {
                const size_t count = min(block_size, coeff_count_ - start);

                // Convert [input * m_tilde]_q to Bsk, with the output multiplied by m_tilde^(-1): for each prime m in
                // Bsk this gives [input * m_tilde]_q * m_tilde^(-1) mod m.
                base_q_to_Bsk_mont_conv_->fast_convert_block(
                    input[0].ptr() + start, coeff_count_, count, false, conv_out, count, conv_temp);

                // r_m_tilde (as in sm_mrq) from the first-step values y_i = [input_i * m_tilde * (q/q_i)^(-1)]_{q_i}
                // in conv_temp (see BaseConverter::fast_convert_block), as
                // sum_i y_i * [(q/q_i) * (-prod(q)^(-1))]_{m_tilde}, exactly modulo m_tilde, which divides 2^64
                uint64_t *r_m_tilde = conv_out + base_Bsk_size * count;
                for (size_t k = 0; k < count; k++)
                {
                    r_m_tilde[k] = conv_temp[k] * m_tilde_row[0];
                }
                for (size_t i = 1; i < base_q_size; i++)
                {
                    const uint64_t *y = conv_temp + i * count;
                    const uint64_t c = m_tilde_row[i];
                    for (size_t k = 0; k < count; k++)
                    {
                        r_m_tilde[k] += y[k] * c;
                    }
                }
                for (size_t k = 0; k < count; k++)
                {
                    r_m_tilde[k] &= m_tilde_mask;
                }

                // Compute (temp_m + q * r_m_tilde * m_tilde^(-1)) mod m for each m in Bsk, where r_m_tilde is
                // centered. Note that m_tilde is chosen to be a power of two so we have '>=' below.
                for (size_t j = 0; j < base_Bsk_size; j++)
                {
                    const Modulus &modulus = base_Bsk_->base()[j];
                    const uint64_t modulus_value = modulus.value();
                    const uint64_t two_times_modulus_value = modulus_value << 1;
                    const uint64_t centering_correction = modulus_value - m_tilde_value;
                    const MultiplyUIntModOperand prod_q_inv_m_tilde_elt = prod_q_inv_m_tilde_mod_Bsk_[j];
                    const uint64_t *conv = conv_out + j * count;
                    uint64_t *dest = destination[j].ptr() + start;
                    for (size_t k = 0; k < count; k++)
                    {
                        uint64_t r = r_m_tilde[k];
                        r += SEAL_COND_SELECT(r >= m_tilde_div_2, centering_correction, uint64_t(0));
                        // conv[k] is fully reduced, so the sum is in [0, 3 * modulus)
                        const uint64_t sum = conv[k] + multiply_uint_mod_lazy(r, prod_q_inv_m_tilde_elt, modulus);
                        dest[k] = lazy_output
                                      ? sum
                                      : sub_if_ge_uint64(sub_if_ge_uint64(sum, two_times_modulus_value), modulus_value);
                    }
                }
            }
        }

        void RNSTool::inverse_ntt_multiply_t_fast_floor_fastbconv_sk(
            RNSIter input_q, RNSIter input_Bsk, ConstNTTTablesIter base_q_ntt_tables, bool input_montgomery_form,
            RNSIter destination, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (!input_q || !input_Bsk)
            {
                throw invalid_argument("input cannot be null");
            }
            if (input_q.poly_modulus_degree() != coeff_count_ || input_Bsk.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("input is not valid for encryption parameters");
            }
            if (!base_q_ntt_tables)
            {
                throw invalid_argument("base_q_ntt_tables cannot be null");
            }
            if (!destination)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (destination.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("destination is not valid for encryption parameters");
            }
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            if (!base_q_to_Bsk_floor_conv_)
            {
                throw logic_error("plain modulus is not set");
            }

            const size_t base_q_size = base_q_->size();
            const size_t base_B_size = base_B_->size();
            const size_t base_Bsk_size = base_Bsk_->size();
            const uint64_t *scalar_q = intt_scalar_q_.get() + (input_montgomery_form ? base_q_size : 0);
            const uint64_t *scalar_Bsk = intt_scalar_Bsk_.get() + (input_montgomery_form ? base_Bsk_size : 0);

            // Inverse NTT in base q, scaled by t * (q/q_i)^(-1) (times 2^64 for Montgomery-form input): the output is
            // [t * x * (q/q_i)^(-1)]_{q_i}, exactly what the fast floor's conversion q -> Bsk computes in its first
            // step after the multiplication by t. Its converter therefore has first-step constants 1.
            for (size_t i = 0; i < base_q_size; i++)
            {
                inverse_ntt_negacyclic_harvey_scaled(input_q[i], scalar_q[i], base_q_ntt_tables[i], input_q[i]);
            }

            // Inverse NTT in base Bsk, scaled by t * prod(q)^(-1) * (prod(B)/b_j)^(-1) for b_j in B, and by
            // t * prod(q)^(-1) for m_sk (times 2^64 for Montgomery-form input)
            for (size_t j = 0; j < base_Bsk_size; j++)
            {
                inverse_ntt_negacyclic_harvey_scaled(
                    input_Bsk[j], scalar_Bsk[j], base_Bsk_ntt_tables_[j], input_Bsk[j]);
            }

            // The rest is computed one block of coefficients at a time, so that all intermediate values stay in
            // cache. Scratch space for one block: the conversions' first-step values (max(|q|, |B|) rows), the fast
            // floor output in Bsk (|Bsk| rows), the Shenoy-Kumaresan conversion output in q U {m_sk} (|q| + 1 rows),
            // and two rows for the Shenoy-Kumaresan correction, where |.| is the number of primes in a base.
            const size_t block_size = min(BaseConverter::max_block_size, coeff_count_);
            const size_t conv_temp_rows = max(base_q_size, base_B_size);
            auto scratch(
                allocate_uint(mul_safe(block_size, conv_temp_rows + base_Bsk_size + base_q_size + 1 + 2), pool));
            uint64_t *conv_temp = scratch.get();
            uint64_t *floor_Bsk = conv_temp + block_size * conv_temp_rows;
            uint64_t *conv_q_m_sk = floor_Bsk + block_size * base_Bsk_size;
            uint64_t *finish_scratch = conv_q_m_sk + block_size * (base_q_size + 1);

            for (size_t start = 0; start < coeff_count_; start += block_size)
            {
                const size_t count = min(block_size, coeff_count_ - start);

                // Fast floor: convert [t * x]_q -> Bsk, with the output scaled by the same factors as above (without t)
                base_q_to_Bsk_floor_conv_->fast_convert_block(
                    input_q[0].ptr() + start, coeff_count_, count, true, floor_Bsk, count, conv_temp);

                // Subtract: for b_j in B this yields [z_j * (prod(B)/b_j)^(-1)]_{b_j}, where z is the fast floor
                // output, i.e., exactly what the Shenoy-Kumaresan conversion B -> q U {m_sk} computes in its first
                // step (its converter has first-step constants 1); for m_sk it yields z_{m_sk}.
                for (size_t j = 0; j < base_Bsk_size; j++)
                {
                    const Modulus &modulus = base_Bsk_->base()[j];
                    const uint64_t *y = input_Bsk[j].ptr() + start;
                    uint64_t *z = floor_Bsk + j * count;
                    for (size_t k = 0; k < count; k++)
                    {
                        z[k] = sub_uint_mod(y[k], z[k], modulus);
                    }
                }

                // Shenoy-Kumaresan conversion from Bsk to q
                base_B_to_q_m_sk_unit_conv_->fast_convert_block(
                    floor_Bsk, count, count, true, conv_q_m_sk, count, conv_temp);
                fastbconv_sk_finish(
                    conv_q_m_sk, count, floor_Bsk + base_B_size * count, destination[0].ptr() + start, coeff_count_,
                    count, finish_scratch);
            }
        }

        void RNSTool::decrypt_scale_and_round(ConstRNSIter input, CoeffIter destination, MemoryPoolHandle pool) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (input.poly_modulus_degree() != coeff_count_)
            {
                throw invalid_argument("input is not valid for encryption parameters");
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
            size_t base_q_size = base_q_->size();
            size_t base_t_gamma_size = base_t_gamma_->size();

            // Compute |gamma * t|_qi * ct(s)
            SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count_, base_q_size, pool);
            SEAL_ITERATE(iter(input, prod_t_gamma_mod_q_, base_q_->base(), temp), base_q_size, [&](auto I) {
                multiply_poly_scalar_coeffmod(get<0>(I), coeff_count_, get<1>(I), get<2>(I), get<3>(I));
            });

            // Make another temp destination to get the poly in mod {t, gamma}
            SEAL_ALLOCATE_GET_RNS_ITER(temp_t_gamma, coeff_count_, base_t_gamma_size, pool);

            // Convert from q to {t, gamma}
            base_q_to_t_gamma_conv_->fast_convert_array(temp, temp_t_gamma, pool);

            // Multiply by -prod(q)^(-1) mod {t, gamma}
            SEAL_ITERATE(
                iter(temp_t_gamma, neg_inv_q_mod_t_gamma_, base_t_gamma_->base(), temp_t_gamma), base_t_gamma_size,
                [&](auto I) {
                    multiply_poly_scalar_coeffmod(get<0>(I), coeff_count_, get<1>(I), get<2>(I), get<3>(I));
                });

            // Need to correct values in temp_t_gamma (gamma component only) which are
            // larger than floor(gamma/2)
            uint64_t gamma_div_2 = (*base_t_gamma_)[1].value() >> 1;

            // Now compute the subtraction to remove error and perform final multiplication by
            // gamma inverse mod t
            SEAL_ITERATE(iter(temp_t_gamma[0], temp_t_gamma[1], destination), coeff_count_, [&](auto I) {
                uint64_t gamma_component = get<1>(I);
                uint64_t add_result =
                    add_uint_mod(get<0>(I), barrett_reduce_64(gamma_.value() - gamma_component, t_), t_);
                uint64_t sub_result = sub_uint_mod(get<0>(I), barrett_reduce_64(gamma_component, t_), t_);
                get<2>(I) = SEAL_COND_SELECT(gamma_component > gamma_div_2, add_result, sub_result);

                // Perform final multiplication by gamma inverse mod t
                get<2>(I) = multiply_uint_mod(get<2>(I), inv_gamma_mod_t_, t_);
            });
        }

        void RNSTool::mod_t_and_divide_q_last_ntt_inplace(
            RNSIter input, ConstNTTTablesIter rns_ntt_tables, MemoryPoolHandle pool) const
        {
            size_t modulus_size = base_q_->size();
            const Modulus *curr_modulus = base_q_->base();
            const Modulus plain_modulus = t_;
            uint64_t last_modulus_value = curr_modulus[modulus_size - 1].value();

            SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(neg_c_last_mod_t, coeff_count_, pool);
            // neg_c_last_mod_t = - c_last (mod t)
            CoeffIter c_last = input[modulus_size - 1];
            inverse_ntt_negacyclic_harvey(c_last, rns_ntt_tables[modulus_size - 1]);
            modulo_poly_coeffs(c_last, coeff_count_, plain_modulus, neg_c_last_mod_t);
            negate_poly_coeffmod(neg_c_last_mod_t, coeff_count_, plain_modulus, neg_c_last_mod_t);
            if (inv_q_last_mod_t_ != 1)
            {
                // neg_c_last_mod_t *= q_last^(-1) (mod t)
                multiply_poly_scalar_coeffmod(
                    neg_c_last_mod_t, coeff_count_, inv_q_last_mod_t_, plain_modulus, neg_c_last_mod_t);
            }

            SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(delta_mod_q_i, coeff_count_, pool);

            SEAL_ITERATE(iter(input, curr_modulus, inv_q_last_mod_q_, rns_ntt_tables), modulus_size - 1, [&](auto I) {
                // delta_mod_q_i = neg_c_last_mod_t (mod q_i)
                modulo_poly_coeffs(neg_c_last_mod_t, coeff_count_, get<1>(I), delta_mod_q_i);

                // delta_mod_q_i *= q_last (mod q_i)
                multiply_poly_scalar_coeffmod(
                    delta_mod_q_i, coeff_count_, last_modulus_value, get<1>(I), delta_mod_q_i);

                // c_i = c_i - c_last - neg_c_last_mod_t * q_last (mod 2q_i)
                SEAL_ITERATE(iter(delta_mod_q_i, c_last), coeff_count_, [&](auto J) {
                    get<0>(J) = add_uint_mod(get<0>(J), barrett_reduce_64(get<1>(J), get<1>(I)), get<1>(I));
                });
                ntt_negacyclic_harvey(delta_mod_q_i, get<3>(I));
                SEAL_ITERATE(iter(get<0>(I), delta_mod_q_i), coeff_count_, [&](auto J) {
                    get<0>(J) = sub_uint_mod(get<0>(J), get<1>(J), get<1>(I));
                });

                // c_i = c_i * inv_q_last_mod_q_i (mod q_i)
                multiply_poly_scalar_coeffmod(get<0>(I), coeff_count_, get<2>(I), get<1>(I), get<0>(I));
            });
        }

        void RNSTool::decrypt_modt(RNSIter phase, CoeffIter destination, MemoryPoolHandle pool) const
        {
            // Use exact base convension rather than convert the base through the compose API
            base_q_to_t_conv_->exact_convert_array(phase, destination, pool);
        }

        namespace
        {
#ifndef SEAL_USE_INTEL_HEXL
            // Number of products of inputs reduced to [0, 2p), each below 4p^2, that are summed before a reduction
            constexpr size_t behz_lazy_product_count = 2;

            // Returns sum_{s < count} in1[s][l] * in2[s][l] * 2^(-64) mod p, fully reduced, for inputs in [0, 4p)
            SEAL_NODISCARD SEAL_FORCE_INLINE uint64_t behz_dot_product(
                const uint64_t *const *in1, const uint64_t *const *in2, size_t count, size_t l,
                const DyadicMontgomeryReducer &reducer, const Modulus &modulus)
            {
                uint64_t result = 0;
                for (size_t s = 0; s < count; s += behz_lazy_product_count)
                {
                    const size_t chunk_end = min<size_t>(count, s + behz_lazy_product_count);
                    unsigned long long acc[2]{ 0, 0 };
                    for (size_t u = s; u < chunk_end; u++)
                    {
                        unsigned long long prod[2];
                        multiply_uint64(reducer.reduce_input(in1[u][l]), reducer.reduce_input(in2[u][l]), prod);
                        add_uint128(prod, acc, acc);
                    }
                    result = sub_if_ge_uint64(result + reducer.reduce(acc[0], acc[1]), modulus.value());
                }
                return result;
            }
#endif

            /**
            Computes the BEHZ square of a size-2 ciphertext for one RNS base, with all polynomials in NTT form:

                out[0] = in[0]^2, out[1] = 2 * in[0] * in[1], out[2] = in[1]^2.

            The input coefficients can be lazily reduced to [0, 4 * modulus), and every modulus must have at most
            SEAL_MOD_BIT_COUNT_MAX bits. The outputs are fully reduced. If behz_tensor_product_montgomery_form is true,
            the outputs are multiplied by 2^(-64).
            */
            void behz_tensor_square_size2(
                ConstPolyIter in, ConstModulusIter base, size_t base_size, size_t coeff_count, PolyIter out)
            {
#ifdef SEAL_USE_INTEL_HEXL
                (void)coeff_count;

                // Compute c0^2
                dyadic_product_coeffmod(in[0], in[0], base_size, base, out[0]);

                // Compute 2*c0*c1
                dyadic_product_coeffmod(in[0], in[1], base_size, base, out[1]);
                add_poly_coeffmod(out[1], out[1], base_size, base, out[1]);

                // Compute c1^2
                dyadic_product_coeffmod(in[1], in[1], base_size, base, out[2]);
#else
                for (size_t j = 0; j < base_size; j++)
                {
                    const DyadicMontgomeryReducer reducer(base[j]);
                    const uint64_t *a0 = in[0][j];
                    const uint64_t *a1 = in[1][j];
                    uint64_t *c0 = out[0][j];
                    uint64_t *c1 = out[1][j];
                    uint64_t *c2 = out[2][j];
                    for (size_t l = 0; l < coeff_count; l++)
                    {
                        // With inputs reduced to [0, 2 * modulus), 2 * x0 is below 2^63 and the product 2 * x0 * x1 is
                        // below 8 * modulus^2.
                        const uint64_t x0 = reducer.reduce_input(a0[l]);
                        const uint64_t x1 = reducer.reduce_input(a1[l]);
                        unsigned long long p0[2], p1[2], p2[2];
                        multiply_uint64(x0, x0, p0);
                        multiply_uint64(x0 << 1, x1, p1);
                        multiply_uint64(x1, x1, p2);
                        c0[l] = reducer.reduce(p0[0], p0[1]);
                        c1[l] = reducer.reduce(p1[0], p1[1]);
                        c2[l] = reducer.reduce(p2[0], p2[1]);
                    }
                }
#endif
            }
        } // namespace

        void behz_tensor_product(
            ConstPolyIter in1, size_t in1_size, ConstPolyIter in2, size_t in2_size, ConstModulusIter base,
            size_t base_size, size_t coeff_count, PolyIter out, MemoryPoolHandle pool)
        {
            // The caller passes the same iterators for in1 and in2 when squaring
            const bool is_square = in1_size == in2_size && in1[0][0].ptr() == in2[0][0].ptr();
            if (is_square && in1_size == 2)
            {
                behz_tensor_square_size2(in1, base, base_size, coeff_count, out);
                return;
            }

            size_t dest_size = in1_size + in2_size - 1;
#ifdef SEAL_USE_INTEL_HEXL
            // Use the (HEXL-accelerated) dyadic product, accumulating with modular additions
            SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, pool);
            for (size_t k = 0; k < dest_size; k++)
            {
                size_t in1_last = min<size_t>(k, in1_size - 1);
                size_t in2_first = min<size_t>(k, in2_size - 1);
                size_t in1_first = k - in2_first;
                for (size_t j = 0; j < base_size; j++)
                {
                    dyadic_product_coeffmod(in1[in1_first][j], in2[in2_first][j], coeff_count, base[j], out[k][j]);
                    for (size_t i = in1_first + 1; i <= in1_last; i++)
                    {
                        dyadic_product_coeffmod(in1[i][j], in2[k - i][j], coeff_count, base[j], temp);
                        add_poly_coeffmod(temp, out[k][j], coeff_count, base[j], out[k][j]);
                    }
                }
            }
#else
            (void)pool;
            if (in1_size == 2 && in2_size == 2)
            {
                // Karatsuba: out[1] = (a0 + a1)(b0 + b1) - a0 * b0 - a1 * b1 = a0 * b1 + a1 * b0 exactly as integers.
                // With inputs reduced to [0, 2 * modulus), the sums are below 4 * modulus < 2^63, their product is
                // below 16 * modulus^2 < 2^128, and out[1] is below 8 * modulus^2.
                for (size_t j = 0; j < base_size; j++)
                {
                    const DyadicMontgomeryReducer reducer(base[j]);
                    const uint64_t *a0 = in1[0][j];
                    const uint64_t *a1 = in1[1][j];
                    const uint64_t *b0 = in2[0][j];
                    const uint64_t *b1 = in2[1][j];
                    uint64_t *c0 = out[0][j];
                    uint64_t *c1 = out[1][j];
                    uint64_t *c2 = out[2][j];
                    for (size_t l = 0; l < coeff_count; l++)
                    {
                        const uint64_t x0 = reducer.reduce_input(a0[l]);
                        const uint64_t x1 = reducer.reduce_input(a1[l]);
                        const uint64_t y0 = reducer.reduce_input(b0[l]);
                        const uint64_t y1 = reducer.reduce_input(b1[l]);
                        unsigned long long p0[2], p2[2], pm[2];
                        multiply_uint64(x0, y0, p0);
                        multiply_uint64(x1, y1, p2);
                        multiply_uint64(x0 + x1, y0 + y1, pm);
                        unsigned char borrow = sub_uint64(pm[0], p0[0], pm);
                        pm[1] = pm[1] - p0[1] - borrow;
                        borrow = sub_uint64(pm[0], p2[0], pm);
                        pm[1] = pm[1] - p2[1] - borrow;
                        c0[l] = reducer.reduce(p0[0], p0[1]);
                        c1[l] = reducer.reduce(pm[0], pm[1]);
                        c2[l] = reducer.reduce(p2[0], p2[1]);
                    }
                }
                return;
            }

            if (is_square)
            {
                // out[k] = 2 * sum_{i < k - i} in[i] * in[k - i] + (k even ? in[k / 2]^2 : 0)
                const uint64_t *cross1_ptrs[SEAL_CIPHERTEXT_SIZE_MAX];
                const uint64_t *cross2_ptrs[SEAL_CIPHERTEXT_SIZE_MAX];
                for (size_t k = 0; k < dest_size; k++)
                {
                    // The indices i of the cross terms satisfy i_first <= i < (k + 1) / 2
                    const size_t i_first = k >= in1_size ? k - (in1_size - 1) : 0;
                    const size_t i_end = (k + 1) / 2;
                    const size_t cross_count = i_end > i_first ? i_end - i_first : 0;
                    const bool has_square = !(k & 1);
                    for (size_t j = 0; j < base_size; j++)
                    {
                        const Modulus &modulus = base[j];
                        const DyadicMontgomeryReducer reducer(modulus);
                        for (size_t s = 0; s < cross_count; s++)
                        {
                            cross1_ptrs[s] = in1[i_first + s][j];
                            cross2_ptrs[s] = in1[k - i_first - s][j];
                        }
                        const uint64_t *square_ptr =
                            has_square ? static_cast<const uint64_t *>(in1[k / 2][j]) : nullptr;
                        uint64_t *dest = out[k][j];
                        for (size_t l = 0; l < coeff_count; l++)
                        {
                            uint64_t cross =
                                behz_dot_product(cross1_ptrs, cross2_ptrs, cross_count, l, reducer, modulus);
                            uint64_t result = sub_if_ge_uint64(cross + cross, modulus.value());
                            if (has_square)
                            {
                                const uint64_t x = reducer.reduce_input(square_ptr[l]);
                                unsigned long long prod[2];
                                multiply_uint64(x, x, prod);
                                result = sub_if_ge_uint64(result + reducer.reduce(prod[0], prod[1]), modulus.value());
                            }
                            dest[l] = result;
                        }
                    }
                }
                return;
            }

            const uint64_t *in1_ptrs[SEAL_CIPHERTEXT_SIZE_MAX];
            const uint64_t *in2_ptrs[SEAL_CIPHERTEXT_SIZE_MAX];
            for (size_t k = 0; k < dest_size; k++)
            {
                size_t in1_last = min<size_t>(k, in1_size - 1);
                size_t in2_first = min<size_t>(k, in2_size - 1);
                size_t in1_first = k - in2_first;
                size_t term_count = in1_last - in1_first + 1;
                if (term_count > SEAL_CIPHERTEXT_SIZE_MAX)
                {
                    throw logic_error("invalid ciphertext size");
                }
                for (size_t j = 0; j < base_size; j++)
                {
                    const Modulus &modulus = base[j];
                    const DyadicMontgomeryReducer reducer(modulus);
                    for (size_t s = 0; s < term_count; s++)
                    {
                        in1_ptrs[s] = in1[in1_first + s][j];
                        in2_ptrs[s] = in2[in2_first - s][j];
                    }
                    uint64_t *dest = out[k][j];
                    for (size_t l = 0; l < coeff_count; l++)
                    {
                        dest[l] = behz_dot_product(in1_ptrs, in2_ptrs, term_count, l, reducer, modulus);
                    }
                }
            }
#endif
        }
    } // namespace util
} // namespace seal
