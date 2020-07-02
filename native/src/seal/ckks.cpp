// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ckks.h"
#include <cinttypes>
#include <limits>
#include <random>
#include <stdexcept>

using namespace std;
using namespace seal::util;

namespace seal
{
    CKKSEncoder::CKKSEncoder(shared_ptr<SEALContext> context) : context_(context)
    {
        // Verify parameters
        if (!context_)
        {
            throw invalid_argument("invalid context");
        }
        if (!context_->parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        auto &context_data = *context_->first_context_data();
        if (context_data.parms().scheme() != scheme_type::CKKS)
        {
            throw invalid_argument("unsupported scheme");
        }

        size_t coeff_count = context_data.parms().poly_modulus_degree();
        slots_ = coeff_count >> 1;
        int logn = get_power_of_two(coeff_count);

        matrix_reps_index_map_ = allocate<size_t>(coeff_count, pool_);

        // Copy from the matrix to the value vectors
        uint64_t gen = 3;
        uint64_t pos = 1;
        uint64_t m = static_cast<uint64_t>(coeff_count) << 1;
        for (size_t i = 0; i < slots_; i++)
        {
            // Position in normal bit order
            uint64_t index1 = (pos - 1) >> 1;
            uint64_t index2 = (m - pos - 1) >> 1;

            // Set the bit-reversed locations
            matrix_reps_index_map_[i] = safe_cast<size_t>(reverse_bits(index1, logn));
            matrix_reps_index_map_[slots_ | i] = safe_cast<size_t>(reverse_bits(index2, logn));

            // Next primitive root
            pos *= gen;
            pos &= (m - 1);
        }

        // we need 0~(n-1)-th powers of the primitive 2n-th root, m = 2n
        roots_ = allocate<complex<double>>(coeff_count, pool_);
        inv_roots_ = allocate<complex<double>>(coeff_count, pool_);
        // 0~(n-1)-th powers of the primitive 2n-th root have 4-fold symmetry
        if (m >= 8)
        {
            complex_roots_ = make_shared<util::ComplexRoots>(util::ComplexRoots(static_cast<size_t>(m), pool_));
            for (size_t i = 0; i < coeff_count; i++)
            {
                roots_[i] = complex_roots_->get_root(static_cast<size_t>(reverse_bits(i, logn)));
                inv_roots_[i] = conj(roots_[i]);
            }
        }
        else if (m == 4)
        {
            roots_[0] = { 0, 1 };
            roots_[1] = { 0, -1 };
            inv_roots_[0] = conj(roots_[0]);
            inv_roots_[1] = conj(roots_[1]);
        }
    }

    void CKKSEncoder::encode_internal(
        double value, parms_id_type parms_id, double scale, Plaintext &destination, MemoryPoolHandle pool)
    {
        // Verify parameters.
        auto context_data_ptr = context_->get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.poly_modulus_degree();

        // Quick sanity check
        if (!product_fits_in(coeff_modulus_size, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        // Check that scale is positive and not too large
        if (scale <= 0 || (static_cast<int>(log2(scale)) >= context_data.total_coeff_modulus_bit_count()))
        {
            throw invalid_argument("scale out of bounds");
        }

        // Compute the scaled value
        value *= scale;

        int coeff_bit_count = static_cast<int>(log2(fabs(value))) + 2;
        if (coeff_bit_count >= context_data.total_coeff_modulus_bit_count())
        {
            throw invalid_argument("encoded value is too large");
        }

        double two_pow_64 = pow(2.0, 64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parms_id() = parms_id_zero;
        destination.resize(coeff_count * coeff_modulus_size);

        double coeffd = round(value);
        bool is_negative = signbit(coeffd);
        coeffd = fabs(coeffd);

        // Use faster decomposition methods when possible
        if (coeff_bit_count <= 64)
        {
            uint64_t coeffu = static_cast<uint64_t>(fabs(coeffd));

            if (is_negative)
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(
                        destination.data() + (j * coeff_count), coeff_count,
                        negate_uint_mod(barrett_reduce_64(coeffu, coeff_modulus[j]), coeff_modulus[j]));
                }
            }
            else
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(
                        destination.data() + (j * coeff_count), coeff_count,
                        barrett_reduce_64(coeffu, coeff_modulus[j]));
                }
            }
        }
        else if (coeff_bit_count <= 128)
        {
            uint64_t coeffu[2]{ static_cast<uint64_t>(fmod(coeffd, two_pow_64)),
                                static_cast<uint64_t>(coeffd / two_pow_64) };

            if (is_negative)
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(
                        destination.data() + (j * coeff_count), coeff_count,
                        negate_uint_mod(barrett_reduce_128(coeffu, coeff_modulus[j]), coeff_modulus[j]));
                }
            }
            else
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(
                        destination.data() + (j * coeff_count), coeff_count,
                        barrett_reduce_128(coeffu, coeff_modulus[j]));
                }
            }
        }
        else
        {
            // Slow case
            auto coeffu(allocate_uint(coeff_modulus_size, pool));

            // We are at this point guaranteed to fit in the allocated space
            set_zero_uint(coeff_modulus_size, coeffu.get());
            auto coeffu_ptr = coeffu.get();
            while (coeffd >= 1)
            {
                *coeffu_ptr++ = static_cast<uint64_t>(fmod(coeffd, two_pow_64));
                coeffd /= two_pow_64;
            }

            // Next decompose this coefficient
            context_data.rns_tool()->base_q()->decompose(coeffu.get(), pool);

            // Finally replace the sign if necessary
            if (is_negative)
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(
                        destination.data() + (j * coeff_count), coeff_count,
                        negate_uint_mod(coeffu[j], coeff_modulus[j]));
                }
            }
            else
            {
                for (size_t j = 0; j < coeff_modulus_size; j++)
                {
                    fill_n(destination.data() + (j * coeff_count), coeff_count, coeffu[j]);
                }
            }
        }

        destination.parms_id() = parms_id;
        destination.scale() = scale;
    }

    void CKKSEncoder::encode_internal(int64_t value, parms_id_type parms_id, Plaintext &destination)
    {
        // Verify parameters.
        auto context_data_ptr = context_->get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.poly_modulus_degree();

        // Quick sanity check
        if (!product_fits_in(coeff_modulus_size, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        int coeff_bit_count = get_significant_bit_count(static_cast<uint64_t>(llabs(value))) + 2;
        if (coeff_bit_count >= context_data.total_coeff_modulus_bit_count())
        {
            throw invalid_argument("encoded value is too large");
        }

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parms_id() = parms_id_zero;
        destination.resize(coeff_count * coeff_modulus_size);

        if (value < 0)
        {
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                uint64_t tmp = static_cast<uint64_t>(value);
                tmp += coeff_modulus[j].value();
                tmp = barrett_reduce_64(tmp, coeff_modulus[j]);
                fill_n(destination.data() + (j * coeff_count), coeff_count, tmp);
            }
        }
        else
        {
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                uint64_t tmp = static_cast<uint64_t>(value);
                tmp = barrett_reduce_64(tmp, coeff_modulus[j]);
                fill_n(destination.data() + (j * coeff_count), coeff_count, tmp);
            }
        }

        destination.parms_id() = parms_id;
        destination.scale() = 1.0;
    }
} // namespace seal
