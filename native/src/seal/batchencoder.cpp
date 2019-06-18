// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdexcept>
#include <cstdlib>
#include <random>
#include <limits>
#include "seal/batchencoder.h"
#include "seal/util/polycore.h"
#include "seal/valcheck.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    BatchEncoder::BatchEncoder(std::shared_ptr<SEALContext> context) :
        context_(std::move(context))
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
        if (context_data.parms().scheme() != scheme_type::BFV)
        {
            throw invalid_argument("unsupported scheme");
        }
        if (!context_data.qualifiers().using_batching)
        {
            throw invalid_argument("encryption parameters are not valid for batching");
        }

        // Set the slot count
        slots_ = context_data.parms().poly_modulus_degree();

        // Reserve space for all of the primitive roots
        roots_of_unity_ = allocate_uint(slots_, pool_);

        // Fill the vector of roots of unity with all distinct odd powers of generator.
        // These are all the primitive (2*slots_)-th roots of unity in integers modulo
        // parms.plain_modulus().
        populate_roots_of_unity_vector(context_data);

        // Populate matrix representation index map
        populate_matrix_reps_index_map();
    }

    void BatchEncoder::populate_roots_of_unity_vector(
        const SEALContext::ContextData &context_data)
    {
        uint64_t root = context_data.plain_ntt_tables()->get_root();
        auto &modulus = context_data.parms().plain_modulus();

        uint64_t generator_sq = multiply_uint_uint_mod(root, root, modulus);
        roots_of_unity_[0] = root;

        for (size_t i = 1; i < slots_; i++)
        {
            roots_of_unity_[i] = multiply_uint_uint_mod(roots_of_unity_[i - 1],
                generator_sq, modulus);
        }
    }

    void BatchEncoder::populate_matrix_reps_index_map()
    {
        int logn = get_power_of_two(slots_);
        matrix_reps_index_map_ = allocate_uint(slots_, pool_);

        // Copy from the matrix to the value vectors
        size_t row_size = slots_ >> 1;
        size_t m = slots_ << 1;
        uint64_t gen = 3;
        uint64_t pos = 1;
        for (size_t i = 0; i < row_size; i++)
        {
            // Position in normal bit order
            uint64_t index1 = (pos - 1) >> 1;
            uint64_t index2 = (m - pos - 1) >> 1;

            // Set the bit-reversed locations
            matrix_reps_index_map_[i] = util::reverse_bits(index1, logn);
            matrix_reps_index_map_[row_size | i] = util::reverse_bits(index2, logn);

            // Next primitive root
            pos *= gen;
            pos &= (m - 1);
        }
    }

    void BatchEncoder::reverse_bits(uint64_t *input)
    {
#ifdef SEAL_DEBUG
        if (input == nullptr)
        {
            throw invalid_argument("input cannot be null");
        }
#endif
        size_t coeff_count = context_->first_context_data()->parms().poly_modulus_degree();
        int logn = get_power_of_two(coeff_count);
        for (size_t i = 0; i < coeff_count; i++)
        {
            uint64_t reversed_i = util::reverse_bits(i, logn);
            if (i < reversed_i)
            {
                swap(input[i], input[reversed_i]);
            }
        }
    }

    void BatchEncoder::encode(const vector<uint64_t> &values_matrix,
        Plaintext &destination)
    {
        auto &context_data = *context_->first_context_data();

        // Validate input parameters
        size_t values_matrix_size = values_matrix.size();
        if (values_matrix_size > slots_)
        {
            throw logic_error("values_matrix size is too large");
        }
#ifdef SEAL_DEBUG
        uint64_t modulus = context_data.parms().plain_modulus().value();
        for (auto v : values_matrix)
        {
            // Validate the i-th input
            if (v >= modulus)
            {
                throw invalid_argument("input value is larger than plain_modulus");
            }
        }
#endif
        // Set destination to full size
        destination.resize(slots_);
        destination.parms_id() = parms_id_zero;

        // First write the values to destination coefficients.
        // Read in top row, then bottom row.
        for (size_t i = 0; i < values_matrix_size; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) = values_matrix[i];
        }
        for (size_t i = values_matrix_size; i < slots_; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) = 0;
        }

        // Transform destination using inverse of negacyclic NTT
        // Note: We already performed bit-reversal when reading in the matrix
        inverse_ntt_negacyclic_harvey(destination.data(), *context_data.plain_ntt_tables());
    }

    void BatchEncoder::encode(const vector<int64_t> &values_matrix,
        Plaintext &destination)
    {
        auto &context_data = *context_->first_context_data();
        uint64_t modulus = context_data.parms().plain_modulus().value();

        // Validate input parameters
        size_t values_matrix_size = values_matrix.size();
        if (values_matrix_size > slots_)
        {
            throw logic_error("values_matrix size is too large");
        }
#ifdef SEAL_DEBUG
        uint64_t plain_modulus_div_two = modulus >> 1;
        for (auto v : values_matrix)
        {
            // Validate the i-th input
            if (unsigned_gt(llabs(v), plain_modulus_div_two))
            {
                throw invalid_argument("input value is larger than plain_modulus");
            }
        }
#endif
        // Set destination to full size
        destination.resize(slots_);
        destination.parms_id() = parms_id_zero;

        // First write the values to destination coefficients.
        // Read in top row, then bottom row.
        for (size_t i = 0; i < values_matrix_size; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) =
                (values_matrix[i] < 0) ? (modulus + static_cast<uint64_t>(values_matrix[i])) :
                    static_cast<uint64_t>(values_matrix[i]);
        }
        for (size_t i = values_matrix_size; i < slots_; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) = 0;
        }

        // Transform destination using inverse of negacyclic NTT
        // Note: We already performed bit-reversal when reading in the matrix
        inverse_ntt_negacyclic_harvey(destination.data(), *context_data.plain_ntt_tables());
    }
#ifdef SEAL_USE_MSGSL_SPAN
    void BatchEncoder::encode(gsl::span<const uint64_t> values_matrix,
        Plaintext &destination)
    {
        auto &context_data = *context_->first_context_data();

        // Validate input parameters
        size_t values_matrix_size = static_cast<size_t>(values_matrix.size());
        if (values_matrix_size > slots_)
        {
            throw logic_error("values_matrix size is too large");
        }
#ifdef SEAL_DEBUG
        uint64_t modulus = context_data.parms().plain_modulus().value();
        for (auto v : values_matrix)
        {
            // Validate the i-th input
            if (v >= modulus)
            {
                throw invalid_argument("input value is larger than plain_modulus");
            }
        }
#endif
        // Set destination to full size
        destination.resize(slots_);
        destination.parms_id() = parms_id_zero;

        // First write the values to destination coefficients. Read
        // in top row, then bottom row.
        using index_type = decltype(values_matrix)::index_type;
        for (size_t i = 0; i < values_matrix_size; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) =
                values_matrix[static_cast<index_type>(i)];
        }
        for (size_t i = values_matrix_size; i < slots_; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) = 0;
        }

        // Transform destination using inverse of negacyclic NTT
        // Note: We already performed bit-reversal when reading in the matrix
        inverse_ntt_negacyclic_harvey(destination.data(), *context_data.plain_ntt_tables());
    }

    void BatchEncoder::encode(gsl::span<const int64_t> values_matrix,
        Plaintext &destination)
    {
        auto &context_data = *context_->first_context_data();
        uint64_t modulus = context_data.parms().plain_modulus().value();

        // Validate input parameters
        size_t values_matrix_size = static_cast<size_t>(values_matrix.size());
        if (values_matrix_size > slots_)
        {
            throw logic_error("values_matrix size is too large");
        }
#ifdef SEAL_DEBUG
        uint64_t plain_modulus_div_two = modulus >> 1;
        for (auto v : values_matrix)
        {
            // Validate the i-th input
            if (unsigned_gt(llabs(v), plain_modulus_div_two))
            {
                throw invalid_argument("input value is larger than plain_modulus");
            }
        }
#endif
        // Set destination to full size
        destination.resize(slots_);
        destination.parms_id() = parms_id_zero;

        // First write the values to destination coefficients. Read
        // in top row, then bottom row.
        using index_type = decltype(values_matrix)::index_type;
        for (size_t i = 0; i < values_matrix_size; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) =
                (values_matrix[static_cast<index_type>(i)] < 0) ?
                (modulus + static_cast<uint64_t>(values_matrix[static_cast<index_type>(i)])) :
                static_cast<uint64_t>(values_matrix[static_cast<index_type>(i)]);
        }
        for (size_t i = values_matrix_size; i < slots_; i++)
        {
            *(destination.data() + matrix_reps_index_map_[i]) = 0;
        }

        // Transform destination using inverse of negacyclic NTT
        // Note: We already performed bit-reversal when reading in the matrix
        inverse_ntt_negacyclic_harvey(destination.data(), *context_data.plain_ntt_tables());
    }
#endif
    void BatchEncoder::encode(Plaintext &plain, MemoryPoolHandle pool)
    {
        if (plain.is_ntt_form())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_->first_context_data();

        // Validate input parameters
        if (plain.coeff_count() > context_data.parms().poly_modulus_degree())
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#ifdef SEAL_DEBUG
        if (!are_poly_coefficients_less_than(plain.data(),
            plain.coeff_count(), context_data.parms().plain_modulus().value()))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#endif
        // We need to permute the coefficients of plain. To do this, we allocate
        // temporary space.
        size_t input_plain_coeff_count = min(plain.coeff_count(), slots_);
        auto temp(allocate_uint(input_plain_coeff_count, pool));
        set_uint_uint(plain.data(), input_plain_coeff_count, temp.get());

        // Set plain to full slot count size.
        plain.resize(slots_);
        plain.parms_id() = parms_id_zero;

        // First write the values to destination coefficients. Read
        // in top row, then bottom row.
        for (size_t i = 0; i < input_plain_coeff_count; i++)
        {
            *(plain.data() + matrix_reps_index_map_[i]) = temp[i];
        }
        for (size_t i = input_plain_coeff_count; i < slots_; i++)
        {
            *(plain.data() + matrix_reps_index_map_[i]) = 0;
        }

        // Transform destination using inverse of negacyclic NTT
        // Note: We already performed bit-reversal when reading in the matrix
        inverse_ntt_negacyclic_harvey(plain.data(), *context_data.plain_ntt_tables());
    }

    void BatchEncoder::decode(const Plaintext &plain, vector<uint64_t> &destination,
        MemoryPoolHandle pool)
    {
        if (!is_valid_for(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (plain.is_ntt_form())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_->first_context_data();

        // Set destination size
        destination.resize(slots_);

        // Never include the leading zero coefficient (if present)
        size_t plain_coeff_count = min(plain.coeff_count(), slots_);

        auto temp_dest(allocate_uint(slots_, pool));

        // Make a copy of poly
        set_uint_uint(plain.data(), plain_coeff_count, temp_dest.get());
        set_zero_uint(slots_ - plain_coeff_count, temp_dest.get() + plain_coeff_count);

        // Transform destination using negacyclic NTT.
        ntt_negacyclic_harvey(temp_dest.get(), *context_data.plain_ntt_tables());

        // Read top row
        for (size_t i = 0; i < slots_; i++)
        {
            destination[i] = temp_dest[matrix_reps_index_map_[i]];
        }
    }

    void BatchEncoder::decode(const Plaintext &plain, vector<int64_t> &destination,
        MemoryPoolHandle pool)
    {
        if (!is_valid_for(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (plain.is_ntt_form())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_->first_context_data();
        uint64_t modulus = context_data.parms().plain_modulus().value();

        // Set destination size
        destination.resize(slots_);

        // Never include the leading zero coefficient (if present)
        size_t plain_coeff_count = min(plain.coeff_count(), slots_);

        auto temp_dest(allocate_uint(slots_, pool));

        // Make a copy of poly
        set_uint_uint(plain.data(), plain_coeff_count, temp_dest.get());
        set_zero_uint(slots_ - plain_coeff_count, temp_dest.get() + plain_coeff_count);

        // Transform destination using negacyclic NTT.
        ntt_negacyclic_harvey(temp_dest.get(), *context_data.plain_ntt_tables());

        // Read top row, then bottom row
        uint64_t plain_modulus_div_two = modulus >> 1;
        for (size_t i = 0; i < slots_; i++)
        {
            uint64_t curr_value = temp_dest[matrix_reps_index_map_[i]];
            destination[i] = (curr_value > plain_modulus_div_two) ?
                (static_cast<int64_t>(curr_value) - static_cast<int64_t>(modulus)) :
                static_cast<int64_t>(curr_value);
        }
    }
#ifdef SEAL_USE_MSGSL_SPAN
    void BatchEncoder::decode(const Plaintext &plain, gsl::span<uint64_t> destination,
        MemoryPoolHandle pool)
    {
        if (!is_valid_for(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (plain.is_ntt_form())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_->first_context_data();

        using index_type = decltype(destination)::index_type;
        if(unsigned_gt(destination.size(), numeric_limits<int>::max()) ||
            unsigned_neq(destination.size(), slots_))
        {
            throw invalid_argument("destination has incorrect size");
        }

        // Never include the leading zero coefficient (if present)
        size_t plain_coeff_count = min(plain.coeff_count(), slots_);

        auto temp_dest(allocate_uint(slots_, pool));

        // Make a copy of poly
        set_uint_uint(plain.data(), plain_coeff_count, temp_dest.get());
        set_zero_uint(slots_ - plain_coeff_count, temp_dest.get() + plain_coeff_count);

        // Transform destination using negacyclic NTT.
        ntt_negacyclic_harvey(temp_dest.get(), *context_data.plain_ntt_tables());

        // Read top row
        for (size_t i = 0; i < slots_; i++)
        {
            destination[static_cast<index_type>(i)] = temp_dest[matrix_reps_index_map_[i]];
        }
    }

    void BatchEncoder::decode(const Plaintext &plain, gsl::span<int64_t> destination,
        MemoryPoolHandle pool)
    {
        if (!is_valid_for(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (plain.is_ntt_form())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_->first_context_data();
        uint64_t modulus = context_data.parms().plain_modulus().value();

        using index_type = decltype(destination)::index_type;
        if(unsigned_gt(destination.size(), numeric_limits<int>::max()) ||
            unsigned_neq(destination.size(), slots_))
        {
            throw invalid_argument("destination has incorrect size");
        }

        // Never include the leading zero coefficient (if present)
        size_t plain_coeff_count = min(plain.coeff_count(), slots_);

        auto temp_dest(allocate_uint(slots_, pool));

        // Make a copy of poly
        set_uint_uint(plain.data(), plain_coeff_count, temp_dest.get());
        set_zero_uint(slots_ - plain_coeff_count, temp_dest.get() + plain_coeff_count);

        // Transform destination using negacyclic NTT.
        ntt_negacyclic_harvey(temp_dest.get(), *context_data.plain_ntt_tables());

        // Read top row, then bottom row
        uint64_t plain_modulus_div_two = modulus >> 1;
        for (size_t i = 0; i < slots_; i++)
        {
            uint64_t curr_value = temp_dest[matrix_reps_index_map_[i]];
            destination[static_cast<index_type>(i)] = (curr_value > plain_modulus_div_two) ?
                    (static_cast<int64_t>(curr_value) - static_cast<int64_t>(modulus)) :
                    static_cast<int64_t>(curr_value);
        }
    }
#endif
    void BatchEncoder::decode(Plaintext &plain, MemoryPoolHandle pool)
    {
        if (!is_valid_for(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (plain.is_ntt_form())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_->first_context_data();

        // Never include the leading zero coefficient (if present)
        size_t plain_coeff_count = min(plain.coeff_count(), slots_);

        // Allocate temporary space to store a wide copy of plain
        auto temp(allocate_uint(slots_, pool));

        // Make a copy of poly
        set_uint_uint(plain.data(), plain_coeff_count, temp.get());
        set_zero_uint(slots_ - plain_coeff_count, temp.get() + plain_coeff_count);

        // Transform destination using negacyclic NTT.
        ntt_negacyclic_harvey(temp.get(), *context_data.plain_ntt_tables());

        // Set plain to full slot count size (note that all new coefficients are
        // set to zero).
        plain.resize(slots_);

        // Read top row, then bottom row
        for (size_t i = 0; i < slots_; i++)
        {
            *(plain.data() + i) = temp[matrix_reps_index_map_[i]];
        }
    }
}