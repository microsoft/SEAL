// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdexcept>
#include <algorithm>
#include <cmath>
#include "seal/intencoder.h"
#include "seal/util/common.h"
#include "seal/util/polyarith.h"
#include "seal/util/pointer.h"
#include "seal/util/defines.h"
#include "seal/util/uintarithsmallmod.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    IntegerEncoder::IntegerEncoder(std::shared_ptr<SEALContext> context) :
        context_(std::move(context))
    {
        // Verify parameters
        if (!context_)
        {
            throw invalid_argument("invalid context");
        }

        // Unlike in other classes, we do not check "context_->parameters_set()".
        // The IntegerEncoder should function without valid encryption parameters
        // as long as the scheme is BFV and the plaintext modulus is at least 2.
        auto &context_data = *context_->first_context_data();
        if (context_data.parms().scheme() != scheme_type::BFV)
        {
            throw invalid_argument("unsupported scheme");
        }
        if (plain_modulus().bit_count() <= 1)
        {
            throw invalid_argument("plain_modulus must be at least 2");
        }

        if (plain_modulus().value() == 2)
        {
            // In this case we don't allow any negative numbers
            coeff_neg_threshold_ = 2;
        }
        else
        {
            // Normal negative threshold case
            coeff_neg_threshold_ = (plain_modulus().value() + 1) >> 1;
        }
        neg_one_ = plain_modulus().value() - 1;
    }

    Plaintext IntegerEncoder::encode(uint64_t value)
    {
        Plaintext result;
        encode(value, result);
        return result;
    }

    void IntegerEncoder::encode(uint64_t value, Plaintext &destination)
    {
        size_t encode_coeff_count = safe_cast<size_t>(
            get_significant_bit_count(value));
        destination.resize(encode_coeff_count);
        destination.set_zero();

        size_t coeff_index = 0;
        while (value != 0)
        {
            if ((value & 1) != 0)
            {
                destination[coeff_index] = 1;
            }
            value >>= 1;
            coeff_index++;
        }
    }

    Plaintext IntegerEncoder::encode(int64_t value)
    {
        Plaintext result;
        encode(value, result);
        return result;
    }

    void IntegerEncoder::encode(int64_t value, Plaintext &destination)
    {
        if (value < 0)
        {
            uint64_t pos_value = static_cast<uint64_t>(-value);
            size_t encode_coeff_count = safe_cast<size_t>(
                get_significant_bit_count(pos_value));
            destination.resize(encode_coeff_count);
            destination.set_zero();

            size_t coeff_index = 0;
            while (pos_value != 0)
            {
                if ((pos_value & 1) != 0)
                {
                    destination[coeff_index] = neg_one_;
                }
                pos_value >>= 1;
                coeff_index++;
            }
        }
        else
        {
            encode(static_cast<uint64_t>(value), destination);
        }
    }

    Plaintext IntegerEncoder::encode(const BigUInt &value)
    {
        Plaintext result;
        encode(value, result);
        return result;
    }

    void IntegerEncoder::encode(const BigUInt &value, Plaintext &destination)
    {
        size_t encode_coeff_count = safe_cast<size_t>(
            value.significant_bit_count());
        destination.resize(encode_coeff_count);
        destination.set_zero();

        size_t coeff_index = 0;
        size_t coeff_count = safe_cast<size_t>(value.significant_bit_count());
        size_t coeff_uint64_count = value.uint64_count();
        while (coeff_index < coeff_count)
        {
            if (is_bit_set_uint(value.data(), coeff_uint64_count,
                safe_cast<int>(coeff_index)))
            {
                destination[coeff_index] = 1;
            }
            coeff_index++;
        }
    }

    uint32_t IntegerEncoder::decode_uint32(const Plaintext &plain)
    {
        uint64_t value64 = decode_uint64(plain);
        if (value64 > UINT32_MAX)
        {
            throw invalid_argument("output out of range");
        }
        return static_cast<uint32_t>(value64);
    }

    uint64_t IntegerEncoder::decode_uint64(const Plaintext &plain)
    {
        BigUInt bigvalue = decode_biguint(plain);
        int bit_count = bigvalue.significant_bit_count();
        if (bit_count > bits_per_uint64)
        {
            // Decoded value has more bits than fit in a 64-bit uint.
            throw invalid_argument("output out of range");
        }
        return bit_count > 0 ? bigvalue.data()[0] : 0;
    }

    int32_t IntegerEncoder::decode_int32(const Plaintext &plain)
    {
        int64_t value64 = decode_int64(plain);
        return safe_cast<int32_t>(value64);
    }

    int64_t IntegerEncoder::decode_int64(const Plaintext &plain)
    {
        int64_t result = 0;
        for (size_t bit_index = plain.significant_coeff_count(); bit_index--; )
        {
            unsigned long long coeff = plain[bit_index];

            // Left shift result.
            int64_t next_result = result << 1;
            if ((next_result < 0) != (result < 0))
            {
                // Check for overflow.
                throw invalid_argument("output out of range");
            }

            // Get sign/magnitude of coefficient.
            int coeff_bit_count = get_significant_bit_count(coeff);
            if (coeff >= plain_modulus().value())
            {
                // Coefficient is bigger than plaintext modulus
                throw invalid_argument("plain does not represent a valid plaintext polynomial");
            }
            bool coeff_is_negative = coeff >= coeff_neg_threshold_;
            unsigned long long pos_value = coeff;
            if (coeff_is_negative)
            {
                pos_value = plain_modulus().value() - pos_value;
                coeff_bit_count = get_significant_bit_count(pos_value);
            }

            if (coeff_bit_count > bits_per_uint64 - 1)
            {
                // Absolute value of coefficient is too large to represent in a int64_t, so overflow.
                throw invalid_argument("output out of range");
            }

            int64_t coeff_value = safe_cast<int64_t>(pos_value);
            if (coeff_is_negative)
            {
                coeff_value = -coeff_value;
            }
            bool next_result_was_negative = next_result < 0;
            next_result += coeff_value;
            bool next_result_is_negative = next_result < 0;
            if ((next_result_was_negative == coeff_is_negative) &&
                (next_result_was_negative != next_result_is_negative))
            {
                // Accumulation and coefficient had same signs, but accumulator changed signs after addition, so must be overflow.
                throw invalid_argument("output out of range");
            }
            result = next_result;
        }
        return result;
    }

    BigUInt IntegerEncoder::decode_biguint(const Plaintext &plain)
    {
        size_t result_uint64_count = 1;
        size_t bits_per_uint64_sz = safe_cast<size_t>(bits_per_uint64);
        size_t result_bit_capacity = result_uint64_count * bits_per_uint64_sz;
        BigUInt resultint(safe_cast<int>(result_bit_capacity));
        bool result_is_negative = false;
        uint64_t *result = resultint.data();
        for (size_t bit_index = plain.significant_coeff_count(); bit_index--; )
        {
            unsigned long long coeff = plain[bit_index];

            // Left shift result, resizing if highest bit set.
            if (is_bit_set_uint(result, result_uint64_count,
                safe_cast<int>(result_bit_capacity) - 1))
            {
                // Resize to make bigger.
                result_uint64_count++;
                result_bit_capacity = mul_safe(result_uint64_count, bits_per_uint64_sz);
                resultint.resize(safe_cast<int>(result_bit_capacity));
                result = resultint.data();
            }
            left_shift_uint(result, 1, result_uint64_count, result);

            // Get sign/magnitude of coefficient.
            if (coeff >= plain_modulus().value())
            {
                // Coefficient is bigger than plaintext modulus
                throw invalid_argument("plain does not represent a valid plaintext polynomial");
            }
            bool coeff_is_negative = coeff >= coeff_neg_threshold_;
            unsigned long long pos_value = coeff;
            if (coeff_is_negative)
            {
                pos_value = plain_modulus().value() - pos_value;
            }

            // Add or subtract-in coefficient.
            if (result_is_negative == coeff_is_negative)
            {
                // Result and coefficient have same signs so add.
                if (add_uint_uint64(result, pos_value, result_uint64_count, result))
                {
                    // Add produced a carry that didn't fit, so resize and put it in.
                    int carry_bit_index = safe_cast<int>(mul_safe(
                        result_uint64_count, bits_per_uint64_sz));
                    result_uint64_count++;
                    result_bit_capacity = mul_safe(
                        result_uint64_count, bits_per_uint64_sz);
                    resultint.resize(safe_cast<int>(result_bit_capacity));
                    result = resultint.data();
                    set_bit_uint(result, result_uint64_count, carry_bit_index);
                }
            }
            else
            {
                // Result and coefficient have opposite signs so subtract.
                if (sub_uint_uint64(result, pos_value, result_uint64_count, result))
                {
                    // Subtraction produced a borrow so coefficient is larger (in magnitude)
                    // than result, so need to negate result.
                    negate_uint(result, result_uint64_count, result);
                    result_is_negative = !result_is_negative;
                }
            }
        }

        // Verify result is non-negative.
        if (result_is_negative && !resultint.is_zero())
        {
            throw invalid_argument("poly must decode to positive value");
        }
        return resultint;
    }
}
