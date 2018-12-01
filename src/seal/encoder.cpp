// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdexcept>
#include <algorithm>
#include <cmath>
#include "seal/encoder.h"
#include "seal/util/common.h"
#include "seal/util/polyarith.h"
#include "seal/util/pointer.h"
#include "seal/util/defines.h"
#include "seal/util/uintarithsmallmod.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    BinaryEncoder::BinaryEncoder(const SmallModulus &plain_modulus) :
        plain_modulus_(plain_modulus),
        coeff_neg_threshold_((plain_modulus.value() + 1) >> 1),
        neg_one_(plain_modulus_.value() - 1)
    {
        if (plain_modulus.bit_count() <= 1)
        {
            throw invalid_argument("plain_modulus must be at least 2");
        }
    }

    Plaintext BinaryEncoder::encode(uint64_t value)
    {
        Plaintext result;
        encode(value, result);
        return result;
    }

    void BinaryEncoder::encode(uint64_t value, Plaintext &destination)
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

    Plaintext BinaryEncoder::encode(int64_t value)
    {
        Plaintext result;
        encode(value, result);
        return result;
    }

    void BinaryEncoder::encode(int64_t value, Plaintext &destination)
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

    Plaintext BinaryEncoder::encode(const BigUInt &value)
    {
        Plaintext result;
        encode(value, result);
        return result;
    }

    void BinaryEncoder::encode(const BigUInt &value, Plaintext &destination)
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

    uint32_t BinaryEncoder::decode_uint32(const Plaintext &plain)
    {
        uint64_t value64 = decode_uint64(plain);
        if (value64 > UINT32_MAX)
        {
            throw invalid_argument("output out of range");
        }
        return static_cast<uint32_t>(value64);
    }

    uint64_t BinaryEncoder::decode_uint64(const Plaintext &plain)
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

    int32_t BinaryEncoder::decode_int32(const Plaintext &plain)
    {
        int64_t value64 = decode_int64(plain);
        return safe_cast<int32_t>(value64);
    }

    int64_t BinaryEncoder::decode_int64(const Plaintext &plain)
    {
        unsigned long long pos_value;

        // Determine coefficient threshold for negative numbers.
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
            if (coeff >= plain_modulus_.value())
            {
                // Coefficient is bigger than plaintext modulus
                throw invalid_argument("plain does not represent a valid plaintext polynomial");
            }
            bool coeff_is_negative = coeff >= coeff_neg_threshold_;
            const unsigned long long *pos_pointer;
            if (coeff_is_negative)
            {
                if (sub_uint64(plain_modulus_.value(), coeff, 0, &pos_value))
                {
                    // Check for borrow, which means value is greater than plain_modulus.
                    throw invalid_argument("plain does not represent a valid plaintext polynomial");
                }
                pos_pointer = &pos_value;
                coeff_bit_count = get_significant_bit_count(pos_value);
            }
            else
            {
                pos_pointer = &coeff;
            }
            if (coeff_bit_count > bits_per_uint64 - 1)
            {
                // Absolute value of coefficient is too large to represent in a int64_t, so overflow.
                throw invalid_argument("output out of range");
            }
            int64_t coeff_value = safe_cast<int64_t>(*pos_pointer);
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

    BigUInt BinaryEncoder::decode_biguint(const Plaintext &plain)
    {
        unsigned long long pos_value;

        // Determine coefficient threshold for negative numbers.
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
            if (coeff >= plain_modulus_.value())
            {
                // Coefficient is bigger than plaintext modulus
                throw invalid_argument("plain does not represent a valid plaintext polynomial");
            }
            bool coeff_is_negative = coeff >= coeff_neg_threshold_;
            const unsigned long long *pos_pointer;
            if (coeff_is_negative)
            {
                if (sub_uint64(plain_modulus_.value(), coeff, 0, &pos_value))
                {
                    // Check for borrow, which means value is greater than plain_modulus.
                    throw invalid_argument("plain does not represent a valid plaintext polynomial");
                }
                pos_pointer = &pos_value;
            }
            else
            {
                pos_pointer = &coeff;
            }

            // Add or subtract-in coefficient.
            if (result_is_negative == coeff_is_negative)
            {
                // Result and coefficient have same signs so add.
                if (add_uint_uint64(result, *pos_pointer, result_uint64_count, result))
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
                if (sub_uint_uint64(result, *pos_pointer, result_uint64_count, result))
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

    void BinaryEncoder::decode_biguint(const Plaintext &plain, BigUInt &destination)
    {
        unsigned long long pos_value;

        // Determine coefficient threshold for negative numbers.
        destination.set_zero();
        size_t bits_per_uint64_sz = static_cast<size_t>(bits_per_uint64);
        size_t result_uint64_count = destination.uint64_count();
        size_t result_bit_capacity = result_uint64_count * bits_per_uint64_sz;
        bool result_is_negative = false;
        uint64_t *result = destination.data();
        for (size_t bit_index = plain.significant_coeff_count(); bit_index--; )
        {
            unsigned long long coeff = plain[bit_index];

            // Left shift result, failing if highest bit set.
            if (is_bit_set_uint(result, result_uint64_count, 
                safe_cast<int>(result_bit_capacity) - 1))
            {
                throw invalid_argument("plain does not represent a valid plaintext polynomial");
            }
            left_shift_uint(result, 1, result_uint64_count, result);

            // Get sign/magnitude of coefficient.
            if (coeff >= plain_modulus_.value())
            {
                // Coefficient is bigger than plaintext modulus.
                throw invalid_argument("plain does not represent a valid plaintext polynomial");
            }
            bool coeff_is_negative = coeff >= coeff_neg_threshold_;
            const unsigned long long *pos_pointer;
            if (coeff_is_negative)
            {
                if (sub_uint64(plain_modulus_.value(), coeff, 0, &pos_value))
                {
                    // Check for borrow, which means value is greater than plain_modulus.
                    throw invalid_argument("plain does not represent a valid plaintext polynomial"); 
                }
                pos_pointer = &pos_value;
            }
            else
            {
                pos_pointer = &coeff;
            }

            // Add or subtract-in coefficient.
            if (result_is_negative == coeff_is_negative)
            {
                // Result and coefficient have same signs so add.
                if (add_uint_uint64(result, *pos_pointer, result_uint64_count, result))
                {
                    // Add produced a carry that didn't fit.
                    throw invalid_argument("output out of range");
                }
            }
            else
            {
                // Result and coefficient have opposite signs so subtract.
                if (sub_uint_uint64(result, *pos_pointer, result_uint64_count, result))
                {
                    // Subtraction produced a borrow so coefficient is larger (in magnitude) 
                    // than result, so need to negate result.
                    negate_uint(result, result_uint64_count, result);
                    result_is_negative = !result_is_negative;
                }
            }
        }

        // Verify result is non-negative.
        if (result_is_negative && !destination.is_zero())
        {
            throw invalid_argument("poly must decode to a positive value");
        }

        // Verify result fits in actual bit-width (as opposed to capacity) of destination.
        if (destination.significant_bit_count() > destination.bit_count())
        {
            throw invalid_argument("output out of range");
        }
    }

    BalancedEncoder::BalancedEncoder(const SmallModulus &plain_modulus, uint64_t base) : 
        plain_modulus_(plain_modulus), 
        base_(base),
        coeff_neg_threshold_((plain_modulus.value() + 1) >> 1)
    {
        if (base <= 2)
        {
            throw invalid_argument("base must be at least 3");
        }
        if (*plain_modulus.data() < base)
        {
            throw invalid_argument("plain_modulus must be at least b");
        }
    }

    Plaintext BalancedEncoder::encode(uint64_t value)
    {
        Plaintext result;
        encode(value, result);

        return result;
    }

    void BalancedEncoder::encode(uint64_t value, Plaintext &destination)
    {
        // We estimate the number of coefficients in the expansion
        size_t encode_coeff_count = static_cast<size_t>(ceil(
            static_cast<double>(get_significant_bit_count(value)) / log2(base_)) + 1);
        destination.resize(encode_coeff_count);
        destination.set_zero();

        size_t coeff_index = 0;
        while (value)
        {
            uint64_t remainder = value % base_;
            if (0 < remainder && remainder <= (base_ - 1) / 2)
            {
                destination[coeff_index] = remainder;
            }
            else if (remainder > (base_ - 1) / 2)
            {
                destination[coeff_index] = plain_modulus_.value() - base_ + remainder;
            }
            value = (value + base_ / 2) / base_;

            coeff_index++;
        }
    }

    Plaintext BalancedEncoder::encode(int64_t value)
    {
        Plaintext result;
        encode(value, result);
        return result;
    }

    void BalancedEncoder::encode(int64_t value, Plaintext &destination)
    {
        if (value < 0)
        {
            uint64_t pos_value = static_cast<uint64_t>(-value);

            // We estimate the number of coefficients in the expansion
            size_t encode_coeff_count = static_cast<size_t>(ceil(
                static_cast<double>(get_significant_bit_count(pos_value)) / log2(base_)) + 1);
            destination.resize(encode_coeff_count);
            destination.set_zero();

            size_t coeff_index = 0;
            while (pos_value)
            {
                uint64_t remainder = pos_value % base_;
                if (0 < remainder && remainder <= (base_ - 1) / 2)
                {
                    destination[coeff_index] = plain_modulus_.value() - remainder;
                }
                else if (remainder > (base_ - 1) / 2)
                {
                    destination[coeff_index] = base_ - remainder;

                    if ((base_ % 2 == 0) && (remainder == base_ / 2))
                    {
                        destination[coeff_index] = 
                            plain_modulus_.value() - destination[coeff_index];
                    }
                }

                // Note that we are adding now (base_-1)/2 instead of base_/2 as in the even case, 
                // because value is negative.
                pos_value = (pos_value + ((base_ - 1) / 2)) / base_;

                coeff_index++;
            }
        }
        else
        {
            encode(static_cast<uint64_t>(value), destination);
        }
    }

    Plaintext BalancedEncoder::encode(const BigUInt &value)
    {
        Plaintext result;
        encode(value, result);
        return result;
    }

    void BalancedEncoder::encode(const BigUInt &value, Plaintext &destination)
    {
        if (value.is_zero())
        {
            destination.set_zero();
            return;
        }

        // We estimate the number of coefficients in the expansion
        size_t bits_per_uint64_sz = static_cast<size_t>(bits_per_uint64);
        size_t encode_coeff_count = static_cast<size_t>(ceil(
            static_cast<double>(value.significant_bit_count()) / log2(base_)) + 1);
        size_t encode_uint64_count = 
            divide_round_up(encode_coeff_count, bits_per_uint64_sz);

        destination.resize(encode_coeff_count);
        destination.set_zero();

        auto base_uint(allocate_uint(encode_uint64_count, pool_));
        set_uint(base_, encode_uint64_count, base_uint.get());
        auto base_div_two_uint(allocate_uint(encode_uint64_count, pool_));
        right_shift_uint(base_uint.get(), 1, encode_uint64_count, base_div_two_uint.get());
        uint64_t mod_minus_base = plain_modulus_.value() - base_;

        auto quotient(allocate_uint(encode_uint64_count, pool_));
        auto remainder(allocate_uint(encode_uint64_count, pool_));
        auto temp(allocate_uint(value.uint64_count(), pool_));
        set_uint_uint(value.data(), value.uint64_count(), temp.get());

        size_t coeff_index = 0;
        while (!is_zero_uint(temp.get(), value.uint64_count()))
        {
            divide_uint_uint(temp.get(), base_uint.get(), encode_uint64_count, 
                quotient.get(), remainder.get(), pool_);
            uint64_t *dest_coeff = destination.data() + coeff_index;
            if (is_greater_than_uint_uint(remainder.get(), base_div_two_uint.get(), 
                encode_uint64_count))
            {
                *dest_coeff = mod_minus_base + remainder[0];
            }
            else if (!is_zero_uint(remainder.get(), encode_uint64_count))
            {
                *dest_coeff = remainder[0];
            }
            add_uint_uint(temp.get(), base_div_two_uint.get(), encode_uint64_count, temp.get());
            divide_uint_uint(temp.get(), base_uint.get(), encode_uint64_count, 
                quotient.get(), remainder.get(), pool_);
            set_uint_uint(quotient.get(), encode_uint64_count, temp.get());

            coeff_index++;
        }
    }

    uint32_t BalancedEncoder::decode_uint32(const Plaintext &plain)
    {
        return safe_cast<uint32_t>(decode_uint64(plain));
    }

    uint64_t BalancedEncoder::decode_uint64(const Plaintext &plain)
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

    int32_t BalancedEncoder::decode_int32(const Plaintext &plain)
    {
        return safe_cast<int32_t>(decode_int64(plain));
    }

    int64_t BalancedEncoder::decode_int64(const Plaintext &plain)
    {
        unsigned long long pos_value;

        // Determine coefficient threshold for negative numbers.
        int64_t result = 0;
        int64_t base_int = safe_cast<int64_t>(base_);
        for (size_t bit_index = plain.significant_coeff_count(); bit_index--; )
        {
            unsigned long long coeff = plain[bit_index];

            // Multiply result by base.
            int64_t next_result = mul_safe(result, base_int);

            // Get sign/magnitude of coefficient.
            int coeff_bit_count = get_significant_bit_count(coeff);
            if (coeff >= plain_modulus_.value())
            {
                // Coefficient is bigger than plaintext modulus
                throw invalid_argument("plain does not represent a valid plaintext polynomial");
            }
            bool coeff_is_negative = coeff >= coeff_neg_threshold_;
            const unsigned long long *pos_pointer;
            if (coeff_is_negative)
            {
                if (sub_uint64(plain_modulus_.value(), coeff, 0, &pos_value))
                {
                    // Check for borrow, which means value is greater than plain_modulus.
                    throw invalid_argument("plain does not represent a valid plaintext polynomial");
                }
                pos_pointer = &pos_value;
                coeff_bit_count = get_significant_bit_count(pos_value);
            }
            else
            {
                pos_pointer = &coeff;
            }
            if (coeff_bit_count > bits_per_uint64 - 1)
            {
                // Absolute value of coefficient is too large to represent in a int64_t, so overflow.
                throw invalid_argument("output out of range");
            }
            int64_t coeff_value = static_cast<int64_t>(*pos_pointer);
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
                // Accumulation and coefficient had same signs, but accumulator changed signs after 
                // addition, so must be overflow.
                throw invalid_argument("output out of range");
            }
            result = next_result;
        }
        return result;
    }

    BigUInt BalancedEncoder::decode_biguint(const Plaintext &plain)
    {
        // Determine plain_modulus width.
        unsigned long long pos_value;

        // Determine coefficient threshold for negative numbers.
        size_t bits_per_uint64_sz = static_cast<size_t>(bits_per_uint64);
        size_t result_uint64_count = 1;
        size_t result_bit_capacity = result_uint64_count * bits_per_uint64_sz;

        // Quick sanity check
        if (!fits_in<int>(result_bit_capacity))
        {
            throw logic_error("invalid parameters");
        }

        BigUInt resultint(static_cast<int>(result_bit_capacity));
        bool result_is_negative = false;
        uint64_t *result = resultint.data();

        BigUInt base_uint(static_cast<int>(result_bit_capacity));
        base_uint = base_;
        BigUInt temp_result(static_cast<int>(result_bit_capacity));

        for (size_t bit_index = plain.significant_coeff_count(); bit_index--; )
        {
            unsigned long long coeff = plain[bit_index];

            // Multiply result by base. Resize if highest bit set.
            if (is_bit_set_uint(result, result_uint64_count, 
                safe_cast<int>(result_bit_capacity) - 1))
            {
                // Resize to make bigger.
                result_uint64_count++;
                result_bit_capacity = mul_safe(result_uint64_count, bits_per_uint64_sz);
                resultint.resize(safe_cast<int>(result_bit_capacity));
                result = resultint.data();
            }
            set_uint_uint(result, result_uint64_count, temp_result.data());
            multiply_uint_uint(temp_result.data(), result_uint64_count, base_uint.data(), 
                result_uint64_count, result_uint64_count, result);

            // Get sign/magnitude of coefficient.
            if (coeff >= plain_modulus_.value())
            {
                // Coefficient is bigger than plaintext modulus.
                throw invalid_argument("plain does not represent a valid plaintext polynomial");
            }
            bool coeff_is_negative = coeff >= coeff_neg_threshold_;
            const unsigned long long *pos_pointer;
            if (coeff_is_negative)
            {
                if (sub_uint64(plain_modulus_.value(), coeff, 0, &pos_value))
                {
                    // Check for borrow, which means value is greater than plain_modulus.
                    throw invalid_argument("plain does not represent a valid plaintext polynomial");
                }
                pos_pointer = &pos_value;
            }
            else
            {
                pos_pointer = &coeff;
            }

            // Add or subtract-in coefficient.
            if (result_is_negative == coeff_is_negative)
            {
                // Result and coefficient have same signs so add.
                if (add_uint_uint64(result, *pos_pointer, result_uint64_count, result))
                {
                    // Add produced a carry that didn't fit, so resize and put it in.
                    int carry_bit_index = safe_cast<int>(
                        mul_safe(result_uint64_count, bits_per_uint64_sz));
                    result_uint64_count++;
                    result_bit_capacity = mul_safe(result_uint64_count, bits_per_uint64_sz);
                    resultint.resize(safe_cast<int>(result_bit_capacity));
                    result = resultint.data();
                    set_bit_uint(result, result_uint64_count, carry_bit_index);
                }
            }
            else
            {
                // Result and coefficient have opposite signs so subtract.
                if (sub_uint_uint64(result, *pos_pointer, result_uint64_count, result))
                {
                    // Subtraction produced a borrow so coefficient is larger (in magnitude) than result, so need to negate result.
                    negate_uint(result, result_uint64_count, result);
                    result_is_negative = !result_is_negative;
                }
            }
        }

        // Verify result is non-negative.
        if (result_is_negative && !resultint.is_zero())
        {
            throw invalid_argument("poly must decode to a positive value");
        }
        return resultint;
    }

    void BalancedEncoder::decode_biguint(const Plaintext &plain, BigUInt &destination)
    {
        // Determine plain_modulus width.
        unsigned long long pos_value;

        // Determine coefficient threshold for negative numbers.
        destination.set_zero();
        size_t bits_per_uint64_sz = static_cast<size_t>(bits_per_uint64);
        size_t result_uint64_count = destination.uint64_count();
        size_t result_bit_capacity = result_uint64_count * bits_per_uint64_sz;
        bool result_is_negative = false;
        uint64_t *result = destination.data();

        // Quick sanity check
        if (!fits_in<int>(result_bit_capacity))
        {
            throw logic_error("invalid parameters");
        }

        BigUInt base_uint(static_cast<int>(result_bit_capacity));
        BigUInt temp_result(static_cast<int>(result_bit_capacity));
        base_uint = base_;

        for (size_t bit_index = plain.significant_coeff_count(); bit_index--; )
        {
            unsigned long long coeff = plain[bit_index];

            // Multiply result by base, failing if highest bit set.
            if (is_bit_set_uint(result, result_uint64_count, 
                safe_cast<int>(result_bit_capacity) - 1))
            {
                throw invalid_argument("plain does not represent a valid plaintext polynomial");
            }
            set_uint_uint(result, result_uint64_count, temp_result.data());
            multiply_truncate_uint_uint(temp_result.data(), base_uint.data(), 
                result_uint64_count, result);

            // Get sign/magnitude of coefficient.
            if (coeff >= plain_modulus_.value())
            {
                // Coefficient has more bits than plain_modulus.
                throw invalid_argument("plain does not represent a valid plaintext polynomial");
            }
            bool coeff_is_negative = coeff >= coeff_neg_threshold_;
            const unsigned long long *pos_pointer;
            if (coeff_is_negative)
            {
                if (sub_uint64(plain_modulus_.value(), coeff, 0, &pos_value))
                {
                    // Check for borrow, which means value is greater than plain_modulus.
                    throw invalid_argument("plain does not represent a valid plaintext polynomial");
                }
                pos_pointer = &pos_value;
            }
            else
            {
                pos_pointer = &coeff;
            }

            // Add or subtract-in coefficient.
            if (result_is_negative == coeff_is_negative)
            {
                // Result and coefficient have same signs so add.
                if (add_uint_uint64(result, *pos_pointer, result_uint64_count, result))
                {
                    // Add produced a carry that didn't fit.
                    throw invalid_argument("output out of range");
                }
            }
            else
            {
                // Result and coefficient have opposite signs so subtract.
                if (sub_uint_uint64(result, *pos_pointer, result_uint64_count, result))
                {
                    // Subtraction produced a borrow so coefficient is larger (in magnitude) than result, 
                    // so need to negate result.
                    negate_uint(result, result_uint64_count, result);
                    result_is_negative = !result_is_negative;
                }
            }
        }

        // Verify result is non-negative.
        if (result_is_negative && !destination.is_zero())
        {
            throw invalid_argument("poly must decode to a positive value");
        }

        // Verify result fits in actual bit-width (as opposed to capacity) of destination.
        if (destination.significant_bit_count() > destination.bit_count())
        {
            throw invalid_argument("output out of range");
        }
    }

    BinaryFractionalEncoder::BinaryFractionalEncoder(
        const SmallModulus &plain_modulus, 
        size_t poly_modulus_degree, size_t integer_coeff_count, 
        size_t fraction_coeff_count) : 
        encoder_(plain_modulus), 
        fraction_coeff_count_(fraction_coeff_count), 
        integer_coeff_count_(integer_coeff_count), 
        poly_modulus_degree_(poly_modulus_degree)
    {
        if (integer_coeff_count <= 0)
        {
            throw invalid_argument("integer_coeff_count must be positive");
        }
        if (fraction_coeff_count <= 0)
        {
            throw invalid_argument("fraction_coeff_count must be positive");
        }
        if (poly_modulus_degree_ < SEAL_POLY_MOD_DEGREE_MIN ||
            poly_modulus_degree_ > SEAL_POLY_MOD_DEGREE_MAX)
        {
            throw invalid_argument("poly_modulus_degree is invalid");
        }
        if (add_safe(integer_coeff_count_, fraction_coeff_count_) > poly_modulus_degree_)
        {
            throw invalid_argument("integer/fractional parts are too large for poly_modulus_degree");
        }
    }

    Plaintext BinaryFractionalEncoder::encode(double value)
    {
        // Take care of the integral part
        int64_t value_int = safe_cast<int64_t>(value);
        Plaintext encoded_int;
        encoder_.encode(value_int, encoded_int);
        value -= static_cast<double>(value_int);

        // If the fractional part is zero, return encoded_int
        if (value == 0)
        {
            return encoded_int;
        }

        bool is_negative = value < 0;

        //Extract the fractional part
        Plaintext encoded_fract(poly_modulus_degree_);
        for (size_t i = 0; i < fraction_coeff_count_; i++)
        {
            value *= 2;
            value_int = safe_cast<int64_t>(value);
            value -= static_cast<double>(value_int);

            // We want to encode the least significant bit of value_int to the least 
            // significant bit of encoded_fract. First set it to 1 if it is to be set 
            // at all. Later we will negate them all if the number was negative.
            encoded_fract[0] = static_cast<uint64_t>(value_int & 1);

            // Shift encoded_fract by one coefficient unless we are at the last coefficient
            if (i < fraction_coeff_count_ - 1)
            {
                left_shift_uint(encoded_fract.data(), bits_per_uint64, 
                    poly_modulus_degree_, encoded_fract.data());
            }
        }

        // We negate the coefficients only if the number was NOT negative.
        // This is because the coefficients will have to be negated in any case (sign changes 
        // at "wrapping around" the polynomial modulus).
        if (!is_negative)
        {
            for (size_t i = 0; i < fraction_coeff_count_; i++)
            {
                if (encoded_fract[i] != 0)
                {
                    encoded_fract[i] = encoder_.neg_one_;
                }
            }
        }

        // Shift the fractional part to top of polynomial
        left_shift_uint(encoded_fract.data(), mul_safe(bits_per_uint64, 
            safe_cast<int>(poly_modulus_degree_ - fraction_coeff_count_)),
            poly_modulus_degree_, encoded_fract.data());

        // Combine everything together
        set_uint_uint(encoded_int.data(), encoded_int.coeff_count(), encoded_fract.data());

        return encoded_fract;
    }

    double BinaryFractionalEncoder::decode(const Plaintext &plain)
    {
        // Validate input parameters
        if (plain.coeff_count() > poly_modulus_degree_)
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#ifdef SEAL_DEBUG
        if (!are_poly_coefficients_less_than(plain.data(),
            plain.coeff_count(), 1, encoder_.plain_modulus_.data(), 
            encoder_.plain_modulus().uint64_count()))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#endif
        // Do we have an empty plaintext
        if (plain.coeff_count() == 0)
        {
            return 0;
        }

        // plain might be smaller than expected if leading coefficients are missing
        auto plain_copy(allocate_zero_uint(poly_modulus_degree_, pool_));
        set_uint_uint(plain.data(), plain.coeff_count(), plain_copy.get());

        // Extract the fractional and integral parts
        Plaintext encoded_int(integer_coeff_count_);
        auto encoded_fract(allocate_zero_uint(fraction_coeff_count_, pool_));

        // Integer part
        set_uint_uint(plain_copy.get(), integer_coeff_count_, encoded_int.data());

        // Read from the top of the poly all the way to the top of the integral part
        // to obtain the fractional part
        set_uint_uint(plain_copy.get() + poly_modulus_degree_ - fraction_coeff_count_, 
            fraction_coeff_count_, encoded_fract.get());

        // Decode integral part
        int64_t integral_part = encoder_.decode_int64(encoded_int);

        // Decode fractional part (or rather negative of it), one coefficient at a time
        double fractional_part = 0;
        Plaintext temp_int_part(1);
        for (size_t i = 0; i < fraction_coeff_count_; i++)
        {
            temp_int_part[0] = encoded_fract[i];
            fractional_part += static_cast<double>(encoder_.decode_int64(temp_int_part));
            fractional_part /= 2;
        }

        return static_cast<double>(integral_part) - fractional_part;
    }

    BalancedFractionalEncoder::BalancedFractionalEncoder(
        const SmallModulus &plain_modulus, 
        size_t poly_modulus_degree, size_t integer_coeff_count, 
        size_t fraction_coeff_count, uint64_t base) : 
        encoder_(plain_modulus, base), 
        fraction_coeff_count_(fraction_coeff_count), 
        integer_coeff_count_(integer_coeff_count), 
        poly_modulus_degree_(poly_modulus_degree)
    {
        if (integer_coeff_count == 0)
        {
            throw invalid_argument("integer_coeff_count must be positive");
        }
        if (fraction_coeff_count == 0)
        {
            throw invalid_argument("fraction_coeff_count must be positive");
        }
        if (poly_modulus_degree_ < SEAL_POLY_MOD_DEGREE_MIN ||
            poly_modulus_degree_ > SEAL_POLY_MOD_DEGREE_MAX)
        {
            throw invalid_argument("poly_modulus_degree is invalid");
        }
        if (add_safe(integer_coeff_count_, fraction_coeff_count_) > poly_modulus_degree_)
        {
            throw invalid_argument("integer/fractional parts are too large for poly_modulus_degree");
        }
    }

    // We encode differently based on whether the base is odd or even.
    Plaintext BalancedFractionalEncoder::encode(double value)
    {
        if (encoder_.base_ & 1)
        {
            return encode_odd(value);
        }
        else
        {
            return encode_even(value);
        }
    }

    Plaintext BalancedFractionalEncoder::encode_odd(double value)
    {
        // Take care of the integral part
        int64_t value_int = safe_cast<int64_t>(round(value));
        Plaintext encoded_int;
        encoder_.encode(value_int, encoded_int);
        value -= static_cast<double>(value_int);

        // If the fractional part is zero, return encoded_int
        if (value == 0)
        {
            return encoded_int;
        }

        // Extract the fractional part
        Plaintext encoded_fract(poly_modulus_degree_);
        for (size_t i = 0; i < fraction_coeff_count_; i++)
        {
            value *= static_cast<double>(encoder_.base());

            // When computing the next value_int we need to round e.g. 0.5 to 0 (not to 1) and
            // -0.5 to 0 (not to -1), i.e. always towards zero.
            int sign = (value >= 0 ? 1 : -1);
            value_int = safe_cast<int64_t>(sign * ceil(abs(value) - 0.5));
            value -= static_cast<double>(value_int);

            // We store the representative of value_int modulo the base (symmetric representative)
            // as the absolute value (in value_int_mod_base) and as the sign (in is_negative).
            bool is_negative = false;

            if (value_int < 0)
            {
                is_negative = true;
                value_int = -value_int;
            }

            // Set the constant coefficient of encoded_fract to be the correct absolute value.
            encoded_fract[0] = static_cast<uint64_t>(value_int);
            // And negate it modulo plain_modulus if it was NOT supposed to be negative, because the
            // fractional encoding requires the signs of the fractional coefficients to be negatives of
            // what one might naively expect, as they change sign when "wrapping around" the polynomial modulus.
            if (!is_negative && value_int != 0)
            {
                encoded_fract[0] = encoder_.plain_modulus_.value() - encoded_fract[0];
            }

            // Shift encoded_fract by one coefficient unless we are at the last coefficient
            if (i < fraction_coeff_count_ - 1)
            {
                left_shift_uint(encoded_fract.data(), bits_per_uint64, 
                    poly_modulus_degree_, encoded_fract.data());
            }
        }

        // Shift the fractional part to top of polynomial
        left_shift_uint(encoded_fract.data(), mul_safe(bits_per_uint64, 
            safe_cast<int>(poly_modulus_degree_ - fraction_coeff_count_)),
            poly_modulus_degree_, encoded_fract.data());

        // Combine everything together
        set_uint_uint(encoded_int.data(), encoded_int.coeff_count(), encoded_fract.data());

        return encoded_fract;
    }

    Plaintext BalancedFractionalEncoder::encode_even(double value)
    {
        // Take care of the integral part
        int64_t value_int = safe_cast<int64_t>(round(value));

        // We store the integral part for further use, since we may end up changing the integral 
        // part based on our encoding of the fractional part
        int64_t initial = value_int;

        Plaintext encoded_int(poly_modulus_degree_);
        encoder_.encode(value_int, encoded_int);
        value -= static_cast<double>(value_int);

        // If the fractional part is zero, return encoded_int
        if (value == 0)
        {
            return encoded_int;
        }

        // Extract the fractional part
        // We will first compute the balanced base b encoding of the fractional part, allowing 
        // coefficients in the range -b/2, ..., b/2. We use Pointer carry to mark the coefficients 
        // that are equal to b/2, and we use Pointer is_less_than_neg_one to mark the coefficients 
        // that are less than -1 (we need this because when we encounter a coefficient greater than 
        // or equal to b/2, we need to store base - coefficient instead and add 1 to the coefficient 
        // to the left, which might change the sign of the coefficient to the left).

        Plaintext encoded_fract(poly_modulus_degree_);
        auto carry(allocate_zero_uint(poly_modulus_degree_, pool_));
        auto is_less_than_neg_one(allocate_zero_uint(poly_modulus_degree_, pool_));
        auto is_negative(allocate_zero_uint(poly_modulus_degree_, pool_));

        for (size_t i = 0; i < fraction_coeff_count_; i++)
        {
            value *= static_cast<double>(encoder_.base());

            // When computing the next value_int we need to round e.g. 0.5 to 0 (not to 1) and
            // -0.5 to 0 (not to -1), i.e. always towards zero.
            int sign = (value >= 0 ? 1 : -1);
            value_int = safe_cast<int64_t>(sign * ceil(abs(value) - 0.5));
            value -= static_cast<double>(value_int);

            // Set the constant coefficients of carry, is_less_than_neg_one, is_negative and 
            // encoded_fract to be the correct values.
            if ((static_cast<uint64_t>(abs(value_int)) >= encoder_.base_ / 2) 
                && (value_int >= 0))
            {
                carry[0] = uint64_t(1);
            }
            if (value_int < -1)
            {
                is_less_than_neg_one[0] = uint64_t(1);
            }
            if (value_int < 0)
            {
                is_negative[0] = uint64_t(1);
                value_int = -value_int;
            }

            // Set the constant coefficient of encoded_fract to be the correct absolute value.
            encoded_fract[0] = static_cast<uint64_t>(value_int);

            // Shift all the polynomials by one coefficient unless we are at the last coefficient
            if (i < fraction_coeff_count_ - 1)
            {
                left_shift_uint(encoded_fract.data(), bits_per_uint64, poly_modulus_degree_, 
                    encoded_fract.data());
                left_shift_uint(carry.get(), bits_per_uint64, poly_modulus_degree_, carry.get());
                left_shift_uint(is_less_than_neg_one.get(), bits_per_uint64, poly_modulus_degree_, 
                    is_less_than_neg_one.get());
                left_shift_uint(is_negative.get(), bits_per_uint64, poly_modulus_degree_, 
                    is_negative.get());
            }
        }

        uint64_t *encoded_fract_ptr = encoded_fract.data();
        uint64_t *is_negative_ptr = is_negative.get();
        uint64_t base_div_two = encoder_.base_ / 2;

        // Now we get rid of those coefficients that are greater than or equal to base / 2
        for (size_t i = 0; i < fraction_coeff_count_ - 1; i++)
        {
            if (carry[i] != 0)
            {
                // Set the sign of the current coefficient to be negative
                is_negative[i] = uint64_t(1);

                // Store base - current coefficient
                *encoded_fract_ptr = encoder_.base_ - *encoded_fract_ptr; 

                // Add 1 to the coefficient to the left. Update the carry entry for the coefficient 
                // to the left.
                if (is_negative[i + 1] == 0)
                {
                    encoded_fract_ptr[1]++;
                }
                else
                {
                    encoded_fract_ptr[1]--;
                    
                    // Update the sign of the coefficient to the left if needed
                    if (!is_less_than_neg_one[i + 1])
                    {
                        is_negative[i + 1] = 0;
                    }
                }

                if (encoded_fract_ptr[1] >= base_div_two) 
                // if (is_greater_than_or_equal_uint_uint(encoded_fract_ptr + plain_uint64_count, 
                //     &base_div_two, plain_uint64_count))
                {
                    carry[i + 1] = uint64_t(1);
                }
            }

            encoded_fract_ptr++;
            is_negative_ptr++;
        }

        // Do we need to change the integral part?
        bool change_int = (carry[fraction_coeff_count_ - 1] != 0);
        if (change_int)
        {
            *encoded_fract_ptr = encoder_.base_ - *encoded_fract_ptr;
            is_negative[fraction_coeff_count_ - 1] = uint64_t(1);
        }

        // And negate it modulo plain_modulus if it was NOT supposed to be negative, because the
        // fractional encoding requires the signs of the fractional coefficients to be negatives of
        // what one might naively expect, as they change sign when "wrapping around" the polynomial modulus.
        for (size_t i = fraction_coeff_count_; i--; encoded_fract_ptr--)
        {
            if ((!is_negative[i]) && (encoded_fract[i] != 0))
            {
                encoded_fract_ptr[0] = encoder_.plain_modulus_.value() - encoded_fract_ptr[0];
            }
        }

        // Shift the fractional part to top of polynomial
        left_shift_uint(encoded_fract.data(), mul_safe(bits_per_uint64, 
            safe_cast<int>(poly_modulus_degree_ - fraction_coeff_count_)),
            poly_modulus_degree_, encoded_fract.data());

        // If change_int is true, then we need to add 1 to the integral part and re-encode it.
        if (change_int)
        {
            encoder_.encode(initial + 1, encoded_int);
        }

        // Combine everything together
        set_uint_uint(encoded_int.data(), encoded_int.coeff_count(), encoded_fract.data());

        return encoded_fract;
    }

    double BalancedFractionalEncoder::decode(const Plaintext &plain)
    {
        // Validate input parameters
        if (plain.coeff_count() > poly_modulus_degree_)
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#ifdef SEAL_DEBUG
        if (!are_poly_coefficients_less_than(plain.data(),
            plain.coeff_count(), 1, encoder_.plain_modulus_.data(), 
            encoder_.plain_modulus_.uint64_count()))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#endif
        // plain might be smaller than expected if leading coefficients are missing
        auto plain_copy(allocate_zero_uint(poly_modulus_degree_, pool_));
        set_uint_uint(plain.data(), plain.coeff_count(), plain_copy.get());
        
        // Extract the fractional and integral parts
        Plaintext encoded_int(integer_coeff_count_);
        auto encoded_fract(allocate_zero_uint(fraction_coeff_count_, pool_));

        // Integer part
        set_uint_uint(plain_copy.get(), integer_coeff_count_, encoded_int.data());

        // Read from the top of the poly all the way to the top of the integral part to obtain the fractional part
        set_uint_uint(plain_copy.get() + poly_modulus_degree_ - fraction_coeff_count_, 
            fraction_coeff_count_, encoded_fract.get());

        // Decode integral part
        int64_t integral_part = encoder_.decode_int64(encoded_int);

        // Decode fractional part (or rather negative of it), one coefficient at a time
        double fractional_part = 0;
        Plaintext temp_int_part(1);
        for (size_t i = 0; i < fraction_coeff_count_; i++)
        {
            temp_int_part[0] = encoded_fract[i];
            fractional_part += static_cast<double>(encoder_.decode_int64(temp_int_part));
            fractional_part /= static_cast<double>(encoder_.base());
        }

        return static_cast<double>(integral_part) - fractional_part;
    }

    IntegerEncoder::IntegerEncoder(const SmallModulus &plain_modulus, uint64_t base)
    {
        if (base == 2)
        {
            encoder_ = new BinaryEncoder(plain_modulus);
        }
        else
        {
            encoder_ = new BalancedEncoder(plain_modulus, base);
        }
    }

    IntegerEncoder::IntegerEncoder(const IntegerEncoder &copy)
    {
        if (copy.base() == 2)
        {
            encoder_ = new BinaryEncoder(*dynamic_cast<BinaryEncoder*>(copy.encoder_));
        }
        else
        {
            encoder_ = new BalancedEncoder(*dynamic_cast<BalancedEncoder*>(copy.encoder_));
        }
    }

    IntegerEncoder::~IntegerEncoder()
    {
        if (encoder_ != nullptr)
        {
            delete encoder_;
            encoder_ = nullptr;
        }
    }

    void IntegerEncoder::encode(uint64_t value, Plaintext &destination)
    {
        encoder_->encode(value, destination);

        // Resize to correct size
        destination.resize(destination.significant_coeff_count());
    }

    void IntegerEncoder::encode(int64_t value, Plaintext &destination)
    {
        encoder_->encode(value, destination);

        // Resize to correct size
        destination.resize(destination.significant_coeff_count());
    }

    void IntegerEncoder::encode(const BigUInt &value, Plaintext &destination)
    {
        encoder_->encode(value, destination);

        // Resize to correct size
        destination.resize(destination.significant_coeff_count());
    }

    void IntegerEncoder::encode(int32_t value, Plaintext &destination)
    {
        encoder_->encode(value, destination);

        // Resize to correct size
        destination.resize(destination.significant_coeff_count());
    }

    void IntegerEncoder::encode(uint32_t value, Plaintext &destination)
    {
        encoder_->encode(value, destination);

        // Resize to correct size
        destination.resize(destination.significant_coeff_count());
    }

    FractionalEncoder::FractionalEncoder(const SmallModulus &plain_modulus, 
        size_t poly_modulus_degree, size_t integer_coeff_count, size_t fraction_coeff_count, 
        uint64_t base)
    {
        if (base == 2)
        {
            encoder_ = new BinaryFractionalEncoder(plain_modulus, poly_modulus_degree, 
                integer_coeff_count, fraction_coeff_count);
        }
        else
        {
            encoder_ = new BalancedFractionalEncoder(plain_modulus, poly_modulus_degree, 
                integer_coeff_count, fraction_coeff_count, base);
        }
    }

    FractionalEncoder::FractionalEncoder(const FractionalEncoder &copy)
    {
        if (copy.base() == 2)
        {
            encoder_ = new BinaryFractionalEncoder(
                *dynamic_cast<BinaryFractionalEncoder*>(copy.encoder_));
        }
        else
        {
            encoder_ = new BalancedFractionalEncoder(
                *dynamic_cast<BalancedFractionalEncoder*>(copy.encoder_));
        }
    }

    FractionalEncoder::~FractionalEncoder()
    {
        if (encoder_ != nullptr)
        {
            delete encoder_;
            encoder_ = nullptr;
        }
    }
}
