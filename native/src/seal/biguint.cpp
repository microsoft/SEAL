// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/biguint.h"
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include <algorithm>

using namespace std;
using namespace seal::util;

namespace seal
{
    BigUInt::BigUInt(int bit_count)
    {
        resize(bit_count);
    }

    BigUInt::BigUInt(const string &hex_value)
    {
        operator =(hex_value);
    }

    BigUInt::BigUInt(int bit_count, const string &hex_value)
    {
        resize(bit_count);
        operator =(hex_value);
        if (bit_count != bit_count_)
        {
            resize(bit_count);
        }
    }

    BigUInt::BigUInt(int bit_count, uint64_t *value) :
        value_(decltype(value_)::Aliasing(value)), bit_count_(bit_count)
    {
        if (bit_count < 0)
        {
            throw invalid_argument("bit_count must be non-negative");
        }
        if (value == nullptr && bit_count > 0)
        {
            throw invalid_argument("value must be non-null for non-zero bit count");
        }
    }
#ifdef SEAL_USE_MSGSL_SPAN
    BigUInt::BigUInt(gsl::span<uint64_t> value)
    {
        if(unsigned_gt(value.size(), numeric_limits<int>::max() / bits_per_uint64))
        {
            throw std::invalid_argument("value has too large size");
        }
        value_ = decltype(value_)::Aliasing(value.data());
        bit_count_ = static_cast<int>(value.size()) * bits_per_uint64;
    }
#endif
    BigUInt::BigUInt(int bit_count, uint64_t value)
    {
        resize(bit_count);
        operator =(value);
        if (bit_count != bit_count_)
        {
            resize(bit_count);
        }
    }

    BigUInt::BigUInt(const BigUInt &copy)
    {
        resize(copy.bit_count());
        operator =(copy);
    }

    BigUInt::BigUInt(BigUInt &&source) noexcept :
        pool_(move(source.pool_)),
        value_(move(source.value_)),
        bit_count_(source.bit_count_)
    {
        // Pointer in source has been taken over so set it to nullptr
        source.bit_count_ = 0;
    }

    BigUInt::~BigUInt() noexcept
    {
        reset();
    }

    string BigUInt::to_string() const
    {
        return uint_to_hex_string(value_.get(), uint64_count());
    }

    string BigUInt::to_dec_string() const
    {
        return uint_to_dec_string(value_.get(), uint64_count(), pool_);
    }

    void BigUInt::resize(int bit_count)
    {
        if (bit_count < 0)
        {
            throw invalid_argument("bit_count must be non-negative");
        }
        if (value_.is_alias())
        {
            throw logic_error("Cannot resize an aliased BigUInt");
        }
        if (bit_count == bit_count_)
        {
            return;
        }

        // Lazy initialization of MemoryPoolHandle
        if (!pool_)
        {
            pool_ = MemoryManager::GetPool();
        }

        // Fast path if allocation size doesn't change.
        size_t old_uint64_count = uint64_count();
        size_t new_uint64_count = safe_cast<size_t>(
            divide_round_up(bit_count, bits_per_uint64));
        if (old_uint64_count == new_uint64_count)
        {
            bit_count_ = bit_count;
            return;
        }

        // Allocate new space.
        decltype(value_) new_value;
        if (new_uint64_count > 0)
        {
            new_value = allocate_uint(new_uint64_count, pool_);
        }

        // Copy over old value.
        if (new_uint64_count > 0)
        {
            set_uint_uint(value_.get(), old_uint64_count, new_uint64_count, new_value.get());
            filter_highbits_uint(new_value.get(), new_uint64_count, bit_count);
        }

        // Deallocate any owned pointers.
        reset();

        // Update class.
        swap(value_, new_value);
        bit_count_ = bit_count;
    }

    BigUInt &BigUInt::operator =(const BigUInt& assign)
    {
        // Do nothing if same thing.
        if (&assign == this)
        {
            return *this;
        }

        // Verify assigned value will fit within bit count.
        int assign_sig_bit_count = assign.significant_bit_count();
        if (assign_sig_bit_count > bit_count_)
        {
            // Size is too large to currently fit, so resize.
            resize(assign_sig_bit_count);
        }

        // Copy over value.
        size_t assign_uint64_count = safe_cast<size_t>(
            divide_round_up(assign_sig_bit_count, bits_per_uint64));
        if (uint64_count() > 0)
        {
            set_uint_uint(assign.value_.get(), assign_uint64_count,
                uint64_count(), value_.get());
        }
        return *this;
    }

    BigUInt &BigUInt::operator =(const string &hex_value)
    {
        int hex_value_length = safe_cast<int>(hex_value.size());

        int assign_bit_count = get_hex_string_bit_count(hex_value.data(), hex_value_length);
        if (assign_bit_count > bit_count_)
        {
            // Size is too large to currently fit, so resize.
            resize(assign_bit_count);
        }
        if (bit_count_ > 0)
        {
            // Copy over value.
            hex_string_to_uint(hex_value.data(), hex_value_length, uint64_count(), value_.get());
        }
        return *this;
    }

    BigUInt BigUInt::operator /(const BigUInt& operand2) const
    {
        int result_bits = significant_bit_count();
        int operand2_bits = operand2.significant_bit_count();
        if (operand2_bits == 0)
        {
            throw invalid_argument("operand2 must be positive");
        }
        if (operand2_bits > result_bits)
        {
            BigUInt zero(result_bits);
            return zero;
        }
        BigUInt result(result_bits);
        BigUInt remainder(result_bits);
        size_t result_uint64_count = result.uint64_count();
        if (result_uint64_count > operand2.uint64_count())
        {
            BigUInt operand2resized(result_bits);
            operand2resized = operand2;
            divide_uint_uint(value_.get(), operand2resized.data(), result_uint64_count,
                result.data(), remainder.data(), pool_);
        }
        else
        {
            divide_uint_uint(value_.get(), operand2.data(), result_uint64_count,
                result.data(), remainder.data(), pool_);
        }
        return result;
    }

    BigUInt BigUInt::divrem(const BigUInt& operand2, BigUInt &remainder) const
    {
        int result_bits = significant_bit_count();
        remainder = *this;
        int operand2_bits = operand2.significant_bit_count();
        if (operand2_bits > result_bits)
        {
            BigUInt zero;
            return zero;
        }
        BigUInt quotient(result_bits);
        size_t uint64_count = remainder.uint64_count();
        if (uint64_count > operand2.uint64_count())
        {
            BigUInt operand2resized(result_bits);
            operand2resized = operand2;
            divide_uint_uint_inplace(remainder.data(), operand2resized.data(),
                uint64_count, quotient.data(), pool_);
        }
        else
        {
            divide_uint_uint_inplace(remainder.data(), operand2.data(),
                uint64_count, quotient.data(), pool_);
        }
        return quotient;
    }

    void BigUInt::save(ostream &stream) const
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            int32_t bit_count32 = safe_cast<int32_t>(bit_count_);
            streamsize data_size = safe_cast<streamsize>(mul_safe(uint64_count(), sizeof(uint64_t)));
            stream.write(reinterpret_cast<const char*>(&bit_count32), sizeof(int32_t));
            stream.write(reinterpret_cast<const char*>(value_.get()), data_size);
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }

        stream.exceptions(old_except_mask);
    }

    void BigUInt::load(istream &stream)
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            int32_t read_bit_count = 0;
            stream.read(reinterpret_cast<char*>(&read_bit_count), sizeof(int32_t));
            if (read_bit_count > bit_count_)
            {
                // Size is too large to currently fit, so resize.
                resize(read_bit_count);
            }
            size_t read_uint64_count = safe_cast<size_t>(
                divide_round_up(read_bit_count, bits_per_uint64));
            streamsize data_size = safe_cast<streamsize>(mul_safe(read_uint64_count, sizeof(uint64_t)));
            stream.read(reinterpret_cast<char*>(value_.get()), data_size);

            // Zero any extra space.
            if (uint64_count() > read_uint64_count)
            {
                set_zero_uint(uint64_count() - read_uint64_count,
                    value_.get() + read_uint64_count);
            }
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }

        stream.exceptions(old_except_mask);
    }
}
