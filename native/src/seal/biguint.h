// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/serialization.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"
#include "seal/util/pointer.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintcore.h"
#include "seal/util/ztools.h"
#include <cstdint>
#include <iostream>
#include <string>
#ifdef SEAL_USE_MSGSL
#include <gsl/span>
#endif

namespace seal
{
    /**
    Represents an unsigned integer with a specified bit width. Non-const
    BigUInts are mutable and able to be resized. The bit count for a BigUInt
    (which can be read with bit_count()) is set initially by the constructor
    and can be resized either explicitly with the resize() function or
    implicitly with an assignment operation (e.g., operator=(), operator+=(),
    etc.). A rich set of unsigned integer operations are provided by the
    BigUInt class, including comparison, traditional arithmetic (addition,
    subtraction, multiplication, division), and modular arithmetic functions.

    @par Backing Array
    The backing array for a BigUInt stores its unsigned integer value as
    a contiguous std::uint64_t array. Each std::uint64_t in the array
    sequentially represents 64-bits of the integer value, with the least
    significant quad-word storing the lower 64-bits and the order of the bits
    for each quad word dependent on the architecture's std::uint64_t
    representation. The size of the array equals the bit count of the BigUInt
    (which can be read with bit_count()) rounded up to the next std::uint64_t
    boundary (i.e., rounded up to the next 64-bit boundary). The uint64_count()
    function returns the number of std::uint64_t in the backing array. The
    data() function returns a pointer to the first std::uint64_t in the array.
    Additionally, the operator [] function allows accessing the individual
    bytes of the integer value in a platform-independent way - for example,
    reading the third byte will always return bits 16-24 of the BigUInt value
    regardless of the platform being little-endian or big-endian.

    @par Implicit Resizing
    Both the copy constructor and operator=() allocate more memory for the
    backing array when needed, i.e. when the source BigUInt has a larger
    backing array than the destination. Conversely, when the destination
    backing array is already large enough, the data is only copied and the
    unnecessary higher order bits are set to zero. When new memory has to be
    allocated, only the significant bits of the source BigUInt are taken
    into account. This is is important, because it avoids unnecessary zero
    bits to be included in the destination, which in some cases could
    accumulate and result in very large unnecessary allocations. However,
    sometimes it is necessary to preserve the original size, even if some
    of the leading bits are zero. For this purpose BigUInt contains functions
    duplicate_from and duplicate_to, which create an exact copy of the source
    BigUInt.

    @par Alias BigUInts
    An aliased BigUInt (which can be determined with is_alias()) is a special
    type of BigUInt that does not manage its underlying std::uint64_t pointer
    used to store the value. An aliased BigUInt supports most of the same
    operations as a non-aliased BigUInt, including reading and writing the
    value, however an aliased BigUInt does not internally allocate or
    deallocate its backing array and, therefore, does not support resizing.
    Any attempt, either explicitly or implicitly, to resize the BigUInt will
    result in an exception being thrown. An aliased BigUInt can be created
    with the BigUInt(int, std::uint64_t*) constructor or the alias() function.
    Note that the pointer specified to be aliased must be deallocated
    externally after the BigUInt is no longer in use. Aliasing is useful in
    cases where it is desirable to not have each BigUInt manage its own memory
    allocation and/or to prevent unnecessary copying.

    @par Thread Safety
    In general, reading a BigUInt is thread-safe while mutating is not.
    Specifically, the backing array may be freed whenever a resize occurs,
    the BigUInt is destroyed, or alias() is called, which would invalidate
    the address returned by data() and the byte references returned by
    operator []. When it is known that a resize will not occur, concurrent
    reading and mutating will not inherently fail but it is possible for
    a read to see a partially updated value from a concurrent write.
    A non-aliased BigUInt allocates its backing array from the global
    (thread-safe) memory pool. Consequently, creating or resizing a large
    number of BigUInt can result in a performance loss due to thread
    contention.
    */
    class BigUInt
    {
    public:
        /**
        Creates an empty BigUInt with zero bit width. No memory is allocated
        by this constructor.
        */
        BigUInt() = default;

        /**
        Creates a zero-initialized BigUInt of the specified bit width.

        @param[in] bit_count The bit width
        @throws std::invalid_argument if bit_count is negative
        */
        BigUInt(int bit_count);

        /**
        Creates a BigUInt initialized and minimally sized to fit the unsigned
        hexadecimal integer specified by the string. The string matches the format
        returned by to_string() and must consist of only the characters 0-9, A-F,
        or a-f, most-significant nibble first.

        @param[in] hex_value The hexadecimal integer string specifying the initial
        value
        @throws std::invalid_argument if hex_value does not adhere to the expected
        format
        */
        BigUInt(const std::string &hex_value);

        /**
        Creates a BigUInt of the specified bit width and initializes it with the
        unsigned hexadecimal integer specified by the string. The string must match
        the format returned by to_string() and must consist of only the characters
        0-9, A-F, or a-f, most-significant nibble first.

        @param[in] bit_count The bit width
        @param[in] hex_value The hexadecimal integer string specifying the initial
        value
        @throws std::invalid_argument if bit_count is negative
        @throws std::invalid_argument if hex_value does not adhere to the expected
        format
        */
        BigUInt(int bit_count, const std::string &hex_value);

        /**
        Creates an aliased BigUInt with the specified bit width and backing array.
        An aliased BigUInt does not internally allocate or deallocate the backing
        array, and instead uses the specified backing array for all read/write
        operations. Note that resizing is not supported by an aliased BigUInt and
        any required deallocation of the specified backing array must occur
        externally after the aliased BigUInt is no longer in use.

        @param[in] bit_count The bit width
        @param[in] value The backing array to use
        @throws std::invalid_argument if bit_count is negative or value is null
        and bit_count is positive
        */
        BigUInt(int bit_count, std::uint64_t *value);
#ifdef SEAL_USE_MSGSL
        /**
        Creates an aliased BigUInt with given backing array and bit width set to
        the size of the backing array. An aliased BigUInt does not internally
        allocate or deallocate the backing array, and instead uses the specified
        backing array for all read/write operations. Note that resizing is not
        supported by an aliased BigUInt and any required deallocation of the
        specified backing array must occur externally after the aliased BigUInt
        is no longer in use.

        @param[in] value The backing array to use
        @throws std::invalid_argument if value has too large size
        */
        BigUInt(gsl::span<std::uint64_t> value);
#endif
        /**
        Creates a BigUInt of the specified bit width and initializes it to the
        specified unsigned integer value.

        @param[in] bit_count The bit width
        @param[in] value The initial value to set the BigUInt
        @throws std::invalid_argument if bit_count is negative
        */
        BigUInt(int bit_count, std::uint64_t value);

        /**
        Creates a deep copy of a BigUInt. The created BigUInt will have the same
        bit count and value as the original.

        @param[in] copy The BigUInt to copy from
        */
        BigUInt(const BigUInt &copy);

        /**
        Creates a new BigUInt by moving an old one.

        @param[in] source The BigUInt to move from
        */
        BigUInt(BigUInt &&source) noexcept;

        /**
        Destroys the BigUInt and deallocates the backing array if it is not
        an aliased BigUInt.
        */
        ~BigUInt() noexcept;

        /**
        Returns whether or not the BigUInt is an alias.
        */
        SEAL_NODISCARD inline bool is_alias() const noexcept
        {
            return value_.is_alias();
        }

        /**
        Returns the bit count for the BigUInt.
        */
        SEAL_NODISCARD inline int bit_count() const noexcept
        {
            return bit_count_;
        }

        /**
        Returns a pointer to the backing array storing the BigUInt value.
        The pointer points to the beginning of the backing array at the
        least-significant quad word.

        @warning The pointer is valid only until the backing array is freed,
        which occurs when the BigUInt is resized, destroyed, or the alias()
        function is called.
        */
        SEAL_NODISCARD inline std::uint64_t *data()
        {
            return value_.get();
        }

        /**
        Returns a const pointer to the backing array storing the BigUInt value.
        The pointer points to the beginning of the backing array at the
        least-significant quad word.

        @warning The pointer is valid only until the backing array is freed, which
        occurs when the BigUInt is resized, destroyed, or the alias() function is
        called.
        */
        SEAL_NODISCARD inline const std::uint64_t *data() const noexcept
        {
            return value_.get();
        }
#ifdef SEAL_USE_MSGSL
        /**
        Returns the backing array storing the BigUInt value.

        @warning The span is valid only until the backing array is freed, which
        occurs when the BigUInt is resized, destroyed, or the alias() function is
        called.
        */
        SEAL_NODISCARD inline gsl::span<std::uint64_t> data_span()
        {
            return gsl::span<std::uint64_t>(value_.get(), uint64_count());
        }

        /**
        Returns the backing array storing the BigUInt value.

        @warning The span is valid only until the backing array is freed, which
        occurs when the BigUInt is resized, destroyed, or the alias() function is
        called.
        */
        SEAL_NODISCARD inline gsl::span<const std::uint64_t> data_span() const
        {
            return gsl::span<const std::uint64_t>(value_.get(), uint64_count());
        }
#endif
        /**
        Returns the number of bytes in the backing array used to store the BigUInt
        value.
        */
        SEAL_NODISCARD inline std::size_t byte_count() const
        {
            return static_cast<std::size_t>(util::divide_round_up(bit_count_, util::bits_per_byte));
        }

        /**
        Returns the number of std::uint64_t in the backing array used to store
        the BigUInt value.
        */
        SEAL_NODISCARD inline std::size_t uint64_count() const
        {
            return static_cast<std::size_t>(util::divide_round_up(bit_count_, util::bits_per_uint64));
        }

        /**
        Returns the number of significant bits for the BigUInt.
        */
        SEAL_NODISCARD inline int significant_bit_count() const
        {
            if (bit_count_ == 0)
            {
                return 0;
            }
            return util::get_significant_bit_count_uint(value_.get(), uint64_count());
        }

        /**
        Returns the BigUInt value as a double. Note that precision may be lost during
        the conversion.
        */
        SEAL_NODISCARD double to_double() const noexcept
        {
            const double TwoToThe64 = 18446744073709551616.0;
            double result = 0;
            for (std::size_t i = uint64_count(); i--;)
            {
                result *= TwoToThe64;
                result += static_cast<double>(value_[i]);
            }
            return result;
        }

        /**
        Returns the BigUInt value as a hexadecimal string.
        */
        SEAL_NODISCARD std::string to_string() const;

        /**
        Returns the BigUInt value as a decimal string.
        */
        SEAL_NODISCARD std::string to_dec_string() const;

        /**
        Returns whether or not the BigUInt has the value zero.
        */
        SEAL_NODISCARD inline bool is_zero() const
        {
            if (bit_count_ == 0)
            {
                return true;
            }
            return util::is_zero_uint(value_.get(), uint64_count());
        }

        /**
        Returns the byte at the corresponding byte index of the BigUInt's integer
        value. The bytes of the BigUInt are indexed least-significant byte first.

        @param[in] index The index of the byte to read
        @throws std::out_of_range if index is not within [0, byte_count())
        */
        SEAL_NODISCARD inline const SEAL_BYTE &operator[](std::size_t index) const
        {
            if (index >= byte_count())
            {
                throw std::out_of_range("index must be within [0, byte count)");
            }
            return reinterpret_cast<const SEAL_BYTE *>(value_.get())[index];
        }

        /**
        Returns an byte reference that can read/write the byte at the corresponding
        byte index of the BigUInt's integer value. The bytes of the BigUInt are
        indexed least-significant byte first.

        @warning The returned byte is an reference backed by the BigUInt's backing
        array. As such, it is only valid until the BigUInt is resized, destroyed,
        or alias() is called.

        @param[in] index The index of the byte to read
        @throws std::out_of_range if index is not within [0, byte_count())
        */
        SEAL_NODISCARD inline SEAL_BYTE &operator[](std::size_t index)
        {
            if (index >= byte_count())
            {
                throw std::out_of_range("index must be within [0, byte count)");
            }
            return reinterpret_cast<SEAL_BYTE *>(value_.get())[index];
        }

        /**
        Sets the BigUInt value to zero. This does not resize the BigUInt.
        */
        inline void set_zero()
        {
            if (bit_count_)
            {
                return util::set_zero_uint(uint64_count(), value_.get());
            }
        }

        /**
        Resizes the BigUInt to the specified bit width, copying over the old value
        as much as will fit.

        @param[in] bit_count The bit width
        @throws std::invalid_argument if bit_count is negative
        @throws std::logic_error if the BigUInt is an alias
        */
        void resize(int bit_count);

        /**
        Makes the BigUInt an aliased BigUInt with the specified bit width and
        backing array. An aliased BigUInt does not internally allocate or
        deallocate the backing array, and instead uses the specified backing array
        for all read/write operations. Note that resizing is not supported by
        an aliased BigUInt and any required deallocation of the specified backing
        array must occur externally after the aliased BigUInt is no longer in use.

        @param[in] bit_count The bit width
        @param[in] value The backing array to use
        @throws std::invalid_argument if bit_count is negative or value is null
        */
        inline void alias(int bit_count, std::uint64_t *value)
        {
            if (bit_count < 0)
            {
                throw std::invalid_argument("bit_count must be non-negative");
            }
            if (value == nullptr && bit_count > 0)
            {
                throw std::invalid_argument("value must be non-null for non-zero bit count");
            }

            // Deallocate any owned pointers.
            reset();

            // Update class.
            value_ = util::Pointer<std::uint64_t>::Aliasing(value);
            bit_count_ = bit_count;
        }
#ifdef SEAL_USE_MSGSL
        /**
        Makes the BigUInt an aliased BigUInt with the given backing array
        and bit width set equal to the size of the backing array. An aliased
        BigUInt does not internally allocate or deallocate the backing array,
        and instead uses the specified backing array for all read/write
        operations. Note that resizing is not supported by an aliased BigUInt
        and any required deallocation of the specified backing array must
        occur externally after the aliased BigUInt is no longer in use.

        @param[in] value The backing array to use
        @throws std::invalid_argument if value has too large size
        */
        inline void alias(gsl::span<std::uint64_t> value)
        {
            if (util::unsigned_gt(value.size(), std::numeric_limits<int>::max()))
            {
                throw std::invalid_argument("value has too large size");
            }

            // Deallocate any owned pointers.
            reset();

            // Update class.
            value_ = util::Pointer<std::uint64_t>::Aliasing(value.data());
            bit_count_ = static_cast<int>(value.size());
            ;
        }
#endif
        /**
        Resets an aliased BigUInt into an empty non-alias BigUInt with bit count
        of zero.

        @throws std::logic_error if BigUInt is not an alias
        */
        inline void unalias()
        {
            if (!value_.is_alias())
            {
                throw std::logic_error("BigUInt is not an alias");
            }

            // Reset class.
            reset();
        }

        /**
        Overwrites the BigUInt with the value of the specified BigUInt, enlarging
        if needed to fit the assigned value. Only significant bits are used to
        size the BigUInt.

        @param[in] assign The BigUInt whose value should be assigned to the
        current BigUInt
        @throws std::logic_error if BigUInt is an alias and the assigned BigUInt is
        too large to fit the current bit width
        */
        BigUInt &operator=(const BigUInt &assign);

        /**
        Overwrites the BigUInt with the unsigned hexadecimal value specified by
        the string, enlarging if needed to fit the assigned value. The string must
        match the format returned by to_string() and must consist of only the
        characters 0-9, A-F, or a-f, most-significant nibble first.

        @param[in] hex_value The hexadecimal integer string specifying the value
        to assign
        @throws std::invalid_argument if hex_value does not adhere to the
        expected format
        @throws std::logic_error if BigUInt is an alias and the assigned value
        is too large to fit the current bit width
        */
        BigUInt &operator=(const std::string &hex_value);

        /**
        Overwrites the BigUInt with the specified integer value, enlarging if
        needed to fit the value.

        @param[in] value The value to assign
        @throws std::logic_error if BigUInt is an alias and the significant bit
        count of value is too large to fit the
        current bit width
        */
        inline BigUInt &operator=(std::uint64_t value)
        {
            int assign_bit_count = util::get_significant_bit_count(value);
            if (assign_bit_count > bit_count_)
            {
                // Size is too large to currently fit, so resize.
                resize(assign_bit_count);
            }
            if (bit_count_ > 0)
            {
                util::set_uint(value, uint64_count(), value_.get());
            }
            return *this;
        }

        /**
        Returns a copy of the BigUInt value resized to the significant bit count.
        */
        SEAL_NODISCARD inline BigUInt operator+() const
        {
            BigUInt result;
            result = *this;
            return result;
        }

        /**
        Returns a negated copy of the BigUInt value. The bit count does not change.
        */
        SEAL_NODISCARD inline BigUInt operator-() const
        {
            BigUInt result(bit_count_);
            util::negate_uint(value_.get(), result.uint64_count(), result.data());
            util::filter_highbits_uint(result.data(), result.uint64_count(), result.bit_count());
            return result;
        }

        /**
        Returns an inverted copy of the BigUInt value. The bit count does not change.
        */
        SEAL_NODISCARD inline BigUInt operator~() const
        {
            BigUInt result(bit_count_);
            util::not_uint(value_.get(), result.uint64_count(), result.data());
            util::filter_highbits_uint(result.data(), result.uint64_count(), result.bit_count());
            return result;
        }

        /**
        Increments the BigUInt and returns the incremented value. The BigUInt will
        increment the bit count if needed to fit the carry.

        @throws std::logic_error if BigUInt is an alias and a carry occurs requiring
        the BigUInt to be resized
        */
        inline BigUInt &operator++()
        {
            if (util::increment_uint(value_.get(), uint64_count(), value_.get()))
            {
                resize(util::add_safe(bit_count_, 1));
                util::set_bit_uint(value_.get(), uint64_count(), bit_count_);
            }
            bit_count_ = std::max(bit_count_, significant_bit_count());
            return *this;
        }

        /**
        Decrements the BigUInt and returns the decremented value. The bit count
        does not change.
        */
        inline BigUInt &operator--()
        {
            util::decrement_uint(value_.get(), uint64_count(), value_.get());
            util::filter_highbits_uint(value_.get(), uint64_count(), bit_count_);
            return *this;
        }
#ifndef SEAL_USE_MAYBE_UNUSED
#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif
#endif
        /**
        Increments the BigUInt but returns its old value. The BigUInt will increment
        the bit count if needed to fit the carry.
        */
        inline BigUInt operator++(int postfix SEAL_MAYBE_UNUSED)
        {
            BigUInt result;
            result = *this;
            if (util::increment_uint(value_.get(), uint64_count(), value_.get()))
            {
                resize(util::add_safe(bit_count_, 1));
                util::set_bit_uint(value_.get(), uint64_count(), bit_count_);
            }
            bit_count_ = std::max(bit_count_, significant_bit_count());
            return result;
        }

        /**
        Decrements the BigUInt but returns its old value. The bit count does not change.
        */
        inline BigUInt operator--(int postfix SEAL_MAYBE_UNUSED)
        {
            BigUInt result;
            result = *this;
            util::decrement_uint(value_.get(), uint64_count(), value_.get());
            util::filter_highbits_uint(value_.get(), uint64_count(), bit_count_);
            return result;
        }
#ifndef SEAL_USE_MAYBE_UNUSED
#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic pop
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic pop
#endif
#endif
        /**
        Adds two BigUInts and returns the sum. The input operands are not modified.
        The bit count of the sum is set to be one greater than the significant bit
        count of the larger of the two input operands.

        @param[in] operand2 The second operand to add
        */
        SEAL_NODISCARD inline BigUInt operator+(const BigUInt &operand2) const
        {
            int result_bits = util::add_safe(std::max(significant_bit_count(), operand2.significant_bit_count()), 1);
            BigUInt result(result_bits);
            util::add_uint(
                value_.get(), uint64_count(), operand2.data(), operand2.uint64_count(), false, result.uint64_count(),
                result.data());
            return result;
        }

        /**
        Adds a BigUInt and an unsigned integer and returns the sum. The input
        operands are not modified. The bit count of the sum is set to be one greater
        than the significant bit count of the larger of the two operands.

        @param[in] operand2 The second operand to add
        */
        SEAL_NODISCARD inline BigUInt operator+(std::uint64_t operand2) const
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return *this + operand2uint;
        }

        /**
        Subtracts two BigUInts and returns the difference. The input operands are
        not modified. The bit count of the difference is set to be the significant
        bit count of the larger of the two input operands.

        @param[in] operand2 The second operand to subtract
        */
        SEAL_NODISCARD inline BigUInt operator-(const BigUInt &operand2) const
        {
            int result_bits = std::max(bit_count_, operand2.bit_count());
            BigUInt result(result_bits);
            util::sub_uint(
                value_.get(), uint64_count(), operand2.data(), operand2.uint64_count(), false, result.uint64_count(),
                result.data());
            util::filter_highbits_uint(result.data(), result.uint64_count(), result_bits);
            return result;
        }

        /**
        Subtracts a BigUInt and an unsigned integer and returns the difference.
        The input operands are not modified. The bit count of the difference is set
        to be the significant bit count of the larger of the two operands.

        @param[in] operand2 The second operand to subtract
        */
        SEAL_NODISCARD inline BigUInt operator-(std::uint64_t operand2) const
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return *this - operand2uint;
        }

        /**
        Multiplies two BigUInts and returns the product. The input operands are
        not modified. The bit count of the product is set to be the sum of the
        significant bit counts of the two input operands.

        @param[in] operand2 The second operand to multiply
        */
        SEAL_NODISCARD inline BigUInt operator*(const BigUInt &operand2) const
        {
            int result_bits = util::add_safe(significant_bit_count(), operand2.significant_bit_count());
            BigUInt result(result_bits);
            util::multiply_uint(
                value_.get(), uint64_count(), operand2.data(), operand2.uint64_count(), result.uint64_count(),
                result.data());
            return result;
        }

        /**
        Multiplies a BigUInt and an unsigned integer and returns the product.
        The input operands are not modified. The bit count of the product is set
        to be the sum of the significant bit counts of the two input operands.

        @param[in] operand2 The second operand to multiply
        */
        SEAL_NODISCARD inline BigUInt operator*(std::uint64_t operand2) const
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return *this * operand2uint;
        }

        /**
        Divides two BigUInts and returns the quotient. The input operands are
        not modified. The bit count of the quotient is set to be the significant
        bit count of the first input operand.

        @param[in] operand2 The second operand to divide
        @throws std::invalid_argument if operand2 is zero
        */
        SEAL_NODISCARD BigUInt operator/(const BigUInt &operand2) const;

        /**
        Divides a BigUInt and an unsigned integer and returns the quotient. The
        input operands are not modified. The bit count of the quotient is set
        to be the significant bit count of the first input operand.

        @param[in] operand2 The second operand to divide
        @throws std::invalid_argument if operand2 is zero
        */
        SEAL_NODISCARD inline BigUInt operator/(std::uint64_t operand2) const
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return *this / operand2uint;
        }

        /**
        Performs a bit-wise XOR operation between two BigUInts and returns the
        result. The input operands are not modified. The bit count of the result
        is set to the maximum of the two input operand bit counts.

        @param[in] operand2 The second operand to XOR
        */
        SEAL_NODISCARD inline BigUInt operator^(const BigUInt &operand2) const
        {
            int result_bits = std::max(bit_count_, operand2.bit_count());
            BigUInt result(result_bits);
            std::size_t uint64_count = result.uint64_count();
            if (uint64_count != this->uint64_count())
            {
                result = *this;
                util::xor_uint(result.data(), operand2.data(), uint64_count, result.data());
            }
            else if (uint64_count != operand2.uint64_count())
            {
                result = operand2;
                util::xor_uint(result.data(), value_.get(), uint64_count, result.data());
            }
            else
            {
                util::xor_uint(value_.get(), operand2.data(), uint64_count, result.data());
            }
            return result;
        }

        /**
        Performs a bit-wise XOR operation between a BigUInt and an unsigned
        integer and returns the result. The input operands are not modified.
        The bit count of the result is set to the maximum of the two input
        operand bit counts.

        @param[in] operand2 The second operand to XOR
        */
        SEAL_NODISCARD inline BigUInt operator^(std::uint64_t operand2) const
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return *this ^ operand2uint;
        }

        /**
        Performs a bit-wise AND operation between two BigUInts and returns the
        result. The input operands are not modified. The bit count of the result
        is set to the maximum of the two input operand bit counts.

        @param[in] operand2 The second operand to AND
        */
        SEAL_NODISCARD inline BigUInt operator&(const BigUInt &operand2) const
        {
            int result_bits = std::max(bit_count_, operand2.bit_count());
            BigUInt result(result_bits);
            std::size_t uint64_count = result.uint64_count();
            if (uint64_count != this->uint64_count())
            {
                result = *this;
                util::and_uint(result.data(), operand2.data(), uint64_count, result.data());
            }
            else if (uint64_count != operand2.uint64_count())
            {
                result = operand2;
                util::and_uint(result.data(), value_.get(), uint64_count, result.data());
            }
            else
            {
                util::and_uint(value_.get(), operand2.data(), uint64_count, result.data());
            }
            return result;
        }

        /**
        Performs a bit-wise AND operation between a BigUInt and an unsigned
        integer and returns the result. The input operands are not modified.
        The bit count of the result is set to the maximum of the two input
        operand bit counts.

        @param[in] operand2 The second operand to AND
        */
        SEAL_NODISCARD inline BigUInt operator&(std::uint64_t operand2) const
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return *this & operand2uint;
        }

        /**
        Performs a bit-wise OR operation between two BigUInts and returns the
        result. The input operands are not modified. The bit count of the result
        is set to the maximum of the two input operand bit counts.

        @param[in] operand2 The second operand to OR
        */
        SEAL_NODISCARD inline BigUInt operator|(const BigUInt &operand2) const
        {
            int result_bits = std::max(bit_count_, operand2.bit_count());
            BigUInt result(result_bits);
            std::size_t uint64_count = result.uint64_count();
            if (uint64_count != this->uint64_count())
            {
                result = *this;
                util::or_uint(result.data(), operand2.data(), uint64_count, result.data());
            }
            else if (uint64_count != operand2.uint64_count())
            {
                result = operand2;
                util::or_uint(result.data(), value_.get(), uint64_count, result.data());
            }
            else
            {
                util::or_uint(value_.get(), operand2.data(), uint64_count, result.data());
            }
            return result;
        }

        /**
        Performs a bit-wise OR operation between a BigUInt and an unsigned
        integer and returns the result. The input operands are not modified.
        The bit count of the result is set to the maximum of the two input
        operand bit counts.

        @param[in] operand2 The second operand to OR
        */
        SEAL_NODISCARD inline BigUInt operator|(std::uint64_t operand2) const
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return *this | operand2uint;
        }

        /**
        Compares two BigUInts and returns -1, 0, or 1 if the BigUInt is
        less-than, equal-to, or greater-than the second operand respectively.
        The input operands are not modified.

        @param[in] compare The value to compare against
        */
        SEAL_NODISCARD inline int compareto(const BigUInt &compare) const
        {
            return util::compare_uint(value_.get(), uint64_count(), compare.value_.get(), compare.uint64_count());
        }

        /**
        Compares a BigUInt and an unsigned integer and returns -1, 0, or 1 if
        the BigUInt is less-than, equal-to, or greater-than the second operand
        respectively. The input operands are not modified.

        @param[in] compare The value to compare against
        */
        SEAL_NODISCARD inline int compareto(std::uint64_t compare) const
        {
            BigUInt compareuint;
            compareuint = compare;
            return compareto(compareuint);
        }

        /**
        Returns whether or not a BigUInt is less-than a second BigUInt. The
        input operands are not modified.

        @param[in] operand2 The value to compare against
        */
        SEAL_NODISCARD inline bool operator<(const BigUInt &compare) const
        {
            return util::compare_uint(value_.get(), uint64_count(), compare.value_.get(), compare.uint64_count()) < 0;
        }

        /**
        Returns whether or not a BigUInt is less-than an unsigned integer.
        The input operands are not modified.

        @param[in] operand2 The value to compare against
        */
        SEAL_NODISCARD inline bool operator<(std::uint64_t compare) const
        {
            BigUInt compareuint;
            compareuint = compare;
            return *this < compareuint;
        }

        /**
        Returns whether or not a BigUInt is greater-than a second BigUInt.
        The input operands are not modified.

        @param[in] operand2 The value to compare against
        */
        SEAL_NODISCARD inline bool operator>(const BigUInt &compare) const
        {
            return util::compare_uint(value_.get(), uint64_count(), compare.value_.get(), compare.uint64_count()) > 0;
        }

        /**
        Returns whether or not a BigUInt is greater-than an unsigned integer.
        The input operands are not modified.

        @param[in] operand2 The value to compare against
        */
        SEAL_NODISCARD inline bool operator>(std::uint64_t compare) const
        {
            BigUInt compareuint;
            compareuint = compare;
            return *this > compareuint;
        }

        /**
        Returns whether or not a BigUInt is less-than or equal to a second
        BigUInt. The input operands are not modified.

        @param[in] operand2 The value to compare against
        */
        SEAL_NODISCARD inline bool operator<=(const BigUInt &compare) const
        {
            return util::compare_uint(value_.get(), uint64_count(), compare.value_.get(), compare.uint64_count()) <= 0;
        }

        /**
        Returns whether or not a BigUInt is less-than or equal to an unsigned
        integer. The input operands are not modified.

        @param[in] operand2 The value to compare against
        */
        SEAL_NODISCARD inline bool operator<=(std::uint64_t compare) const
        {
            BigUInt compareuint;
            compareuint = compare;
            return *this <= compareuint;
        }

        /**
        Returns whether or not a BigUInt is greater-than or equal to a second
        BigUInt. The input operands are not modified.

        @param[in] operand2 The value to compare against
        */
        SEAL_NODISCARD inline bool operator>=(const BigUInt &compare) const
        {
            return util::compare_uint(value_.get(), uint64_count(), compare.value_.get(), compare.uint64_count()) >= 0;
        }

        /**
        Returns whether or not a BigUInt is greater-than or equal to an unsigned
        integer. The input operands are not modified.

        @param[in] operand2 The value to compare against
        */
        SEAL_NODISCARD inline bool operator>=(std::uint64_t compare) const
        {
            BigUInt compareuint;
            compareuint = compare;
            return *this >= compareuint;
        }

        /**
        Returns whether or not a BigUInt is equal to a second BigUInt.
        The input operands are not modified.

        @param[in] compare The value to compare against
        */
        SEAL_NODISCARD inline bool operator==(const BigUInt &compare) const
        {
            return util::compare_uint(value_.get(), uint64_count(), compare.value_.get(), compare.uint64_count()) == 0;
        }

        /**
        Returns whether or not a BigUInt is equal to an unsigned integer.
        The input operands are not modified.

        @param[in] compare The value to compare against
        */
        SEAL_NODISCARD inline bool operator==(std::uint64_t compare) const
        {
            BigUInt compareuint;
            compareuint = compare;
            return *this == compareuint;
        }

        /**
        Returns whether or not a BigUInt is not equal to a second BigUInt.
        The input operands are not modified.

        @param[in] compare The value to compare against
        */
        SEAL_NODISCARD inline bool operator!=(const BigUInt &compare) const
        {
            return !(operator==(compare));
        }

        /**
        Returns whether or not a BigUInt is not equal to an unsigned integer.
        The input operands are not modified.

        @param[in] operand2 The value to compare against
        */
        SEAL_NODISCARD inline bool operator!=(std::uint64_t compare) const
        {
            BigUInt compareuint;
            compareuint = compare;
            return *this != compareuint;
        }

        /**
        Returns a left-shifted copy of the BigUInt. The bit count of the
        returned value is the sum of the original significant bit count and
        the shift amount.

        @param[in] shift The number of bits to shift by
        @throws std::invalid_argument if shift is negative
        */
        SEAL_NODISCARD inline BigUInt operator<<(int shift) const
        {
            if (shift < 0)
            {
                throw std::invalid_argument("shift must be non-negative");
            }
            int result_bits = util::add_safe(significant_bit_count(), shift);
            BigUInt result(result_bits);
            result = *this;
            util::left_shift_uint(result.data(), shift, result.uint64_count(), result.data());
            return result;
        }

        /**
        Returns a right-shifted copy of the BigUInt. The bit count of the
        returned value is the original significant bit count subtracted by
        the shift amount (clipped to zero if negative).

        @param[in] shift The number of bits to shift by
        @throws std::invalid_argument if shift is negative
        */
        SEAL_NODISCARD inline BigUInt operator>>(int shift) const
        {
            if (shift < 0)
            {
                throw std::invalid_argument("shift must be non-negative");
            }
            int result_bits = util::sub_safe(significant_bit_count(), shift);
            if (result_bits <= 0)
            {
                BigUInt zero;
                return zero;
            }
            BigUInt result(result_bits);
            result = *this;
            util::right_shift_uint(result.data(), shift, result.uint64_count(), result.data());
            return result;
        }

        /**
        Adds two BigUInts saving the sum to the first operand, returning
        a reference of the first operand. The second input operand is not
        modified. The first operand is resized if and only if its bit count
        is smaller than one greater than the significant bit count of the
        larger of the two input operands.

        @param[in] operand2 The second operand to add
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator+=(const BigUInt &operand2)
        {
            int result_bits = util::add_safe(std::max(significant_bit_count(), operand2.significant_bit_count()), 1);
            if (bit_count_ < result_bits)
            {
                resize(result_bits);
            }
            util::add_uint(
                value_.get(), uint64_count(), operand2.data(), operand2.uint64_count(), false, uint64_count(),
                value_.get());
            return *this;
        }

        /**
        Adds a BigUInt and an unsigned integer saving the sum to the first operand,
        returning a reference of the first operand. The second input operand is not
        modified. The first operand is resized if and only if its bit count is
        smaller than one greater than the significant bit count of the larger of
        the two input operands.

        @param[in] operand2 The second operand to add
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator+=(std::uint64_t operand2)
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return operator+=(operand2uint);
        }

        /**
        Subtracts two BigUInts saving the difference to the first operand,
        returning a reference of the first operand. The second input operand is
        not modified. The first operand is resized if and only if its bit count
        is smaller than the significant bit count of the second operand.

        @param[in] operand2 The second operand to subtract
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator-=(const BigUInt &operand2)
        {
            int result_bits = std::max(bit_count_, operand2.bit_count());
            if (bit_count_ < result_bits)
            {
                resize(result_bits);
            }
            util::sub_uint(
                value_.get(), uint64_count(), operand2.data(), operand2.uint64_count(), false, uint64_count(),
                value_.get());
            util::filter_highbits_uint(value_.get(), uint64_count(), result_bits);
            return *this;
        }

        /**
        Subtracts a BigUInt and an unsigned integer saving the difference to
        the first operand, returning a reference of the first operand. The second
        input operand is not modified. The first operand is resized if and only
        if its bit count is smaller than the significant bit count of the second
        operand.

        @param[in] operand2 The second operand to subtract
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator-=(std::uint64_t operand2)
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return operator-=(operand2uint);
        }

        /**
        Multiplies two BigUInts saving the product to the first operand,
        returning a reference of the first operand. The second input operand
        is not modified. The first operand is resized if and only if its bit
        count is smaller than the sum of the significant bit counts of the two
        input operands.

        @param[in] operand2 The second operand to multiply
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator*=(const BigUInt &operand2)
        {
            *this = *this * operand2;
            return *this;
        }

        /**
        Multiplies a BigUInt and an unsigned integer saving the product to
        the first operand, returning a reference of the first operand. The
        second input operand is not modified. The first operand is resized if
        and only if its bit count is smaller than the sum of the significant
        bit counts of the two input operands.

        @param[in] operand2 The second operand to multiply
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator*=(std::uint64_t operand2)
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return operator*=(operand2uint);
        }

        /**
        Divides two BigUInts saving the quotient to the first operand,
        returning a reference of the first operand. The second input operand
        is not modified. The first operand is never resized.

        @param[in] operand2 The second operand to divide
        @throws std::invalid_argument if operand2 is zero
        */
        inline BigUInt &operator/=(const BigUInt &operand2)
        {
            *this = *this / operand2;
            return *this;
        }

        /**
        Divides a BigUInt and an unsigned integer saving the quotient to
        the first operand, returning a reference of the first operand. The
        second input operand is not modified. The first operand is never resized.

        @param[in] operand2 The second operand to divide
        @throws std::invalid_argument if operand2 is zero
        */
        inline BigUInt &operator/=(std::uint64_t operand2)
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return operator/=(operand2uint);
        }

        /**
        Performs a bit-wise XOR operation between two BigUInts saving the result
        to the first operand, returning a reference of the first operand. The
        second input operand is not modified. The first operand is resized if
        and only if its bit count is smaller than the significant bit count of
        the second operand.

        @param[in] operand2 The second operand to XOR
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator^=(const BigUInt &operand2)
        {
            int result_bits = std::max(bit_count_, operand2.bit_count());
            if (bit_count_ != result_bits)
            {
                resize(result_bits);
            }
            util::xor_uint(value_.get(), operand2.data(), operand2.uint64_count(), value_.get());
            return *this;
        }

        /**
        Performs a bit-wise XOR operation between a BigUInt and an unsigned integer
        saving the result to the first operand, returning a reference of the first
        operand. The second input operand is not modified. The first operand is
        resized if and only if its bit count is smaller than the significant bit
        count of the second operand.

        @param[in] operand2 The second operand to XOR
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator^=(std::uint64_t operand2)
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return operator^=(operand2uint);
        }

        /**
        Performs a bit-wise AND operation between two BigUInts saving the result
        to the first operand, returning a reference of the first operand. The
        second input operand is not modified. The first operand is resized if
        and only if its bit count is smaller than the significant bit count of
        the second operand.

        @param[in] operand2 The second operand to AND
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator&=(const BigUInt &operand2)
        {
            int result_bits = std::max(bit_count_, operand2.bit_count());
            if (bit_count_ != result_bits)
            {
                resize(result_bits);
            }
            util::and_uint(value_.get(), operand2.data(), operand2.uint64_count(), value_.get());
            return *this;
        }

        /**
        Performs a bit-wise AND operation between a BigUInt and an unsigned integer
        saving the result to the first operand, returning a reference of the first
        operand. The second input operand is not modified. The first operand is
        resized if and only if its bit count is smaller than the significant bit
        count of the second operand.

        @param[in] operand2 The second operand to AND
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator&=(std::uint64_t operand2)
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return operator&=(operand2uint);
        }

        /**
        Performs a bit-wise OR operation between two BigUInts saving the result to
        the first operand, returning a reference of the first operand. The second
        input operand is not modified. The first operand is resized if and only if
        its bit count is smaller than the significant bit count of the second
        operand.

        @param[in] operand2 The second operand to OR
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator|=(const BigUInt &operand2)
        {
            int result_bits = std::max(bit_count_, operand2.bit_count());
            if (bit_count_ != result_bits)
            {
                resize(result_bits);
            }
            util::or_uint(value_.get(), operand2.data(), operand2.uint64_count(), value_.get());
            return *this;
        }

        /**
        Performs a bit-wise OR operation between a BigUInt and an unsigned integer
        saving the result to the first operand, returning a reference of the first
        operand. The second input operand is not modified. The first operand is
        resized if and only if its bit count is smaller than the significant bit
        count of the second operand.

        @param[in] operand2 The second operand to OR
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator|=(std::uint64_t operand2)
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return operator|=(operand2uint);
        }

        /**
        Left-shifts a BigUInt by the specified amount. The BigUInt is resized if
        and only if its bit count is smaller than the sum of its significant bit
        count and the shift amount.

        @param[in] shift The number of bits to shift by
        @throws std::invalid_argument if shift is negative
        @throws std::logic_error if the BigUInt is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        inline BigUInt &operator<<=(int shift)
        {
            if (shift < 0)
            {
                throw std::invalid_argument("shift must be non-negative");
            }
            int result_bits = util::add_safe(significant_bit_count(), shift);
            if (bit_count_ < result_bits)
            {
                resize(result_bits);
            }
            util::left_shift_uint(value_.get(), shift, uint64_count(), value_.get());
            return *this;
        }

        /**
        Right-shifts a BigUInt by the specified amount. The BigUInt is never
        resized.

        @param[in] shift The number of bits to shift by
        @throws std::invalid_argument if shift is negative
        */
        inline BigUInt &operator>>=(int shift)
        {
            if (shift < 0)
            {
                throw std::invalid_argument("shift must be non-negative");
            }
            if (shift > bit_count_)
            {
                set_zero();
                return *this;
            }
            util::right_shift_uint(value_.get(), shift, uint64_count(), value_.get());
            return *this;
        }

        /**
        Divides two BigUInts and returns the quotient and sets the remainder
        parameter to the remainder. The bit count of the quotient is set to be
        the significant bit count of the BigUInt. The remainder is resized if
        and only if it is smaller than the bit count of the BigUInt.

        @param[in] operand2 The second operand to divide
        @param[out] remainder The BigUInt to store the remainder
        @throws std::invalid_argument if operand2 is zero
        @throws std::logic_error if the remainder is an alias and the operator
        attempts to enlarge the BigUInt to fit the result
        */
        BigUInt divrem(const BigUInt &operand2, BigUInt &remainder) const;

        /**
        Divides a BigUInt and an unsigned integer and returns the quotient and
        sets the remainder parameter to the remainder. The bit count of the
        quotient is set to be the significant bit count of the BigUInt. The
        remainder is resized if and only if it is smaller than the bit count
        of the BigUInt.

        @param[in] operand2 The second operand to divide
        @param[out] remainder The BigUInt to store the remainder
        @throws std::invalid_argument if operand2 is zero
        @throws std::logic_error if the remainder is an alias which the
        function attempts to enlarge to fit the result
        */
        inline BigUInt divrem(std::uint64_t operand2, BigUInt &remainder) const
        {
            BigUInt operand2uint;
            operand2uint = operand2;
            return divrem(operand2uint, remainder);
        }

        /**
        Returns the inverse of a BigUInt with respect to the specified modulus.
        The original BigUInt is not modified. The bit count of the inverse is
        set to be the significant bit count of the modulus.

        @param[in] modulus The modulus to calculate the inverse with respect to
        @throws std::invalid_argument if modulus is zero
        @throws std::invalid_argument if modulus is not greater than the BigUInt value
        @throws std::invalid_argument if the BigUInt value and modulus are not co-prime
        @throws std::logic_error if the BigUInt value is zero
        */
        SEAL_NODISCARD inline BigUInt modinv(const BigUInt &modulus) const
        {
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus must be positive");
            }
            if (is_zero())
            {
                throw std::logic_error("BigUInt value cannot be zero");
            }
            int result_bits = modulus.significant_bit_count();
            if (*this >= modulus)
            {
                throw std::invalid_argument("modulus must be greater than BigUInt");
            }
            BigUInt result(result_bits);
            result = *this;
            if (!util::try_invert_uint_mod(result.data(), modulus.data(), result.uint64_count(), result.data(), pool_))
            {
                throw std::invalid_argument("BigUInt and modulus are not co-prime");
            }
            return result;
        }

        /**
        Returns the inverse of a BigUInt with respect to the specified modulus.
        The original BigUInt is not modified. The bit count of the inverse is set
        to be the significant bit count of the modulus.

        @param[in] modulus The modulus to calculate the inverse with respect to
        @throws std::invalid_argument if modulus is zero
        @throws std::invalid_argument if modulus is not greater than the BigUInt value
        @throws std::invalid_argument if the BigUInt value and modulus are not co-prime
        @throws std::logic_error if the BigUInt value is zero
        */
        SEAL_NODISCARD inline BigUInt modinv(std::uint64_t modulus) const
        {
            BigUInt modulusuint;
            modulusuint = modulus;
            return modinv(modulusuint);
        }

        /**
        Attempts to calculate the inverse of a BigUInt with respect to the
        specified modulus, returning whether or not the inverse was successful
        and setting the inverse parameter to the inverse. The original BigUInt
        is not modified. The inverse parameter is resized if and only if its bit
        count is smaller than the significant bit count of the modulus.

        @param[in] modulus The modulus to calculate the inverse with respect to
        @param[out] inverse Stores the inverse if the inverse operation was
        successful
        @throws std::invalid_argument if modulus is zero
        @throws std::invalid_argument if modulus is not greater than the BigUInt
        value
        @throws std::logic_error if the inverse is an alias which the function
        attempts to enlarge to fit the result
        */
        inline bool trymodinv(const BigUInt &modulus, BigUInt &inverse) const
        {
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus must be positive");
            }
            if (is_zero())
            {
                return false;
            }
            int result_bits = modulus.significant_bit_count();
            if (*this >= modulus)
            {
                throw std::invalid_argument("modulus must be greater than BigUInt");
            }
            if (inverse.bit_count() < result_bits)
            {
                inverse.resize(result_bits);
            }
            inverse = *this;
            return util::try_invert_uint_mod(
                inverse.data(), modulus.data(), inverse.uint64_count(), inverse.data(), pool_);
        }

        /**
        Attempts to calculate the inverse of a BigUInt with respect to the
        specified modulus, returning whether or not the inverse was successful
        and setting the inverse parameter to the inverse. The original BigUInt
        is not modified. The inverse parameter is resized if and only if its
        bit count is smaller than the significant bit count of the modulus.

        @param[in] modulus The modulus to calculate the inverse with respect to
        @param[out] inverse Stores the inverse if the inverse operation was
        successful
        @throws std::invalid_argument if modulus is zero
        @throws std::invalid_argument if modulus is not greater than the BigUInt
        value
        @throws std::logic_error if the inverse is an alias which the function
        attempts to enlarge to fit the result
        */
        inline bool trymodinv(std::uint64_t modulus, BigUInt &inverse) const
        {
            BigUInt modulusuint;
            modulusuint = modulus;
            return trymodinv(modulusuint, inverse);
        }

        /**
        Returns an upper bound on the size of the BigUInt, as if it was written
        to an output stream.

        @param[in] compr_mode The compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the size does not fit in the return type
        */
        SEAL_NODISCARD inline std::streamoff save_size(
            compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            std::size_t members_size = Serialization::ComprSizeEstimate(
                util::add_safe(
                    util::mul_safe(uint64_count(), sizeof(std::uint64_t)), // value_
                    sizeof(std::int32_t)),                                 // bit_count_
                compr_mode);

            return util::safe_cast<std::streamoff>(util::add_safe(sizeof(Serialization::SEALHeader), members_size));
        }

        /**
        Saves the BigUInt to an output stream. The full state of the BigUInt is
        serialized, including insignificant bits. The output is in binary format
        and not human-readable. The output stream must have the "binary" flag set.

        @param[out] stream The stream to save the BigUInt to
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            std::ostream &stream, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            using namespace std::placeholders;
            return Serialization::Save(
                std::bind(&BigUInt::save_members, this, _1), save_size(compr_mode_type::none), stream, compr_mode);
        }

        /**
        Loads a BigUInt from an input stream overwriting the current BigUInt.

        @param[in] stream The stream to load the BigUInt from
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, if decompression failed,
        or if the loaded BigUInt is too large for an aliased BigUInt
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(std::istream &stream)
        {
            using namespace std::placeholders;
            return Serialization::Load(std::bind(&BigUInt::load_members, this, _1), stream);
        }

        /**
        Saves the BigUInt to a given memory location. The full state of the
        BigUInt is serialized, including insignificant bits. The output is in
        binary format and not human-readable.

        @param[out] out The memory location to write the BigUInt to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader, or if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            SEAL_BYTE *out, std::size_t size, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            using namespace std::placeholders;
            return Serialization::Save(
                std::bind(&BigUInt::save_members, this, _1), save_size(compr_mode_type::none), out, size, compr_mode);
        }

        /**
        Loads a BigUInt from a memory location overwriting the current BigUInt.

        @param[in] in The memory location to load the BigUInt from
        @param[in] size The number of bytes available in the given memory location
        @throws std::invalid_argument if in is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, if decompression failed,
        or if the loaded BigUInt is too large for an aliased BigUInt
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(const SEAL_BYTE *in, std::size_t size)
        {
            using namespace std::placeholders;
            return Serialization::Load(std::bind(&BigUInt::load_members, this, _1), in, size);
        }

        /**
        Creates a minimally sized BigUInt initialized to the specified unsigned
        integer value.

        @param[in] value The value to initialized the BigUInt to
        */
        SEAL_NODISCARD inline static BigUInt of(std::uint64_t value)
        {
            BigUInt result;
            result = value;
            return result;
        }

        /**
        Duplicates the current BigUInt. The bit count and the value of the
        given BigUInt are set to be exactly the same as in the current one.

        @param[out] destination The BigUInt to overwrite with the duplicate
        @throws std::logic_error if the destination BigUInt is an alias
        */
        inline void duplicate_to(BigUInt &destination) const
        {
            destination.resize(this->bit_count_);
            destination = *this;
        }

        /**
        Duplicates a given BigUInt. The bit count and the value of the current
        BigUInt are set to be exactly the same as in the given one.

        @param[in] value The BigUInt to duplicate
        @throws std::logic_error if the current BigUInt is an alias
        */
        inline void duplicate_from(const BigUInt &value)
        {
            this->resize(value.bit_count_);
            *this = value;
        }

    private:
        MemoryPoolHandle pool_;

        /**
        Resets the entire state of the BigUInt to an empty, zero-sized state,
        freeing any memory it internally allocated. If the BigUInt was an alias,
        the backing array is not freed but the alias is no longer referenced.
        */
        inline void reset() noexcept
        {
            value_.release();
            bit_count_ = 0;
        }

        void save_members(std::ostream &stream) const;

        void load_members(std::istream &stream);

        /**
        Points to the backing array for the BigUInt. This pointer will be set
        to nullptr if and only if the bit count is zero. This pointer is
        automatically allocated and freed by the BigUInt if and only if
        the BigUInt is not an alias. If the BigUInt is an alias, then the
        pointer was passed-in to a constructor or alias() call, and will not be
        deallocated by the BigUInt.
        */
        util::Pointer<std::uint64_t> value_;

        /**
        The bit count for the BigUInt.
        */
        int bit_count_ = 0;
    };
} // namespace seal
