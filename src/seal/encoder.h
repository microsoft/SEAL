// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include "seal/context.h"
#include "seal/biguint.h"
#include "seal/plaintext.h"
#include "seal/smallmodulus.h"
#include "seal/memorymanager.h"

namespace seal
{
    // Abstract base class for integer encoders.
    class AbstractIntegerEncoder
    {
    public:
        virtual ~AbstractIntegerEncoder() = default;

        virtual Plaintext encode(std::uint64_t value) = 0;

        virtual void encode(std::uint64_t value, Plaintext &destination) = 0;

        virtual std::uint32_t decode_uint32(const Plaintext &plain) = 0;

        virtual std::uint64_t decode_uint64(const Plaintext &plain) = 0;

        virtual Plaintext encode(std::int64_t value) = 0;

        virtual void encode(std::int64_t value, Plaintext &destination) = 0;

        virtual Plaintext encode(const BigUInt &value) = 0;

        virtual void encode(const BigUInt &value, Plaintext &destination) = 0;

        virtual std::int32_t decode_int32(const Plaintext &plain) = 0;

        virtual std::int64_t decode_int64(const Plaintext &plain) = 0;

        virtual BigUInt decode_biguint(const Plaintext &plain) = 0;

        virtual void decode_biguint(const Plaintext &plain, BigUInt &destination) = 0;

        virtual Plaintext encode(std::int32_t value) = 0;

        virtual Plaintext encode(std::uint32_t value) = 0;

        virtual void encode(std::int32_t value, Plaintext &destination) = 0;

        virtual void encode(std::uint32_t value, Plaintext &destination) = 0;

        virtual const SmallModulus &plain_modulus() const = 0;

        virtual std::uint64_t base() const = 0;

    private:
    };

    // Abstract base class for fractional encoders.
    class AbstractFractionalEncoder
    {
    public:
        virtual ~AbstractFractionalEncoder() = default;

        virtual Plaintext encode(double value) = 0;

        virtual double decode(const Plaintext &plain) = 0;

        virtual const SmallModulus &plain_modulus() const = 0;

        virtual std::size_t poly_modulus_degree() const = 0;
        
        virtual std::size_t fraction_coeff_count() const = 0;

        virtual std::size_t integer_coeff_count() const = 0;

        virtual std::uint64_t base() const = 0;

    private:
    };

    /**
    Encodes integers into plaintext polynomials that Encryptor can encrypt. An instance of
    the BinaryEncoder class converts an integer into a plaintext polynomial by placing its
    binary digits as the coefficients of the polynomial. Decoding the integer amounts to
    evaluating the plaintext polynomial at X=2.

    Addition and multiplication on the integer side translate into addition and multiplication
    on the encoded plaintext polynomial side, provided that the length of the polynomial
    never grows to be of the size of the polynomial modulus (poly_modulus), and that the
    coefficients of the plaintext polynomials appearing throughout the computations never
    experience coefficients larger than the plaintext modulus (plain_modulus).

    @par Negative Integers
    Negative integers are represented by using -1 instead of 1 in the binary representation,
    and the negative coefficients are stored in the plaintext polynomials as unsigned integers
    that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
    would be stored as a polynomial coefficient plain_modulus-1.

    @see BinaryFractionalEncoder for encoding real numbers.
    @see BalancedEncoder for encoding using base-b representation for b greater than 2.
    @see IntegerEncoder for a common interface to all integer encoders.
    */
    class BinaryEncoder : public AbstractIntegerEncoder
    {
    public:
        /**
        Creates a BinaryEncoder object. The constructor takes as input a reference
        to the plaintext modulus (represented by SmallModulus). 

        @param[in] plain_modulus The plaintext modulus (represented by SmallModulus)
        @throws std::invalid_argument if plain_modulus is not at least 2
        */
        BinaryEncoder(const SmallModulus &plain_modulus);

        /**
        Creates a copy of a BinaryEncoder.

        @param[in] copy The BinaryEncoder to copy from
        */
        BinaryEncoder(const BinaryEncoder &copy) = default;

        /**
        Creates a new BinaryEncoder by moving an old one.

        @param[in] source The BinaryEncoder to move from
        */
        BinaryEncoder(BinaryEncoder &&source) = default;

        /**
        Destroys the BinaryEncoder.
        */
        virtual ~BinaryEncoder() override
        {
        }

        /**
        Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        */
        virtual Plaintext encode(std::uint64_t value) override;

        /**
        Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::uint64_t value, Plaintext &destination) override;

        /**
        Decodes a plaintext polynomial and returns the result as std::uint32_t.
        Mathematically this amounts to evaluating the input polynomial at X=2.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if the output does not fit in std::uint32_t 
        */
        virtual std::uint32_t decode_uint32(const Plaintext &plain) override;

        /**
        Decodes a plaintext polynomial and returns the result as std::uint64_t.
        Mathematically this amounts to evaluating the input polynomial at X=2.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if the output does not fit in std::uint64_t 
        */
        virtual std::uint64_t decode_uint64(const Plaintext &plain) override;

        /**
        Encodes a signed integer (represented by std::uint64_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers are represented by using -1 instead of 1 in the binary representation,
        and the negative coefficients are stored in the plaintext polynomials as unsigned integers
        that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        */
        virtual Plaintext encode(std::int64_t value) override;

        /**
        Encodes a signed integer (represented by std::int64_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers are represented by using -1 instead of 1 in the binary representation,
        and the negative coefficients are stored in the plaintext polynomials as unsigned integers
        that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::int64_t value, Plaintext &destination) override;

        /**
        Encodes an unsigned integer (represented by BigUInt) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        */
        virtual Plaintext encode(const BigUInt &value) override;

        /**
        Encodes an unsigned integer (represented by BigUInt) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(const BigUInt &value, Plaintext &destination) override;

        /**
        Decodes a plaintext polynomial and returns the result as std::int32_t.
        Mathematically this amounts to evaluating the input polynomial at X=2.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in std::int32_t 
        */
        virtual std::int32_t decode_int32(const Plaintext &plain) override;

        /**
        Decodes a plaintext polynomial and returns the result as std::int64_t.
        Mathematically this amounts to evaluating the input polynomial at X=2.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in std::int64_t 
        */
        virtual std::int64_t decode_int64(const Plaintext &plain) override;

        /**
        Decodes a plaintext polynomial and returns the result as BigUInt.
        Mathematically this amounts to evaluating the input polynomial at X=2.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output is negative
        */
        virtual BigUInt decode_biguint(const Plaintext &plain) override;

        /**
        Decodes a plaintext polynomial and stores the result in a given BigUInt.
        Mathematically this amounts to evaluating the input polynomial at X=2.

        @param[in] plain The plaintext to be decoded
        @param[out] destination The BigUInt to overwrite with the decoding
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in destination
        @throws std::invalid_argument if the output is negative 
        */
        virtual void decode_biguint(const Plaintext &plain, BigUInt &destination) override;

        /**
        Encodes a signed integer (represented by std::int32_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers are represented by using -1 instead of 1 in the binary representation,
        and the negative coefficients are stored in the plaintext polynomials as unsigned integers
        that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        */
        virtual Plaintext encode(std::int32_t value) override
        {
            return encode(static_cast<std::int64_t>(value));
        }

        /**
        Encodes an unsigned integer (represented by std::uint32_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        */
        virtual Plaintext encode(std::uint32_t value) override
        {
            return encode(static_cast<std::uint64_t>(value));
        }

        /**
        Encodes a signed integer (represented by std::int32_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers are represented by using -1 instead of 1 in the binary representation,
        and the negative coefficients are stored in the plaintext polynomials as unsigned integers
        that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::int32_t value, Plaintext &destination) override
        {
            encode(static_cast<std::int64_t>(value), destination);
        }

        /**
        Encodes an unsigned integer (represented by std::uint32_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::uint32_t value, Plaintext &destination) override
        {
            encode(static_cast<std::uint64_t>(value), destination);
        }

        /**
        Returns a reference to the plaintext modulus.
        */
        virtual const SmallModulus &plain_modulus() const override
        {
            return plain_modulus_;
        }

        /**
        <summary>Returns the base used for encoding (2).</summary>
        */
        virtual std::uint64_t base() const override
        {
            return 2;
        }

    private:
        BinaryEncoder &operator =(const BinaryEncoder &assign) = delete;

        BinaryEncoder &operator =(BinaryEncoder &&assign) = delete;

        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        SmallModulus plain_modulus_;

        std::uint64_t coeff_neg_threshold_;

        std::uint64_t neg_one_;

        friend class BinaryFractionalEncoder;
    };

    /**
    Encodes integers into plaintext polynomials that Encryptor can encrypt. An instance of
    the BalancedEncoder class converts an integer into a plaintext polynomial by placing its
    digits in balanced base-b representation as the coefficients of the polynomial. The base
    b must be a positive integer at least 3 (which is the default value). When b is odd,
    digits in such a balanced representation are integers in the range
    -(b-1)/2,...,(b-1)/2. When b is even, digits are integers in the range -b/2,..., b/2-1.
    Note that the default value 3 for the base b allows for more compact representation than
    BinaryEncoder without increasing the sizes of the coefficients of freshly encoded plaintext
    polynomials. A larger base allows for an even more compact representation at the cost of
    having larger coefficients in freshly encoded plaintext polynomials. Decoding the integer
    amounts to evaluating the plaintext polynomial at X=b.

    Addition and multiplication on the integer side translate into addition and multiplication
    on the encoded plaintext polynomial side, provided that the length of the polynomial
    never grows to be of the size of the polynomial modulus (poly_modulus), and that the
    coefficients of the plaintext polynomials appearing throughout the computations never
    experience coefficients larger than the plaintext modulus (plain_modulus).

    @par Negative Integers
    Negative integers in the balanced base-b encoding are represented the same way as
    positive integers, namely, both positive and negative integers can have both positive and negative
    digits in their balanced base-b representation. Negative coefficients are stored in the
    plaintext polynomials as unsigned integers that represent them modulo the plaintext modulus.
    Thus, for example, a coefficient of -1 would be stored as a polynomial coefficient plain_modulus-1.

    @see BalancedFractionalEncoder for encoding real numbers.
    @see BinaryEncoder for encoding using the binary representation.
    @see IntegerEncoder for a common interface to all integer encoders.
    */
    class BalancedEncoder : public AbstractIntegerEncoder
    {
    public:
        /**
        Creates a BalancedEncoder object. The constructor takes as input a reference
        to the plaintext modulus (represented by SmallModulus), and optionally an integer,
        at least 3, that is used as a base in the encoding.

        @param[in] plain_modulus The plaintext modulus (represented by SmallModulus)
        @param[in] base The base to be used for encoding (default value is 3)
        @throws std::invalid_argument if base is not an integer and at least 3
        @throws std::invalid_argument if plain_modulus is not at least base
        */
        BalancedEncoder(const SmallModulus &plain_modulus, std::uint64_t base = 3);

        /**
        Creates a copy of a BalancedEncoder.

        @param[in] copy The BalancedEncoder to copy from
        */
        BalancedEncoder(const BalancedEncoder &copy) = default;

        /**
        Creates a new BalancedEncoder by moving an old one.

        @param[in] source The BalancedEncoder to move from
        */
        BalancedEncoder(BalancedEncoder &&source) = default;

        /**
        Destroys the BalancedEncoder.
        */
        virtual ~BalancedEncoder()
        {
        }

        /**
        Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        */
        virtual Plaintext encode(std::uint64_t value) override;

        /**
        Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::uint64_t value, Plaintext &destination) override;

        /**
        Decodes a plaintext polynomial and returns the result as std::uint32_t.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in std::uint32_t 
        */
        virtual std::uint32_t decode_uint32(const Plaintext &plain) override;

        /**
        Decodes a plaintext polynomial and returns the result as std::uint64_t.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in std::uint64_t 
        */
        virtual std::uint64_t decode_uint64(const Plaintext &plain) override;

        /**
        Encodes a signed integer (represented by std::int64_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers in the balanced base-b encoding are represented the same way as
        positive integers, namely, both positive and negative integers can have both positive and negative
        digits in their balanced base-b representation. Negative coefficients are stored in the
        plaintext polynomials as unsigned integers that represent them modulo the plaintext modulus.
        Thus, for example, a coefficient of -1 would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        */
        virtual Plaintext encode(std::int64_t value) override;

        /**
        Encodes a signed integer (represented by std::int64_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers in the balanced base-b encoding are represented the same way as
        positive integers, namely, both positive and negative integers can have both positive and negative
        digits in their balanced base-b representation. Negative coefficients are stored in the
        plaintext polynomials as unsigned integers that represent them modulo the plaintext modulus.
        Thus, for example, a coefficient of -1 would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::int64_t value, Plaintext &destination) override;

        /**
        Encodes an unsigned integer (represented by BigUInt) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        */
        virtual Plaintext encode(const BigUInt &value) override;

        /**
        Encodes an unsigned integer (represented by BigUInt) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(const BigUInt &value, Plaintext &destination) override;

        /**
        Decodes a plaintext polynomial and returns the result as std::int32_t.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in std::int32_t 
        */
        virtual std::int32_t decode_int32(const Plaintext &plain) override;

        /**
        Decodes a plaintext polynomial and returns the result as std::int64_t.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in std::int64_t 
        */
        virtual std::int64_t decode_int64(const Plaintext &plain) override;

        /**
        Decodes a plaintext polynomial and returns the result as BigUInt.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output is negative
        */
        virtual BigUInt decode_biguint(const Plaintext &plain) override;

        /**
        Decodes a plaintext polynomial and stores the result in a given BigUInt.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @param[out] destination The BigUInt to overwrite with the decoding
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in destination
        @throws std::invalid_argument if the output is negative 
        */
        virtual void decode_biguint(const Plaintext &plain, BigUInt &destination) override;

        /**
        Encodes a signed integer (represented by std::int32_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers in the balanced base-b encoding are represented the same way as
        positive integers, namely, both positive and negative integers can have both positive and negative
        digits in their balanced base-b representation. Negative coefficients are stored in the
        plaintext polynomials as unsigned integers that represent them modulo the plaintext modulus.
        Thus, for example, a coefficient of -1 would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        */
        virtual Plaintext encode(std::int32_t value) override
        {
            return encode(static_cast<std::int64_t>(value));
        }

        /**
        Encodes an unsigned integer (represented by std::uint32_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        */
        virtual Plaintext encode(std::uint32_t value) override
        {
            return encode(static_cast<std::uint64_t>(value));
        }

        /**
        Encodes a signed integer (represented by std::int32_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers in the balanced base-b encoding are represented the same way as
        positive integers, namely, both positive and negative integers can have both positive and negative
        digits in their balanced base-b representation. Negative coefficients are stored in the
        plaintext polynomials as unsigned integers that represent them modulo the plaintext modulus.
        Thus, for example, a coefficient of -1 would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::int32_t value, Plaintext &destination) override
        {
            encode(static_cast<std::int64_t>(value), destination);
        }

        /**
        Encodes an unsigned integer (represented by std::uint32_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::uint32_t value, Plaintext &destination) override
        {
            encode(static_cast<std::uint64_t>(value), destination);
        }

        /**
        Returns a reference to the plaintext modulus.
        */
        virtual const SmallModulus &plain_modulus() const override
        {
            return plain_modulus_;
        }

        /**
        Returns the base used for encoding.
        */
        virtual std::uint64_t base() const override
        {
            return base_;
        }

    private:
        BalancedEncoder &operator =(const BalancedEncoder &assign) = delete;

        BalancedEncoder &operator =(BalancedEncoder &&assign) = delete;

        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        SmallModulus plain_modulus_;

        std::uint64_t base_;

        std::uint64_t coeff_neg_threshold_;

        friend class BalancedFractionalEncoder;
    };

    /**
    Encodes floating point numbers into plaintext polynomials that Encryptor can encrypt.
    An instance of the BinaryFractionalEncoder class converts a double-precision floating-point
    number into a plaintext polynomial by computing its binary representation, encoding the
    integral part as in BinaryEncoder, and the fractional part as the highest degree
    terms of the plaintext polynomial, with signs inverted. Decoding the polynomial
    back into a double amounts to evaluating the low degree part at X=2, negating the
    coefficients of the high degree part and evaluating it at X=1/2.

    Addition and multiplication on the double side translate into addition and multiplication
    on the encoded plaintext polynomial side, provided that the integral part never mixes
    with the fractional part in the plaintext polynomials, and that the
    coefficients of the plaintext polynomials appearing throughout the computations never
    experience coefficients larger than the plaintext modulus (plain_modulus).

    @par Integral and Fractional Parts
    When homomorphic multiplications are performed, the integral part "grows up" to higher
    degree coefficients of the plaintext polynomial space, and the fractional part "grows down"
    from the top degree coefficients towards the lower degree coefficients. For decoding to work,
    these parts must not interfere with each other. When setting up the BinaryFractionalEncoder,
    one must specify how many coefficients of a plaintext polynomial are reserved for the integral
    part and how many for the fractional. The sum of these numbers can be at most equal to the
    degree of the polynomial modulus minus one. If homomorphic multiplications are performed, it is
    also necessary to leave enough room for the fractional part to "grow down".

    @par Negative Integers
    Negative integers are represented by using -1 instead of 1 in the binary representation,
    and the negative coefficients are stored in the plaintext polynomials as unsigned integers
    that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
    would be stored as a polynomial coefficient plain_modulus-1.

    @see BinaryEncoder for encoding integers.
    @see BalancedFractionalEncoder for encoding using base-b representation for b greater than 2.
    @see FractionalEncoder for a common interface to all fractional encoders.
    */
    class BinaryFractionalEncoder : public AbstractFractionalEncoder
    {
    public:
        /**
        Creates a new BinaryFractionalEncoder object. The constructor takes as input a reference
        to the plaintext modulus, the degree of the polynomial modulus, and the numbers of 
        coefficients that are reserved for the integral and fractional parts. The coefficients 
        for the integral part are counted starting from the low-degree end of the polynomial, 
        and the coefficients for the fractional part are counted from the high-degree end.

        @param[in] plain_modulus The plaintext modulus (represented by SmallModulus)
        @param[in] poly_modulus_degree The degree of the polynomial modulus
        @param[in] integer_coeff_count The number of polynomial coefficients reserved for the integral part
        @param[in] fraction_coeff_count The number of polynomial coefficients reserved for the fractional part
        @throws std::invalid_argument if plain_modulus_degree is invalid
        @throws std::invalid_argument if integer_coeff_count is not strictly positive
        @throws std::invalid_argument if fraction_coeff_count is not strictly positive
        @throws std::invalid_argument if poly_modulus_degree is too small for the integral and fractional parts
        */
        BinaryFractionalEncoder(const SmallModulus &plain_modulus, std::size_t poly_modulus_degree, 
            std::size_t integer_coeff_count, std::size_t fraction_coeff_count);

        /**
        Creates a copy of a BinaryFractionalEncoder.

        @param[in] copy The BinaryFractionalEncoder to copy from
        */
        BinaryFractionalEncoder(const BinaryFractionalEncoder &copy) = default;

        /**
        Creates a new BinaryFractionalEncoder by moving an old one.

        @param[in] source The BinaryFractionalEncoder to move from
        */
        BinaryFractionalEncoder(BinaryFractionalEncoder &&source) = default;

        /**
        Destroys the BinaryFractionalEncoder.
        */
        virtual ~BinaryFractionalEncoder()
        {
        }

        /**
        Encodes a double precision floating point number into a plaintext polynomial.

        @param[in] value The double-precision floating-point number to encode
        */
        virtual Plaintext encode(double value) override;

        /**
        Decodes a plaintext polynomial and returns the result as a double-precision
        floating-point number.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the integral part does not fit in std::int64_t 
        */
        virtual double decode(const Plaintext &plain) override;

        /**
        Returns a reference to the plaintext modulus.
        */
        virtual const SmallModulus &plain_modulus() const override
        {
            return encoder_.plain_modulus();
        }

        /**
        Returns the degree of the polynomial modulus.
        */
        virtual std::size_t poly_modulus_degree() const override
        {
            return poly_modulus_degree_;
        }

        /**
        Returns the base used for encoding (2).
        */
        virtual std::uint64_t base() const override
        {
            return 2;
        }

        /**
        Returns the number of coefficients reserved for the fractional part.
        */
        virtual std::size_t fraction_coeff_count() const override
        {
            return fraction_coeff_count_;
        }

        /**
        Returns the number of coefficients reserved for the integral part.
        */
        virtual std::size_t integer_coeff_count() const override
        {
            return integer_coeff_count_;
        }

    private:
        BinaryFractionalEncoder &operator =(const BinaryFractionalEncoder &assign) = delete;

        BinaryFractionalEncoder &operator =(BinaryFractionalEncoder &&assign) = delete;

        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        BinaryEncoder encoder_;

        std::size_t fraction_coeff_count_;

        std::size_t integer_coeff_count_;

        std::size_t poly_modulus_degree_;
    };

    /**
    Encodes floating point numbers into plaintext polynomials that Encryptor can encrypt.
    An instance of the BalancedFractionalEncoder class converts a double-precision floating-point
    number into a plaintext polynomial by computing its balanced base-b representation, encoding the
    integral part as in BalancedEncoder, and the fractional part as the highest degree
    terms of the plaintext polynomial, with signs inverted. For an even base b, the
    coefficients of the polynomial are in the range -b/2,...,b/2-1. Decoding the polynomial back
    into a double amounts to evaluating the low degree part at X=b, negating the coefficients
    of the high degree part and evaluating it at X=1/b.

    Addition and multiplication on the double side translate into addition and multiplication
    on the encoded plaintext polynomial side, provided that the integral part never mixes
    with the fractional part in the plaintext polynomials, and that the
    coefficients of the plaintext polynomials appearing throughout the computations never
    experience coefficients larger than the plaintext modulus (plain_modulus).

    @par Integral and Fractional Parts
    When homomorphic multiplications are performed, the integral part "grows up" to higher
    degree coefficients of the plaintext polynomial space, and the fractional part "grows down"
    from the top degree coefficients towards the lower degree coefficients. For decoding to work,
    these parts must not interfere with each other. When setting up the BalancedFractionalEncoder,
    one must specify how many coefficients of a plaintext polynomial are reserved for the integral
    part and how many for the fractional. The sum of these numbers can be at most equal to the
    degree of the polynomial modulus minus one. If homomorphic multiplications are performed, it is
    also necessary to leave enough room for the fractional part to "grow down".

    @par Negative Integers
    Negative integers in the balanced base-b encoding are represented the same way as
    positive integers, namely, both positive and negative integers can have both positive and negative
    digits in their balanced base-b representation. Negative coefficients are stored in the
    plaintext polynomials as unsigned integers that represent them modulo the plaintext modulus.
    Thus, for example, a coefficient of -1 would be stored as a polynomial coefficient plain_modulus-1.

    @see BalancedEncoder for encoding integers.
    @see BinaryFractionalEncoder for encoding using the binary representation.
    @see FractionalEncoder for a common interface to all fractional encoders.
    */
    class BalancedFractionalEncoder : public AbstractFractionalEncoder
    {
    public:
        /**
        Creates a new BalancedFractionalEncoder object. The constructor takes as input a reference
        to the plaintext modulus, the degree of the polynomial modulus, and the numbers of 
        coefficients that are reserved for the integral and fractional parts, and optionally 
        an integer, at least 3, that is used as the base in the encoding. The coefficients for the 
        integral part are counted starting from the low-degree end of the polynomial, and the 
        coefficients for the fractional part are counted from the high-degree end.

        @param[in] plain_modulus The plaintext modulus (represented by SmallModulus)
        @param[in] poly_modulus_degree The degree of the polynomial modulus
        @param[in] integer_coeff_count The number of polynomial coefficients reserved for the integral part
        @param[in] fraction_coeff_count The number of polynomial coefficients reserved for the fractional part
        @param[in] base The base to be used for encoding (default value is 3)
        @throws std::invalid_argument if plain_modulus is not at least base
        @throws std::invalid_argument if integer_coeff_count is not strictly positive
        @throws std::invalid_argument if fraction_coeff_count is not strictly positive
        @throws std::invalid_argument if poly_modulus_degree is too small for the integral and fractional parts
        @throws std::invalid_argument if base is not an integer and at least 3
        */
        BalancedFractionalEncoder(const SmallModulus &plain_modulus, std::size_t poly_modulus_degree, 
            std::size_t integer_coeff_count, std::size_t fraction_coeff_count, std::uint64_t base = 3);

        /**
        Creates a copy of a BalancedFractionalEncoder.

        @param[in] copy The BalancedFractionalEncoder to copy from
        */
        BalancedFractionalEncoder(const BalancedFractionalEncoder &copy) = default;

        /**
        Creates a new BalancedFractionalEncoder by moving an old one.

        @param[in] source The BalancedFractionalEncoder to move from
        */
        BalancedFractionalEncoder(BalancedFractionalEncoder &&source) = default;

        /**
        Destroys the BalancedFractionalEncoder.
        */
        virtual ~BalancedFractionalEncoder()
        {
        }
        
        /**
        Encodes a double precision floating point number into a plaintext polynomial.

        @param[in] value The double-precision floating-point number to encode
        */
        virtual Plaintext encode(double value) override;

        /**
        Decodes a plaintext polynomial and returns the result as a double-precision
        floating-point number.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the integral part does not fit in std::int64_t 
        */
        virtual double decode(const Plaintext &plain) override;

        /**
        Returns a reference to the plaintext modulus.
        */
        virtual const SmallModulus &plain_modulus() const override
        {
            return encoder_.plain_modulus();
        }

        /**
        Returns the degree of the polynomial modulus.
        */
        virtual std::size_t poly_modulus_degree() const override
        {
            return poly_modulus_degree_;
        }

        /**
        Returns the base used for encoding.
        */
        virtual std::uint64_t base() const override
        {
            return encoder_.base();
        }

        /**
        Returns the number of coefficients reserved for the fractional part.
        */
        virtual std::size_t fraction_coeff_count() const override
        {
            return fraction_coeff_count_;
        }

        /**
        Returns the number of coefficients reserved for the integral part.
        */
        virtual std::size_t integer_coeff_count() const override
        {
            return integer_coeff_count_;
        }

    private:
        BalancedFractionalEncoder &operator =(const BalancedFractionalEncoder &assign) = delete;

        BalancedFractionalEncoder &operator =(BalancedFractionalEncoder &&assign) = delete;

        Plaintext encode_even(double value);

        Plaintext encode_odd(double value);

        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        BalancedEncoder encoder_;

        std::size_t fraction_coeff_count_;

        std::size_t integer_coeff_count_;

        std::size_t poly_modulus_degree_;
    };

    /**
    Encodes integers into plaintext polynomials that Encryptor can encrypt. An instance of
    the IntegerEncoder class converts an integer into a plaintext polynomial by placing its
    digits in balanced base-b representation as the coefficients of the polynomial. The base
    b must be a positive integer at least 2 (which is the default value). When b is odd,
    digits in such a balanced representation are integers in the range -(b-1)/2,...,(b-1)/2.
    When b is even, digits are integers in the range -b/2,...,b/2-1. When b is 2, the 
    coefficients are either all non-negative (0 and 1), or all non-positive (0 and -1). A larger 
    base allows for more compact representation at the cost of having larger coefficients in 
    freshly encoded plaintext polynomials. Decoding the integer amounts to evaluating the 
    plaintext polynomial at X=b.

    Addition and multiplication on the integer side translate into addition and multiplication
    on the encoded plaintext polynomial side, provided that the length of the polynomial
    never grows to be of the size of the polynomial modulus (poly_modulus), and that the
    coefficients of the plaintext polynomials appearing throughout the computations never
    experience coefficients larger than the plaintext modulus (plain_modulus).

    @par Negative Integers
    Negative integers in the base-b encoding are represented the same way as positive integers, 
    namely, both positive and negative integers can have both positive and negative digits in their 
    base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned 
    integers that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1 
    would be stored as a polynomial coefficient plain_modulus-1.

    @par BinaryEncoder and BalancedEncoder
    Under the hood IntegerEncoder uses either the BinaryEncoder or the BalancedEncoder classes
    to do the encoding. The first one is used when the base is 2, and the second one when the
    base is at least 3. Currently the BinaryEncoder and BalancedEncoder classes can also be used 
    directly, but this might change in future releases.

    @see BinaryEncoder for encoding using the binary representation.
    @see BalancedEncoder for encoding using base-b representation for b greater than 2.
    @see FractionalEncoder for encoding real numbers.
    */
    class IntegerEncoder : public AbstractIntegerEncoder
    {
    public:
        /**
        Creates an IntegerEncoder object. The constructor takes as input a reference
        to the plaintext modulus (represented by SmallModulus), and optionally an integer,
        at least 2, that is used as a base in the encoding.

        @param[in] plain_modulus The plaintext modulus (represented by SmallModulus)
        @param[in] base The base to be used for encoding (default value is 2)
        @throws std::invalid_argument if base is not an integer and at least 2
        @throws std::invalid_argument if plain_modulus is not at least base
        */
        IntegerEncoder(const SmallModulus &plain_modulus, std::uint64_t base = 2);

        /**
        Creates a copy of a IntegerEncoder.

        @param[in] copy The IntegerEncoder to copy from
        */
        IntegerEncoder(const IntegerEncoder &copy);

        /**
        Creates a new IntegerEncoder by moving an old one.

        @param[in] source The IntegerEncoder to move from
        */
        IntegerEncoder(IntegerEncoder &&source) = default;

        /**
        Destroys the IntegerEncoder.
        */
        virtual ~IntegerEncoder() override;

        /**
        Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        */
        virtual Plaintext encode(std::uint64_t value) override
        {
            return encoder_->encode(value);
        }

        /**
        Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::uint64_t value, Plaintext &destination) override;

        /**
        Decodes a plaintext polynomial and returns the result as std::uint32_t.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in std::uint32_t 
        */
        virtual std::uint32_t decode_uint32(const Plaintext &plain) override
        {
            return encoder_->decode_uint32(plain);
        }

        /**
        Decodes a plaintext polynomial and returns the result as std::uint64_t.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in std::uint64_t 
        */
        virtual std::uint64_t decode_uint64(const Plaintext &plain) override
        {
            return encoder_->decode_uint64(plain);
        }

        /**
        Encodes a signed integer (represented by std::int64_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers in the base-b encoding are represented the same way as positive integers,
        namely, both positive and negative integers can have both positive and negative digits in their
        base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned
        integers that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        */
        virtual Plaintext encode(std::int64_t value) override
        {
            return encoder_->encode(value);
        }

        /**
        Encodes a signed integer (represented by std::int64_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers in the base-b encoding are represented the same way as positive integers,
        namely, both positive and negative integers can have both positive and negative digits in their
        base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned
        integers that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::int64_t value, Plaintext &destination) override;

        /**
        Encodes an unsigned integer (represented by BigUInt) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        */
        virtual Plaintext encode(const BigUInt &value) override
        {
            return encoder_->encode(value);
        }

        /**
        Encodes an unsigned integer (represented by BigUInt) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(const BigUInt &value, Plaintext &destination) override;

        /**
        Decodes a plaintext polynomial and returns the result as std::int32_t.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in std::int32_t 
        */
        virtual std::int32_t decode_int32(const Plaintext &plain) override
        {
            return encoder_->decode_int32(plain);
        }

        /**
        Decodes a plaintext polynomial and returns the result as std::int64_t.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in std::int64_t 
        */
        virtual std::int64_t decode_int64(const Plaintext &plain) override
        {
            return encoder_->decode_int64(plain);
        }

        /**
        Decodes a plaintext polynomial and returns the result as BigUInt.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output is negative 
        */
        virtual BigUInt decode_biguint(const Plaintext &plain) override
        {
            return encoder_->decode_biguint(plain);
        }

        /**
        Decodes a plaintext polynomial and stores the result in a given BigUInt.
        Mathematically this amounts to evaluating the input polynomial at X=base.

        @param[in] plain The plaintext to be decoded
        @param[out] destination The BigUInt to overwrite with the decoding
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the output does not fit in destination
        @throws std::invalid_argument if the output is negative 
        */
        virtual void decode_biguint(const Plaintext &plain, BigUInt &destination) override
        {
            encoder_->decode_biguint(plain, destination);
        }

        /**
        Encodes a signed integer (represented by std::int32_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers in the base-b encoding are represented the same way as positive integers,
        namely, both positive and negative integers can have both positive and negative digits in their
        base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned
        integers that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        */
        virtual Plaintext encode(std::int32_t value) override
        {
            return encoder_->encode(value);
        }

        /**
        Encodes an unsigned integer (represented by std::uint32_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        */
        virtual Plaintext encode(std::uint32_t value) override
        {
            return encoder_->encode(value);
        }

        /**
        Encodes a signed integer (represented by std::int32_t) into a plaintext polynomial.

        @par Negative Integers
        Negative integers in the base-b encoding are represented the same way as positive integers,
        namely, both positive and negative integers can have both positive and negative digits in their
        base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned
        integers that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        would be stored as a polynomial coefficient plain_modulus-1.

        @param[in] value The signed integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::int32_t value, Plaintext &destination) override;

        /**
        Encodes an unsigned integer (represented by std::uint32_t) into a plaintext polynomial.

        @param[in] value The unsigned integer to encode
        @param[out] destination The plaintext to overwrite with the encoding
        */
        virtual void encode(std::uint32_t value, Plaintext &destination) override;

        /**
        Returns a reference to the plaintext modulus.
        */
        virtual const SmallModulus &plain_modulus() const override
        {
            return encoder_->plain_modulus();
        }

        /**
        Returns the base used for encoding.
        */
        virtual std::uint64_t base() const override
        {
            return encoder_->base();
        }

    private:
        IntegerEncoder &operator =(const IntegerEncoder &assign) = delete;

        IntegerEncoder &operator =(IntegerEncoder &&assign) = delete;

        AbstractIntegerEncoder *encoder_;
    };

    /**
    Encodes floating point numbers into plaintext polynomials that Encryptor can encrypt.
    An instance of the FractionalEncoder class converts a double-precision floating-point
    number into a plaintext polynomial by computing its balanced base-b representation, 
    encoding the integral part as in IntegerEncoder, and the fractional part as the highest 
    degree terms of the plaintext polynomial, with signs inverted. For an even base b, the
    coefficients of the polynomial are in the range -b/2,...,b/2-1. When b is 2, the
    coefficients are either all non-negative (0 and 1), or all non-positive (0 and -1).
    Decoding the polynomial back into a double amounts to evaluating the low degree part 
    at X=b, negating the coefficients of the high degree part and evaluating it at X=1/b.

    Addition and multiplication on the double side translate into addition and multiplication
    on the encoded plaintext polynomial side, provided that the integral part never mixes
    with the fractional part in the plaintext polynomials, and that the
    coefficients of the plaintext polynomials appearing throughout the computations never
    experience coefficients larger than the plaintext modulus (plain_modulus).

    @par Integral and Fractional Parts
    When homomorphic multiplications are performed, the integral part "grows up" to higher
    degree coefficients of the plaintext polynomial space, and the fractional part "grows down"
    from the top degree coefficients towards the lower degree coefficients. For decoding to work,
    these parts must not interfere with each other. When setting up the BalancedFractionalEncoder,
    one must specify how many coefficients of a plaintext polynomial are reserved for the integral
    part and how many for the fractional. The sum of these numbers can be at most equal to the
    degree of the polynomial modulus minus one. If homomorphic multiplications are performed, it is
    also necessary to leave enough room for the fractional part to "grow down".

    @par Negative Integers
    Negative integers in the base-b encoding are represented the same way as positive integers,
    namely, both positive and negative integers can have both positive and negative digits in their
    base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned
    integers that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
    would be stored as a polynomial coefficient plain_modulus-1.

    @par BinaryFractionalEncoder and BalancedFractionalEncoder
    Under the hood FractionalEncoder uses either the BinaryFractionalEncoder or the 
    BalancedFractionalEncoder classes to do the encoding. The first one is used when the base is 2, 
    and the second one when the base is at least 3. Currently the BinaryFractionalEncoder and 
    BalancedFractionalEncoder classes can also be used directly, but this might change in future releases.

    @see BinaryFractionalEncoder for encoding using the binary representation.
    @see BalancedFractionalEncoder for encoding using base-b representation for b greater than 2.
    @see IntegerEncoder for encoding integers.
    */
    class FractionalEncoder : public AbstractFractionalEncoder
    {
    public:
        /**
        Creates a new FractionalEncoder object. The constructor takes as input a reference
        to the plaintext modulus, the degree of the polynomial modulus, and the numbers of 
        coefficients that are reserved for the integral and fractional parts, and optionally 
        an integer, at least 2, that is used as the base in the encoding. The coefficients 
        for the integral part are counted starting from the low-degree end of the polynomial, 
        and the coefficients for the fractional part are counted from the high-degree end.

        @param[in] plain_modulus The plaintext modulus (represented by SmallModulus)
        @param[in] poly_modulus_degree The degree of the polynomial modulus
        @param[in] integer_coeff_count The number of polynomial coefficients reserved for the integral part
        @param[in] fraction_coeff_count The number of polynomial coefficients reserved for the fractional part
        @param[in] base The base to be used for encoding (default value is 2)
        @throws std::invalid_argument if plain_modulus is not at least base
        @throws std::invalid_argument if integer_coeff_count is not strictly positive
        @throws std::invalid_argument if fraction_coeff_count is not strictly positive
        @throws std::invalid_argument if poly_modulus_degree is too small for the integral and fractional parts
        @throws std::invalid_argument if base is not an integer and at least 2
        */
        FractionalEncoder(const SmallModulus &plain_modulus, std::size_t poly_modulus_degree, 
            std::size_t integer_coeff_count, std::size_t fraction_coeff_count, std::uint64_t base = 2);

        /**
        Creates a copy of a FractionalEncoder.

        @param[in] copy The FractionalEncoder to copy from
        */
        FractionalEncoder(const FractionalEncoder &copy);

        /**
        Creates a new FractionalEncoder by moving an old one.

        @param[in] source The FractionalEncoder to move from
        */
        FractionalEncoder(FractionalEncoder &&source) = default;

        /**
        Destroys the FractionalEncoder.
        */
        virtual ~FractionalEncoder() override;

        /**
        Encodes a double precision floating point number into a plaintext polynomial.

        @param[in] value The double-precision floating-point number to encode
        */
        virtual Plaintext encode(double value) override
        {
            return encoder_->encode(value);
        }

        /**
        Decodes a plaintext polynomial and returns the result as a double-precision
        floating-point number.

        @param[in] plain The plaintext to be decoded
        @throws std::invalid_argument if plain does not represent a valid plaintext polynomial
        @throws std::invalid_argument if the integral part does not fit in std::int64_t 
        */
        virtual double decode(const Plaintext &plain) override
        {
            return encoder_->decode(plain);
        }

        /**
        Returns a reference to the plaintext modulus.
        */
        virtual const SmallModulus &plain_modulus() const override
        {
            return encoder_->plain_modulus();
        }

        /**
        Returns the degree of the polynomial modulus.
        */
        virtual std::size_t poly_modulus_degree() const override
        {
            return encoder_->poly_modulus_degree();
        }

        /**
        Returns the base used for encoding.
        */
        virtual std::uint64_t base() const override
        {
            return encoder_->base();
        }

        /**
        Returns the number of coefficients reserved for the fractional part.
        */
        virtual std::size_t fraction_coeff_count() const override
        {
            return encoder_->fraction_coeff_count();
        }

        /**
        Returns the number of coefficients reserved for the integral part.
        */
        virtual std::size_t integer_coeff_count() const override
        {
            return encoder_->integer_coeff_count();
        }

    private:
        FractionalEncoder &operator =(const FractionalEncoder &assign) = delete;

        FractionalEncoder &operator =(FractionalEncoder &&assign) = delete;

        AbstractFractionalEncoder *encoder_;
    };
}
