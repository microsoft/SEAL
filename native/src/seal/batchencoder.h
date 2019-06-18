// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <vector>
#include <limits>
#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/plaintext.h"
#include "seal/context.h"

namespace seal
{
    /**
    Provides functionality for CRT batching. If the polynomial modulus degree is N, and
    the plaintext modulus is a prime number T such that T is congruent to 1 modulo 2N,
    then BatchEncoder allows the plaintext elements to be viewed as 2-by-(N/2)
    matrices of integers modulo T. Homomorphic operations performed on such encrypted
    matrices are applied coefficient (slot) wise, enabling powerful SIMD functionality
    for computations that are vectorizable. This functionality is often called "batching"
    in the homomorphic encryption literature.

    @par Mathematical Background
    Mathematically speaking, if the polynomial modulus is X^N+1, N is a power of two, and
    plain_modulus is a prime number T such that 2N divides T-1, then integers modulo T
    contain a primitive 2N-th root of unity and the polynomial X^N+1 splits into n distinct
    linear factors as X^N+1 = (X-a_1)*...*(X-a_N) mod T, where the constants a_1, ..., a_n
    are all the distinct primitive 2N-th roots of unity in integers modulo T. The Chinese
    Remainder Theorem (CRT) states that the plaintext space Z_T[X]/(X^N+1) in this case is
    isomorphic (as an algebra) to the N-fold direct product of fields Z_T. The isomorphism
    is easy to compute explicitly in both directions, which is what this class does.
    Furthermore, the Galois group of the extension is (Z/2NZ)* ~= Z/2Z x Z/(N/2) whose
    action on the primitive roots of unity is easy to describe. Since the batching slots
    correspond 1-to-1 to the primitive roots of unity, applying Galois automorphisms on the
    plaintext act by permuting the slots. By applying generators of the two cyclic
    subgroups of the Galois group, we can effectively view the plaintext as a 2-by-(N/2)
    matrix, and enable cyclic row rotations, and column rotations (row swaps).

    @par Valid Parameters
    Whether batching can be used depends on whether the plaintext modulus has been chosen
    appropriately. Thus, to construct a BatchEncoder the user must provide an instance
    of SEALContext such that its associated EncryptionParameterQualifiers object has the
    flags parameters_set and enable_batching set to true.

    @see EncryptionParameters for more information about encryption parameters.
    @see EncryptionParameterQualifiers for more information about parameter qualifiers.
    @see Evaluator for rotating rows and columns of encrypted matrices.
    */
    class BatchEncoder
    {
    public:
        /**
        Creates a BatchEncoder. It is necessary that the encryption parameters
        given through the SEALContext object support batching.

        @param[in] context The SEALContext
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid for batching
        @throws std::invalid_argument if scheme is not scheme_type::BFV
        */
        BatchEncoder(std::shared_ptr<SEALContext> context);

        /**
        Creates a plaintext from a given matrix. This function "batches" a given matrix
        of integers modulo the plaintext modulus into a plaintext element, and stores
        the result in the destination parameter. The input vector must have size at most equal
        to the degree of the polynomial modulus. The first half of the elements represent the
        first row of the matrix, and the second half represent the second row. The numbers
        in the matrix can be at most equal to the plaintext modulus for it to represent
        a valid plaintext.

        If the destination plaintext overlaps the input values in memory, the behavior of
        this function is undefined.

        @param[in] values The matrix of integers modulo plaintext modulus to batch
        @param[out] destination The plaintext polynomial to overwrite with the result
        @throws std::invalid_argument if values is too large
        */
        void encode(const std::vector<std::uint64_t> &values, Plaintext &destination);

        /**
        Creates a plaintext from a given matrix. This function "batches" a given matrix
        of integers modulo the plaintext modulus into a plaintext element, and stores
        the result in the destination parameter. The input vector must have size at most equal
        to the degree of the polynomial modulus. The first half of the elements represent the
        first row of the matrix, and the second half represent the second row. The numbers
        in the matrix can be at most equal to the plaintext modulus for it to represent
        a valid plaintext.

        If the destination plaintext overlaps the input values in memory, the behavior of
        this function is undefined.

        @param[in] values The matrix of integers modulo plaintext modulus to batch
        @param[out] destination The plaintext polynomial to overwrite with the result
        @throws std::invalid_argument if values is too large
        */
        void encode(const std::vector<std::int64_t> &values, Plaintext &destination);
#ifdef SEAL_USE_MSGSL_SPAN
        /**
        Creates a plaintext from a given matrix. This function "batches" a given matrix
        of integers modulo the plaintext modulus into a plaintext element, and stores
        the result in the destination parameter. The input vector must have size at most equal
        to the degree of the polynomial modulus. The first half of the elements represent the
        first row of the matrix, and the second half represent the second row. The numbers
        in the matrix can be at most equal to the plaintext modulus for it to represent
        a valid plaintext.

        If the destination plaintext overlaps the input values in memory, the behavior of
        this function is undefined.

        @param[in] values The matrix of integers modulo plaintext modulus to batch
        @param[out] destination The plaintext polynomial to overwrite with the result
        @throws std::invalid_argument if values is too large
        */
        void encode(gsl::span<const std::uint64_t> values, Plaintext &destination);

        /**
        Creates a plaintext from a given matrix. This function "batches" a given matrix
        of integers modulo the plaintext modulus into a plaintext element, and stores
        the result in the destination parameter. The input vector must have size at most equal
        to the degree of the polynomial modulus. The first half of the elements represent the
        first row of the matrix, and the second half represent the second row. The numbers
        in the matrix can be at most equal to the plaintext modulus for it to represent
        a valid plaintext.

        If the destination plaintext overlaps the input values in memory, the behavior of
        this function is undefined.

        @param[in] values The matrix of integers modulo plaintext modulus to batch
        @param[out] destination The plaintext polynomial to overwrite with the result
        @throws std::invalid_argument if values is too large
        */
        void encode(gsl::span<const std::int64_t> values, Plaintext &destination);
#ifdef SEAL_USE_MSGSL_MULTISPAN
        /**
        Creates a plaintext from a given matrix. This function "batches" a given matrix
        of integers modulo the plaintext modulus into a plaintext element, and stores
        the result in the destination parameter. The input must have dimensions [2, N/2],
        where N denotes the degree of the polynomial modulus, representing a 2 x (N/2)
        matrix. The numbers in the matrix can be at most equal to the plaintext modulus for
        it to represent a valid plaintext.

        If the destination plaintext overlaps the input values in memory, the behavior of
        this function is undefined.

        @param[in] values The matrix of integers modulo plaintext modulus to batch
        @param[out] destination The plaintext polynomial to overwrite with the result
        @throws std::invalid_argument if values is too large or has incorrect size
        */
        inline void encode(gsl::multi_span<
            const std::uint64_t,
            static_cast<std::ptrdiff_t>(2),
            gsl::dynamic_range> values, Plaintext &destination)
        {
            encode(gsl::span<const std::uint64_t>(values.data(), values.size()),
                destination);
        }

        /**
        Creates a plaintext from a given matrix. This function "batches" a given matrix
        of integers modulo the plaintext modulus into a plaintext element, and stores
        the result in the destination parameter. The input must have dimensions [2, N/2],
        where N denotes the degree of the polynomial modulus, representing a 2 x (N/2)
        matrix. The numbers in the matrix can be at most equal to the plaintext modulus for
        it to represent a valid plaintext.

        If the destination plaintext overlaps the input values in memory, the behavior of
        this function is undefined.

        @param[in] values The matrix of integers modulo plaintext modulus to batch
        @param[out] destination The plaintext polynomial to overwrite with the result
        @throws std::invalid_argument if values is too large or has incorrect size
        */
        inline void encode(gsl::multi_span<
            const std::int64_t,
            static_cast<std::ptrdiff_t>(2),
            gsl::dynamic_range> values, Plaintext &destination)
        {
            encode(gsl::span<const std::int64_t>(values.data(), values.size()),
                destination);
        }
#endif
#endif
        /**
        Creates a plaintext from a given matrix. This function "batches" a given matrix
        of integers modulo the plaintext modulus in-place into a plaintext ready to be
        encrypted. The matrix is given as a plaintext element whose first N/2 coefficients
        represent the first row of the matrix, and the second N/2 coefficients represent the
        second row, where N denotes the degree of the polynomial modulus. The input plaintext
        must have degress less than the polynomial modulus, and coefficients less than the
        plaintext modulus, i.e. it must be a valid plaintext for the encryption parameters.
        Dynamic memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] plain The matrix of integers modulo plaintext modulus to batch
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is in NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        void encode(Plaintext &plain, MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Inverse of encode. This function "unbatches" a given plaintext into a matrix
        of integers modulo the plaintext modulus, and stores the result in the destination
        parameter. The input plaintext must have degress less than the polynomial modulus,
        and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext
        for the encryption parameters. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext polynomial to unbatch
        @param[out] destination The matrix to be overwritten with the values in the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is in NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        void decode(const Plaintext &plain, std::vector<std::uint64_t> &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Inverse of encode. This function "unbatches" a given plaintext into a matrix
        of integers modulo the plaintext modulus, and stores the result in the destination
        parameter. The input plaintext must have degress less than the polynomial modulus,
        and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext
        for the encryption parameters. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext polynomial to unbatch
        @param[out] destination The matrix to be overwritten with the values in the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is in NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        void decode(const Plaintext &plain, std::vector<std::int64_t> &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool());
#ifdef SEAL_USE_MSGSL_SPAN
        /**
        Inverse of encode. This function "unbatches" a given plaintext into a matrix
        of integers modulo the plaintext modulus, and stores the result in the destination
        parameter. The input plaintext must have degress less than the polynomial modulus,
        and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext
        for the encryption parameters. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext polynomial to unbatch
        @param[out] destination The matrix to be overwritten with the values in the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is in NTT form
        @throws std::invalid_argument if destination has incorrect size
        @throws std::invalid_argument if pool is uninitialized
        */
        void decode(const Plaintext &plain, gsl::span<std::uint64_t> destination,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Inverse of encode. This function "unbatches" a given plaintext into a matrix
        of integers modulo the plaintext modulus, and stores the result in the destination
        parameter. The input plaintext must have degress less than the polynomial modulus,
        and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext
        for the encryption parameters. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext polynomial to unbatch
        @param[out] destination The matrix to be overwritten with the values in the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is in NTT form
        @throws std::invalid_argument if destination has incorrect size
        @throws std::invalid_argument if pool is uninitialized
        */
        void decode(const Plaintext &plain, gsl::span<std::int64_t> destination,
            MemoryPoolHandle pool = MemoryManager::GetPool());
#ifdef SEAL_USE_MSGSL_MULTISPAN
        /**
        Inverse of encode. This function "unbatches" a given plaintext into a matrix
        of integers modulo the plaintext modulus, and stores the result in the destination
        parameter. The destination must have dimensions [2, N/2], where N denotes the degree
        of the polynomial modulus, representing a 2 x (N/2) matrix. The input plaintext must
        have degress less than the polynomial modulus, and coefficients less than the
        plaintext modulus, i.e. it must be a valid plaintext for the encryption parameters.
        Dynamic memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] plain The plaintext polynomial to unbatch
        @param[out] destination The matrix to be overwritten with the values in the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is in NTT form
        @throws std::invalid_argument if destination has incorrect size
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void decode(const Plaintext &plain,
            gsl::multi_span<std::uint64_t,
                static_cast<std::ptrdiff_t>(2),
                gsl::dynamic_range> destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            decode(plain, gsl::span<std::uint64_t>(destination.data(),
                destination.size()), std::move(pool));
        }

        /**
        Inverse of encode. This function "unbatches" a given plaintext into a matrix
        of integers modulo the plaintext modulus, and stores the result in the destination
        parameter. The destination must have dimensions [2, N/2], where N denotes the degree
        of the polynomial modulus, representing a 2 x (N/2) matrix. The input plaintext must
        have degress less than the polynomial modulus, and coefficients less than the
        plaintext modulus, i.e. it must be a valid plaintext for the encryption parameters.
        Dynamic memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] plain The plaintext polynomial to unbatch
        @param[out] destination The matrix to be overwritten with the values in the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is in NTT form
        @throws std::invalid_argument if destination has incorrect size
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void decode(const Plaintext &plain,
            gsl::multi_span<std::int64_t,
                static_cast<std::ptrdiff_t>(2),
                gsl::dynamic_range> destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            decode(plain, gsl::span<std::int64_t>(destination.data(),
                destination.size()), std::move(pool));
        }
#endif
#endif
        /**
        Inverse of encode. This function "unbatches" a given plaintext in-place into
        a matrix of integers modulo the plaintext modulus. The input plaintext must have
        degress less than the polynomial modulus, and coefficients less than the plaintext
        modulus, i.e. it must be a valid plaintext for the encryption parameters. Dynamic
        memory allocations in the process are allocated from the memory pool pointed to by
        the given MemoryPoolHandle.

        @param[in] plain The plaintext polynomial to unbatch
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is in NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        void decode(Plaintext &plain, MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Returns the number of slots.
        */
        inline auto slot_count() const noexcept
        {
            return slots_;
        }

    private:
        BatchEncoder(const BatchEncoder &copy) = delete;

        BatchEncoder(BatchEncoder &&source) = delete;

        BatchEncoder &operator =(const BatchEncoder &assign) = delete;

        BatchEncoder &operator =(BatchEncoder &&assign) = delete;

        void populate_roots_of_unity_vector(
            const SEALContext::ContextData &context_data);

        void populate_matrix_reps_index_map();

        void reverse_bits(std::uint64_t *input);

        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        std::shared_ptr<SEALContext> context_{ nullptr };

        std::size_t slots_;

        util::Pointer<std::uint64_t> roots_of_unity_;

        util::Pointer<std::uint64_t> matrix_reps_index_map_;
    };
}
