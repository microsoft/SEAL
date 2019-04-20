// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <vector>
#include <memory>
#include <map>
#include "seal/context.h"
#include "seal/relinkeys.h"
#include "seal/smallmodulus.h"
#include "seal/memorymanager.h"
#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include "seal/galoiskeys.h"
#include "seal/util/pointer.h"
#include "seal/secretkey.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/common.h"
#include "seal/kswitchkeys.h"
#include "seal/valcheck.h"

namespace seal
{
    /**
    Provides operations on ciphertexts. Due to the properties of the encryption
    scheme, the arithmetic operations pass through the encryption layer to the
    underlying plaintext, changing it according to the type of the operation. Since
    the plaintext elements are fundamentally polynomials in the polynomial quotient
    ring Z_T[x]/(X^N+1), where T is the plaintext modulus and X^N+1 is the polynomial
    modulus, this is the ring where the arithmetic operations will take place.
    BatchEncoder (batching) provider an alternative possibly more convenient view
    of the plaintext elements as 2-by-(N2/2) matrices of integers modulo the plaintext
    modulus. In the batching view the arithmetic operations act on the matrices
    element-wise. Some of the operations only apply in the batching view, such as
    matrix row and column rotations. Other operations such as relinearization have
    no semantic meaning but are necessary for performance reasons.

    @par Arithmetic Operations
    The core operations are arithmetic operations, in particular multiplication
    and addition of ciphertexts. In addition to these, we also provide negation,
    subtraction, squaring, exponentiation, and multiplication and addition of
    several ciphertexts for convenience. in many cases some of the inputs to a
    computation are plaintext elements rather than ciphertexts. For this we
    provide fast "plain" operations: plain addition, plain subtraction, and plain
    multiplication.

    @par Relinearization
    One of the most important non-arithmetic operations is relinearization, which
    takes as input a ciphertext of size K+1 and relinearization keys (at least K-1
    keys are needed), and changes the size of the ciphertext down to 2 (minimum size).
    For most use-cases only one relinearization key suffices, in which case
    relinearization should be performed after every multiplication. Homomorphic
    multiplication of ciphertexts of size K+1 and L+1 outputs a ciphertext of size
    K+L+1, and the computational cost of multiplication is proportional to K*L.
    Plain multiplication and addition operations of any type do not change the
    size. Relinearization requires relinearization keys to have been generated.

    @par Rotations
    When batching is enabled, we provide operations for rotating the plaintext matrix
    rows cyclically left or right, and for rotating the columns (swapping the rows).
    Rotations require Galois keys to have been generated.

    @par Other Operations
    We also provide operations for transforming ciphertexts to NTT form and back,
    and for transforming plaintext polynomials to NTT form. These can be used in
    a very fast plain multiplication variant, that assumes the inputs to be in NTT
    form. Since the NTT has to be done in any case in plain multiplication, this
    function can be used when e.g. one plaintext input is used in several plain
    multiplication, and transforming it several times would not make sense.

    @par NTT form
    When using the BFV scheme (scheme_type::BFV), all plaintexts and ciphertexts
    should remain by default in the usual coefficient representation, i.e., not
    in NTT form. When using the CKKS scheme (scheme_type::CKKS), all plaintexts
    and ciphertexts should remain by default in NTT form. We call these scheme-
    specific NTT states the "default NTT form". Some functions, such as add, work
    even if the inputs are not in the default state, but others, such as multiply,
    will throw an exception. The output of all evaluation functions will be in
    the same state as the input(s), with the exception of the transform_to_ntt
    and transform_from_ntt functions, which change the state. Ideally, unless these
    two functions are called, all other functions should "just work".

    @see EncryptionParameters for more details on encryption parameters.
    @see BatchEncoder for more details on batching
    @see RelinKeys for more details on relinearization keys.
    @see GaloisKeys for more details on Galois keys.
    */
    class Evaluator
    {
    public:
        /**
        Creates an Evaluator instance initialized with the specified SEALContext.

        @param[in] context The SEALContext
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        */
        Evaluator(std::shared_ptr<SEALContext> context);

        /**
        Negates a ciphertext.

        @param[in] encrypted The ciphertext to negate
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        */
        void negate_inplace(Ciphertext &encrypted);

        /**
        Negates a ciphertext and stores the result in the destination parameter.

        @param[in] encrypted The ciphertext to negate
        @param[out] destination The ciphertext to overwrite with the negated result
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void negate(const Ciphertext &encrypted, Ciphertext &destination)
        {
            destination = encrypted;
            negate_inplace(destination);
        }

        /**
        Adds two ciphertexts. This function adds together encrypted1 and encrypted2
        and stores the result in encrypted1.

        @param[in] encrypted1 The first ciphertext to add
        @param[in] encrypted2 The second ciphertext to add
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for
        the encryption parameters
        @throws std::invalid_argument if encrypted1 and encrypted2 are in different
        NTT forms
        @throws std::invalid_argument if encrypted1 and encrypted2 have different scale
        @throws std::logic_error if result ciphertext is transparent
        */
        void add_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2);

        /**
        Adds two ciphertexts. This function adds together encrypted1 and encrypted2
        and stores the result in the destination parameter.

        @param[in] encrypted1 The first ciphertext to add
        @param[in] encrypted2 The second ciphertext to add
        @param[out] destination The ciphertext to overwrite with the addition result
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for
        the encryption parameters
        @throws std::invalid_argument if encrypted1 and encrypted2 are in different
        NTT forms
        @throws std::invalid_argument if encrypted1 and encrypted2 have different scale
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void add(const Ciphertext &encrypted1, const Ciphertext &encrypted2,
            Ciphertext &destination)
        {
            if (&encrypted2 == &destination)
            {
                add_inplace(destination, encrypted1);
            }
            else
            {
                destination = encrypted1;
                add_inplace(destination, encrypted2);
            }
        }

        /**
        Adds together a vector of ciphertexts and stores the result in the destination
        parameter.

        @param[in] encrypteds The ciphertexts to add
        @param[out] destination The ciphertext to overwrite with the addition result
        @throws std::invalid_argument if encrypteds is empty
        @throws std::invalid_argument if the encrypteds are not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypteds are in different NTT forms
        @throws std::invalid_argument if encrypteds have different scale
        @throws std::invalid_argument if destination is one of encrypteds
        @throws std::logic_error if result ciphertext is transparent
        */
        void add_many(const std::vector<Ciphertext> &encrypteds, Ciphertext &destination);

        /**
        Subtracts two ciphertexts. This function computes the difference of encrypted1
        and encrypted2, and stores the result in encrypted1.

        @param[in] encrypted1 The ciphertext to subtract from
        @param[in] encrypted2 The ciphertext to subtract
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted1 and encrypted2 are in different
        NTT forms
        @throws std::invalid_argument if encrypted1 and encrypted2 have different scale
        @throws std::logic_error if result ciphertext is transparent
        */
        void sub_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2);

        /**
        Subtracts two ciphertexts. This function computes the difference of encrypted1
        and encrypted2 and stores the result in the destination parameter.

        @param[in] encrypted1 The ciphertext to subtract from
        @param[in] encrypted2 The ciphertext to subtract
        @param[out] destination The ciphertext to overwrite with the subtraction result
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted1 and encrypted2 are in different
        NTT forms
        @throws std::invalid_argument if encrypted1 and encrypted2 have different scale
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void sub(const Ciphertext &encrypted1, const Ciphertext &encrypted2,
            Ciphertext &destination)
        {
            if (&encrypted2 == &destination)
            {
                sub_inplace(destination, encrypted1);
                negate_inplace(destination);
            }
            else
            {
                destination = encrypted1;
                sub_inplace(destination, encrypted2);
            }
        }

        /**
        Multiplies two ciphertexts. This functions computes the product of encrypted1
        and encrypted2 and stores the result in encrypted1. Dynamic memory allocations
        in the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        @param[in] encrypted1 The first ciphertext to multiply
        @param[in] encrypted2 The second ciphertext to multiply
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted1 or encrypted2 is not in the default
        NTT form
        @throws std::invalid_argument if, when using scheme_type::CKKS, the output scale
        is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void multiply_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Multiplies two ciphertexts. This functions computes the product of encrypted1
        and encrypted2 and stores the result in the destination parameter. Dynamic
        memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] encrypted1 The first ciphertext to multiply
        @param[in] encrypted2 The second ciphertext to multiply
        @param[out] destination The ciphertext to overwrite with the multiplication result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted1 or encrypted2 is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted1 or encrypted2 is not in the default
        NTT form
        @throws std::invalid_argument if, when using scheme_type::CKKS, the output scale
        is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void multiply(const Ciphertext &encrypted1,
            const Ciphertext &encrypted2, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            if (&encrypted2 == &destination)
            {
                multiply_inplace(destination, encrypted1, std::move(pool));
            }
            else
            {
                destination = encrypted1;
                multiply_inplace(destination, encrypted2, std::move(pool));
            }
        }

        /**
        Squares a ciphertext. This functions computes the square of encrypted. Dynamic
        memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to square
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if, when using scheme_type::CKKS, the output scale
        is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void square_inplace(Ciphertext &encrypted,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Squares a ciphertext. This functions computes the square of encrypted and
        stores the result in the destination parameter. Dynamic memory allocations
        in the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        @param[in] encrypted The ciphertext to square
        @param[out] destination The ciphertext to overwrite with the square
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if, when using scheme_type::CKKS, the output scale
        is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void square(const Ciphertext &encrypted, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            square_inplace(destination, std::move(pool));
        }

        /**
        Relinearizes a ciphertext. This functions relinearizes encrypted, reducing
        its size down to 2. If the size of encrypted is K+1, the given relinearization
        keys need to have size at least K-1. Dynamic memory allocations in the
        process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        @param[in] encrypted The ciphertext to relinearize
        @param[in] relin_keys The relinearization keys
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted or relin_keys is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if relin_keys do not correspond to the top level
        parameters in the current context
        @throws std::invalid_argument if the size of relin_keys is too small
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void relinearize_inplace(Ciphertext &encrypted, const RelinKeys &relin_keys,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            relinearize_internal(encrypted, relin_keys, 2, std::move(pool));
        }

        /**
        Relinearizes a ciphertext. This functions relinearizes encrypted, reducing
        its size down to 2, and stores the result in the destination parameter.
        If the size of encrypted is K+1, the given relinearization keys need to
        have size at least K-1. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to relinearize
        @param[in] relin_keys The relinearization keys
        @param[out] destination The ciphertext to overwrite with the relinearized result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted or relin_keys is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if relin_keys do not correspond to the top level
        parameters in the current context
        @throws std::invalid_argument if the size of relin_keys is too small
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void relinearize(const Ciphertext &encrypted,
            const RelinKeys &relin_keys, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            relinearize_inplace(destination, relin_keys, std::move(pool));
        }

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the
        modulus down to q_1...q_{k-1} and stores the result in the destination
        parameter. Dynamic memory allocations in the process are allocated from
        the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @param[out] destination The ciphertext to overwrite with the modulus switched result
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted is already at lowest level
        @throws std::invalid_argument if, when using scheme_type::CKKS, the scale is too
        large for the new encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void mod_switch_to_next(const Ciphertext &encrypted, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the
        modulus down to q_1...q_{k-1}. Dynamic memory allocations in the process
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted is already at lowest level
        @throws std::invalid_argument if, when using scheme_type::CKKS, the scale is too
        large for the new encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void mod_switch_to_next_inplace(Ciphertext &encrypted,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            mod_switch_to_next(encrypted, encrypted, std::move(pool));
        }

        /**
        Modulus switches an NTT transformed plaintext from modulo q_1...q_k down
        to modulo q_1...q_{k-1}.

        @param[in] plain The plaintext to be switched to a smaller modulus
        @throws std::invalid_argument if plain is not in NTT form
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is already at lowest level
        @throws std::invalid_argument if, when using scheme_type::CKKS, the scale is too
        large for the new encryption parameters
        */
        inline void mod_switch_to_next_inplace(Plaintext &plain)
        {
            // Verify parameters.
            if (!is_valid_for(plain, context_))
            {
                throw std::invalid_argument("plain is not valid for encryption parameters");
            }
            mod_switch_drop_to_next(plain);
        }

        /**
        Modulus switches an NTT transformed plaintext from modulo q_1...q_k down
        to modulo q_1...q_{k-1} and stores the result in the destination parameter.

        @param[in] plain The plaintext to be switched to a smaller modulus
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @param[out] destination The plaintext to overwrite with the modulus switched result
        @throws std::invalid_argument if plain is not in NTT form
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is already at lowest level
        @throws std::invalid_argument if, when using scheme_type::CKKS, the scale is too
        large for the new encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void mod_switch_to_next(const Plaintext &plain, Plaintext &destination)
        {
            destination = plain;
            mod_switch_to_next_inplace(destination);
        }

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the
        modulus down until the parameters reach the given parms_id. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is already at lower level in modulus chain
        than the parameters corresponding to parms_id
        @throws std::invalid_argument if, when using scheme_type::CKKS, the scale is too
        large for the new encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void mod_switch_to_inplace(Ciphertext &encrypted, parms_id_type parms_id,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the
        modulus down until the parameters reach the given parms_id and stores the
        result in the destination parameter. Dynamic memory allocations in the process
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @param[out] destination The ciphertext to overwrite with the modulus switched result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is already at lower level in modulus chain
        than the parameters corresponding to parms_id
        @throws std::invalid_argument if, when using scheme_type::CKKS, the scale is too
        large for the new encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void mod_switch_to(const Ciphertext &encrypted,
            parms_id_type parms_id, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            mod_switch_to_inplace(destination, parms_id, std::move(pool));
        }

        /**
        Given an NTT transformed plaintext modulo q_1...q_k, this function switches
        the modulus down until the parameters reach the given parms_id.

        @param[in] plain The plaintext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @throws std::invalid_argument if plain is not in NTT form
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if plain is already at lower level in modulus chain
        than the parameters corresponding to parms_id
        @throws std::invalid_argument if, when using scheme_type::CKKS, the scale is too
        large for the new encryption parameters
        */
        void mod_switch_to_inplace(Plaintext &plain, parms_id_type parms_id);

        /**
        Given an NTT transformed plaintext modulo q_1...q_k, this function switches
        the modulus down until the parameters reach the given parms_id and stores
        the result in the destination parameter.

        @param[in] plain The plaintext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @param[out] destination The plaintext to overwrite with the modulus switched result
        @throws std::invalid_argument if plain is not in NTT form
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if plain is already at lower level in modulus chain
        than the parameters corresponding to parms_id
        @throws std::invalid_argument if, when using scheme_type::CKKS, the scale is too
        large for the new encryption parameters
        */
        inline void mod_switch_to(const Plaintext &plain, parms_id_type parms_id,
            Plaintext &destination)
        {
            destination = plain;
            mod_switch_to_inplace(destination, parms_id);
        }

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the
        modulus down to q_1...q_{k-1}, scales the message down accordingly, and
        stores the result in the destination parameter. Dynamic memory allocations
        in the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @param[out] destination The ciphertext to overwrite with the modulus switched result
        @throws std::invalid_argument if the scheme is invalid for rescaling
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted is already at lowest level
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void rescale_to_next(const Ciphertext &encrypted, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the
        modulus down to q_1...q_{k-1} and scales the message down accordingly. Dynamic
        memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if the scheme is invalid for rescaling
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted is already at lowest level
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rescale_to_next_inplace(Ciphertext &encrypted,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            rescale_to_next(encrypted, encrypted, std::move(pool));
        }

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the
        modulus down until the parameters reach the given parms_id and scales the
        message down accordingly. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if the scheme is invalid for rescaling
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is already at lower level in modulus chain
        than the parameters corresponding to parms_id
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void rescale_to_inplace(Ciphertext &encrypted, parms_id_type parms_id,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Given a ciphertext encrypted modulo q_1...q_k, this function switches the
        modulus down until the parameters reach the given parms_id, scales the message
        down accordingly, and stores the result in the destination parameter. Dynamic
        memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to be switched to a smaller modulus
        @param[in] parms_id The target parms_id
        @param[out] destination The ciphertext to overwrite with the modulus switched result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if the scheme is invalid for rescaling
        @throws std::invalid_argument if encrypted is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if encrypted is already at lower level in modulus chain
        than the parameters corresponding to parms_id
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rescale_to(const Ciphertext &encrypted,
            parms_id_type parms_id, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            rescale_to_inplace(destination, parms_id, std::move(pool));
        }

        /**
        Multiplies several ciphertexts together. This function computes the product
        of several ciphertext given as an std::vector and stores the result in the
        destination parameter. The multiplication is done in a depth-optimal order,
        and relinearization is performed automatically after every multiplication
        in the process. In relinearization the given relinearization keys are used.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypteds The ciphertexts to multiply
        @param[in] relin_keys The relinearization keys
        @param[out] destination The ciphertext to overwrite with the multiplication result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::BFV
        @throws std::invalid_argument if encrypteds is empty
        @throws std::invalid_argument if the ciphertexts or relin_keys are not valid for
        the encryption parameters
        @throws std::invalid_argument if encrypteds are not in the default NTT form
        @throws std::invalid_argument if, when using scheme_type::CKKS, the output scale
        is too large for the encryption parameters
        @throws std::invalid_argument if the size of relin_keys is too small
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        void multiply_many(std::vector<Ciphertext> &encrypteds,
            const RelinKeys &relin_keys, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Exponentiates a ciphertext. This functions raises encrypted to a power.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle. The exponentiation is done
        in a depth-optimal order, and relinearization is performed automatically
        after every multiplication in the process. In relinearization the given
        relinearization keys are used.

        @param[in] encrypted The ciphertext to exponentiate
        @param[in] exponent The power to raise the ciphertext to
        @param[in] relin_keys The relinearization keys
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::BFV
        @throws std::invalid_argument if encrypted or relin_keys is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if, when using scheme_type::CKKS, the output scale
        is too large for the encryption parameters
        @throws std::invalid_argument if exponent is zero
        @throws std::invalid_argument if the size of relin_keys is too small
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        void exponentiate_inplace(Ciphertext &encrypted,
            std::uint64_t exponent, const RelinKeys &relin_keys,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Exponentiates a ciphertext. This functions raises encrypted to a power and
        stores the result in the destination parameter. Dynamic memory allocations
        in the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle. The exponentiation is done in a depth-optimal order, and
        relinearization is performed automatically after every multiplication in
        the process. In relinearization the given relinearization keys are used.

        @param[in] encrypted The ciphertext to exponentiate
        @param[in] exponent The power to raise the ciphertext to
        @param[in] relin_keys The relinearization keys
        @param[out] destination The ciphertext to overwrite with the power
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::BFV
        @throws std::invalid_argument if encrypted or relin_keys is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if, when using scheme_type::CKKS, the output scale
        is too large for the encryption parameters
        @throws std::invalid_argument if exponent is zero
        @throws std::invalid_argument if the size of relin_keys is too small
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void exponentiate(const Ciphertext &encrypted, std::uint64_t exponent,
            const RelinKeys &relin_keys, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            exponentiate_inplace(destination, exponent, relin_keys, std::move(pool));
        }

        /**
        Adds a ciphertext and a plaintext. The plaintext must be valid for the current
        encryption parameters.

        @param[in] encrypted The ciphertext to add
        @param[in] plain The plaintext to add
        @throws std::invalid_argument if encrypted or plain is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted or plain is in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        void add_plain_inplace(Ciphertext &encrypted, const Plaintext &plain);

        /**
        Adds a ciphertext and a plaintext. This function adds a ciphertext and
        a plaintext and stores the result in the destination parameter. The plaintext
        must be valid for the current encryption parameters.

        @param[in] encrypted The ciphertext to add
        @param[in] plain The plaintext to add
        @param[out] destination The ciphertext to overwrite with the addition result
        @throws std::invalid_argument if encrypted or plain is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted or plain is in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void add_plain(const Ciphertext &encrypted, const Plaintext &plain,
            Ciphertext &destination)
        {
            destination = encrypted;
            add_plain_inplace(destination, plain);
        }

        /**
        Subtracts a plaintext from a ciphertext. The plaintext must be valid for the
        current encryption parameters.

        @param[in] encrypted The ciphertext to subtract from
        @param[in] plain The plaintext to subtract
        @throws std::invalid_argument if encrypted or plain is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted or plain is in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        void sub_plain_inplace(Ciphertext &encrypted, const Plaintext &plain);

        /**
        Subtracts a plaintext from a ciphertext. This function subtracts a plaintext
        from a ciphertext and stores the result in the destination parameter. The
        plaintext must be valid for the current encryption parameters.

        @param[in] encrypted The ciphertext to subtract from
        @param[in] plain The plaintext to subtract
        @param[out] destination The ciphertext to overwrite with the subtraction result
        @throws std::invalid_argument if encrypted or plain is not valid for the
        encryption parameters
        @throws std::invalid_argument if encrypted or plain is in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void sub_plain(const Ciphertext &encrypted, const Plaintext &plain,
            Ciphertext &destination)
        {
            destination = encrypted;
            sub_plain_inplace(destination, plain);
        }

        /**
        Multiplies a ciphertext with a plaintext. The plaintext must be valid for the
        current encryption parameters, and cannot be identially 0. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to by
        the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to multiply
        @param[in] plain The plaintext to multiply
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if the encrypted or plain is not valid for
        the encryption parameters
        @throws std::invalid_argument if encrypted and plain are in different NTT forms
        @throws std::invalid_argument if, when using scheme_type::CKKS, the output
        scale is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        void multiply_plain_inplace(Ciphertext &encrypted, const Plaintext &plain,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Multiplies a ciphertext with a plaintext. This function multiplies
        a ciphertext with a plaintext and stores the result in the destination
        parameter. The plaintext must be a valid for the current encryption parameters,
        and cannot be identially 0. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to multiply
        @param[in] plain The plaintext to multiply
        @param[out] destination The ciphertext to overwrite with the multiplication result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if the encrypted or plain is not valid for
        the encryption parameters
        @throws std::invalid_argument if encrypted and plain are in different NTT forms
        @throws std::invalid_argument if plain is zero
        @throws std::invalid_argument if, when using scheme_type::CKKS, the output
        scale is too large for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void multiply_plain(const Ciphertext &encrypted,
            const Plaintext &plain, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            multiply_plain_inplace(destination, plain, std::move(pool));
        }

        /**
        Transforms a plaintext to NTT domain. This functions applies the Number
        Theoretic Transform to a plaintext by first embedding integers modulo the
        plaintext modulus to integers modulo the coefficient modulus and then
        performing David Harvey's NTT on the resulting polynomial. The transformation
        is done with respect to encryption parameters corresponding to a given parms_id.
        For the operation to be valid, the plaintext must have degree less than
        poly_modulus_degree and each coefficient must be less than the plaintext
        modulus, i.e., the plaintext must be a valid plaintext under the current
        encryption parameters. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext to transform
        @param[in] parms_id The parms_id with respect to which the NTT is done
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is already in NTT form
        @throws std::invalid_argument if plain or parms_id is not valid for the
        encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        void transform_to_ntt_inplace(Plaintext &plain, parms_id_type parms_id,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Transforms a plaintext to NTT domain. This functions applies the Number
        Theoretic Transform to a plaintext by first embedding integers modulo the
        plaintext modulus to integers modulo the coefficient modulus and then
        performing David Harvey's NTT on the resulting polynomial. The transformation
        is done with respect to encryption parameters corresponding to a given
        parms_id. The result is stored in the destination_ntt parameter. For the
        operation to be valid, the plaintext must have degree less than poly_modulus_degree
        and each coefficient must be less than the plaintext modulus, i.e., the plaintext
        must be a valid plaintext under the current encryption parameters. Dynamic
        memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] plain The plaintext to transform
        @param[in] parms_id The parms_id with respect to which the NTT is done
        @param[out] destinationNTT The plaintext to overwrite with the transformed result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is already in NTT form
        @throws std::invalid_argument if plain or parms_id is not valid for the
        encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void transform_to_ntt(const Plaintext &plain,
            parms_id_type parms_id, Plaintext &destination_ntt,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination_ntt = plain;
            transform_to_ntt_inplace(destination_ntt, parms_id, std::move(pool));
        }

        /**
        Transforms a ciphertext to NTT domain. This functions applies David Harvey's
        Number Theoretic Transform separately to each polynomial of a ciphertext.

        @param[in] encrypted The ciphertext to transform
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted is already in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        void transform_to_ntt_inplace(Ciphertext &encrypted);

        /**
        Transforms a ciphertext to NTT domain. This functions applies David Harvey's
        Number Theoretic Transform separately to each polynomial of a ciphertext.
        The result is stored in the destination_ntt parameter.

        @param[in] encrypted The ciphertext to transform
        @param[out] destination_ntt The ciphertext to overwrite with the transformed result
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted is already in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void transform_to_ntt(const Ciphertext &encrypted,
            Ciphertext &destination_ntt)
        {
            destination_ntt = encrypted;
            transform_to_ntt_inplace(destination_ntt);
        }

        /**
        Transforms a ciphertext back from NTT domain. This functions applies the
        inverse of David Harvey's Number Theoretic Transform separately to each
        polynomial of a ciphertext.

        @param[in] encrypted_ntt The ciphertext to transform
        @throws std::invalid_argument if encrypted_ntt is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted_ntt is not in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        void transform_from_ntt_inplace(Ciphertext &encrypted_ntt);

        /**
        Transforms a ciphertext back from NTT domain. This functions applies the
        inverse of David Harvey's Number Theoretic Transform separately to each
        polynomial of a ciphertext. The result is stored in the destination parameter.

        @param[in] encrypted_ntt The ciphertext to transform
        @param[out] destination The ciphertext to overwrite with the transformed result
        @throws std::invalid_argument if encrypted_ntt is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted_ntt is not in NTT form
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void transform_from_ntt(const Ciphertext &encrypted_ntt,
            Ciphertext &destination)
        {
            destination = encrypted_ntt;
            transform_from_ntt_inplace(destination);
        }

        /**
        Applies a Galois automorphism to a ciphertext. To evaluate the Galois
        automorphism, an appropriate set of Galois keys must also be provided.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.


        The desired Galois automorphism is given as a Galois element, and must be
        an odd integer in the interval [1, M-1], where M = 2*N, and N = degree(poly_modulus).
        Used with batching, a Galois element 3^i % M corresponds to a cyclic row
        rotation i steps to the left, and a Galois element 3^(N/2-i) % M corresponds
        to a cyclic row rotation i steps to the right. The Galois element M-1 corresponds
        to a column rotation (row swap) in BFV, and complex conjugation in CKKS.
        In the polynomial view (not batching), a Galois automorphism by a Galois
        element p changes Enc(plain(x)) to Enc(plain(x^p)).

        @param[in] encrypted The ciphertext to apply the Galois automorphism to
        @param[in] galois_elt The Galois element
        @param[in] galois_keys The Galois keys
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if the Galois element is not valid
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        void apply_galois_inplace(Ciphertext &encrypted,
            std::uint64_t galois_elt, const GaloisKeys &galois_keys,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Applies a Galois automorphism to a ciphertext and writes the result to the
        destination parameter. To evaluate the Galois automorphism, an appropriate
        set of Galois keys must also be provided. Dynamic memory allocations in
        the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        The desired Galois automorphism is given as a Galois element, and must be
        an odd integer in the interval [1, M-1], where M = 2*N, and N = degree(poly_modulus).
        Used with batching, a Galois element 3^i % M corresponds to a cyclic row
        rotation i steps to the left, and a Galois element 3^(N/2-i) % M corresponds
        to a cyclic row rotation i steps to the right. The Galois element M-1 corresponds
        to a column rotation (row swap) in BFV, and complex conjugation in CKKS.
        In the polynomial view (not batching), a Galois automorphism by a Galois
        element p changes Enc(plain(x)) to Enc(plain(x^p)).

        @param[in] encrypted The ciphertext to apply the Galois automorphism to
        @param[in] galois_elt The Galois element
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if the Galois element is not valid
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void apply_galois(const Ciphertext &encrypted,
            std::uint64_t galois_elt, const GaloisKeys &galois_keys,
            Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            apply_galois_inplace(destination, galois_elt, galois_keys, std::move(pool));
        }

        /**
        Rotates plaintext matrix rows cyclically. When batching is used with the
        BFV scheme, this function rotates the encrypted plaintext matrix rows
        cyclically to the left (steps > 0) or to the right (steps < 0). Since
        the size of the batched matrix is 2-by-(N/2), where N is the degree of
        the polynomial modulus, the number of steps to rotate must have absolute
        value at most N/2-1. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.


        @param[in] encrypted The ciphertext to rotate
        @param[in] steps The number of steps to rotate (negative left, positive right)
        @param[in] galois_keys The Galois keys
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support batching
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if steps has too big absolute value
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotate_rows_inplace(Ciphertext &encrypted,
            int steps, const GaloisKeys &galois_keys,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            if (context_->key_context_data()->parms().scheme() != scheme_type::BFV)
            {
                throw std::logic_error("unsupported scheme");
            }
            rotate_internal(encrypted, steps, galois_keys, std::move(pool));
        }

        /**
        Rotates plaintext matrix rows cyclically. When batching is used with the
        BFV scheme, this function rotates the encrypted plaintext matrix rows
        cyclically to the left (steps > 0) or to the right (steps < 0) and writes
        the result to the destination parameter. Since the size of the batched
        matrix is 2-by-(N/2), where N is the degree of the polynomial modulus,
        the number of steps to rotate must have absolute value at most N/2-1. Dynamic
        memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] steps The number of steps to rotate (negative left, positive right)
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support batching
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if steps has too big absolute value
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotate_rows(const Ciphertext &encrypted, int steps,
            const GaloisKeys &galois_keys, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            rotate_rows_inplace(destination, steps, galois_keys, std::move(pool));
        }

        /**
        Rotates plaintext matrix columns cyclically. When batching is used with
        the BFV scheme, this function rotates the encrypted plaintext matrix
        columns cyclically. Since the size of the batched matrix is 2-by-(N/2),
        where N is the degree of the polynomial modulus, this means simply swapping
        the two rows. Dynamic memory allocations in the process are allocated from
        the memory pool pointed to by the given MemoryPoolHandle.


        @param[in] encrypted The ciphertext to rotate
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support batching
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotate_columns_inplace(Ciphertext &encrypted,
            const GaloisKeys &galois_keys,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            if (context_->key_context_data()->parms().scheme() != scheme_type::BFV)
            {
                throw std::logic_error("unsupported scheme");
            }
            conjugate_internal(encrypted, galois_keys, std::move(pool));
        }

        /**
        Rotates plaintext matrix columns cyclically. When batching is used with
        the BFV scheme, this function rotates the encrypted plaintext matrix columns
        cyclically, and writes the result to the destination parameter. Since the
        size of the batched matrix is 2-by-(N/2), where N is the degree of the
        polynomial modulus, this means simply swapping the two rows. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support batching
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotate_columns(const Ciphertext &encrypted,
            const GaloisKeys &galois_keys, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            rotate_columns_inplace(destination, galois_keys, std::move(pool));
        }

        /**
        Rotates plaintext vector cyclically. When using the CKKS scheme, this function
        rotates the encrypted plaintext vector cyclically to the left (steps > 0)
        or to the right (steps < 0). Since the size of the batched matrix is
        2-by-(N/2), where N is the degree of the polynomial modulus, the number
        of steps to rotate must have absolute value at most N/2-1. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] steps The number of steps to rotate (negative left, positive right)
        @param[in] galois_keys The Galois keys
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::CKKS
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is not in the default NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if steps has too big absolute value
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotate_vector_inplace(Ciphertext &encrypted,
            int steps, const GaloisKeys &galois_keys,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            if (context_->key_context_data()->parms().scheme() != scheme_type::CKKS)
            {
                throw std::logic_error("unsupported scheme");
            }
            rotate_internal(encrypted, steps, galois_keys, std::move(pool));
        }

        /**
        Rotates plaintext vector cyclically. When using the CKKS scheme, this function
        rotates the encrypted plaintext vector cyclically to the left (steps > 0)
        or to the right (steps < 0) and writes the result to the destination parameter.
        Since the size of the batched matrix is 2-by-(N/2), where N is the degree
        of the polynomial modulus, the number of steps to rotate must have absolute
        value at most N/2-1. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] steps The number of steps to rotate (negative left, positive right)
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::CKKS
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if steps has too big absolute value
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void rotate_vector(const Ciphertext &encrypted, int steps,
            const GaloisKeys &galois_keys, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            rotate_vector_inplace(destination, steps, galois_keys, std::move(pool));
        }

        /**
        Complex conjugates plaintext slot values. When using the CKKS scheme, this
        function complex conjugates all values in the underlying plaintext. Dynamic
        memory allocations in the process are allocated from the memory pool pointed
        to by the given MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::CKKS
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void complex_conjugate_inplace(Ciphertext &encrypted,
            const GaloisKeys &galois_keys,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            if (context_->key_context_data()->parms().scheme() != scheme_type::CKKS)
            {
                throw std::logic_error("unsupported scheme");
            }
            conjugate_internal(encrypted, galois_keys, std::move(pool));
        }

        /**
        Complex conjugates plaintext slot values. When using the CKKS scheme, this
        function complex conjugates all values in the underlying plaintext, and
        writes the result to the destination parameter. Dynamic memory allocations
        in the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        @param[in] encrypted The ciphertext to rotate
        @param[in] galois_keys The Galois keys
        @param[out] destination The ciphertext to overwrite with the rotated result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if scheme is not scheme_type::CKKS
        @throws std::invalid_argument if encrypted or galois_keys is not valid for
        the encryption parameters
        @throws std::invalid_argument if galois_keys do not correspond to the top
        level parameters in the current context
        @throws std::invalid_argument if encrypted is in NTT form
        @throws std::invalid_argument if encrypted has size larger than 2
        @throws std::invalid_argument if necessary Galois keys are not present
        @throws std::invalid_argument if pool is uninitialized
        @throws std::logic_error if keyswitching is not supported by the context
        @throws std::logic_error if result ciphertext is transparent
        */
        inline void complex_conjugate(const Ciphertext &encrypted,
            const GaloisKeys &galois_keys, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            destination = encrypted;
            complex_conjugate_inplace(destination, galois_keys, std::move(pool));
        }

        /**
        Enables access to private members of seal::Evaluator for .NET wrapper.
        */
        struct EvaluatorPrivateHelper;

    private:
        Evaluator(const Evaluator &copy) = delete;

        Evaluator(Evaluator &&source) = delete;

        Evaluator &operator =(const Evaluator &assign) = delete;

        Evaluator &operator =(Evaluator &&assign) = delete;

        void bfv_multiply(Ciphertext &encrypted1, const Ciphertext &encrypted2,
            MemoryPoolHandle pool);

        void ckks_multiply(Ciphertext &encrypted1, const Ciphertext &encrypted2,
            MemoryPoolHandle pool);

        void bfv_square(Ciphertext &encrypted, MemoryPoolHandle pool);

        void ckks_square(Ciphertext &encrypted, MemoryPoolHandle pool);

        void relinearize_internal(Ciphertext &encrypted, const RelinKeys &relin_keys,
            std::size_t destination_size, MemoryPoolHandle pool);

        void mod_switch_scale_to_next(const Ciphertext &encrypted, Ciphertext &destination,
            MemoryPoolHandle pool);

        void mod_switch_drop_to_next(const Ciphertext &encrypted, Ciphertext &destination,
            MemoryPoolHandle pool);

        void mod_switch_drop_to_next(Plaintext &plain);

        void rotate_internal(Ciphertext &encrypted, int steps,
            const GaloisKeys &galois_keys, MemoryPoolHandle pool);

        inline void conjugate_internal(Ciphertext &encrypted,
            const GaloisKeys &galois_keys, MemoryPoolHandle pool)
        {
            // Verify parameters.
            auto context_data_ptr = context_->get_context_data(encrypted.parms_id());
            if (!context_data_ptr)
            {
                throw std::invalid_argument("encrypted is not valid for encryption parameters");
            }

            // Extract encryption parameters.
            auto &context_data = *context_data_ptr;
            if (!context_data.qualifiers().using_batching)
            {
                throw std::logic_error("encryption parameters do not support batching");
            }

            auto &parms = context_data.parms();
            std::size_t coeff_count = parms.poly_modulus_degree();

            // Perform rotation and key switching
            apply_galois_inplace(encrypted, util::steps_to_galois_elt(0, coeff_count),
                galois_keys, std::move(pool));
        }

        inline void decompose_single_coeff(const SEALContext::ContextData &context_data,
            const std::uint64_t *value, std::uint64_t *destination, util::MemoryPool &pool)
        {
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            std::size_t coeff_mod_count = coeff_modulus.size();
#ifdef SEAL_DEBUG
            if (value == nullptr)
            {
                throw std::invalid_argument("value cannot be null");
            }
            if (destination == nullptr)
            {
                throw std::invalid_argument("destination cannot be null");
            }
            if (destination == value)
            {
                throw std::invalid_argument("value cannot be the same as destination");
            }
#endif
            if (coeff_mod_count == 1)
            {
                util::set_uint_uint(value, coeff_mod_count, destination);
                return;
            }

            auto value_copy(util::allocate_uint(coeff_mod_count, pool));
            for (std::size_t j = 0; j < coeff_mod_count; j++)
            {
                //destination[j] = util::modulo_uint(
                //    value, coeff_mod_count, coeff_modulus_[j], pool);

                // Manually inlined for efficiency
                // Make a fresh copy of value
                util::set_uint_uint(value, coeff_mod_count, value_copy.get());

                // Starting from the top, reduce always 128-bit blocks
                for (std::size_t k = coeff_mod_count - 1; k--; )
                {
                    value_copy[k] = util::barrett_reduce_128(
                        value_copy.get() + k, coeff_modulus[j]);
                }
                destination[j] = value_copy[0];
            }
        }

        inline void decompose(const SEALContext::ContextData &context_data,
            const std::uint64_t *value, std::uint64_t *destination, util::MemoryPool &pool)
        {
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            std::size_t coeff_count = parms.poly_modulus_degree();
            std::size_t coeff_mod_count = coeff_modulus.size();
            std::size_t rns_poly_uint64_count =
                util::mul_safe(coeff_mod_count, coeff_count);
#ifdef SEAL_DEBUG
            if (value == nullptr)
            {
                throw std::invalid_argument("value cannot be null");
            }
            if (destination == nullptr)
            {
                throw std::invalid_argument("destination cannot be null");
            }
            if (destination == value)
            {
                throw std::invalid_argument("value cannot be the same as destination");
            }
#endif
            if (coeff_mod_count == 1)
            {
                util::set_uint_uint(value, rns_poly_uint64_count, destination);
                return;
            }

            auto value_copy(util::allocate_uint(coeff_mod_count, pool));
            for (std::size_t i = 0; i < coeff_count; i++)
            {
                for (std::size_t j = 0; j < coeff_mod_count; j++)
                {
                    //destination[i + (j * coeff_count)] =
                    //    util::modulo_uint(value + (i * coeff_mod_count),
                    //        coeff_mod_count, coeff_modulus_[j], pool);

                    // Manually inlined for efficiency
                    // Make a fresh copy of value + (i * coeff_mod_count)
                    util::set_uint_uint(
                        value + (i * coeff_mod_count), coeff_mod_count, value_copy.get());

                    // Starting from the top, reduce always 128-bit blocks
                    for (std::size_t k = coeff_mod_count - 1; k--; )
                    {
                        value_copy[k] = util::barrett_reduce_128(
                            value_copy.get() + k, coeff_modulus[j]);
                    }
                    destination[i + (j * coeff_count)] = value_copy[0];
                }
            }
        }

        void switch_key_inplace(Ciphertext &encrypted,
            const std::uint64_t *target,
            const KSwitchKeys &kswitch_keys,
            std::size_t key_index,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        void multiply_plain_normal(Ciphertext &encrypted, const Plaintext &plain,
            util::MemoryPool &pool);

        void multiply_plain_ntt(Ciphertext &encrypted_ntt, const Plaintext &plain_ntt);

        void populate_Zmstar_to_generator();

        std::shared_ptr<SEALContext> context_{ nullptr };

        std::map<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>> Zmstar_to_generator_{};
    };
}