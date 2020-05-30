// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/encryptionparams.h"
#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "seal/plaintext.h"
#include "seal/randomgen.h"
#include "seal/secretkey.h"
#include "seal/util/defines.h"
#include "seal/util/iterator.h"
#include "seal/util/locks.h"
#include "seal/util/ntt.h"
#include "seal/util/rns.h"
#include <memory>

namespace seal
{
    /**
    Decrypts Ciphertext objects into Plaintext objects. Constructing a Decryptor
    requires a SEALContext with valid encryption parameters, and the secret key.
    The Decryptor is also used to compute the invariant noise budget in a given
    ciphertext.

    @par Overloads
    For the decrypt function we provide two overloads concerning the memory pool
    used in allocations needed during the operation. In one overload the global
    memory pool is used for this purpose, and in another overload the user can
    supply a MemoryPoolHandle to be used instead. This is to allow one single
    Decryptor to be used concurrently by several threads without running into
    thread contention in allocations taking place during operations. For example,
    one can share one single Decryptor across any number of threads, but in each
    thread call the decrypt function by giving it a thread-local MemoryPoolHandle
    to use. It is important for a developer to understand how this works to avoid
    unnecessary performance bottlenecks.


    @par NTT form
    When using the BFV scheme (scheme_type::BFV), all plaintext and ciphertexts
    should remain by default in the usual coefficient representation, i.e. not in
    NTT form. When using the CKKS scheme (scheme_type::CKKS), all plaintexts and
    ciphertexts should remain by default in NTT form. We call these scheme-specific
    NTT states the "default NTT form". Decryption requires the input ciphertexts
    to be in the default NTT form, and will throw an exception if this is not the
    case.
    */
    class Decryptor
    {
    public:
        /**
        Creates a Decryptor instance initialized with the specified SEALContext
        and secret key.

        @param[in] context The SEALContext
        @param[in] secret_key The secret key
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::invalid_argument if secret_key is not valid
        */
        Decryptor(std::shared_ptr<SEALContext> context, const SecretKey &secret_key);

        /*
        Decrypts a Ciphertext and stores the result in the destination parameter.

        @param[in] encrypted The ciphertext to decrypt
        @param[out] destination The plaintext to overwrite with the decrypted
        ciphertext
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted is not in the default NTT form
        */
        void decrypt(const Ciphertext &encrypted, Plaintext &destination);

        /*
        Computes the invariant noise budget (in bits) of a ciphertext. The
        invariant noise budget measures the amount of room there is for the noise
        to grow while ensuring correct decryptions. This function works only with
        the BFV scheme.

        @par Invariant Noise Budget
        The invariant noise polynomial of a ciphertext is a rational coefficient
        polynomial, such that a ciphertext decrypts correctly as long as the
        coefficients of the invariantnoise polynomial are of absolute value less
        than 1/2. Thus, we call the infinity-norm of the invariant noise polynomial
        the invariant noise, and for correct decryption requireit to be less than
        1/2. If v denotes the invariant noise, we define the invariant noise budget
        as -log2(2v). Thus, the invariant noise budget starts from some initial
        value, which depends on the encryption parameters, and decreases when
        computations are performed. When the budget reaches zero, the ciphertext
        becomes too noisy to decrypt correctly.

        @param[in] encrypted The ciphertext
        @throws std::invalid_argument if the scheme is not BFV
        @throws std::invalid_argument if encrypted is not valid for the encryption
        parameters
        @throws std::invalid_argument if encrypted is in NTT form
        */
        SEAL_NODISCARD int invariant_noise_budget(const Ciphertext &encrypted);

    private:
        void bfv_decrypt(const Ciphertext &encrypted, Plaintext &destination, MemoryPoolHandle pool);

        void ckks_decrypt(const Ciphertext &encrypted, Plaintext &destination, MemoryPoolHandle pool);

        Decryptor(const Decryptor &copy) = delete;

        Decryptor(Decryptor &&source) = delete;

        Decryptor &operator=(const Decryptor &assign) = delete;

        Decryptor &operator=(Decryptor &&assign) = delete;

        void compute_secret_key_array(std::size_t max_power);

        // Compute c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q.
        // Store result in destination in RNS form.
        // destination has the size of an RNS polynomial.
        void dot_product_ct_sk_array(const Ciphertext &encrypted, util::RNSIter destination, MemoryPoolHandle pool);

        // We use a fresh memory pool with `clear_on_destruction' enabled.
        MemoryPoolHandle pool_ = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true);

        std::shared_ptr<SEALContext> context_{ nullptr };

        std::size_t secret_key_array_size_ = 0;

        util::Pointer<std::uint64_t> secret_key_array_;

        mutable util::ReaderWriterLocker secret_key_array_locker_;
    };
} // namespace seal
