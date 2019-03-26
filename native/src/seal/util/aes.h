// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/defines.h"

#ifdef SEAL_USE_AES_NI_PRNG

#include <cstddef>
#include <cstdint>
#include <wmmintrin.h>

namespace seal
{
    union aes_block
    {
        std::uint32_t u32[4];
        std::uint64_t u64[2];
        __m128i i128;
    };

    class AESEncryptor
    {
    public:
        AESEncryptor() = default;

        AESEncryptor(const aes_block &key)
        {
            set_key(key);
        }

        AESEncryptor(std::uint64_t key_lw, std::uint64_t key_hw)
        {
            aes_block key;
            key.u64[0] = key_lw;
            key.u64[1] = key_hw;
            set_key(key);
        }

        void set_key(const aes_block &key);

        void ecb_encrypt(const aes_block &plaintext, aes_block &ciphertext) const;

        inline aes_block ecb_encrypt(const aes_block &plaintext) const
        {
            aes_block ret;
            ecb_encrypt(plaintext, ret);
            return ret;
        }

        // ECB mode encryption
        void ecb_encrypt(const aes_block *plaintext,
            std::size_t aes_block_count, aes_block *ciphertext) const;

        // Counter Mode encryption: encrypts the counter
        void counter_encrypt(std::size_t start_index,
            std::size_t aes_block_count, aes_block *ciphertext) const;

    private:
        __m128i round_key_[11];
    };

    class AESDecryptor
    {
    public:
        AESDecryptor() = default;

        AESDecryptor(const aes_block &key);

        void set_key(const aes_block &key);

        void ecb_decrypt(const aes_block &ciphertext, aes_block &plaintext);

        inline aes_block ecb_decrypt(const aes_block &ciphertext)
        {
            aes_block ret;
            ecb_decrypt(ciphertext, ret);
            return ret;
        }

    private:
        __m128i round_key_[11];
    };
}

#endif
