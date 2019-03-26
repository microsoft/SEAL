// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "aes.h"

#ifdef SEAL_USE_AES_NI_PRNG

namespace seal
{
    namespace
    {
        __m128i keygen_helper(__m128i key, __m128i key_rcon)
        {
            key_rcon = _mm_shuffle_epi32(key_rcon, _MM_SHUFFLE(3, 3, 3, 3));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            return _mm_xor_si128(key, key_rcon);
        }
    }

    void AESEncryptor::set_key(const aes_block &key)
    {
        round_key_[0] = key.i128;
        round_key_[1] = keygen_helper(round_key_[0], _mm_aeskeygenassist_si128(round_key_[0], 0x01));
        round_key_[2] = keygen_helper(round_key_[1], _mm_aeskeygenassist_si128(round_key_[1], 0x02));
        round_key_[3] = keygen_helper(round_key_[2], _mm_aeskeygenassist_si128(round_key_[2], 0x04));
        round_key_[4] = keygen_helper(round_key_[3], _mm_aeskeygenassist_si128(round_key_[3], 0x08));
        round_key_[5] = keygen_helper(round_key_[4], _mm_aeskeygenassist_si128(round_key_[4], 0x10));
        round_key_[6] = keygen_helper(round_key_[5], _mm_aeskeygenassist_si128(round_key_[5], 0x20));
        round_key_[7] = keygen_helper(round_key_[6], _mm_aeskeygenassist_si128(round_key_[6], 0x40));
        round_key_[8] = keygen_helper(round_key_[7], _mm_aeskeygenassist_si128(round_key_[7], 0x80));
        round_key_[9] = keygen_helper(round_key_[8], _mm_aeskeygenassist_si128(round_key_[8], 0x1B));
        round_key_[10] = keygen_helper(round_key_[9], _mm_aeskeygenassist_si128(round_key_[9], 0x36));
    }

    void AESEncryptor::ecb_encrypt(const aes_block &plaintext, aes_block &ciphertext) const
    {
        ciphertext.i128 = _mm_xor_si128(plaintext.i128, round_key_[0]);
        ciphertext.i128 = _mm_aesenc_si128(ciphertext.i128, round_key_[1]);
        ciphertext.i128 = _mm_aesenc_si128(ciphertext.i128, round_key_[2]);
        ciphertext.i128 = _mm_aesenc_si128(ciphertext.i128, round_key_[3]);
        ciphertext.i128 = _mm_aesenc_si128(ciphertext.i128, round_key_[4]);
        ciphertext.i128 = _mm_aesenc_si128(ciphertext.i128, round_key_[5]);
        ciphertext.i128 = _mm_aesenc_si128(ciphertext.i128, round_key_[6]);
        ciphertext.i128 = _mm_aesenc_si128(ciphertext.i128, round_key_[7]);
        ciphertext.i128 = _mm_aesenc_si128(ciphertext.i128, round_key_[8]);
        ciphertext.i128 = _mm_aesenc_si128(ciphertext.i128, round_key_[9]);
        ciphertext.i128 = _mm_aesenclast_si128(ciphertext.i128, round_key_[10]);
    }

    void AESEncryptor::ecb_encrypt(const aes_block *plaintext,
        size_t aes_block_count, aes_block *ciphertext) const
    {
        for (; aes_block_count--; ciphertext++, plaintext++)
        {
            ciphertext->i128 = _mm_xor_si128(plaintext->i128, round_key_[0]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[1]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[2]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[3]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[4]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[5]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[6]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[7]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[8]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[9]);
            ciphertext->i128 = _mm_aesenclast_si128(ciphertext->i128, round_key_[10]);
        }
    }

    void AESEncryptor::counter_encrypt(size_t start_index,
        size_t aes_block_count, aes_block *ciphertext) const
    {
        for (; aes_block_count--; start_index++, ciphertext++)
        {
            ciphertext->i128 = _mm_xor_si128(
                _mm_set_epi64x(0, static_cast<int64_t>(start_index)), round_key_[0]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[1]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[2]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[3]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[4]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[5]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[6]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[7]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[8]);
            ciphertext->i128 = _mm_aesenc_si128(ciphertext->i128, round_key_[9]);
            ciphertext->i128 = _mm_aesenclast_si128(ciphertext->i128, round_key_[10]);
        }
    }

    AESDecryptor::AESDecryptor(const aes_block &key)
    {
        set_key(key);
    }

    void AESDecryptor::set_key(const aes_block &key)
    {
        const __m128i &v0 = key.i128;
        const __m128i v1 = keygen_helper(v0, _mm_aeskeygenassist_si128(v0, 0x01));
        const __m128i v2 = keygen_helper(v1, _mm_aeskeygenassist_si128(v1, 0x02));
        const __m128i v3 = keygen_helper(v2, _mm_aeskeygenassist_si128(v2, 0x04));
        const __m128i v4 = keygen_helper(v3, _mm_aeskeygenassist_si128(v3, 0x08));
        const __m128i v5 = keygen_helper(v4, _mm_aeskeygenassist_si128(v4, 0x10));
        const __m128i v6 = keygen_helper(v5, _mm_aeskeygenassist_si128(v5, 0x20));
        const __m128i v7 = keygen_helper(v6, _mm_aeskeygenassist_si128(v6, 0x40));
        const __m128i v8 = keygen_helper(v7, _mm_aeskeygenassist_si128(v7, 0x80));
        const __m128i v9 = keygen_helper(v8, _mm_aeskeygenassist_si128(v8, 0x1B));
        const __m128i v10 = keygen_helper(v9, _mm_aeskeygenassist_si128(v9, 0x36));

        _mm_storeu_si128(round_key_, v10);
        _mm_storeu_si128(round_key_ + 1, _mm_aesimc_si128(v9));
        _mm_storeu_si128(round_key_ + 2, _mm_aesimc_si128(v8));
        _mm_storeu_si128(round_key_ + 3, _mm_aesimc_si128(v7));
        _mm_storeu_si128(round_key_ + 4, _mm_aesimc_si128(v6));
        _mm_storeu_si128(round_key_ + 5, _mm_aesimc_si128(v5));
        _mm_storeu_si128(round_key_ + 6, _mm_aesimc_si128(v4));
        _mm_storeu_si128(round_key_ + 7, _mm_aesimc_si128(v3));
        _mm_storeu_si128(round_key_ + 8, _mm_aesimc_si128(v2));
        _mm_storeu_si128(round_key_ + 9, _mm_aesimc_si128(v1));
        _mm_storeu_si128(round_key_ + 10, v0);
    }

    void AESDecryptor::ecb_decrypt(const aes_block &ciphertext, aes_block &plaintext)
    {
        plaintext.i128 = _mm_xor_si128(ciphertext.i128, round_key_[0]);
        plaintext.i128 = _mm_aesdec_si128(plaintext.i128, round_key_[1]);
        plaintext.i128 = _mm_aesdec_si128(plaintext.i128, round_key_[2]);
        plaintext.i128 = _mm_aesdec_si128(plaintext.i128, round_key_[3]);
        plaintext.i128 = _mm_aesdec_si128(plaintext.i128, round_key_[4]);
        plaintext.i128 = _mm_aesdec_si128(plaintext.i128, round_key_[5]);
        plaintext.i128 = _mm_aesdec_si128(plaintext.i128, round_key_[6]);
        plaintext.i128 = _mm_aesdec_si128(plaintext.i128, round_key_[7]);
        plaintext.i128 = _mm_aesdec_si128(plaintext.i128, round_key_[8]);
        plaintext.i128 = _mm_aesdec_si128(plaintext.i128, round_key_[9]);
        plaintext.i128 = _mm_aesdeclast_si128(plaintext.i128, round_key_[10]);
    }
}

#endif
