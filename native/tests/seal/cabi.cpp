// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// This file is compiled only when the C export library (sealc) is built; the
// test CMakeLists adds it to sealtest under `if(TARGET sealc)`.

#include "seal/c/encryptor.h"
#include "seal/c/kswitchkeys.h"
#include "seal/c/memorymanager.h"
#include "seal/c/memorypoolhandle.h"
#include "seal/c/plaintext.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include "gtest/gtest.h"

namespace sealtest
{
    // Every C export must translate C++ exceptions into an HRESULT rather than let them
    // cross the extern "C" boundary. Plaintext::to_string() (reached through
    // Plaintext_ToString) throws invalid_argument for an NTT-form plaintext; the export
    // returns E_INVALIDARG. The plaintext is built entirely through the C ABI so it stays
    // in the export library's world.
    TEST(CAbiExceptionFirewallTest, ThrowingExportReturnsHResult)
    {
        void *plain = nullptr;
        ASSERT_EQ(S_OK, Plaintext_Create1(nullptr, &plain));

        // A nonzero parms_id puts the plaintext in NTT form, for which to_string() throws.
        uint64_t ntt_parms_id[]{ 1ULL, 2ULL, 3ULL, 4ULL };
        ASSERT_EQ(S_OK, Plaintext_SetParmsId(plain, ntt_parms_id));

        uint64_t length = 0;
        ASSERT_EQ(E_INVALIDARG, Plaintext_ToString(plain, nullptr, &length));

        ASSERT_EQ(S_OK, Plaintext_Destroy(plain));
    }

    TEST(CAbiBoundsTest, KeyListBoundsPreserveEmptySlots)
    {
        void *keys = nullptr;
        ASSERT_EQ(S_OK, KSwitchKeys_Create1(&keys));

        uint64_t count = 0;
        ASSERT_EQ(HRESULT_FROM_WIN32(ERROR_INVALID_INDEX), KSwitchKeys_GetKeyList(keys, 0, &count, nullptr));

        void *unused_key_list[1]{ nullptr };
        ASSERT_EQ(S_OK, KSwitchKeys_AddKeyList(keys, 0, unused_key_list));
        ASSERT_EQ(S_OK, KSwitchKeys_GetKeyList(keys, 0, &count, nullptr));
        ASSERT_EQ(0, count);
        ASSERT_EQ(HRESULT_FROM_WIN32(ERROR_INVALID_INDEX), KSwitchKeys_GetKeyList(keys, 1, &count, nullptr));

        ASSERT_EQ(S_OK, KSwitchKeys_Destroy(keys));
    }

    TEST(CAbiLifetimeTest, EncryptorCreateReleasesPublicKeyOnInvalidSecretKey)
    {
        seal::EncryptionParameters parms(seal::scheme_type::bfv);
        parms.set_poly_modulus_degree(1024);
        parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(1024));
        parms.set_plain_modulus(257);
        seal::SEALContext context(parms, false);

        seal::KeyGenerator keygen(context);
        seal::PublicKey public_key;
        keygen.create_public_key(public_key);
        seal::SecretKey valid_secret_key = keygen.secret_key();
        seal::SecretKey invalid_secret_key;

        void *active_pool = nullptr;
        ASSERT_EQ(S_OK, MemoryManager_GetPool2(&active_pool));
        void *same_pool = nullptr;
        ASSERT_EQ(S_OK, MemoryManager_GetPool2(&same_pool));
        bool pools_equal = false;
        ASSERT_EQ(S_OK, MemoryPoolHandle_Equals(active_pool, same_pool, &pools_equal));
        ASSERT_TRUE(pools_equal);
        ASSERT_EQ(S_OK, MemoryPoolHandle_Destroy(same_pool));

        void *valid_encryptor = nullptr;
        ASSERT_EQ(S_OK, Encryptor_Create(&context, &public_key, nullptr, &valid_encryptor));
        ASSERT_EQ(S_OK, Encryptor_Destroy(valid_encryptor));

        valid_encryptor = nullptr;
        ASSERT_EQ(S_OK, Encryptor_Create(&context, &public_key, &valid_secret_key, &valid_encryptor));
        ASSERT_EQ(S_OK, Encryptor_Destroy(valid_encryptor));

        long use_count_before = 0;
        ASSERT_EQ(S_OK, MemoryPoolHandle_UseCount(active_pool, &use_count_before));

        void *encryptor = nullptr;
        ASSERT_EQ(E_INVALIDARG, Encryptor_Create(&context, &public_key, &invalid_secret_key, &encryptor));
        ASSERT_EQ(nullptr, encryptor);

        long use_count_after = 0;
        ASSERT_EQ(S_OK, MemoryPoolHandle_UseCount(active_pool, &use_count_after));
        EXPECT_EQ(use_count_before, use_count_after);
        EXPECT_EQ(S_OK, MemoryPoolHandle_Destroy(active_pool));
    }
} // namespace sealtest
