// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/c/batchencoder.h"
#include "seal/c/ciphertext.h"
#include "seal/c/ckksencoder.h"
#include "seal/c/contextdata.h"
#include "seal/c/encryptionparameters.h"
#include "seal/c/encryptor.h"
#include "seal/c/evaluator.h"
#include "seal/c/keygenerator.h"
#include "seal/c/kswitchkeys.h"
#include "seal/c/memorymanager.h"
#include "seal/c/memorypoolhandle.h"
#include "seal/c/modulus.h"
#include "seal/c/plaintext.h"
#include "seal/c/publickey.h"
#include "seal/c/sealcontext.h"
#include "seal/c/secretkey.h"
#include <algorithm>
#include <limits>
#include <vector>
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

    TEST(CAbiOutputCapacityTest, RejectsInsufficientStringAndModulusBuffers)
    {
        void *plain = nullptr;
        ASSERT_EQ(S_OK, Plaintext_Create2(2, nullptr, &plain));
        ASSERT_EQ(S_OK, Plaintext_SetCoeffAt(plain, 0, 3));
        ASSERT_EQ(S_OK, Plaintext_SetCoeffAt(plain, 1, 5));

        uint64_t text_required = 0;
        ASSERT_EQ(S_OK, Plaintext_ToString(plain, nullptr, &text_required));
        std::vector<char> text(text_required + 1, 'x');
        uint64_t text_capacity = text_required - 1;
        EXPECT_EQ(
            HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER), Plaintext_ToString(plain, text.data(), &text_capacity));
        EXPECT_EQ(text_required, text_capacity);
        EXPECT_TRUE(std::all_of(text.cbegin(), text.cend(), [](char value) { return value == 'x'; }));
        EXPECT_EQ(S_OK, Plaintext_Destroy(plain));

        constexpr int tc128 = 128;
        constexpr uint64_t poly_modulus_degree = 1024;
        uint64_t required = 0;
        ASSERT_EQ(S_OK, CoeffModulus_BFVDefault(poly_modulus_degree, tc128, &required, nullptr));

        std::vector<void *> coeffs(required);
        uint64_t coeff_capacity = 0;
        HRESULT result = CoeffModulus_BFVDefault(poly_modulus_degree, tc128, &coeff_capacity, coeffs.data());
        bool coeffs_modified =
            std::any_of(coeffs.cbegin(), coeffs.cend(), [](void *coeff) { return coeff != nullptr; });
        for (void *coeff : coeffs)
        {
            if (coeff)
            {
                EXPECT_EQ(S_OK, Modulus_Destroy(coeff));
            }
        }

        EXPECT_EQ(HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER), result);
        EXPECT_EQ(required, coeff_capacity);
        EXPECT_FALSE(coeffs_modified);
    }

    TEST(CAbiOutputCapacityTest, RejectsInsufficientKeyListBuffer)
    {
        void *keys = nullptr;
        ASSERT_EQ(S_OK, KSwitchKeys_Create1(&keys));
        void *public_key = nullptr;
        ASSERT_EQ(S_OK, PublicKey_Create1(&public_key));
        void *key_list[]{ public_key };
        ASSERT_EQ(S_OK, KSwitchKeys_AddKeyList(keys, 1, key_list));

        uint64_t required = 0;
        ASSERT_EQ(S_OK, KSwitchKeys_GetKeyList(keys, 0, &required, nullptr));

        std::vector<void *> output(required);
        uint64_t capacity = 0;
        HRESULT result = KSwitchKeys_GetKeyList(keys, 0, &capacity, output.data());
        bool output_modified = std::any_of(output.cbegin(), output.cend(), [](void *key) { return key != nullptr; });
        for (void *key : output)
        {
            if (key)
            {
                EXPECT_EQ(S_OK, PublicKey_Destroy(key));
            }
        }

        EXPECT_EQ(HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER), result);
        EXPECT_EQ(required, capacity);
        EXPECT_FALSE(output_modified);
        EXPECT_EQ(S_OK, PublicKey_Destroy(public_key));
        EXPECT_EQ(S_OK, KSwitchKeys_Destroy(keys));
    }

    TEST(CAbiOutputCapacityTest, RejectsInsufficientCKKSDecodeBuffers)
    {
        constexpr uint8_t ckks_scheme = 0x2;
        constexpr int sec_level_none = 0;
        constexpr uint64_t poly_modulus_degree = 64;

        void *parms = nullptr;
        ASSERT_EQ(S_OK, EncParams_Create1(ckks_scheme, &parms));
        ASSERT_EQ(S_OK, EncParams_SetPolyModulusDegree(parms, poly_modulus_degree));

        int bit_sizes[]{ 40, 40, 40, 40 };
        void *coeffs[4]{};
        ASSERT_EQ(S_OK, CoeffModulus_Create1(poly_modulus_degree, 4, bit_sizes, coeffs));
        ASSERT_EQ(S_OK, EncParams_SetCoeffModulus(parms, 4, coeffs));
        for (void *coeff : coeffs)
        {
            ASSERT_EQ(S_OK, Modulus_Destroy(coeff));
        }

        void *context = nullptr;
        ASSERT_EQ(S_OK, SEALContext_Create(parms, false, sec_level_none, &context));

        void *context_data = nullptr;
        ASSERT_EQ(S_OK, SEALContext_FirstContextData(context, &context_data));
        uint64_t context_required = 0;
        ASSERT_EQ(S_OK, ContextData_TotalCoeffModulus(context_data, &context_required, nullptr));
        constexpr uint64_t context_sentinel = 0xDEADBEEF;
        std::vector<uint64_t> total_coeff_modulus(context_required, context_sentinel);
        uint64_t context_capacity = 0;
        EXPECT_EQ(
            HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER),
            ContextData_TotalCoeffModulus(context_data, &context_capacity, total_coeff_modulus.data()));
        EXPECT_EQ(context_required, context_capacity);
        EXPECT_TRUE(
            std::all_of(total_coeff_modulus.cbegin(), total_coeff_modulus.cend(), [context_sentinel](uint64_t value) {
                return value == context_sentinel;
            }));
        void *encoder = nullptr;
        ASSERT_EQ(S_OK, CKKSEncoder_Create(context, &encoder));
        void *plain = nullptr;
        ASSERT_EQ(S_OK, Plaintext_Create1(nullptr, &plain));

        uint64_t parms_id[4]{};
        ASSERT_EQ(S_OK, SEALContext_FirstParmsId(context, parms_id));
        ASSERT_EQ(S_OK, CKKSEncoder_Encode3(encoder, 1.0, parms_id, 1048576.0, plain, nullptr));

        uint64_t slot_count = 0;
        ASSERT_EQ(S_OK, CKKSEncoder_SlotCount(encoder, &slot_count));
        constexpr double sentinel = -12345.0;

        std::vector<double> real_values(slot_count, sentinel);
        uint64_t real_capacity = 0;
        EXPECT_EQ(
            HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER),
            CKKSEncoder_Decode1(encoder, plain, &real_capacity, real_values.data(), nullptr));
        EXPECT_EQ(slot_count, real_capacity);
        EXPECT_TRUE(std::all_of(real_values.cbegin(), real_values.cend(), [sentinel](double value) {
            return value == sentinel;
        }));

        std::vector<double> complex_values(slot_count * 2, sentinel);
        uint64_t complex_capacity = 0;
        EXPECT_EQ(
            HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER),
            CKKSEncoder_Decode2(encoder, plain, &complex_capacity, complex_values.data(), nullptr));
        EXPECT_EQ(slot_count, complex_capacity);
        EXPECT_TRUE(std::all_of(complex_values.cbegin(), complex_values.cend(), [sentinel](double value) {
            return value == sentinel;
        }));

        EXPECT_EQ(S_OK, Plaintext_Destroy(plain));
        EXPECT_EQ(S_OK, CKKSEncoder_Destroy(encoder));
        EXPECT_EQ(S_OK, SEALContext_Destroy(context));
        EXPECT_EQ(S_OK, EncParams_Destroy(parms));
    }

    TEST(CAbiOutputCapacityTest, RejectsInsufficientBatchDecodeBuffers)
    {
        constexpr uint8_t bfv_scheme = 0x1;
        constexpr int sec_level_none = 0;
        constexpr uint64_t poly_modulus_degree = 64;

        void *parms = nullptr;
        ASSERT_EQ(S_OK, EncParams_Create1(bfv_scheme, &parms));
        ASSERT_EQ(S_OK, EncParams_SetPolyModulusDegree(parms, poly_modulus_degree));
        ASSERT_EQ(S_OK, EncParams_SetPlainModulus2(parms, 257));

        int bit_size = 40;
        void *coeff = nullptr;
        ASSERT_EQ(S_OK, CoeffModulus_Create1(poly_modulus_degree, 1, &bit_size, &coeff));
        void *coeffs[]{ coeff };
        ASSERT_EQ(S_OK, EncParams_SetCoeffModulus(parms, 1, coeffs));
        ASSERT_EQ(S_OK, Modulus_Destroy(coeff));

        void *context = nullptr;
        ASSERT_EQ(S_OK, SEALContext_Create(parms, false, sec_level_none, &context));
        void *encoder = nullptr;
        ASSERT_EQ(S_OK, BatchEncoder_Create(context, &encoder));
        void *plain = nullptr;
        ASSERT_EQ(S_OK, Plaintext_Create1(nullptr, &plain));

        uint64_t input = 1;
        ASSERT_EQ(S_OK, BatchEncoder_Encode1(encoder, 1, &input, plain));
        uint64_t slot_count = 0;
        ASSERT_EQ(S_OK, BatchEncoder_GetSlotCount(encoder, &slot_count));

        constexpr uint64_t unsigned_sentinel = static_cast<uint64_t>(-1);
        std::vector<uint64_t> unsigned_values(slot_count, unsigned_sentinel);
        uint64_t unsigned_capacity = 0;
        EXPECT_EQ(
            HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER),
            BatchEncoder_Decode1(encoder, plain, &unsigned_capacity, unsigned_values.data(), nullptr));
        EXPECT_EQ(slot_count, unsigned_capacity);
        EXPECT_TRUE(std::all_of(unsigned_values.cbegin(), unsigned_values.cend(), [unsigned_sentinel](uint64_t value) {
            return value == unsigned_sentinel;
        }));

        constexpr int64_t signed_sentinel = (std::numeric_limits<int64_t>::min)();
        std::vector<int64_t> signed_values(slot_count, signed_sentinel);
        uint64_t signed_capacity = 0;
        EXPECT_EQ(
            HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER),
            BatchEncoder_Decode2(encoder, plain, &signed_capacity, signed_values.data(), nullptr));
        EXPECT_EQ(slot_count, signed_capacity);
        EXPECT_TRUE(std::all_of(signed_values.cbegin(), signed_values.cend(), [signed_sentinel](int64_t value) {
            return value == signed_sentinel;
        }));

        EXPECT_EQ(S_OK, Plaintext_Destroy(plain));
        EXPECT_EQ(S_OK, BatchEncoder_Destroy(encoder));
        EXPECT_EQ(S_OK, SEALContext_Destroy(context));
        EXPECT_EQ(S_OK, EncParams_Destroy(parms));
    }

    TEST(CAbiLifetimeTest, EncryptorCreateReleasesPublicKeyOnInvalidSecretKey)
    {
        constexpr uint8_t bfv_scheme = 0x1;
        constexpr int tc128 = 128;
        constexpr uint64_t poly_modulus_degree = 1024;

        void *parms = nullptr;
        ASSERT_EQ(S_OK, EncParams_Create1(bfv_scheme, &parms));
        ASSERT_EQ(S_OK, EncParams_SetPolyModulusDegree(parms, poly_modulus_degree));

        uint64_t coeff_modulus_size = 0;
        ASSERT_EQ(S_OK, CoeffModulus_BFVDefault(poly_modulus_degree, tc128, &coeff_modulus_size, nullptr));
        std::vector<void *> coeff_modulus(coeff_modulus_size);
        ASSERT_EQ(S_OK, CoeffModulus_BFVDefault(poly_modulus_degree, tc128, &coeff_modulus_size, coeff_modulus.data()));
        ASSERT_EQ(S_OK, EncParams_SetCoeffModulus(parms, coeff_modulus_size, coeff_modulus.data()));
        for (void *modulus : coeff_modulus)
        {
            ASSERT_EQ(S_OK, Modulus_Destroy(modulus));
        }
        ASSERT_EQ(S_OK, EncParams_SetPlainModulus2(parms, 257));

        void *context = nullptr;
        ASSERT_EQ(S_OK, SEALContext_Create(parms, false, tc128, &context));

        void *keygen = nullptr;
        ASSERT_EQ(S_OK, KeyGenerator_Create1(context, &keygen));
        void *public_key = nullptr;
        ASSERT_EQ(S_OK, KeyGenerator_CreatePublicKey(keygen, false, &public_key));
        void *valid_secret_key = nullptr;
        ASSERT_EQ(S_OK, KeyGenerator_SecretKey(keygen, &valid_secret_key));
        void *invalid_secret_key = nullptr;
        ASSERT_EQ(S_OK, SecretKey_Create1(&invalid_secret_key));

        void *active_pool = nullptr;
        ASSERT_EQ(S_OK, MemoryManager_GetPool2(&active_pool));
        void *same_pool = nullptr;
        ASSERT_EQ(S_OK, MemoryManager_GetPool2(&same_pool));
        bool pools_equal = false;
        ASSERT_EQ(S_OK, MemoryPoolHandle_Equals(active_pool, same_pool, &pools_equal));
        ASSERT_TRUE(pools_equal);
        ASSERT_EQ(S_OK, MemoryPoolHandle_Destroy(same_pool));

        void *valid_encryptor = nullptr;
        ASSERT_EQ(S_OK, Encryptor_Create(context, public_key, nullptr, &valid_encryptor));
        ASSERT_EQ(S_OK, Encryptor_Destroy(valid_encryptor));

        valid_encryptor = nullptr;
        ASSERT_EQ(S_OK, Encryptor_Create(context, public_key, valid_secret_key, &valid_encryptor));
        ASSERT_EQ(S_OK, Encryptor_Destroy(valid_encryptor));

        long use_count_before = 0;
        ASSERT_EQ(S_OK, MemoryPoolHandle_UseCount(active_pool, &use_count_before));

        void *encryptor = nullptr;
        ASSERT_EQ(E_INVALIDARG, Encryptor_Create(context, public_key, invalid_secret_key, &encryptor));
        ASSERT_EQ(nullptr, encryptor);

        long use_count_after = 0;
        ASSERT_EQ(S_OK, MemoryPoolHandle_UseCount(active_pool, &use_count_after));
        EXPECT_EQ(use_count_before, use_count_after);
        EXPECT_EQ(S_OK, MemoryPoolHandle_Destroy(active_pool));

        EXPECT_EQ(S_OK, SecretKey_Destroy(invalid_secret_key));
        EXPECT_EQ(S_OK, SecretKey_Destroy(valid_secret_key));
        EXPECT_EQ(S_OK, PublicKey_Destroy(public_key));
        EXPECT_EQ(S_OK, KeyGenerator_Destroy(keygen));
        EXPECT_EQ(S_OK, SEALContext_Destroy(context));
        EXPECT_EQ(S_OK, EncParams_Destroy(parms));
    }

    TEST(CAbiNullInputTest, RejectsNullRequiredInputArrays)
    {
        constexpr uint8_t ckks_scheme = 0x2;
        constexpr int sec_level_none = 0;
        constexpr uint64_t poly_modulus_degree = 64;

        void *parms = nullptr;
        ASSERT_EQ(S_OK, EncParams_Create1(ckks_scheme, &parms));
        ASSERT_EQ(S_OK, EncParams_SetPolyModulusDegree(parms, poly_modulus_degree));

        int bit_sizes[]{ 40, 40, 40, 40 };
        void *coeffs[4]{};
        ASSERT_EQ(S_OK, CoeffModulus_Create1(poly_modulus_degree, 4, bit_sizes, coeffs));
        ASSERT_EQ(S_OK, EncParams_SetCoeffModulus(parms, 4, coeffs));

        uint64_t const_ratio[3]{};
        EXPECT_EQ(S_OK, Modulus_ConstRatio(coeffs[0], 3, const_ratio));
        EXPECT_EQ(E_POINTER, Modulus_ConstRatio(coeffs[0], 3, nullptr));

        for (void *coeff : coeffs)
        {
            ASSERT_EQ(S_OK, Modulus_Destroy(coeff));
        }

        void *context = nullptr;
        ASSERT_EQ(S_OK, SEALContext_Create(parms, false, sec_level_none, &context));
        void *encoder = nullptr;
        ASSERT_EQ(S_OK, CKKSEncoder_Create(context, &encoder));
        void *plain = nullptr;
        ASSERT_EQ(S_OK, Plaintext_Create1(nullptr, &plain));

        uint64_t parms_id[4]{};
        ASSERT_EQ(S_OK, SEALContext_FirstParmsId(context, parms_id));

        EXPECT_EQ(E_POINTER, CKKSEncoder_Encode1(encoder, 1, nullptr, parms_id, 1048576.0, plain, nullptr));
        EXPECT_EQ(E_POINTER, CKKSEncoder_Encode2(encoder, 1, nullptr, parms_id, 1048576.0, plain, nullptr));
        EXPECT_EQ(E_POINTER, Plaintext_Set4(plain, 1, nullptr));

        // The guards are unconditional, matching the other array-taking exports.
        EXPECT_EQ(E_POINTER, CKKSEncoder_Encode1(encoder, 0, nullptr, parms_id, 1048576.0, plain, nullptr));
        EXPECT_EQ(E_POINTER, CKKSEncoder_Encode2(encoder, 0, nullptr, parms_id, 1048576.0, plain, nullptr));
        EXPECT_EQ(E_POINTER, Plaintext_Set4(plain, 0, nullptr));

        EXPECT_EQ(S_OK, Plaintext_Destroy(plain));
        EXPECT_EQ(S_OK, CKKSEncoder_Destroy(encoder));
        EXPECT_EQ(S_OK, SEALContext_Destroy(context));
        EXPECT_EQ(S_OK, EncParams_Destroy(parms));
    }

    TEST(CAbiNullInputTest, RejectsNullOutputHandles)
    {
        constexpr uint8_t bfv_scheme = 0x1;
        constexpr int tc128 = 128;
        constexpr uint64_t poly_modulus_degree = 1024;

        void *parms = nullptr;
        ASSERT_EQ(S_OK, EncParams_Create1(bfv_scheme, &parms));
        ASSERT_EQ(S_OK, EncParams_SetPolyModulusDegree(parms, poly_modulus_degree));

        uint64_t coeff_modulus_size = 0;
        ASSERT_EQ(S_OK, CoeffModulus_BFVDefault(poly_modulus_degree, tc128, &coeff_modulus_size, nullptr));
        std::vector<void *> coeff_modulus(coeff_modulus_size);
        ASSERT_EQ(S_OK, CoeffModulus_BFVDefault(poly_modulus_degree, tc128, &coeff_modulus_size, coeff_modulus.data()));
        ASSERT_EQ(S_OK, EncParams_SetCoeffModulus(parms, coeff_modulus_size, coeff_modulus.data()));
        ASSERT_EQ(S_OK, EncParams_SetPlainModulus2(parms, 257));

        EXPECT_EQ(E_POINTER, Modulus_Create2(coeff_modulus[0], nullptr));

        void *context = nullptr;
        ASSERT_EQ(S_OK, SEALContext_Create(parms, false, tc128, &context));

        uint64_t parms_id[4]{};
        ASSERT_EQ(S_OK, SEALContext_FirstParmsId(context, parms_id));
        void *context_data = nullptr;
        ASSERT_EQ(S_OK, SEALContext_GetContextData(context, parms_id, &context_data));

        EXPECT_EQ(E_POINTER, ContextData_Parms(context_data, nullptr));

        for (void *modulus : coeff_modulus)
        {
            ASSERT_EQ(S_OK, Modulus_Destroy(modulus));
        }
        EXPECT_EQ(S_OK, SEALContext_Destroy(context));
        EXPECT_EQ(S_OK, EncParams_Destroy(parms));
    }

    TEST(CAbiNullInputTest, RejectsNullHandleArrayElements)
    {
        constexpr uint8_t bfv_scheme = 0x1;
        constexpr int tc128 = 128;
        constexpr uint64_t poly_modulus_degree = 4096;

        void *parms = nullptr;
        ASSERT_EQ(S_OK, EncParams_Create1(bfv_scheme, &parms));
        ASSERT_EQ(S_OK, EncParams_SetPolyModulusDegree(parms, poly_modulus_degree));

        uint64_t coeff_modulus_size = 0;
        ASSERT_EQ(S_OK, CoeffModulus_BFVDefault(poly_modulus_degree, tc128, &coeff_modulus_size, nullptr));
        std::vector<void *> coeff_modulus(coeff_modulus_size);
        ASSERT_EQ(S_OK, CoeffModulus_BFVDefault(poly_modulus_degree, tc128, &coeff_modulus_size, coeff_modulus.data()));

        std::vector<void *> with_null(coeff_modulus);
        with_null.back() = nullptr;
        EXPECT_EQ(E_POINTER, EncParams_SetCoeffModulus(parms, coeff_modulus_size, with_null.data()));

        ASSERT_EQ(S_OK, EncParams_SetCoeffModulus(parms, coeff_modulus_size, coeff_modulus.data()));
        ASSERT_EQ(S_OK, EncParams_SetPlainModulus2(parms, 257));
        for (void *modulus : coeff_modulus)
        {
            ASSERT_EQ(S_OK, Modulus_Destroy(modulus));
        }

        void *context = nullptr;
        ASSERT_EQ(S_OK, SEALContext_Create(parms, false, tc128, &context));
        void *keygen = nullptr;
        ASSERT_EQ(S_OK, KeyGenerator_Create1(context, &keygen));
        void *public_key = nullptr;
        ASSERT_EQ(S_OK, KeyGenerator_CreatePublicKey(keygen, false, &public_key));
        void *relin_keys = nullptr;
        ASSERT_EQ(S_OK, KeyGenerator_CreateRelinKeys(keygen, false, &relin_keys));

        void *evaluator = nullptr;
        ASSERT_EQ(S_OK, Evaluator_Create(context, &evaluator));
        void *cipher = nullptr;
        ASSERT_EQ(S_OK, Ciphertext_Create1(nullptr, &cipher));
        void *destination = nullptr;
        ASSERT_EQ(S_OK, Ciphertext_Create1(nullptr, &destination));

        void *encrypteds[2]{ cipher, nullptr };
        EXPECT_EQ(E_POINTER, Evaluator_AddMany(evaluator, 2, encrypteds, destination));
        EXPECT_EQ(E_POINTER, Evaluator_MultiplyMany(evaluator, 2, encrypteds, relin_keys, destination, nullptr));

        void *keys = nullptr;
        ASSERT_EQ(S_OK, KSwitchKeys_Create1(&keys));
        void *key_list[2]{ public_key, nullptr };
        EXPECT_EQ(E_POINTER, KSwitchKeys_AddKeyList(keys, 2, key_list));
        void *leading_null[2]{ nullptr, public_key };
        EXPECT_EQ(E_POINTER, KSwitchKeys_AddKeyList(keys, 2, leading_null));

        // Neither rejected call may have added a key list slot.
        uint64_t raw_size = 0;
        ASSERT_EQ(S_OK, KSwitchKeys_RawSize(keys, &raw_size));
        EXPECT_EQ(0, raw_size);

        EXPECT_EQ(S_OK, KSwitchKeys_Destroy(keys));
        EXPECT_EQ(S_OK, Ciphertext_Destroy(destination));
        EXPECT_EQ(S_OK, Ciphertext_Destroy(cipher));
        EXPECT_EQ(S_OK, Evaluator_Destroy(evaluator));
        EXPECT_EQ(S_OK, KSwitchKeys_Destroy(relin_keys));
        EXPECT_EQ(S_OK, PublicKey_Destroy(public_key));
        EXPECT_EQ(S_OK, KeyGenerator_Destroy(keygen));
        EXPECT_EQ(S_OK, SEALContext_Destroy(context));
        EXPECT_EQ(S_OK, EncParams_Destroy(parms));
    }

    TEST(CAbiLifetimeTest, PlainModulusHandleIsIndependentCopy)
    {
        constexpr uint8_t bfv_scheme = 0x1;

        void *parms = nullptr;
        ASSERT_EQ(S_OK, EncParams_Create1(bfv_scheme, &parms));
        ASSERT_EQ(S_OK, EncParams_SetPlainModulus2(parms, 65537));

        uint64_t parms_id_before[4]{};
        ASSERT_EQ(S_OK, EncParams_GetParmsId(parms, parms_id_before));

        void *first = nullptr;
        void *second = nullptr;
        ASSERT_EQ(S_OK, EncParams_GetPlainModulus(parms, &first));
        ASSERT_EQ(S_OK, EncParams_GetPlainModulus(parms, &second));
        EXPECT_NE(first, second);

        // Each handle is owned by the caller, so mutating or destroying one leaves both
        // the other handle and the parameters untouched.
        ASSERT_EQ(S_OK, Modulus_Set2(first, 257));
        EXPECT_EQ(S_OK, Modulus_Destroy(first));

        uint64_t value = 0;
        ASSERT_EQ(S_OK, Modulus_Value(second, &value));
        EXPECT_EQ(65537, value);
        EXPECT_EQ(S_OK, Modulus_Destroy(second));

        void *third = nullptr;
        ASSERT_EQ(S_OK, EncParams_GetPlainModulus(parms, &third));
        ASSERT_EQ(S_OK, Modulus_Value(third, &value));
        EXPECT_EQ(65537, value);
        EXPECT_EQ(S_OK, Modulus_Destroy(third));

        uint64_t parms_id_after[4]{};
        ASSERT_EQ(S_OK, EncParams_GetParmsId(parms, parms_id_after));
        EXPECT_TRUE(std::equal(parms_id_before, parms_id_before + 4, parms_id_after));

        EXPECT_EQ(S_OK, EncParams_Destroy(parms));
    }
    TEST(CAbiExceptionFirewallTest, OversizedCountReturnsHResult)
    {
        constexpr uint8_t bfv_scheme = 0x1;
        constexpr int sec_level_none = 0;
        constexpr uint64_t poly_modulus_degree = 64;
        constexpr uint64_t oversized_count = uint64_t(1) << 62;

        void *parms = nullptr;
        ASSERT_EQ(S_OK, EncParams_Create1(bfv_scheme, &parms));
        ASSERT_EQ(S_OK, EncParams_SetPolyModulusDegree(parms, poly_modulus_degree));

        int bit_sizes[]{ 40, 40, 40, 40 };
        void *coeffs[4]{};
        ASSERT_EQ(S_OK, CoeffModulus_Create1(poly_modulus_degree, 4, bit_sizes, coeffs));

        EXPECT_EQ(COR_E_INVALIDOPERATION, EncParams_SetCoeffModulus(parms, oversized_count, coeffs));

        ASSERT_EQ(S_OK, EncParams_SetCoeffModulus(parms, 4, coeffs));
        ASSERT_EQ(S_OK, EncParams_SetPlainModulus2(parms, 257));
        for (void *coeff : coeffs)
        {
            ASSERT_EQ(S_OK, Modulus_Destroy(coeff));
        }

        void *context = nullptr;
        ASSERT_EQ(S_OK, SEALContext_Create(parms, false, sec_level_none, &context));
        void *encoder = nullptr;
        ASSERT_EQ(S_OK, BatchEncoder_Create(context, &encoder));
        void *plain = nullptr;
        ASSERT_EQ(S_OK, Plaintext_Create1(nullptr, &plain));

        uint64_t uvalues[1]{ 1 };
        int64_t ivalues[1]{ 1 };
        EXPECT_EQ(COR_E_INVALIDOPERATION, BatchEncoder_Encode1(encoder, oversized_count, uvalues, plain));
        EXPECT_EQ(COR_E_INVALIDOPERATION, BatchEncoder_Encode2(encoder, oversized_count, ivalues, plain));

        void *keygen = nullptr;
        ASSERT_EQ(S_OK, KeyGenerator_Create1(context, &keygen));
        void *relin_keys = nullptr;
        ASSERT_EQ(S_OK, KeyGenerator_CreateRelinKeys(keygen, false, &relin_keys));

        uint32_t galois_elts[1]{ 3 };
        int galois_steps[1]{ 1 };
        void *galois_keys = nullptr;
        EXPECT_EQ(
            COR_E_INVALIDOPERATION,
            KeyGenerator_CreateGaloisKeysFromElts(keygen, oversized_count, galois_elts, false, &galois_keys));
        EXPECT_EQ(
            COR_E_INVALIDOPERATION,
            KeyGenerator_CreateGaloisKeysFromSteps(keygen, oversized_count, galois_steps, false, &galois_keys));

        void *evaluator = nullptr;
        ASSERT_EQ(S_OK, Evaluator_Create(context, &evaluator));
        void *cipher = nullptr;
        ASSERT_EQ(S_OK, Ciphertext_Create1(nullptr, &cipher));
        void *destination = nullptr;
        ASSERT_EQ(S_OK, Ciphertext_Create1(nullptr, &destination));

        void *encrypteds[1]{ cipher };
        EXPECT_EQ(COR_E_INVALIDOPERATION, Evaluator_AddMany(evaluator, oversized_count, encrypteds, destination));
        EXPECT_EQ(
            COR_E_INVALIDOPERATION,
            Evaluator_MultiplyMany(evaluator, oversized_count, encrypteds, relin_keys, destination, nullptr));

        void *public_key = nullptr;
        ASSERT_EQ(S_OK, KeyGenerator_CreatePublicKey(keygen, false, &public_key));
        void *keys = nullptr;
        ASSERT_EQ(S_OK, KSwitchKeys_Create1(&keys));
        void *key_list[1]{ public_key };
        EXPECT_EQ(COR_E_INVALIDOPERATION, KSwitchKeys_AddKeyList(keys, oversized_count, key_list));

        // The rejected call may not have added a key list slot.
        uint64_t raw_size = 0;
        ASSERT_EQ(S_OK, KSwitchKeys_RawSize(keys, &raw_size));
        EXPECT_EQ(0, raw_size);

        EXPECT_EQ(S_OK, KSwitchKeys_Destroy(keys));
        EXPECT_EQ(S_OK, PublicKey_Destroy(public_key));
        EXPECT_EQ(S_OK, Ciphertext_Destroy(destination));
        EXPECT_EQ(S_OK, Ciphertext_Destroy(cipher));
        EXPECT_EQ(S_OK, Evaluator_Destroy(evaluator));
        EXPECT_EQ(S_OK, KSwitchKeys_Destroy(relin_keys));
        EXPECT_EQ(S_OK, KeyGenerator_Destroy(keygen));
        EXPECT_EQ(S_OK, Plaintext_Destroy(plain));
        EXPECT_EQ(S_OK, BatchEncoder_Destroy(encoder));
        EXPECT_EQ(S_OK, SEALContext_Destroy(context));
        EXPECT_EQ(S_OK, EncParams_Destroy(parms));
    }

    TEST(CAbiExceptionFirewallTest, OversizedCKKSEncodeReturnsHResult)
    {
        constexpr uint8_t ckks_scheme = 0x2;
        constexpr int sec_level_none = 0;
        constexpr uint64_t poly_modulus_degree = 64;
        constexpr uint64_t oversized_count = uint64_t(1) << 62;

        void *parms = nullptr;
        ASSERT_EQ(S_OK, EncParams_Create1(ckks_scheme, &parms));
        ASSERT_EQ(S_OK, EncParams_SetPolyModulusDegree(parms, poly_modulus_degree));

        int bit_sizes[]{ 40, 40, 40, 40 };
        void *coeffs[4]{};
        ASSERT_EQ(S_OK, CoeffModulus_Create1(poly_modulus_degree, 4, bit_sizes, coeffs));
        ASSERT_EQ(S_OK, EncParams_SetCoeffModulus(parms, 4, coeffs));
        for (void *coeff : coeffs)
        {
            ASSERT_EQ(S_OK, Modulus_Destroy(coeff));
        }

        void *context = nullptr;
        ASSERT_EQ(S_OK, SEALContext_Create(parms, false, sec_level_none, &context));
        void *encoder = nullptr;
        ASSERT_EQ(S_OK, CKKSEncoder_Create(context, &encoder));
        void *plain = nullptr;
        ASSERT_EQ(S_OK, Plaintext_Create1(nullptr, &plain));

        uint64_t parms_id[4]{};
        ASSERT_EQ(S_OK, SEALContext_FirstParmsId(context, parms_id));

        double values[2]{ 1.0, 1.0 };
        EXPECT_EQ(
            COR_E_INVALIDOPERATION,
            CKKSEncoder_Encode1(encoder, oversized_count, values, parms_id, 1048576.0, plain, nullptr));
        EXPECT_EQ(
            COR_E_INVALIDOPERATION,
            CKKSEncoder_Encode2(encoder, oversized_count, values, parms_id, 1048576.0, plain, nullptr));

        EXPECT_EQ(S_OK, Plaintext_Destroy(plain));
        EXPECT_EQ(S_OK, CKKSEncoder_Destroy(encoder));
        EXPECT_EQ(S_OK, SEALContext_Destroy(context));
        EXPECT_EQ(S_OK, EncParams_Destroy(parms));
    }
} // namespace sealtest
