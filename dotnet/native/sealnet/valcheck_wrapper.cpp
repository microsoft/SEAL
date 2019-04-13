// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/valcheck_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/valcheck.h"

using namespace std;
using namespace seal;
using namespace sealnet;

SEALNETNATIVE HRESULT SEALCALL ValCheck_Plaintext_IsMetadataValidFor(void *plaintext, void *contextptr, bool *result)
{
    Plaintext *plain = FromVoid<Plaintext>(plaintext);
    IfNullRet(plain, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_metadata_valid_for(*plain, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_Ciphertext_IsMetadataValidFor(void *ciphertext, void *contextptr, bool *result)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(ciphertext);
    IfNullRet(cipher, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_metadata_valid_for(*cipher, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_SecretKey_IsMetadataValidFor(void *secret_key, void *contextptr, bool *result)
{
    SecretKey *skey = FromVoid<SecretKey>(secret_key);
    IfNullRet(skey, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_metadata_valid_for(*skey, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_PublicKey_IsMetadataValidFor(void *public_key, void *contextptr, bool *result)
{
    PublicKey *pkey = FromVoid<PublicKey>(public_key);
    IfNullRet(pkey, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_metadata_valid_for(*pkey, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_KSwitchKeys_IsMetadataValidFor(void *kswitch_keys, void *contextptr, bool *result)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(kswitch_keys);
    IfNullRet(keys, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_metadata_valid_for(*keys, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_RelinKeys_IsMetadataValidFor(void *relin_keys, void *contextptr, bool *result)
{
    RelinKeys *keys = FromVoid<RelinKeys>(relin_keys);
    IfNullRet(keys, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_metadata_valid_for(*keys, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_GaloisKeys_IsMetadataValidFor(void *galois_keys, void *contextptr, bool *result)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(galois_keys);
    IfNullRet(keys, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_metadata_valid_for(*keys, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_Plaintext_IsValidFor(void *plaintext, void *contextptr, bool *result)
{
    Plaintext *plain = FromVoid<Plaintext>(plaintext);
    IfNullRet(plain, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*plain, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_Ciphertext_IsValidFor(void *ciphertext, void *contextptr, bool *result)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(ciphertext);
    IfNullRet(cipher, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*cipher, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_SecretKey_IsValidFor(void *secret_key, void *contextptr, bool *result)
{
    SecretKey *skey = FromVoid<SecretKey>(secret_key);
    IfNullRet(skey, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*skey, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_PublicKey_IsValidFor(void *public_key, void *contextptr, bool *result)
{
    PublicKey *pkey = FromVoid<PublicKey>(public_key);
    IfNullRet(pkey, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*pkey, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_KSwitchKeys_IsValidFor(void *kswitch_keys, void *contextptr, bool *result)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(kswitch_keys);
    IfNullRet(keys, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*keys, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_RelinKeys_IsValidFor(void *relin_keys, void *contextptr, bool *result)
{
    RelinKeys *keys = FromVoid<RelinKeys>(relin_keys);
    IfNullRet(keys, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*keys, sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL ValCheck_GaloisKeys_IsValidFor(void *galois_keys, void *contextptr, bool *result)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(galois_keys);
    IfNullRet(keys, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*keys, sharedctx);
    return S_OK;
}