// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/utilities.h"
#include "seal/c/valcheck.h"

// SEAL
#include "seal/valcheck.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC ValCheck_Plaintext_IsValidFor(void *plaintext, void *context, bool *result)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plaintext);
    IfNullRet(plain, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*plain, *ctx);
    return S_OK;
}

SEAL_C_FUNC ValCheck_Ciphertext_IsValidFor(void *ciphertext, void *context, bool *result)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(ciphertext);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*cipher, *ctx);
    return S_OK;
}

SEAL_C_FUNC ValCheck_SecretKey_IsValidFor(void *secret_key, void *context, bool *result)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);
    SecretKey *skey = FromVoid<SecretKey>(secret_key);
    IfNullRet(skey, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*skey, *ctx);
    return S_OK;
}

SEAL_C_FUNC ValCheck_PublicKey_IsValidFor(void *public_key, void *context, bool *result)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);
    PublicKey *pkey = FromVoid<PublicKey>(public_key);
    IfNullRet(pkey, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*pkey, *ctx);
    return S_OK;
}

SEAL_C_FUNC ValCheck_KSwitchKeys_IsValidFor(void *kswitch_keys, void *context, bool *result)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(kswitch_keys);
    IfNullRet(keys, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*keys, *ctx);
    return S_OK;
}

SEAL_C_FUNC ValCheck_RelinKeys_IsValidFor(void *relin_keys, void *context, bool *result)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);
    RelinKeys *keys = FromVoid<RelinKeys>(relin_keys);
    IfNullRet(keys, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*keys, *ctx);
    return S_OK;
}

SEAL_C_FUNC ValCheck_GaloisKeys_IsValidFor(void *galois_keys, void *context, bool *result)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);
    GaloisKeys *keys = FromVoid<GaloisKeys>(galois_keys);
    IfNullRet(keys, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = is_valid_for(*keys, *ctx);
    return S_OK;
}
