// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Microsoft SEAL library
// that can be PInvoked by .Net code.
//
///////////////////////////////////////////////////////////////////////////

#include "sealnet/defines.h"
#include <stdint.h>

SEALNETNATIVE HRESULT SEALCALL Evaluator_Create(void *sealContext, void **evaluator);

SEALNETNATIVE HRESULT SEALCALL Evaluator_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL Evaluator_Negate(void *thisptr, void *encrypted, void *destination);

SEALNETNATIVE HRESULT SEALCALL Evaluator_Add(void *thisptr, void *encrypted1, void *encrypted2, void *destination);

SEALNETNATIVE HRESULT SEALCALL Evaluator_AddMany(void *thisptr, uint64_t count, void **encrypteds, void *destination);

SEALNETNATIVE HRESULT SEALCALL Evaluator_AddPlain(void *thisptr, void *encrypted, void *plain, void *destination);

SEALNETNATIVE HRESULT SEALCALL Evaluator_Sub(void *thisptr, void *encrypted1, void *encrypted2, void *destination);

SEALNETNATIVE HRESULT SEALCALL Evaluator_SubPlain(void *thisptr, void *encrypted, void *plain, void *destination);

SEALNETNATIVE HRESULT SEALCALL Evaluator_Multiply(void *thisptr, void *encrypted1, void *encrypted2, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_MultiplyMany(void *thisptr, uint64_t count, void **encrypteds, void *relin_keys, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_MultiplyPlain(void *thisptr, void *encrypted, void *plain, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_Square(void *thisptr, void *encrypted, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_Relinearize(void *thisptr, void *encrypted, void *relinKeys, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_ModSwitchToNext1(void *thisptr, void *encrypted, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_ModSwitchToNext2(void *thisptr, void *plain, void *destination);

SEALNETNATIVE HRESULT SEALCALL Evaluator_ModSwitchTo1(void *thisptr, void *encrypted, uint64_t *parms_id, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_ModSwitchTo2(void *thisptr, void *plain, uint64_t *parms_id, void *destination);

SEALNETNATIVE HRESULT SEALCALL Evaluator_RescaleToNext(void *thisptr, void *encrypted, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_RescaleTo(void *thisptr, void *encrypted, uint64_t *parms_id, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_Exponentiate(void *thisptr, void *encrypted, uint64_t exponent, void *relin_keys, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_TransformToNTT1(void *thisptr, void *plain, uint64_t *parms_id, void *destination_ntt, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_TransformToNTT2(void *thisptr, void *encrypted, void *destination_ntt);

SEALNETNATIVE HRESULT SEALCALL Evaluator_TransformFromNTT(void *thisptr, void *encrypted_ntt, void *destination);

SEALNETNATIVE HRESULT SEALCALL Evaluator_ApplyGalois(void *thisptr, void *encrypted, uint64_t galois_elt, void *galois_keys, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_RotateRows(void *thisptr, void *encrypted, int steps, void *galoisKeys, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_RotateColumns(void *thisptr, void *encrypted, void *galois_keys, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_RotateVector(void *thisptr, void *encrypted, int steps, void *galois_keys, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_ComplexConjugate(void *thisptr, void *encrypted, void *galois_keys, void *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL Evaluator_ContextUsingKeyswitching(void *thisptr, bool *using_keyswitching);
