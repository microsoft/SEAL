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

SEALMETHOD Evaluator_Create(void *sealContext, void **evaluator);

SEALMETHOD Evaluator_Destroy(void *thisptr);

SEALMETHOD Evaluator_Negate(void *thisptr, void *encrypted, void *destination);

SEALMETHOD Evaluator_Add(void *thisptr, void *encrypted1, void *encrypted2, void *destination);

SEALMETHOD Evaluator_AddMany(void *thisptr, uint64_t count, void **encrypteds, void *destination);

SEALMETHOD Evaluator_AddPlain(void *thisptr, void *encrypted, void *plain, void *destination);

SEALMETHOD Evaluator_Sub(void *thisptr, void *encrypted1, void *encrypted2, void *destination);

SEALMETHOD Evaluator_SubPlain(void *thisptr, void *encrypted, void *plain, void *destination);

SEALMETHOD Evaluator_Multiply(void *thisptr, void *encrypted1, void *encrypted2, void *destination, void *pool);

SEALMETHOD Evaluator_MultiplyMany(void *thisptr, uint64_t count, void **encrypteds, void *relin_keys, void *destination, void *pool);

SEALMETHOD Evaluator_MultiplyPlain(void *thisptr, void *encrypted, void *plain, void *destination, void *pool);

SEALMETHOD Evaluator_Square(void *thisptr, void *encrypted, void *destination, void *pool);

SEALMETHOD Evaluator_Relinearize(void *thisptr, void *encrypted, void *relinKeys, void *destination, void *pool);

SEALMETHOD Evaluator_ModSwitchToNext1(void *thisptr, void *encrypted, void *destination, void *pool);

SEALMETHOD Evaluator_ModSwitchToNext2(void *thisptr, void *plain, void *destination);

SEALMETHOD Evaluator_ModSwitchTo1(void *thisptr, void *encrypted, uint64_t *parms_id, void *destination, void *pool);

SEALMETHOD Evaluator_ModSwitchTo2(void *thisptr, void *plain, uint64_t *parms_id, void *destination);

SEALMETHOD Evaluator_RescaleToNext(void *thisptr, void *encrypted, void *destination, void *pool);

SEALMETHOD Evaluator_RescaleTo(void *thisptr, void *encrypted, uint64_t *parms_id, void *destination, void *pool);

SEALMETHOD Evaluator_Exponentiate(void *thisptr, void *encrypted, uint64_t exponent, void *relin_keys, void *destination, void *pool);

SEALMETHOD Evaluator_TransformToNTT1(void *thisptr, void *plain, uint64_t *parms_id, void *destination_ntt, void *pool);

SEALMETHOD Evaluator_TransformToNTT2(void *thisptr, void *encrypted, void *destination_ntt);

SEALMETHOD Evaluator_TransformFromNTT(void *thisptr, void *encrypted_ntt, void *destination);

SEALMETHOD Evaluator_ApplyGalois(void *thisptr, void *encrypted, uint64_t galois_elt, void *galois_keys, void *destination, void *pool);

SEALMETHOD Evaluator_RotateRows(void *thisptr, void *encrypted, int steps, void *galoisKeys, void *destination, void *pool);

SEALMETHOD Evaluator_RotateColumns(void *thisptr, void *encrypted, void *galois_keys, void *destination, void *pool);

SEALMETHOD Evaluator_RotateVector(void *thisptr, void *encrypted, int steps, void *galois_keys, void *destination, void *pool);

SEALMETHOD Evaluator_ComplexConjugate(void *thisptr, void *encrypted, void *galois_keys, void *destination, void *pool);

SEALMETHOD Evaluator_ContextUsingKeyswitching(void *thisptr, bool *using_keyswitching);
