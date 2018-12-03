#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL Evaluator_Create(void* sealContext, void** evaluator);

SEALDLL HRESULT SEALCALL Evaluator_Destroy(void* thisptr);

SEALDLL HRESULT SEALCALL Evaluator_Negate(void* thisptr, void* encrypted, void* destination);

SEALDLL HRESULT SEALCALL Evaluator_Add(void* thisptr, void* encrypted1, void* encrypted2, void* destination);

SEALDLL HRESULT SEALCALL Evaluator_AddMany(void* thisptr, int count, void** encrypteds, void* destination);

SEALDLL HRESULT SEALCALL Evaluator_AddPlain(void* thisptr, void* encrypted, void* plain, void* destination);

SEALDLL HRESULT SEALCALL Evaluator_Sub(void* thisptr, void* encrypted1, void* encrypted2, void* destination);

SEALDLL HRESULT SEALCALL Evaluator_SubPlain(void* thisptr, void* encrypted, void* plain, void* destination);

SEALDLL HRESULT SEALCALL Evaluator_Multiply(void* thisptr, void* encrypted1, void* encrypted2, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_MultiplyMany(void* thisptr, int count, void** encrypteds, void* relin_keys, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_MultiplyPlain(void* thisptr, void* encrypted, void* plain, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_Square(void* thisptr, void* encrypted, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_Relinearize(void* thisptr, void* encrypted, void* relinKeys, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_ModSwitchToNext1(void* thisptr, void* encrypted, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_ModSwitchToNext2(void* thisptr, void* plain, void* destination);

SEALDLL HRESULT SEALCALL Evaluator_ModSwitchTo1(void* thisptr, void* encrypted, uint64_t* parms_id, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_ModSwitchTo2(void* thisptr, void* plain, uint64_t* parms_id, void* destination);

SEALDLL HRESULT SEALCALL Evaluator_RescaleToNext(void* thisptr, void* encrypted, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_RescaleTo(void* thisptr, void* encrypted, uint64_t* parms_id, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_Exponentiate(void* thisptr, void* encrypted, uint64_t exponent, void* relin_keys, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_TransformToNTT1(void* thisptr, void* plain, uint64_t* parms_id, void* destination_ntt, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_TransformToNTT2(void* thisptr, void* encrypted, void* destination_ntt);

SEALDLL HRESULT SEALCALL Evaluator_TransformFromNTT(void* thisptr, void* encrypted_ntt, void* destination);

SEALDLL HRESULT SEALCALL Evaluator_ApplyGalois(void* thisptr, void* encrypted, uint64_t galois_elt, void* galois_keys, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_RotateRows(void* thisptr, void* encrypted, int steps, void* galoisKeys, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_RotateColumns(void* thisptr, void* encrypted, void* galois_keys, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_RotateVector(void* thisptr, void* encrypted, int steps, void* galois_keys, void* destination, void* pool);

SEALDLL HRESULT SEALCALL Evaluator_ComplexConjugate(void* thisptr, void* encrypted, void* galois_keys, void* destination, void* pool);
