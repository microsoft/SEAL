// SEALDll
#include "stdafx.h"
#include "decryptor.h"
#include "utilities.h"

// SEAL
#include "seal/decryptor.h"

using namespace std;
using namespace seal;
using namespace seal::dll;


SEALDLL HRESULT SEALCALL Decryptor_Create(void* context, void* secret_key, void** decryptor)
{
    SEALContext* contextptr = FromVoid<SEALContext>(context);
    IfNullRet(contextptr, E_POINTER);
    SecretKey* secretKey = FromVoid<SecretKey>(secret_key);
    IfNullRet(secretKey, E_POINTER);
    const auto& sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(decryptor, E_POINTER);

    try
    {
        Decryptor* decr = new Decryptor(sharedctx, *secretKey);
        *decryptor = decr;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL Decryptor_Destroy(void* thisptr)
{
    Decryptor* decryptor = FromVoid<Decryptor>(thisptr);
    IfNullRet(decryptor, E_POINTER);

    delete decryptor;
    return S_OK;
}

SEALDLL HRESULT SEALCALL Decryptor_Decrypt(void* thisptr, void* encrypted, void* destination, void* pool_handle)
{
    Decryptor* decryptor = FromVoid<Decryptor>(thisptr);
    IfNullRet(decryptor, E_POINTER);
    Ciphertext* encryptedptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encryptedptr, E_POINTER);
    Plaintext* destinationptr = FromVoid<Plaintext>(destination);
    IfNullRet(destinationptr, E_POINTER);
    MemoryPoolHandle* handle = FromVoid<MemoryPoolHandle>(pool_handle);
    if (nullptr == handle)
        handle = &MemoryManager::GetPool();

    try
    {
        decryptor->decrypt(*encryptedptr, *destinationptr, *handle);
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL Decryptor_InvariantNoiseBudget(void* thisptr, void* encrypted, void* pool_handle, int* invariant_noise_budget)
{
    Decryptor* decryptor = FromVoid<Decryptor>(thisptr);
    IfNullRet(decryptor, E_POINTER);
    Ciphertext* encryptedptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encryptedptr, E_POINTER);
    MemoryPoolHandle* handle = FromVoid<MemoryPoolHandle>(pool_handle);
    if (nullptr == handle)
        handle = &MemoryManager::GetPool();
    IfNullRet(invariant_noise_budget, E_POINTER);

    try
    {
        *invariant_noise_budget = decryptor->invariant_noise_budget(*encryptedptr, *handle);
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}
