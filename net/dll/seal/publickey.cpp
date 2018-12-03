// SEALDll
#include "stdafx.h"
#include "publickey.h"
#include "utilities.h"

// SEAL
#include "seal/publickey.h"

using namespace std;
using namespace seal;
using namespace seal::dll;


SEALDLL HRESULT SEALCALL PublicKey_Create1(void** public_key)
{
    IfNullRet(public_key, E_POINTER);

    PublicKey* pkey = new PublicKey();
    *public_key = pkey;
    return S_OK;
}

SEALDLL HRESULT SEALCALL PublicKey_Create2(void* copy, void** public_key)
{
    PublicKey* copyptr = FromVoid<PublicKey>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(public_key, E_POINTER);

    PublicKey* pkey = new PublicKey(*copyptr);
    *public_key = pkey;
    return S_OK;
}

SEALDLL HRESULT SEALCALL PublicKey_Set(void* thisptr, void* assign)
{
    PublicKey* pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    PublicKey* assignptr = FromVoid<PublicKey>(assign);
    IfNullRet(assignptr, E_POINTER);

    *pkey = *assignptr;
    return S_OK;
}

SEALDLL HRESULT SEALCALL PublicKey_Data(void* thisptr, void** data)
{
    PublicKey* pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    IfNullRet(data, E_POINTER);

    // This returns a pointer to an existing object, not a new object.
    // Make sure the managed side does not try to delete it.
    Ciphertext* cipher = &pkey->data();
    *data = cipher;
    return S_OK;
}

SEALDLL HRESULT SEALCALL PublicKey_Destroy(void* thisptr)
{
    PublicKey* pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);

    delete pkey;
    return S_OK;
}

