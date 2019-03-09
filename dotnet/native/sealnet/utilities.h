// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <vector>
#include <memory>
#include <unordered_map>
#include <string>

// SEALNet
#include "sealnet/defines.h"

// SEAL
#include "seal/encryptionparams.h"

namespace seal
{
    class SmallModulus;
    class SEALContext;
    class MemoryPoolHandle;
}

namespace sealnet
{
    /**
    Return a pointer of the given type from a void pointer.
    */
    template <class T>
    T *FromVoid(void *voidptr)
    {
        T *result = reinterpret_cast<T*>(voidptr);
        return result;
    }

    /**
    Get MemoryPoolHandle from a void pointer.
    Returns a default if void pointer is null.
    */
    std::unique_ptr<seal::MemoryPoolHandle> MemHandleFromVoid(void *voidptr);

    /**
    Build and array of SmallModulus pointers from a vector
    */
    void BuildCoeffPointers(const std::vector<seal::SmallModulus> &coefficients, uint64_t *length, void **coeffs);

    /**
    Get a shared pointer to a SEALContext from a void pointer.
    */
    const std::shared_ptr<seal::SEALContext> &SharedContextFromVoid(void *context);

    /**
    Get a parms_id_type from an uint64_t pointer
    */
    void CopyParmsId(const uint64_t *src, seal::parms_id_type &dest);

    /**
    Copy parms_id_type to a uint64_t pointer
    */
    void CopyParmsId(const seal::parms_id_type &src, uint64_t *dest);

    /**
    Convert std::string to char*
    */
    HRESULT ToStringHelper(const std::string &str, char *outstr, uint64_t *length);
}
