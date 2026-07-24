// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <algorithm>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

// SEALNet
#include "seal/c/defines.h"

// SEAL
#include "seal/encryptionparams.h"

namespace seal
{
    class Modulus;
    class SEALContext;
    class MemoryPoolHandle;
} // namespace seal

namespace seal
{
    namespace c
    {
        /**
        Return a pointer of the given type from a void pointer.
        */
        template <class T>
        inline T *FromVoid(void *voidptr)
        {
            T *result = reinterpret_cast<T *>(voidptr);
            return result;
        }

        /**
        Get MemoryPoolHandle from a void pointer.
        Returns a default if void pointer is null.
        */
        std::unique_ptr<seal::MemoryPoolHandle> MemHandleFromVoid(void *voidptr);

        /**
        Set the required output size and validate the incoming capacity when output is non-null.
        */
        HRESULT PrepareOutputBuffer(uint64_t required, uint64_t *size, const void *output);

        /**
        Build an array of Modulus pointers from a vector.
        When out_mods is non-null, length is the input capacity and output required size.
        */
        HRESULT BuildModulusPointers(const std::vector<seal::Modulus> &in_mods, uint64_t *length, void **out_mods);

        /**
        Get a parms_id_type from an uint64_t pointer
        */
        inline void CopyParmsId(const uint64_t *src, seal::parms_id_type &dest)
        {
            if (nullptr != src)
            {
                std::copy_n(src, dest.size(), std::begin(dest));
            }
        }

        /**
        Copy parms_id_type to a uint64_t pointer
        */
        inline void CopyParmsId(const seal::parms_id_type &src, uint64_t *dest)
        {
            if (nullptr != dest)
            {
                std::copy_n(std::cbegin(src), src.size(), dest);
            }
        }

        /**
        Convert std::string to char* with null terminator.
        When outstr is non-null, length is the input capacity excluding the terminator and output required size.
        */
        HRESULT ToStringHelper(const std::string &str, char *outstr, uint64_t *length);

        /**
        Convert const char * to char* with null terminator.
        When outstr is non-null, length is the input capacity excluding the terminator and output required size.
        */
        HRESULT ToStringHelper2(const char *str, char *outstr, uint64_t *length);
    } // namespace c
} // namespace seal
