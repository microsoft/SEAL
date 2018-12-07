#pragma once

// STD
#include <vector>
#include <memory>
#include <unordered_map>
#include <string>

// SEAL
#include "seal/encryptionparams.h"

namespace seal
{
    class SmallModulus;
    class SEALContext;

    namespace dll
    {
        /**
        Return a pointer of the given type from a void pointer.
        */
        template <class T>
        T* FromVoid(void* voidptr)
        {
            T* result = reinterpret_cast<T*>(voidptr);
            return result;
        }

        /**
        Build and array of SmallModulus pointers from a vector
        */
        void BuildCoeffPointers(const std::vector<seal::SmallModulus>& coefficients, uint64_t* length, void** coeffs);

        /**
        Get a shared pointer to a SEALContext from a void pointer.
        */
        const std::shared_ptr<SEALContext>& SharedContextFromVoid(void* context);

        /**
        Get a parms_id_type from an uint64_t pointer
        */
        void CopyParmsId(const uint64_t* src, seal::parms_id_type& dest);

        /**
        Copy parms_id_type to a uint64_t pointer
        */
        void CopyParmsId(const seal::parms_id_type& src, uint64_t* dest);

        /**
        Convert std::string to char*
        */
        HRESULT ToStringHelper(const std::string& str, char* outstr, int* length);
    }
}
