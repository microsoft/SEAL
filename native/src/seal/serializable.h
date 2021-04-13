// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/serialization.h"
#include "seal/util/defines.h"
#include "seal/util/streambuf.h"
#include <ios>
#include <iostream>

namespace seal
{
    /**
    Class to represent a serializable object. Some functions return serializable
    objects rather than normal objects. For example, Encryptor can be used in
    symmetric-key mode to create symmetric-key ciphertexts, where half of the
    ciphertext data is pseudo-random and can be generated from a seed, reducing
    the size of the newly created ciphertext object by nearly 50%. This makes
    sense when, e.g., the ciphertexts need to be communicated from a client to
    a server for encrypted computation. When loading an serializable object,
    if a seed was used, the seed will be automatically expanded.

    Serializable objects also expose the save_size function that behaves just
    as the save_size functions of other objects in Microsoft SEAL: it returns
    an upper bound on the size of a buffer needed to hold the serialized data.

    The following illustrates the use of serializable objects:

           +--------------------------+
           | Serializable<GaloisKeys> |  Size ~1 MB (example)
           +------------+-------------+
                        |
                        |                Serializable<GaloisKeys>::save
                        v
                +---------------+
                | Stream/Buffer |        Size ~1 MB (example)
                +-------+-------+
                        |
                        |
                        v
                   +---------+
                   | Network |           Minimized communication
                   +----+----+
                        |
                        |                GaloisKeys::load
                        v
                  +------------+
                  | GaloisKeys |         Size 2 MB (example)
                  +------------+
    */
    template <class T>
    class Serializable
    {
        friend class KeyGenerator;
        friend class Encryptor;

    public:
        /**
        Creates a new serializable object by copying a given one.

        @param[in] copy The serializable object to copy from
        */
        Serializable(const Serializable<T> &copy) = default;

        /**
        Creates a new serializable object by moving a given one.

        @param[in] source The serializable object to move from
        */
        Serializable(Serializable<T> &&source) = default;

        /**
        Moves a given serializable object to the current one.

        @param[in] assign The serializable object to move from
        */
        Serializable &operator=(Serializable<T> &&assign) = default;

        /**
        Copies a given serializable object to the current one.

        @param[in] copy The serializable object to copy from
        */
        Serializable &operator=(const Serializable<T> &copy) = default;

        /**
        Returns an upper bound on the size of the serializable object, as if it
        was written to an output stream.

        @param[in] compr_mode The compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the size does not fit in the return type
        */
        SEAL_NODISCARD inline std::streamoff save_size(
            compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            return obj_.save_size(compr_mode);
        }

        /**
        Saves the serializable object to an output stream. The output is in binary
        format and not human-readable. The output stream must have the "binary"
        flag set.

        @param[out] stream The stream to save the serializable object to
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            std::ostream &stream, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            return obj_.save(stream, compr_mode);
        }

        /**
        Saves the serializable object to a given memory location. The output is in
        binary format and is not human-readable.

        @param[out] out The memory location to write the serializable object to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader, or if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            seal_byte *out, std::size_t size, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            return obj_.save(out, size, compr_mode);
        }

    private:
        Serializable(T &&obj) : obj_(std::move(obj))
        {}

        T obj_;
    };
} // namespace seal
