// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <ios>
#include "seal/util/defines.h"
#include "seal/intarray.h"
#include "seal/memorymanager.h"

namespace seal
{
    namespace util
    {
        namespace ztools
        {
            constexpr std::size_t buf_size = 16384;

            /**
            Compresses data in the given buffer, completes the given SEALHeader
            by writing in the size of the output and setting the compression mode
            to compr_mode_type::deflate, and finally writes the SEALHeader followed
            by the compressed data in the given stream.

            @param[in] in The buffer to compress
            @param[in] in_size The size of the buffer to compress in bytes
            @param[out] header A pointer to a SEALHeader instance matching the output
            of the compression
            @param[out] out_stream The stream to write to
            @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
            @throws std::invalid_argument if pool is uninitialized
            @throws std::logic_error if compression failed
            */
            void write_header_deflate_buffer(
                const IntArray<SEAL_BYTE> &in,
                void *header_ptr,
                std::ostream &out_stream,
                MemoryPoolHandle pool);

            int deflate_array(
                const IntArray<SEAL_BYTE> &in,
                IntArray<SEAL_BYTE> &out,
                MemoryPoolHandle pool);

            int inflate_stream(std::istream &in_stream,
                std::streamoff in_size, std::ostream &out_stream,
                MemoryPoolHandle pool);

            SEAL_NODISCARD std::size_t deflate_size_bound(std::size_t in_size) noexcept;
        }
    }
}
