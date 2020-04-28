// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/intarray.h"
#include "seal/memorymanager.h"
#include "seal/util/defines.h"
#include <ios>
#include <iostream>

namespace seal
{
    namespace util
    {
        namespace ztools
        {
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
                IntArray<SEAL_BYTE> &in, void *header_ptr, std::ostream &out_stream, MemoryPoolHandle pool);

            int deflate_array(const IntArray<SEAL_BYTE> &in, IntArray<SEAL_BYTE> &out, MemoryPoolHandle pool);

            int deflate_array_inplace(IntArray<SEAL_BYTE> &in, MemoryPoolHandle pool);

            int inflate_stream(
                std::istream &in_stream, std::streamoff in_size, std::ostream &out_stream, MemoryPoolHandle pool);

            template <typename SizeT>
            SEAL_NODISCARD SizeT deflate_size_bound(SizeT in_size)
            {
                return util::add_safe<SizeT>(in_size, in_size >> 12, in_size >> 14, in_size >> 25, SizeT(17));
            }
        } // namespace ztools
    }     // namespace util
} // namespace seal
