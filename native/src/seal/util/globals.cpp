// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <cstdint>
#include "seal/util/globals.h"
#include "seal/smallmodulus.h"

using namespace std;

namespace seal
{
    namespace util
    {
        namespace global_variables
        {
            std::shared_ptr<MemoryPool> const global_memory_pool{ std::make_shared<MemoryPoolMT>() };
#ifndef _M_CEE
            thread_local std::shared_ptr<MemoryPool> const tls_memory_pool{ std::make_shared<MemoryPoolST>() };
#else
#pragma message("WARNING: Thread-local memory pools disabled to support /clr")
#endif
            const map<size_t, vector<SmallModulus>> default_coeff_modulus_128
            {
                /*
                Polynomial modulus: 1x^1024 + 1
                Modulus count: 1
                Total bit count: 27
                */
                { 1024,{
                    0x7e00001
                } },

                /*
                Polynomial modulus: 1x^2048 + 1
                Modulus count: 1
                Total bit count: 54
                */
                { 2048,{
                    0x3fffffff000001
                } },

                /*
                Polynomial modulus: 1x^4096 + 1
                Modulus count: 3
                Total bit count: 109 = 2 * 36 + 37
                */
                { 4096,{
                    0xffffee001, 0xffffc4001, 0x1ffffe0001
                } },

                /*
                Polynomial modulus: 1x^8192 + 1
                Modulus count: 5
                Total bit count: 218 = 2 * 43 + 3 * 44
                */
                { 8192,{
                    0x7fffffd8001, 0x7fffffc8001,
                    0xfffffffc001, 0xffffff6c001, 0xfffffebc001
                } },

                /*
                Polynomial modulus: 1x^16384 + 1
                Modulus count: 9
                Total bit count: 438 = 3 * 48 + 6 * 49
                */
                { 16384,{
                    0xfffffffd8001, 0xfffffffa0001, 0xfffffff00001,
                    0x1fffffff68001, 0x1fffffff50001, 0x1ffffffee8001,
                    0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001
                } },

                /*
                Polynomial modulus: 1x^32768 + 1
                Modulus count: 16
                Total bit count: 881 = 15 * 55 + 56
                */
                { 32768,{
                    0x7fffffffe90001, 0x7fffffffbf0001, 0x7fffffffbd0001,
                    0x7fffffffba0001, 0x7fffffffaa0001, 0x7fffffffa50001,
                    0x7fffffff9f0001, 0x7fffffff7e0001, 0x7fffffff770001,
                    0x7fffffff380001, 0x7fffffff330001, 0x7fffffff2d0001,
                    0x7fffffff170001, 0x7fffffff150001, 0x7ffffffef00001,
                    0xfffffffff70001
                } }
            };

            const map<size_t, vector<SmallModulus>> default_coeff_modulus_192
            {
                /*
                Polynomial modulus: 1x^1024 + 1
                Modulus count: 1
                Total bit count: 19
                */
                { 1024,{
                    0x7f001
                } },

                /*
                Polynomial modulus: 1x^2048 + 1
                Modulus count: 1
                Total bit count: 37
                */
                { 2048,{
                    0x1ffffc0001
                } },

                /*
                Polynomial modulus: 1x^4096 + 1
                Modulus count: 3
                Total bit count: 75 = 3 * 25
                */
                { 4096,{
                    0x1ffc001, 0x1fce001, 0x1fc0001
                } },

                /*
                Polynomial modulus: 1x^8192 + 1
                Modulus count: 4
                Total bit count: 152 = 4 * 38
                */
                { 8192,{
                    0x3ffffac001, 0x3ffff54001,
                    0x3ffff48001, 0x3ffff28001
                } },

                /*
                Polynomial modulus: 1x^16384 + 1
                Modulus count: 6
                Total bit count: 300 = 6 * 50
                */
                { 16384,{
                    0x3ffffffdf0001, 0x3ffffffd48001, 0x3ffffffd20001,
                    0x3ffffffd18001, 0x3ffffffcd0001, 0x3ffffffc70001
                } },

                /*
                Polynomial modulus: 1x^32768 + 1
                Modulus count: 11
                Total bit count: 600 = 5 * 54 + 6 * 55
                */
                { 32768,{
                    0x3fffffffd60001, 0x3fffffffca0001, 0x3fffffff6d0001,
                    0x3fffffff5d0001, 0x3fffffff550001, 0x7fffffffe90001,
                    0x7fffffffbf0001, 0x7fffffffbd0001, 0x7fffffffba0001,
                    0x7fffffffaa0001, 0x7fffffffa50001
                } }
            };

            const map<size_t, vector<SmallModulus>> default_coeff_modulus_256
            {
                /*
                Polynomial modulus: 1x^1024 + 1
                Modulus count: 1
                Total bit count: 14
                */
                { 1024,{
                    0x3001
                } },

                /*
                Polynomial modulus: 1x^2048 + 1
                Modulus count: 1
                Total bit count: 29
                */
                { 2048,{
                    0x1ffc0001
                } },

                /*
                Polynomial modulus: 1x^4096 + 1
                Modulus count: 1
                Total bit count: 58
                */
                { 4096,{
                    0x3ffffffff040001
                } },

                /*
                Polynomial modulus: 1x^8192 + 1
                Modulus count: 3
                Total bit count: 118 = 2 * 39 + 40
                */
                { 8192,{
                    0x7ffffec001, 0x7ffffb0001, 0xfffffdc001
                } },

                /*
                Polynomial modulus: 1x^16384 + 1
                Modulus count: 5
                Total bit count: 237 = 3 * 47 + 2 * 48
                */
                { 16384,{
                    0x7ffffffc8001, 0x7ffffff00001, 0x7fffffe70001,
                    0xfffffffd8001, 0xfffffffa0001
                } },

                /*
                Polynomial modulus: 1x^32768 + 1
                Modulus count: 9
                Total bit count: 476 = 52 + 8 * 53
                */
                { 32768,{
                    0xffffffff00001, 0x1fffffffe30001, 0x1fffffffd80001,
                    0x1fffffffd10001, 0x1fffffffc50001, 0x1fffffffbf0001,
                    0x1fffffffb90001, 0x1fffffffb60001, 0x1fffffffa50001
                } }
            };

            namespace internal_mods
            {
                const SmallModulus m_sk(0x1fffffffffe00001);

                const SmallModulus m_tilde(uint64_t(1) << 32);

                const SmallModulus gamma(0x1fffffffffc80001);

                const vector<SmallModulus> aux_small_mods{
                    0x1fffffffffb40001, 0x1fffffffff500001, 0x1fffffffff380001, 0x1fffffffff000001,
                    0x1ffffffffef00001, 0x1ffffffffee80001, 0x1ffffffffeb40001, 0x1ffffffffe780001,
                    0x1ffffffffe600001, 0x1ffffffffe4c0001, 0x1ffffffffdf40001, 0x1ffffffffdac0001,
                    0x1ffffffffda40001, 0x1ffffffffc680001, 0x1ffffffffc000001, 0x1ffffffffb880001,
                    0x1ffffffffb7c0001, 0x1ffffffffb300001, 0x1ffffffffb1c0001, 0x1ffffffffadc0001,
                    0x1ffffffffa400001, 0x1ffffffffa140001, 0x1ffffffff9d80001, 0x1ffffffff9140001,
                    0x1ffffffff8ac0001, 0x1ffffffff8a80001, 0x1ffffffff81c0001, 0x1ffffffff7800001,
                    0x1ffffffff7680001, 0x1ffffffff7080001, 0x1ffffffff6c80001, 0x1ffffffff6140001,
                    0x1ffffffff5f40001, 0x1ffffffff5700001, 0x1ffffffff4bc0001, 0x1ffffffff4380001,
                    0x1ffffffff3240001, 0x1ffffffff2dc0001, 0x1ffffffff1a40001, 0x1ffffffff11c0001,
                    0x1ffffffff0fc0001, 0x1ffffffff0d80001, 0x1ffffffff0c80001, 0x1ffffffff08c0001,
                    0x1fffffffefd00001, 0x1fffffffef9c0001, 0x1fffffffef600001, 0x1fffffffeef40001,
                    0x1fffffffeed40001, 0x1fffffffeed00001, 0x1fffffffeebc0001, 0x1fffffffed540001,
                    0x1fffffffed440001, 0x1fffffffed2c0001, 0x1fffffffed200001, 0x1fffffffec940001,
                    0x1fffffffec6c0001, 0x1fffffffebe80001, 0x1fffffffebac0001, 0x1fffffffeba40001,
                    0x1fffffffeb4c0001, 0x1fffffffeb280001, 0x1fffffffea780001, 0x1fffffffea440001,
                    0x1fffffffe9f40001, 0x1fffffffe97c0001, 0x1fffffffe9300001, 0x1fffffffe8d00001,
                    0x1fffffffe8400001, 0x1fffffffe7cc0001, 0x1fffffffe7bc0001, 0x1fffffffe7a80001,
                    0x1fffffffe7600001, 0x1fffffffe7500001, 0x1fffffffe6fc0001, 0x1fffffffe6d80001,
                    0x1fffffffe6ac0001, 0x1fffffffe6000001, 0x1fffffffe5d40001, 0x1fffffffe5a00001,
                    0x1fffffffe5940001, 0x1fffffffe54c0001, 0x1fffffffe5340001, 0x1fffffffe4bc0001,
                    0x1fffffffe4a40001, 0x1fffffffe3fc0001, 0x1fffffffe3540001, 0x1fffffffe2b00001,
                    0x1fffffffe2680001, 0x1fffffffe0480001, 0x1fffffffe00c0001, 0x1fffffffdfd00001,
                    0x1fffffffdfc40001, 0x1fffffffdf700001, 0x1fffffffdf340001, 0x1fffffffdef80001,
                    0x1fffffffdea80001, 0x1fffffffde680001, 0x1fffffffde000001, 0x1fffffffdde40001,
                    0x1fffffffddd80001, 0x1fffffffddd00001, 0x1fffffffddb40001, 0x1fffffffdd780001,
                    0x1fffffffdd4c0001, 0x1fffffffdcb80001, 0x1fffffffdca40001, 0x1fffffffdc380001,
                    0x1fffffffdc040001, 0x1fffffffdbb40001, 0x1fffffffdba80001, 0x1fffffffdb9c0001,
                    0x1fffffffdb740001, 0x1fffffffdb380001, 0x1fffffffda600001, 0x1fffffffda340001,
                    0x1fffffffda180001, 0x1fffffffd9700001, 0x1fffffffd9680001, 0x1fffffffd9440001,
                    0x1fffffffd9080001, 0x1fffffffd8c80001, 0x1fffffffd8800001, 0x1fffffffd82c0001,
                    0x1fffffffd7cc0001, 0x1fffffffd7b80001, 0x1fffffffd7840001, 0x1fffffffd73c0001
                };
            }
        }
    }
}