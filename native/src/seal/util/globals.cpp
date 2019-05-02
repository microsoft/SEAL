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

// \todo make the first one extra large
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

            const vector<SmallModulus> default_small_mods_60bit{
                0xffffffffffc0001,  0xfffffffff840001,  0xfffffffff240001,  0xffffffffe7c0001,
                0xffffffffe740001,  0xffffffffe4c0001,  0xffffffffe440001,  0xffffffffe400001,
                0xffffffffdbc0001,  0xffffffffd840001,  0xffffffffd680001,  0xffffffffd000001,
                0xffffffffcf00001,  0xffffffffcdc0001,  0xffffffffcc40001,  0xffffffffc300001,
                0xffffffffbf40001,  0xffffffffbdc0001,  0xffffffffb880001,  0xffffffffaec0001,
                0xffffffffa380001,  0xffffffffa200001,  0xffffffffa0c0001,  0xffffffff9600001,
                0xffffffff91c0001,  0xffffffff8f40001,  0xffffffff8680001,  0xffffffff7e40001,
                0xffffffff7bc0001,  0xffffffff76c0001,  0xffffffff7680001,  0xffffffff6fc0001,
                0xffffffff6880001,  0xffffffff6340001,  0xffffffff5d40001,  0xffffffff54c0001,
                0xffffffff4d40001,  0xffffffff4380001,  0xffffffff3e80001,  0xffffffff37c0001,
                0xffffffff36c0001,  0xffffffff2100001,  0xffffffff1d80001,  0xffffffff1cc0001,
                0xffffffff1900001,  0xffffffff1740001,  0xffffffff15c0001,  0xffffffff0e80001,
                0xfffffffeff80001,  0xfffffffeff40001,  0xfffffffeefc0001,  0xfffffffee8c0001,
                0xfffffffede40001,  0xfffffffedcc0001,  0xfffffffed040001,  0xfffffffecf40001,
                0xfffffffecec0001,  0xfffffffecb00001,  0xfffffffec380001,  0xfffffffebb40001,
                0xfffffffeb200001,  0xfffffffeaf40001,  0xfffffffea700001,  0xfffffffea400001
            };

            const vector<SmallModulus> default_small_mods_50bit{
                0x3ffffffb80001,  0x3fffffec80001,  0x3fffffea40001,  0x3fffffe940001,
                0x3fffffdd40001,  0x3fffffd900001,  0x3fffffd540001,  0x3fffffd500001,
                0x3fffffcc40001,  0x3fffffcb40001,  0x3fffffc600001,  0x3fffffc4c0001,
                0x3fffffc3c0001,  0x3fffffc240001,  0x3fffffc0c0001,  0x3fffffbb00001,
                0x3fffffbac0001,  0x3fffffb800001,  0x3fffffb7c0001,  0x3fffffb580001,
                0x3fffffafc0001,  0x3fffffaf80001,  0x3fffffaf00001,  0x3fffffac00001,
                0x3fffffaa40001,  0x3fffffa440001,  0x3fffffa0c0001,  0x3fffff9a00001,
                0x3fffff9640001,  0x3fffff9300001,  0x3fffff8b80001,  0x3fffff8740001,
                0x3fffff8340001,  0x3fffff7ec0001,  0x3fffff7e40001,  0x3fffff76c0001,
                0x3fffff6e80001,  0x3fffff6900001,  0x3fffff6600001,  0x3fffff6580001,
                0x3fffff6100001,  0x3fffff5d40001,  0x3fffff5ac0001,  0x3fffff55c0001,
                0x3fffff5400001,  0x3fffff5040001,  0x3fffff4b00001,  0x3fffff4680001,
                0x3fffff4080001,  0x3fffff3880001,  0x3fffff3400001,  0x3fffff30c0001,
                0x3fffff2f80001,  0x3fffff2280001,  0x3fffff21c0001,  0x3fffff1e40001,
                0x3fffff1080001,  0x3fffff0fc0001,  0x3fffff0d00001,  0x3fffff07c0001,
                0x3fffff0540001,  0x3fffff00c0001,  0x3fffff0040001,  0x3ffffefd00001
            };

            const vector<SmallModulus> default_small_mods_40bit{
                0xffffe80001,  0xffffc40001,  0xffff940001,  0xffff780001,
                0xffff580001,  0xffff480001,  0xffff340001,  0xfffeb00001,
                0xfffe680001,  0xfffe2c0001,  0xfffe100001,  0xfffd800001,
                0xfffd080001,  0xfffca00001,  0xfffc940001,  0xfffc880001,
                0xfffc640001,  0xfffc600001,  0xfffc540001,  0xfffbf40001,
                0xfffbdc0001,  0xfffbb80001,  0xfffba00001,  0xfffb340001,
                0xfffaf80001,  0xfffaf00001,  0xfffad80001,  0xfffa800001,
                0xfffa780001,  0xfffa6c0001,  0xfffa5c0001,  0xfffa240001,
                0xfffa140001,  0xfff9a80001,  0xfff9880001,  0xfff9240001,
                0xfff9040001,  0xfff8dc0001,  0xfff8ac0001,  0xfff8a40001,
                0xfff8800001,  0xfff8440001,  0xfff8340001,  0xfff8080001,
                0xfff7ec0001,  0xfff6dc0001,  0xfff6cc0001,  0xfff67c0001,
                0xfff6780001,  0xfff6100001,  0xfff58c0001,  0xfff5440001,
                0xfff51c0001,  0xfff4d40001,  0xfff3c00001,  0xfff3940001,
                0xfff36c0001,  0xfff3400001,  0xfff2c80001,  0xfff2b00001,
                0xfff2680001,  0xfff2440001,  0xfff1e00001,  0xfff1b40001
            };

            const vector<SmallModulus> default_small_mods_30bit{
                0x3ffc0001,  0x3fac0001,  0x3f540001,  0x3ef80001,
                0x3ef40001,  0x3ed00001,  0x3ebc0001,  0x3eb00001,
                0x3e880001,  0x3e500001,  0x3dd40001,  0x3dcc0001,
                0x3cfc0001,  0x3cc40001,  0x3cb40001,  0x3c840001,
                0x3c600001,  0x3c3c0001,  0x3c100001,  0x3bf80001,
                0x3be80001,  0x3be00001,  0x3b800001,  0x3b580001,
                0x3b340001,  0x3ac00001,  0x3aa40001,  0x3a6c0001,
                0x3a5c0001,  0x3a440001,  0x3a300001,  0x3a200001,
                0x39f00001,  0x39e40001,  0x39c40001,  0x39640001,
                0x39600001,  0x39280001,  0x391c0001,  0x39100001,
                0x38b80001,  0x38a00001,  0x388c0001,  0x38680001,
                0x38400001,  0x38100001,  0x37f00001,  0x37c00001,
                0x379c0001,  0x37300001,  0x37200001,  0x36d00001,
                0x36cc0001,  0x36c00001,  0x367c0001,  0x36700001,
                0x36340001,  0x36240001,  0x361c0001,  0x36180001,
                0x36100001,  0x35d40001,  0x35ac0001,  0x35a00001
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
