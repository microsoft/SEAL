// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/modulus.h"
#include "seal/util/globals.h"
#include <cstdint>

using namespace std;

namespace seal
{
    namespace util
    {
        namespace global_variables
        {
            shared_ptr<MemoryPool> const global_memory_pool{ make_shared<MemoryPoolMT>() };
#ifndef _M_CEE
            thread_local shared_ptr<MemoryPool> const tls_memory_pool{ make_shared<MemoryPoolST>() };
#else
#pragma message("WARNING: Thread-local memory pools disabled to support /clr")
#endif
            const std::map<std::size_t, std::vector<Modulus>> &GetDefaultCoeffModulus128()
            {
                static const map<size_t, vector<Modulus>> default_coeff_modulus_128{
                    /*
                    Polynomial modulus: 1x^1024 + 1
                    Modulus count: 1
                    Total bit count: 27
                    */
                    { 1024, { 0x7e00001 } },

                    /*
                    Polynomial modulus: 1x^2048 + 1
                    Modulus count: 1
                    Total bit count: 54
                    */
                    { 2048, { 0x3fffffff000001 } },

                    /*
                    Polynomial modulus: 1x^4096 + 1
                    Modulus count: 3
                    Total bit count: 109 = 2 * 36 + 37
                    */
                    { 4096, { 0xffffee001, 0xffffc4001, 0x1ffffe0001 } },

                    /*
                    Polynomial modulus: 1x^8192 + 1
                    Modulus count: 5
                    Total bit count: 218 = 2 * 43 + 3 * 44
                    */
                    { 8192, { 0x7fffffd8001, 0x7fffffc8001, 0xfffffffc001, 0xffffff6c001, 0xfffffebc001 } },

                    /*
                    Polynomial modulus: 1x^16384 + 1
                    Modulus count: 9
                    Total bit count: 438 = 3 * 48 + 6 * 49
                    */
                    { 16384,
                      { 0xfffffffd8001, 0xfffffffa0001, 0xfffffff00001, 0x1fffffff68001, 0x1fffffff50001,
                        0x1ffffffee8001, 0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001 } },

                    /*
                    Polynomial modulus: 1x^32768 + 1
                    Modulus count: 16
                    Total bit count: 881 = 15 * 55 + 56
                    */
                    { 32768,
                      { 0x7fffffffe90001, 0x7fffffffbf0001, 0x7fffffffbd0001, 0x7fffffffba0001, 0x7fffffffaa0001,
                        0x7fffffffa50001, 0x7fffffff9f0001, 0x7fffffff7e0001, 0x7fffffff770001, 0x7fffffff380001,
                        0x7fffffff330001, 0x7fffffff2d0001, 0x7fffffff170001, 0x7fffffff150001, 0x7ffffffef00001,
                        0xfffffffff70001 } }
                };

                return default_coeff_modulus_128;
            }

            const map<size_t, vector<Modulus>> &GetDefaultCoeffModulus192()
            {
                static const map<size_t, vector<Modulus>> default_coeff_modulus_192{
                    /*
                    Polynomial modulus: 1x^1024 + 1
                    Modulus count: 1
                    Total bit count: 19
                    */
                    { 1024, { 0x7f001 } },

                    /*
                    Polynomial modulus: 1x^2048 + 1
                    Modulus count: 1
                    Total bit count: 37
                    */
                    { 2048, { 0x1ffffc0001 } },

                    /*
                    Polynomial modulus: 1x^4096 + 1
                    Modulus count: 3
                    Total bit count: 75 = 3 * 25
                    */
                    { 4096, { 0x1ffc001, 0x1fce001, 0x1fc0001 } },

                    /*
                    Polynomial modulus: 1x^8192 + 1
                    Modulus count: 4
                    Total bit count: 152 = 4 * 38
                    */
                    { 8192, { 0x3ffffac001, 0x3ffff54001, 0x3ffff48001, 0x3ffff28001 } },

                    /*
                    Polynomial modulus: 1x^16384 + 1
                    Modulus count: 6
                    Total bit count: 300 = 6 * 50
                    */
                    { 16384,
                      { 0x3ffffffdf0001, 0x3ffffffd48001, 0x3ffffffd20001, 0x3ffffffd18001, 0x3ffffffcd0001,
                        0x3ffffffc70001 } },

                    /*
                    Polynomial modulus: 1x^32768 + 1
                    Modulus count: 11
                    Total bit count: 600 = 5 * 54 + 6 * 55
                    */
                    { 32768,
                      { 0x3fffffffd60001, 0x3fffffffca0001, 0x3fffffff6d0001, 0x3fffffff5d0001, 0x3fffffff550001,
                        0x7fffffffe90001, 0x7fffffffbf0001, 0x7fffffffbd0001, 0x7fffffffba0001, 0x7fffffffaa0001,
                        0x7fffffffa50001 } }
                };

                return default_coeff_modulus_192;
            }

            const map<size_t, vector<Modulus>> &GetDefaultCoeffModulus256()
            {
                static const map<size_t, vector<Modulus>> default_coeff_modulus_256{
                    /*
                    Polynomial modulus: 1x^1024 + 1
                    Modulus count: 1
                    Total bit count: 14
                    */
                    { 1024, { 0x3001 } },

                    /*
                    Polynomial modulus: 1x^2048 + 1
                    Modulus count: 1
                    Total bit count: 29
                    */
                    { 2048, { 0x1ffc0001 } },

                    /*
                    Polynomial modulus: 1x^4096 + 1
                    Modulus count: 1
                    Total bit count: 58
                    */
                    { 4096, { 0x3ffffffff040001 } },

                    /*
                    Polynomial modulus: 1x^8192 + 1
                    Modulus count: 3
                    Total bit count: 118 = 2 * 39 + 40
                    */
                    { 8192, { 0x7ffffec001, 0x7ffffb0001, 0xfffffdc001 } },

                    /*
                    Polynomial modulus: 1x^16384 + 1
                    Modulus count: 5
                    Total bit count: 237 = 3 * 47 + 2 * 48
                    */
                    { 16384, { 0x7ffffffc8001, 0x7ffffff00001, 0x7fffffe70001, 0xfffffffd8001, 0xfffffffa0001 } },

                    /*
                    Polynomial modulus: 1x^32768 + 1
                    Modulus count: 9
                    Total bit count: 476 = 52 + 8 * 53
                    */
                    { 32768,
                      { 0xffffffff00001, 0x1fffffffe30001, 0x1fffffffd80001, 0x1fffffffd10001, 0x1fffffffc50001,
                        0x1fffffffbf0001, 0x1fffffffb90001, 0x1fffffffb60001, 0x1fffffffa50001 } }
                };

                return default_coeff_modulus_256;
            }
        } // namespace global_variables
    }     // namespace util
} // namespace seal
