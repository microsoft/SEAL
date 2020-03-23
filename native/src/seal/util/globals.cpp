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
                const SmallModulus m_sk(576460752213245953UL);

                const SmallModulus m_tilde(uint64_t(1) << 32);

                const SmallModulus gamma(576460752154525697UL);

                const vector<SmallModulus> aux_small_mods{
                    576460752144039937UL, 576460752129359873UL,
                    576460752118874113UL, 576460752066445313UL, 576460752034988033UL, 576460751821078529UL,
                    576460751716220929UL, 576460751665889281UL, 576460751531671553UL, 576460751493922817UL,
                    576460751464562689UL, 576460751357607937UL, 576460751336636417UL, 576460751300984833UL,
                    576460751288401921UL, 576460751244361729UL, 576460751066103809UL, 576460751053520897UL,
                    576460751022063617UL, 576460751003189249UL, 576460750961246209UL, 576460750902525953UL,
                    576460750892040193UL, 576460750889943041UL, 576460750871068673UL, 576460750866874369UL,
                    576460750864777217UL, 576460750791376897UL, 576460750776696833UL, 576460750745239553UL,
                    576460750720073729UL, 576460750625701889UL, 576460750606827521UL, 576460750602633217UL,
                    576460750594244609UL, 576460750489387009UL, 576460750430666753UL, 576460750426472449UL,
                    576460750395015169UL, 576460750363557889UL, 576460750344683521UL, 576460750336294913UL,
                    576460750330003457UL, 576460750279671809UL, 576460750256603137UL, 576460750218854401UL,
                    576460750168522753UL, 576460750166425601UL, 576460750028013569UL, 576460749923155969UL,
                    576460749921058817UL, 576460749904281601UL, 576460749822492673UL, 576460749809909761UL,
                    576460749795229697UL, 576460749726023681UL, 576460749663109121UL, 576460749596000257UL,
                    576460749476462593UL, 576460749451296769UL, 576460749398867969UL, 576460749350633473UL,
                    576460749329661953UL, 576460749235290113UL, 576460749128335361UL, 576460749105266689UL,
                    576460749084295169UL, 576460749073809409UL, 576460749040254977UL, 576460749010894849UL,
                    576460748929105921UL, 576460748885065729UL, 576460748878774273UL, 576460748820054017UL,
                    576460748750848001UL, 576460748746653697UL, 576460748700516353UL, 576460748690030593UL,
                    576460748633407489UL, 576460748526452737UL, 576460748369166337UL, 576460748360777729UL,
                    576460748331417601UL, 576460748291571713UL, 576460748281085953UL, 576460748278988801UL,
                    576460748142673921UL, 576460748048302081UL, 576460747985387521UL, 576460747953930241UL,
                    576460747882627073UL, 576460747876335617UL, 576460747872141313UL, 576460747870044161UL,
                    576460747857461249UL, 576460747719049217UL, 576460747599511553UL, 576460747582734337UL};
            }
        }
    }
}
