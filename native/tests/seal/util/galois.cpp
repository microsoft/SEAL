// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/context.h"
#include "seal/memorymanager.h"
#include "seal/util/galois.h"
#include <stdexcept>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(GaloisToolTest, Create)
        {
            auto pool = MemoryManager::GetPool();
            ASSERT_THROW(GaloisTool galois_tool(0, pool), invalid_argument);
            ASSERT_THROW(GaloisTool galois_tool(18, pool), invalid_argument);
            ASSERT_NO_THROW(GaloisTool galois_tool(1, pool));
            ASSERT_NO_THROW(GaloisTool galois_tool(17, pool));
        }

        TEST(GaloisToolTest, EltFromStep)
        {
            auto pool = MemoryManager::GetPool();
            {
                GaloisTool galois_tool(3, pool);
                ASSERT_EQ(15, galois_tool.get_elt_from_step(0));
                ASSERT_EQ(3, galois_tool.get_elt_from_step(1));
                ASSERT_EQ(3, galois_tool.get_elt_from_step(-3));
                ASSERT_EQ(9, galois_tool.get_elt_from_step(2));
                ASSERT_EQ(9, galois_tool.get_elt_from_step(-2));
                ASSERT_EQ(11, galois_tool.get_elt_from_step(3));
                ASSERT_EQ(11, galois_tool.get_elt_from_step(-1));
            }
        }

        TEST(GaloisToolTest, EltsFromSteps)
        {
            auto pool = MemoryManager::GetPool();
            {
                GaloisTool galois_tool(3, pool);
                auto elts = galois_tool.get_elts_from_steps({ 0, 1, -3, 2, -2, 3, -1 });
                uint32_t elts_true[7]{ 15, 3, 3, 9, 9, 11, 11 };
                for (size_t i = 0; i < elts.size(); i++)
                {
                    ASSERT_EQ(elts_true[i], elts[i]);
                }
            }
        }

        TEST(GaloisToolTest, EltsAll)
        {
            auto pool = MemoryManager::GetPool();
            {
                GaloisTool galois_tool(3, pool);
                auto elts = galois_tool.get_elts_all();
                uint32_t elts_true[5]{ 15, 3, 11, 9, 9 };
                for (size_t i = 0; i < elts.size(); i++)
                {
                    ASSERT_EQ(elts_true[i], elts[i]);
                }
            }
        }

        TEST(GaloisToolTest, IndexFromElt)
        {
            ASSERT_EQ(7, GaloisTool::GetIndexFromElt(15));
            ASSERT_EQ(1, GaloisTool::GetIndexFromElt(3));
            ASSERT_EQ(4, GaloisTool::GetIndexFromElt(9));
            ASSERT_EQ(5, GaloisTool::GetIndexFromElt(11));
        }

        TEST(GaloisToolTest, ApplyGalois)
        {
            EncryptionParameters parms(scheme_type::CKKS);
            parms.set_poly_modulus_degree(8);
            parms.set_coeff_modulus({ 17 });
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            auto context_data = context->key_context_data();
            auto galois_tool = context_data->galois_tool();
            uint64_t in[8]{ 0, 1, 2, 3, 4, 5, 6, 7 };
            uint64_t out[8];
            uint64_t out_true[8]{ 0, 14, 6, 1, 13, 7, 2, 12 };
            galois_tool->apply_galois(in, 3, Modulus(17), out);
            for (size_t i = 0; i < 8; i++)
            {
                ASSERT_EQ(out_true[i], out[i]);
            }
        }

        TEST(GaloisToolTest, ApplyGaloisNTT)
        {
            EncryptionParameters parms(scheme_type::CKKS);
            parms.set_poly_modulus_degree(8);
            parms.set_coeff_modulus({ 17 });
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            auto context_data = context->key_context_data();
            auto galois_tool = context_data->galois_tool();
            uint64_t in[8]{ 0, 1, 2, 3, 4, 5, 6, 7 };
            uint64_t out[8];
            uint64_t out_true[8]{ 4, 5, 7, 6, 1, 0, 2, 3 };
            const_cast<GaloisTool *>(galois_tool)->apply_galois_ntt(in, 3, out);
            for (size_t i = 0; i < 8; i++)
            {
                ASSERT_EQ(out_true[i], out[i]);
            }
        }
    } // namespace util
} // namespace sealtest
