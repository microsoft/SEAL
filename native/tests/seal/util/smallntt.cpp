// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/mempool.h"
#include "seal/util/uintcore.h"
#include "seal/util/polycore.h"
#include "seal/util/smallntt.h"
#include "seal/util/numth.h"
#include <random>
#include <cstddef>
#include <cstdint>

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
   namespace util
   {
        TEST(SmallNTTTablesTest, SmallNTTBasics)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            SmallNTTTables tables;
            int coeff_count_power = 1;
            SmallModulus modulus(get_prime(uint64_t(1) << coeff_count_power, 60));
            tables.generate(coeff_count_power, modulus);
            ASSERT_EQ(2ULL, tables.coeff_count());
            ASSERT_TRUE(tables.is_generated());
            ASSERT_EQ(1, tables.coeff_count_power());

            coeff_count_power = 2;
            modulus = get_prime(uint64_t(1) << coeff_count_power, 50);
            tables.generate(coeff_count_power, modulus);
            ASSERT_EQ(4ULL, tables.coeff_count());
            ASSERT_TRUE(tables.is_generated());
            ASSERT_EQ(2, tables.coeff_count_power());

            coeff_count_power = 10;
            modulus = get_prime(uint64_t(1) << coeff_count_power, 40);
            tables.generate(coeff_count_power, modulus);
            ASSERT_EQ(1024ULL, tables.coeff_count());
            ASSERT_TRUE(tables.is_generated());
            ASSERT_EQ(10, tables.coeff_count_power());
        }

        TEST(SmallNTTTablesTest, SmallNTTPrimitiveRootsTest)
        {
        MemoryPoolHandle pool = MemoryPoolHandle::Global();
        SmallNTTTables tables;

            int coeff_count_power = 1;
            SmallModulus modulus(0xffffffffffc0001ULL);
            tables.generate(coeff_count_power, modulus);
            ASSERT_EQ(1ULL, tables.get_from_root_powers(0));
            ASSERT_EQ(288794978602139552ULL, tables.get_from_root_powers(1));
            uint64_t inv;
            try_mod_inverse(tables.get_from_root_powers(1), modulus.value(), inv);
            ASSERT_EQ(inv, tables.get_from_inv_root_powers(1));

            coeff_count_power = 2;
            tables.generate(coeff_count_power, modulus);
            ASSERT_EQ(1ULL, tables.get_from_root_powers(0));
            ASSERT_EQ(288794978602139552ULL, tables.get_from_root_powers(1));
            ASSERT_EQ(178930308976060547ULL, tables.get_from_root_powers(2));
            ASSERT_EQ(748001537669050592ULL, tables.get_from_root_powers(3));
        }

        TEST(SmallNTTTablesTest, NegacyclicSmallNTTTest)
        {
        MemoryPoolHandle pool = MemoryPoolHandle::Global();
        SmallNTTTables tables;

            int coeff_count_power = 1;
            SmallModulus modulus(0xffffffffffc0001ULL);
            tables.generate(coeff_count_power, modulus);
            auto poly(allocate_poly(2, 1, pool));
            poly[0] = 0;
            poly[1] = 0;
            ntt_negacyclic_harvey(poly.get(), tables);
            ASSERT_EQ(0ULL, poly[0]);
            ASSERT_EQ(0ULL, poly[1]);

            poly[0] = 1;
            poly[1] = 0;
            ntt_negacyclic_harvey(poly.get(), tables);
            ASSERT_EQ(1ULL, poly[0]);
            ASSERT_EQ(1ULL, poly[1]);

            poly[0] = 1;
            poly[1] = 1;
            ntt_negacyclic_harvey(poly.get(), tables);
            ASSERT_EQ(288794978602139553ULL, poly[0]);
            ASSERT_EQ(864126526004445282ULL, poly[1]);
        }

        TEST(SmallNTTTablesTest, InverseNegacyclicSmallNTTTest)
        {
        MemoryPoolHandle pool = MemoryPoolHandle::Global();
        SmallNTTTables tables;

            int coeff_count_power = 3;
            SmallModulus modulus(0xffffffffffc0001ULL);
            tables.generate(coeff_count_power, modulus);
            auto poly(allocate_zero_poly(800, 1, pool));
            auto temp(allocate_zero_poly(800, 1, pool));

            inverse_ntt_negacyclic_harvey(poly.get(), tables);
            for (size_t i = 0; i < 800; i++)
            {
                ASSERT_EQ(0ULL, poly[i]);
            }

            random_device rd;
            for (size_t i = 0; i < 800; i++)
            {
                poly[i] = static_cast<uint64_t>(rd()) % modulus.value();
                temp[i] = poly[i];
            }

            ntt_negacyclic_harvey(poly.get(), tables);
            inverse_ntt_negacyclic_harvey(poly.get(), tables);
            for (size_t i = 0; i < 800; i++)
            {
                ASSERT_EQ(temp[i], poly[i]);
            }
        }
   }
}
