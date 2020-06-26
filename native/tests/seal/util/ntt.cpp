// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/modulus.h"
#include "seal/util/mempool.h"
#include "seal/util/ntt.h"
#include "seal/util/numth.h"
#include "seal/util/polycore.h"
#include "seal/util/uintcore.h"
#include <cstddef>
#include <cstdint>
#include <random>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(NTTTablesTest, NTTBasics)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            Pointer<NTTTables> tables;
            int coeff_count_power = 1;
            Modulus modulus(get_prime(uint64_t(1) << coeff_count_power, 60));
            ASSERT_NO_THROW(tables = allocate<NTTTables>(pool, coeff_count_power, modulus, pool));
            ASSERT_EQ(2ULL, tables->coeff_count());
            ASSERT_EQ(1, tables->coeff_count_power());

            coeff_count_power = 2;
            modulus = get_prime(uint64_t(1) << coeff_count_power, 50);
            ASSERT_NO_THROW(tables = allocate<NTTTables>(pool, coeff_count_power, modulus, pool));
            ASSERT_EQ(4ULL, tables->coeff_count());
            ASSERT_EQ(2, tables->coeff_count_power());

            coeff_count_power = 10;
            modulus = get_prime(uint64_t(1) << coeff_count_power, 40);
            ASSERT_NO_THROW(tables = allocate<NTTTables>(pool, coeff_count_power, modulus, pool));
            ASSERT_EQ(1024ULL, tables->coeff_count());
            ASSERT_EQ(10, tables->coeff_count_power());

            ASSERT_NO_THROW(CreateNTTTables(
                coeff_count_power, CoeffModulus::Create(uint64_t(1) << coeff_count_power, { 20, 20, 20, 20, 20 }),
                tables, pool));
            for (size_t i = 0; i < 5; i++)
            {
                ASSERT_EQ(1024ULL, tables[i].coeff_count());
                ASSERT_EQ(10, tables[i].coeff_count_power());
            }
        }

        TEST(NTTTablesTest, NTTPrimitiveRootsTest)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            Pointer<NTTTables> tables;

            int coeff_count_power = 1;
            Modulus modulus(0xffffffffffc0001ULL);
            ASSERT_NO_THROW(tables = allocate<NTTTables>(pool, coeff_count_power, modulus, pool));
            ASSERT_EQ(1ULL, tables->get_from_root_powers(0).operand);
            ASSERT_EQ(288794978602139552ULL, tables->get_from_root_powers(1).operand);
            uint64_t inv;
            try_invert_uint_mod(tables->get_from_root_powers(1).operand, modulus.value(), inv);
            ASSERT_EQ(inv, tables->get_from_inv_root_powers(1).operand);

            coeff_count_power = 2;
            ASSERT_NO_THROW(tables = allocate<NTTTables>(pool, coeff_count_power, modulus, pool));
            ASSERT_EQ(1ULL, tables->get_from_root_powers(0).operand);
            ASSERT_EQ(288794978602139552ULL, tables->get_from_root_powers(1).operand);
            ASSERT_EQ(178930308976060547ULL, tables->get_from_root_powers(2).operand);
            ASSERT_EQ(748001537669050592ULL, tables->get_from_root_powers(3).operand);
        }

        TEST(NTTTablesTest, NegacyclicNTTTest)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            Pointer<NTTTables> tables;

            int coeff_count_power = 1;
            Modulus modulus(0xffffffffffc0001ULL);
            ASSERT_NO_THROW(tables = allocate<NTTTables>(pool, coeff_count_power, modulus, pool));
            auto poly(allocate_poly(2, 1, pool));
            poly[0] = 0;
            poly[1] = 0;
            ntt_negacyclic_harvey(poly.get(), *tables);
            ASSERT_EQ(0ULL, poly[0]);
            ASSERT_EQ(0ULL, poly[1]);

            poly[0] = 1;
            poly[1] = 0;
            ntt_negacyclic_harvey(poly.get(), *tables);
            ASSERT_EQ(1ULL, poly[0]);
            ASSERT_EQ(1ULL, poly[1]);

            poly[0] = 1;
            poly[1] = 1;
            ntt_negacyclic_harvey(poly.get(), *tables);
            ASSERT_EQ(288794978602139553ULL, poly[0]);
            ASSERT_EQ(864126526004445282ULL, poly[1]);
        }

        TEST(NTTTablesTest, InverseNegacyclicNTTTest)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            Pointer<NTTTables> tables;

            int coeff_count_power = 3;
            Modulus modulus(0xffffffffffc0001ULL);
            ASSERT_NO_THROW(tables = allocate<NTTTables>(pool, coeff_count_power, modulus, pool));
            auto poly(allocate_zero_poly(800, 1, pool));
            auto temp(allocate_zero_poly(800, 1, pool));

            inverse_ntt_negacyclic_harvey(poly.get(), *tables);
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

            ntt_negacyclic_harvey(poly.get(), *tables);
            inverse_ntt_negacyclic_harvey(poly.get(), *tables);
            for (size_t i = 0; i < 800; i++)
            {
                ASSERT_EQ(temp[i], poly[i]);
            }
        }
    } // namespace util
} // namespace sealtest
