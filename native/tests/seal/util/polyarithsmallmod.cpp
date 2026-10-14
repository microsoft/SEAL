// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/defines.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(PolyArithSmallMod, ModuloPolyCoeffs)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            {
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly, 3, pool);
                auto modulus(allocate_uint(2, pool));
                poly[0] = 2;
                poly[1] = 15;
                poly[2] = 77;
                Modulus mod(15);
                modulo_poly_coeffs(poly, 3, mod, poly);
                ASSERT_EQ(2ULL, poly[0]);
                ASSERT_EQ(0ULL, poly[1]);
                ASSERT_EQ(2ULL, poly[2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly, 3, 2, pool);
                auto modulus(allocate_uint(2, pool));
                poly[0][0] = 2;
                poly[0][1] = 15;
                poly[0][2] = 77;
                poly[1][0] = 2;
                poly[1][1] = 15;
                poly[1][2] = 77;
                vector<Modulus> mod{ 15, 3 };
                modulo_poly_coeffs(poly, 2, mod, poly);
                ASSERT_EQ(0ULL, poly[0][1]);
                ASSERT_EQ(2ULL, poly[0][2]);
                ASSERT_EQ(2ULL, poly[0][0]);
                ASSERT_EQ(2ULL, poly[1][0]);
                ASSERT_EQ(0ULL, poly[1][1]);
                ASSERT_EQ(2ULL, poly[1][2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly, 2, 3, 2, pool);
                auto modulus(allocate_uint(2, pool));
                poly[0][0][0] = 2;
                poly[0][0][1] = 15;
                poly[0][0][2] = 77;
                poly[0][1][0] = 2;
                poly[0][1][1] = 15;
                poly[0][1][2] = 77;
                poly[1][0][0] = 2;
                poly[1][0][1] = 15;
                poly[1][0][2] = 77;
                poly[1][1][0] = 2;
                poly[1][1][1] = 15;
                poly[1][1][2] = 77;
                vector<Modulus> mod{ 15, 3 };
                modulo_poly_coeffs(poly, 2, mod, poly);
                ASSERT_EQ(2ULL, poly[0][0][0]);
                ASSERT_EQ(0ULL, poly[0][0][1]);
                ASSERT_EQ(2ULL, poly[0][0][2]);
                ASSERT_EQ(2ULL, poly[0][1][0]);
                ASSERT_EQ(0ULL, poly[0][1][1]);
                ASSERT_EQ(2ULL, poly[0][1][2]);
                ASSERT_EQ(2ULL, poly[1][0][0]);
                ASSERT_EQ(0ULL, poly[1][0][1]);
                ASSERT_EQ(2ULL, poly[1][0][2]);
                ASSERT_EQ(2ULL, poly[1][1][0]);
                ASSERT_EQ(0ULL, poly[1][1][1]);
                ASSERT_EQ(2ULL, poly[1][1][2]);
            }
        }

        TEST(PolyArithSmallMod, NegatePolyCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            {
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly, 3, pool);
                poly[0] = 2;
                poly[1] = 3;
                poly[2] = 4;
                Modulus mod(15);
                negate_poly_coeffmod(poly, 3, mod, poly);
                ASSERT_EQ(static_cast<uint64_t>(13), poly[0]);
                ASSERT_EQ(static_cast<uint64_t>(12), poly[1]);
                ASSERT_EQ(static_cast<uint64_t>(11), poly[2]);

                poly[0] = 2;
                poly[1] = 3;
                poly[2] = 4;
                mod = 0xFFFFFFFFFFFFFFULL;
                negate_poly_coeffmod(poly, 3, mod, poly);
                ASSERT_EQ(0xFFFFFFFFFFFFFDULL, poly[0]);
                ASSERT_EQ(0xFFFFFFFFFFFFFCULL, poly[1]);
                ASSERT_EQ(0xFFFFFFFFFFFFFBULL, poly[2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly, 3, 2, pool);
                poly[0][0] = 2;
                poly[0][1] = 3;
                poly[0][2] = 4;
                poly[1][0] = 2;
                poly[1][1] = 0;
                poly[1][2] = 1;
                vector<Modulus> mod{ 15, 3 };
                negate_poly_coeffmod(poly, 2, mod, poly);
                ASSERT_EQ(static_cast<uint64_t>(13), poly[0][0]);
                ASSERT_EQ(static_cast<uint64_t>(12), poly[0][1]);
                ASSERT_EQ(static_cast<uint64_t>(11), poly[0][2]);
                ASSERT_EQ(static_cast<uint64_t>(1), poly[1][0]);
                ASSERT_EQ(static_cast<uint64_t>(0), poly[1][1]);
                ASSERT_EQ(static_cast<uint64_t>(2), poly[1][2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly, 2, 3, 2, pool);
                poly[0][0][0] = 2;
                poly[0][0][1] = 3;
                poly[0][0][2] = 4;
                poly[0][1][0] = 2;
                poly[0][1][1] = 0;
                poly[0][1][2] = 1;
                poly[1][0][0] = 2;
                poly[1][0][1] = 3;
                poly[1][0][2] = 4;
                poly[1][1][0] = 2;
                poly[1][1][1] = 0;
                poly[1][1][2] = 1;
                vector<Modulus> mod{ 15, 3 };
                negate_poly_coeffmod(poly, 2, mod, poly);
                ASSERT_EQ(static_cast<uint64_t>(13), poly[0][0][0]);
                ASSERT_EQ(static_cast<uint64_t>(12), poly[0][0][1]);
                ASSERT_EQ(static_cast<uint64_t>(11), poly[0][0][2]);
                ASSERT_EQ(static_cast<uint64_t>(1), poly[0][1][0]);
                ASSERT_EQ(static_cast<uint64_t>(0), poly[0][1][1]);
                ASSERT_EQ(static_cast<uint64_t>(2), poly[0][1][2]);
                ASSERT_EQ(static_cast<uint64_t>(13), poly[1][0][0]);
                ASSERT_EQ(static_cast<uint64_t>(12), poly[1][0][1]);
                ASSERT_EQ(static_cast<uint64_t>(11), poly[1][0][2]);
                ASSERT_EQ(static_cast<uint64_t>(1), poly[1][1][0]);
                ASSERT_EQ(static_cast<uint64_t>(0), poly[1][1][1]);
                ASSERT_EQ(static_cast<uint64_t>(2), poly[1][1][2]);
            }
        }

        TEST(PolyArithSmallMod, AddPolyCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            {
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly1, 3, pool);
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly2, 3, pool);
                poly1[0] = 1;
                poly1[1] = 3;
                poly1[2] = 4;
                poly2[0] = 1;
                poly2[1] = 2;
                poly2[2] = 4;
                Modulus mod(5);
                add_poly_coeffmod(poly1, poly2, 3, mod, poly1);
                ASSERT_EQ(2ULL, poly1[0]);
                ASSERT_EQ(0ULL, poly1[1]);
                ASSERT_EQ(3ULL, poly1[2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly1, 3, 2, pool);
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly2, 3, 2, pool);
                poly1[0][0] = 1;
                poly1[0][1] = 3;
                poly1[0][2] = 4;
                poly1[1][0] = 0;
                poly1[1][1] = 1;
                poly1[1][2] = 2;

                poly2[0][0] = 1;
                poly2[0][1] = 2;
                poly2[0][2] = 4;
                poly2[1][0] = 2;
                poly2[1][1] = 1;
                poly2[1][2] = 0;

                vector<Modulus> mod{ 5, 3 };
                add_poly_coeffmod(poly1, poly2, 2, mod, poly1);

                ASSERT_EQ(2ULL, poly1[0][0]);
                ASSERT_EQ(0ULL, poly1[0][1]);
                ASSERT_EQ(3ULL, poly1[0][2]);
                ASSERT_EQ(2ULL, poly1[1][0]);
                ASSERT_EQ(2ULL, poly1[1][1]);
                ASSERT_EQ(2ULL, poly1[1][2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly1, 2, 3, 2, pool);
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly2, 2, 3, 2, pool);
                poly1[0][0][0] = 1;
                poly1[0][0][1] = 3;
                poly1[0][0][2] = 4;
                poly1[0][1][0] = 0;
                poly1[0][1][1] = 1;
                poly1[0][1][2] = 2;
                poly1[1][0][0] = 2;
                poly1[1][0][1] = 4;
                poly1[1][0][2] = 0;
                poly1[1][1][0] = 1;
                poly1[1][1][1] = 2;
                poly1[1][1][2] = 0;

                poly2[0][0][0] = 1;
                poly2[0][0][1] = 2;
                poly2[0][0][2] = 4;
                poly2[0][1][0] = 2;
                poly2[0][1][1] = 1;
                poly2[0][1][2] = 0;
                poly2[1][0][0] = 2;
                poly2[1][0][1] = 4;
                poly2[1][0][2] = 0;
                poly2[1][1][0] = 0;
                poly2[1][1][1] = 2;
                poly2[1][1][2] = 1;

                vector<Modulus> mod{ 5, 3 };
                add_poly_coeffmod(poly1, poly2, 2, mod, poly1);

                ASSERT_EQ(2ULL, poly1[0][0][0]);
                ASSERT_EQ(0ULL, poly1[0][0][1]);
                ASSERT_EQ(3ULL, poly1[0][0][2]);
                ASSERT_EQ(2ULL, poly1[0][1][0]);
                ASSERT_EQ(2ULL, poly1[0][1][1]);
                ASSERT_EQ(2ULL, poly1[0][1][2]);
                ASSERT_EQ(4ULL, poly1[1][0][0]);
                ASSERT_EQ(3ULL, poly1[1][0][1]);
                ASSERT_EQ(0ULL, poly1[1][0][2]);
                ASSERT_EQ(1ULL, poly1[1][1][0]);
                ASSERT_EQ(1ULL, poly1[1][1][1]);
                ASSERT_EQ(1ULL, poly1[1][1][2]);
            }
        }

        TEST(PolyArithSmallMod, SubPolyCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            {
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly1, 3, pool);
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly2, 3, pool);
                poly1[0] = 4;
                poly1[1] = 3;
                poly1[2] = 2;
                poly2[0] = 2;
                poly2[1] = 3;
                poly2[2] = 4;
                Modulus mod(5);
                sub_poly_coeffmod(poly1, poly2, 3, mod, poly1);
                ASSERT_EQ(2ULL, poly1[0]);
                ASSERT_EQ(0ULL, poly1[1]);
                ASSERT_EQ(3ULL, poly1[2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly1, 3, 2, pool);
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly2, 3, 2, pool);
                poly1[0][0] = 1;
                poly1[0][1] = 3;
                poly1[0][2] = 4;
                poly1[1][0] = 0;
                poly1[1][1] = 1;
                poly1[1][2] = 2;

                poly2[0][0] = 1;
                poly2[0][1] = 2;
                poly2[0][2] = 4;
                poly2[1][0] = 2;
                poly2[1][1] = 1;
                poly2[1][2] = 0;

                vector<Modulus> mod{ 5, 3 };
                sub_poly_coeffmod(poly1, poly2, 2, mod, poly1);

                ASSERT_EQ(0ULL, poly1[0][0]);
                ASSERT_EQ(1ULL, poly1[0][1]);
                ASSERT_EQ(0ULL, poly1[0][2]);
                ASSERT_EQ(1ULL, poly1[1][0]);
                ASSERT_EQ(0ULL, poly1[1][1]);
                ASSERT_EQ(2ULL, poly1[1][2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly1, 2, 3, 2, pool);
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly2, 2, 3, 2, pool);
                poly1[0][0][0] = 1;
                poly1[0][0][1] = 3;
                poly1[0][0][2] = 4;
                poly1[0][1][0] = 0;
                poly1[0][1][1] = 1;
                poly1[0][1][2] = 2;
                poly1[1][0][0] = 2;
                poly1[1][0][1] = 4;
                poly1[1][0][2] = 0;
                poly1[1][1][0] = 1;
                poly1[1][1][1] = 2;
                poly1[1][1][2] = 0;

                poly2[0][0][0] = 1;
                poly2[0][0][1] = 2;
                poly2[0][0][2] = 4;
                poly2[0][1][0] = 2;
                poly2[0][1][1] = 1;
                poly2[0][1][2] = 0;
                poly2[1][0][0] = 2;
                poly2[1][0][1] = 4;
                poly2[1][0][2] = 0;
                poly2[1][1][0] = 0;
                poly2[1][1][1] = 2;
                poly2[1][1][2] = 1;

                vector<Modulus> mod{ 5, 3 };
                sub_poly_coeffmod(poly1, poly2, 2, mod, poly1);

                ASSERT_EQ(0ULL, poly1[0][0][0]);
                ASSERT_EQ(1ULL, poly1[0][0][1]);
                ASSERT_EQ(0ULL, poly1[0][0][2]);
                ASSERT_EQ(1ULL, poly1[0][1][0]);
                ASSERT_EQ(0ULL, poly1[0][1][1]);
                ASSERT_EQ(2ULL, poly1[0][1][2]);
                ASSERT_EQ(0ULL, poly1[1][0][0]);
                ASSERT_EQ(0ULL, poly1[1][0][1]);
                ASSERT_EQ(0ULL, poly1[1][0][2]);
                ASSERT_EQ(1ULL, poly1[1][1][0]);
                ASSERT_EQ(0ULL, poly1[1][1][1]);
                ASSERT_EQ(2ULL, poly1[1][1][2]);
            }
        }

        TEST(PolyArithSmallMod, MultiplyPolyScalarCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            {
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly, 3, pool);

                poly[0] = 1;
                poly[1] = 3;
                poly[2] = 4;

                uint64_t scalar = 3;
                Modulus mod(5);
                multiply_poly_scalar_coeffmod(poly, 3, scalar, mod, poly);
                ASSERT_EQ(3ULL, poly[0]);
                ASSERT_EQ(4ULL, poly[1]);
                ASSERT_EQ(2ULL, poly[2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly, 3, 2, pool);

                poly[0][0] = 1;
                poly[0][1] = 3;
                poly[0][2] = 4;
                poly[1][0] = 1;
                poly[1][1] = 0;
                poly[1][2] = 2;

                uint64_t scalar = 2;
                vector<Modulus> mod{ 5, 3 };
                multiply_poly_scalar_coeffmod(poly, 2, scalar, mod, poly);
                ASSERT_EQ(2ULL, poly[0][0]);
                ASSERT_EQ(1ULL, poly[0][1]);
                ASSERT_EQ(3ULL, poly[0][2]);
                ASSERT_EQ(2ULL, poly[1][0]);
                ASSERT_EQ(0ULL, poly[1][1]);
                ASSERT_EQ(1ULL, poly[1][2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly, 2, 3, 2, pool);

                poly[0][0][0] = 1;
                poly[0][0][1] = 3;
                poly[0][0][2] = 4;
                poly[0][1][0] = 1;
                poly[0][1][1] = 0;
                poly[0][1][2] = 2;
                poly[1][0][0] = 1;
                poly[1][0][1] = 3;
                poly[1][0][2] = 4;
                poly[1][1][0] = 1;
                poly[1][1][1] = 0;
                poly[1][1][2] = 2;

                uint64_t scalar = 2;
                vector<Modulus> mod{ 5, 3 };
                multiply_poly_scalar_coeffmod(poly, 2, scalar, mod, poly);
                ASSERT_EQ(2ULL, poly[0][0][0]);
                ASSERT_EQ(1ULL, poly[0][0][1]);
                ASSERT_EQ(3ULL, poly[0][0][2]);
                ASSERT_EQ(2ULL, poly[0][1][0]);
                ASSERT_EQ(0ULL, poly[0][1][1]);
                ASSERT_EQ(1ULL, poly[0][1][2]);
                ASSERT_EQ(2ULL, poly[1][0][0]);
                ASSERT_EQ(1ULL, poly[1][0][1]);
                ASSERT_EQ(3ULL, poly[1][0][2]);
                ASSERT_EQ(2ULL, poly[1][1][0]);
                ASSERT_EQ(0ULL, poly[1][1][1]);
                ASSERT_EQ(1ULL, poly[1][1][2]);
            }
        }

        TEST(PolyArithSmallMod, MultiplyPolyMonoCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            {
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly, 4, pool);
                poly[0] = 1;
                poly[1] = 3;
                poly[2] = 4;
                poly[3] = 2;
                uint64_t mono_coeff = 3;
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(result, 4, pool);
                Modulus mod(5);

                size_t mono_exponent = 0;
                negacyclic_multiply_poly_mono_coeffmod(poly, 1, mono_coeff, mono_exponent, mod, result, pool);
                ASSERT_EQ(3ULL, result[0]);
                ASSERT_EQ(0ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);

                negacyclic_multiply_poly_mono_coeffmod(poly, 2, mono_coeff, mono_exponent, mod, result, pool);
                ASSERT_EQ(3ULL, result[0]);
                ASSERT_EQ(4ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);

                mono_exponent = 1;
                negacyclic_multiply_poly_mono_coeffmod(poly, 2, mono_coeff, mono_exponent, mod, result, pool);
                ASSERT_EQ(1ULL, result[0]);
                ASSERT_EQ(3ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);

                negacyclic_multiply_poly_mono_coeffmod(poly, 4, mono_coeff, mono_exponent, mod, result, pool);
                ASSERT_EQ(4ULL, result[0]);
                ASSERT_EQ(3ULL, result[1]);
                ASSERT_EQ(4ULL, result[2]);
                ASSERT_EQ(2ULL, result[3]);

                mono_coeff = 1;
                negacyclic_multiply_poly_mono_coeffmod(poly, 4, mono_coeff, mono_exponent, mod, result, pool);
                ASSERT_EQ(3ULL, result[0]);
                ASSERT_EQ(1ULL, result[1]);
                ASSERT_EQ(3ULL, result[2]);
                ASSERT_EQ(4ULL, result[3]);

                mono_coeff = 4;
                mono_exponent = 3;
                negacyclic_multiply_poly_mono_coeffmod(poly, 4, mono_coeff, mono_exponent, mod, result, pool);
                ASSERT_EQ(3ULL, result[0]);
                ASSERT_EQ(4ULL, result[1]);
                ASSERT_EQ(2ULL, result[2]);
                ASSERT_EQ(4ULL, result[3]);

                mono_coeff = 1;
                mono_exponent = 0;
                negacyclic_multiply_poly_mono_coeffmod(poly, 4, mono_coeff, mono_exponent, mod, result, pool);
                ASSERT_EQ(1ULL, result[0]);
                ASSERT_EQ(3ULL, result[1]);
                ASSERT_EQ(4ULL, result[2]);
                ASSERT_EQ(2ULL, result[3]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly, 4, 2, pool);
                poly[0][0] = 1;
                poly[0][1] = 3;
                poly[0][2] = 4;
                poly[0][3] = 2;
                poly[1][0] = 1;
                poly[1][1] = 3;
                poly[1][2] = 4;
                poly[1][3] = 2;

                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(result, 4, 2, pool);
                vector<Modulus> mod{ 5, 7 };

                uint64_t mono_coeff = 4;
                size_t mono_exponent = 2;
                negacyclic_multiply_poly_mono_coeffmod(poly, 2, mono_coeff, mono_exponent, mod, result, pool);

                ASSERT_EQ(4ULL, result[0][0]);
                ASSERT_EQ(2ULL, result[0][1]);
                ASSERT_EQ(4ULL, result[0][2]);
                ASSERT_EQ(2ULL, result[0][3]);
                ASSERT_EQ(5ULL, result[1][0]);
                ASSERT_EQ(6ULL, result[1][1]);
                ASSERT_EQ(4ULL, result[1][2]);
                ASSERT_EQ(5ULL, result[1][3]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly, 2, 4, 2, pool);
                poly[0][0][0] = 1;
                poly[0][0][1] = 3;
                poly[0][0][2] = 4;
                poly[0][0][3] = 2;
                poly[0][1][0] = 1;
                poly[0][1][1] = 3;
                poly[0][1][2] = 4;
                poly[0][1][3] = 2;
                poly[1][0][0] = 1;
                poly[1][0][1] = 3;
                poly[1][0][2] = 4;
                poly[1][0][3] = 2;
                poly[1][1][0] = 1;
                poly[1][1][1] = 3;
                poly[1][1][2] = 4;
                poly[1][1][3] = 2;

                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(result, 2, 4, 2, pool);
                vector<Modulus> mod{ 5, 7 };

                uint64_t mono_coeff = 4;
                size_t mono_exponent = 2;
                negacyclic_multiply_poly_mono_coeffmod(poly, 2, mono_coeff, mono_exponent, mod, result, pool);

                ASSERT_EQ(4ULL, result[0][0][0]);
                ASSERT_EQ(2ULL, result[0][0][1]);
                ASSERT_EQ(4ULL, result[0][0][2]);
                ASSERT_EQ(2ULL, result[0][0][3]);
                ASSERT_EQ(5ULL, result[0][1][0]);
                ASSERT_EQ(6ULL, result[0][1][1]);
                ASSERT_EQ(4ULL, result[0][1][2]);
                ASSERT_EQ(5ULL, result[0][1][3]);
                ASSERT_EQ(4ULL, result[1][0][0]);
                ASSERT_EQ(2ULL, result[1][0][1]);
                ASSERT_EQ(4ULL, result[1][0][2]);
                ASSERT_EQ(2ULL, result[1][0][3]);
                ASSERT_EQ(5ULL, result[1][1][0]);
                ASSERT_EQ(6ULL, result[1][1][1]);
                ASSERT_EQ(4ULL, result[1][1][2]);
                ASSERT_EQ(5ULL, result[1][1][3]);
            }
        }

        TEST(PolyArithSmallMod, DyadicProductCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            {
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly1, 3, pool);
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly2, 3, pool);
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(result, 3, pool);
                Modulus mod(13);

                poly1[0] = 1;
                poly1[1] = 1;
                poly1[2] = 1;
                poly2[0] = 2;
                poly2[1] = 3;
                poly2[2] = 4;

                dyadic_product_coeffmod(poly1, poly2, 3, mod, result);
                ASSERT_EQ(2ULL, result[0]);
                ASSERT_EQ(3ULL, result[1]);
                ASSERT_EQ(4ULL, result[2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly1, 3, 2, pool);
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly2, 3, 2, pool);
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(result, 3, 2, pool);
                vector<Modulus> mod{ 13, 7 };

                poly1[0][0] = 1;
                poly1[0][1] = 2;
                poly1[0][2] = 1;
                poly1[1][0] = 2;
                poly1[1][1] = 1;
                poly1[1][2] = 2;

                poly2[0][0] = 2;
                poly2[0][1] = 3;
                poly2[0][2] = 4;
                poly2[1][0] = 2;
                poly2[1][1] = 3;
                poly2[1][2] = 4;

                dyadic_product_coeffmod(poly1, poly2, 2, mod, result);
                ASSERT_EQ(2ULL, result[0][0]);
                ASSERT_EQ(6ULL, result[0][1]);
                ASSERT_EQ(4ULL, result[0][2]);
                ASSERT_EQ(4ULL, result[1][0]);
                ASSERT_EQ(3ULL, result[1][1]);
                ASSERT_EQ(1ULL, result[1][2]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly1, 2, 3, 2, pool);
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly2, 2, 3, 2, pool);
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(result, 2, 3, 2, pool);
                vector<Modulus> mod{ 13, 7 };

                poly1[0][0][0] = 1;
                poly1[0][0][1] = 2;
                poly1[0][0][2] = 1;
                poly1[0][1][0] = 2;
                poly1[0][1][1] = 1;
                poly1[0][1][2] = 2;
                poly1[1][0][0] = 1;
                poly1[1][0][1] = 2;
                poly1[1][0][2] = 1;
                poly1[1][1][0] = 2;
                poly1[1][1][1] = 1;
                poly1[1][1][2] = 2;

                poly2[0][0][0] = 2;
                poly2[0][0][1] = 3;
                poly2[0][0][2] = 4;
                poly2[0][1][0] = 2;
                poly2[0][1][1] = 3;
                poly2[0][1][2] = 4;
                poly2[1][0][0] = 2;
                poly2[1][0][1] = 3;
                poly2[1][0][2] = 4;
                poly2[1][1][0] = 2;
                poly2[1][1][1] = 3;
                poly2[1][1][2] = 4;

                dyadic_product_coeffmod(poly1, poly2, 2, mod, result);
                ASSERT_EQ(2ULL, result[0][0][0]);
                ASSERT_EQ(6ULL, result[0][0][1]);
                ASSERT_EQ(4ULL, result[0][0][2]);
                ASSERT_EQ(4ULL, result[0][1][0]);
                ASSERT_EQ(3ULL, result[0][1][1]);
                ASSERT_EQ(1ULL, result[0][1][2]);
                ASSERT_EQ(2ULL, result[1][0][0]);
                ASSERT_EQ(6ULL, result[1][0][1]);
                ASSERT_EQ(4ULL, result[1][0][2]);
                ASSERT_EQ(4ULL, result[1][1][0]);
                ASSERT_EQ(3ULL, result[1][1][1]);
                ASSERT_EQ(1ULL, result[1][1][2]);
            }
        }

        TEST(PolyArithSmallMod, PolyInftyNormCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly, 4, pool);
            Modulus mod(10);

            poly[0] = 0;
            poly[1] = 1;
            poly[2] = 2;
            poly[3] = 3;
            ASSERT_EQ(0x3ULL, poly_infty_norm_coeffmod(poly, 4, mod));

            poly[0] = 0;
            poly[1] = 1;
            poly[2] = 2;
            poly[3] = 8;
            ASSERT_EQ(0x2ULL, poly_infty_norm_coeffmod(poly, 4, mod));
        }

        TEST(PolyArithSmallMod, NegacyclicShiftPolyCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            {
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(poly, 4, pool);
                SEAL_ALLOCATE_ZERO_GET_COEFF_ITER(result, 4, pool);

                Modulus mod(10);

                negacyclic_shift_poly_coeffmod(poly, 4, 0, mod, result);
                ASSERT_EQ(0ULL, result[0]);
                ASSERT_EQ(0ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);
                negacyclic_shift_poly_coeffmod(poly, 4, 1, mod, result);
                ASSERT_EQ(0ULL, result[0]);
                ASSERT_EQ(0ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);
                negacyclic_shift_poly_coeffmod(poly, 4, 2, mod, result);
                ASSERT_EQ(0ULL, result[0]);
                ASSERT_EQ(0ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);
                negacyclic_shift_poly_coeffmod(poly, 4, 3, mod, result);
                ASSERT_EQ(0ULL, result[0]);
                ASSERT_EQ(0ULL, result[1]);
                ASSERT_EQ(0ULL, result[2]);
                ASSERT_EQ(0ULL, result[3]);

                poly[0] = 1;
                poly[1] = 2;
                poly[2] = 3;
                poly[3] = 4;
                negacyclic_shift_poly_coeffmod(poly, 4, 0, mod, result);
                ASSERT_EQ(1ULL, result[0]);
                ASSERT_EQ(2ULL, result[1]);
                ASSERT_EQ(3ULL, result[2]);
                ASSERT_EQ(4ULL, result[3]);
                negacyclic_shift_poly_coeffmod(poly, 4, 1, mod, result);
                ASSERT_EQ(6ULL, result[0]);
                ASSERT_EQ(1ULL, result[1]);
                ASSERT_EQ(2ULL, result[2]);
                ASSERT_EQ(3ULL, result[3]);
                negacyclic_shift_poly_coeffmod(poly, 4, 2, mod, result);
                ASSERT_EQ(7ULL, result[0]);
                ASSERT_EQ(6ULL, result[1]);
                ASSERT_EQ(1ULL, result[2]);
                ASSERT_EQ(2ULL, result[3]);
                negacyclic_shift_poly_coeffmod(poly, 4, 3, mod, result);
                ASSERT_EQ(8ULL, result[0]);
                ASSERT_EQ(7ULL, result[1]);
                ASSERT_EQ(6ULL, result[2]);
                ASSERT_EQ(1ULL, result[3]);

                poly[0] = 1;
                poly[1] = 2;
                poly[2] = 3;
                poly[3] = 4;
                negacyclic_shift_poly_coeffmod(poly, 2, 1, mod, result);
                negacyclic_shift_poly_coeffmod(poly + 2, 2, 1, mod, result + 2);
                ASSERT_EQ(8ULL, result[0]);
                ASSERT_EQ(1ULL, result[1]);
                ASSERT_EQ(6ULL, result[2]);
                ASSERT_EQ(3ULL, result[3]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(poly, 4, 2, pool);
                SEAL_ALLOCATE_ZERO_GET_RNS_ITER(result, 4, 2, pool);

                vector<Modulus> mod{ 10, 11 };

                poly[0][0] = 1;
                poly[0][1] = 2;
                poly[0][2] = 3;
                poly[0][3] = 4;
                poly[1][0] = 1;
                poly[1][1] = 2;
                poly[1][2] = 3;
                poly[1][3] = 4;

                negacyclic_shift_poly_coeffmod(poly, 2, 0, mod, result);
                ASSERT_EQ(1ULL, result[0][0]);
                ASSERT_EQ(2ULL, result[0][1]);
                ASSERT_EQ(3ULL, result[0][2]);
                ASSERT_EQ(4ULL, result[0][3]);
                ASSERT_EQ(1ULL, result[1][0]);
                ASSERT_EQ(2ULL, result[1][1]);
                ASSERT_EQ(3ULL, result[1][2]);
                ASSERT_EQ(4ULL, result[1][3]);

                negacyclic_shift_poly_coeffmod(poly, 2, 1, mod, result);
                ASSERT_EQ(6ULL, result[0][0]);
                ASSERT_EQ(1ULL, result[0][1]);
                ASSERT_EQ(2ULL, result[0][2]);
                ASSERT_EQ(3ULL, result[0][3]);
                ASSERT_EQ(7ULL, result[1][0]);
                ASSERT_EQ(1ULL, result[1][1]);
                ASSERT_EQ(2ULL, result[1][2]);
                ASSERT_EQ(3ULL, result[1][3]);

                negacyclic_shift_poly_coeffmod(poly, 2, 2, mod, result);
                ASSERT_EQ(7ULL, result[0][0]);
                ASSERT_EQ(6ULL, result[0][1]);
                ASSERT_EQ(1ULL, result[0][2]);
                ASSERT_EQ(2ULL, result[0][3]);
                ASSERT_EQ(8ULL, result[1][0]);
                ASSERT_EQ(7ULL, result[1][1]);
                ASSERT_EQ(1ULL, result[1][2]);
                ASSERT_EQ(2ULL, result[1][3]);

                negacyclic_shift_poly_coeffmod(poly, 2, 3, mod, result);
                ASSERT_EQ(8ULL, result[0][0]);
                ASSERT_EQ(7ULL, result[0][1]);
                ASSERT_EQ(6ULL, result[0][2]);
                ASSERT_EQ(1ULL, result[0][3]);
                ASSERT_EQ(9ULL, result[1][0]);
                ASSERT_EQ(8ULL, result[1][1]);
                ASSERT_EQ(7ULL, result[1][2]);
                ASSERT_EQ(1ULL, result[1][3]);
            }
            {
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(poly, 2, 4, 2, pool);
                SEAL_ALLOCATE_ZERO_GET_POLY_ITER(result, 2, 4, 2, pool);

                vector<Modulus> mod{ 10, 11 };

                poly[0][0][0] = 1;
                poly[0][0][1] = 2;
                poly[0][0][2] = 3;
                poly[0][0][3] = 4;
                poly[0][1][0] = 1;
                poly[0][1][1] = 2;
                poly[0][1][2] = 3;
                poly[0][1][3] = 4;

                poly[1][0][0] = 1;
                poly[1][0][1] = 2;
                poly[1][0][2] = 3;
                poly[1][0][3] = 4;
                poly[1][1][0] = 1;
                poly[1][1][1] = 2;
                poly[1][1][2] = 3;
                poly[1][1][3] = 4;

                negacyclic_shift_poly_coeffmod(poly, 2, 0, mod, result);
                ASSERT_EQ(1ULL, result[0][0][0]);
                ASSERT_EQ(2ULL, result[0][0][1]);
                ASSERT_EQ(3ULL, result[0][0][2]);
                ASSERT_EQ(4ULL, result[0][0][3]);
                ASSERT_EQ(1ULL, result[0][1][0]);
                ASSERT_EQ(2ULL, result[0][1][1]);
                ASSERT_EQ(3ULL, result[0][1][2]);
                ASSERT_EQ(4ULL, result[0][1][3]);

                ASSERT_EQ(1ULL, result[1][0][0]);
                ASSERT_EQ(2ULL, result[1][0][1]);
                ASSERT_EQ(3ULL, result[1][0][2]);
                ASSERT_EQ(4ULL, result[1][0][3]);
                ASSERT_EQ(1ULL, result[1][1][0]);
                ASSERT_EQ(2ULL, result[1][1][1]);
                ASSERT_EQ(3ULL, result[1][1][2]);
                ASSERT_EQ(4ULL, result[1][1][3]);

                negacyclic_shift_poly_coeffmod(poly, 2, 1, mod, result);
                ASSERT_EQ(6ULL, result[0][0][0]);
                ASSERT_EQ(1ULL, result[0][0][1]);
                ASSERT_EQ(2ULL, result[0][0][2]);
                ASSERT_EQ(3ULL, result[0][0][3]);
                ASSERT_EQ(7ULL, result[0][1][0]);
                ASSERT_EQ(1ULL, result[0][1][1]);
                ASSERT_EQ(2ULL, result[0][1][2]);
                ASSERT_EQ(3ULL, result[0][1][3]);

                ASSERT_EQ(6ULL, result[1][0][0]);
                ASSERT_EQ(1ULL, result[1][0][1]);
                ASSERT_EQ(2ULL, result[1][0][2]);
                ASSERT_EQ(3ULL, result[1][0][3]);
                ASSERT_EQ(7ULL, result[1][1][0]);
                ASSERT_EQ(1ULL, result[1][1][1]);
                ASSERT_EQ(2ULL, result[1][1][2]);
                ASSERT_EQ(3ULL, result[1][1][3]);

                negacyclic_shift_poly_coeffmod(poly, 2, 2, mod, result);
                ASSERT_EQ(7ULL, result[0][0][0]);
                ASSERT_EQ(6ULL, result[0][0][1]);
                ASSERT_EQ(1ULL, result[0][0][2]);
                ASSERT_EQ(2ULL, result[0][0][3]);
                ASSERT_EQ(8ULL, result[0][1][0]);
                ASSERT_EQ(7ULL, result[0][1][1]);
                ASSERT_EQ(1ULL, result[0][1][2]);
                ASSERT_EQ(2ULL, result[0][1][3]);

                ASSERT_EQ(7ULL, result[1][0][0]);
                ASSERT_EQ(6ULL, result[1][0][1]);
                ASSERT_EQ(1ULL, result[1][0][2]);
                ASSERT_EQ(2ULL, result[1][0][3]);
                ASSERT_EQ(8ULL, result[1][1][0]);
                ASSERT_EQ(7ULL, result[1][1][1]);
                ASSERT_EQ(1ULL, result[1][1][2]);
                ASSERT_EQ(2ULL, result[1][1][3]);

                negacyclic_shift_poly_coeffmod(poly, 2, 3, mod, result);
                ASSERT_EQ(8ULL, result[0][0][0]);
                ASSERT_EQ(7ULL, result[0][0][1]);
                ASSERT_EQ(6ULL, result[0][0][2]);
                ASSERT_EQ(1ULL, result[0][0][3]);
                ASSERT_EQ(9ULL, result[0][1][0]);
                ASSERT_EQ(8ULL, result[0][1][1]);
                ASSERT_EQ(7ULL, result[0][1][2]);
                ASSERT_EQ(1ULL, result[0][1][3]);

                ASSERT_EQ(8ULL, result[1][0][0]);
                ASSERT_EQ(7ULL, result[1][0][1]);
                ASSERT_EQ(6ULL, result[1][0][2]);
                ASSERT_EQ(1ULL, result[1][0][3]);
                ASSERT_EQ(9ULL, result[1][1][0]);
                ASSERT_EQ(8ULL, result[1][1][1]);
                ASSERT_EQ(7ULL, result[1][1][2]);
                ASSERT_EQ(1ULL, result[1][1][3]);
            }
        }

        namespace
        {
            vector<Modulus> kernel_test_moduli()
            {
                return { Modulus(2),
                         Modulus(3),
                         Modulus(4),
                         Modulus(65537),
                         Modulus(uint64_t(1) << 32),
                         Modulus(0xffffffffffc0001ULL),
                         Modulus(0x1fffffffffe00001ULL),
                         Modulus((uint64_t(1) << 61) - 1) };
            }

            const vector<size_t> kernel_test_sizes{ 1, 2, 7, 64, 1001 };

            // Bound on the operands that may be lazily reduced (zero for none); Intel HEXL requires them to be less
            // than 4 * modulus
            uint64_t lazy_operand_bound(const Modulus &modulus)
            {
#ifdef SEAL_USE_INTEL_HEXL
                return modulus.value() << 2;
#else
                (void)modulus;
                return 0;
#endif
            }

            // Extreme and random values less than bound (any 64-bit values if bound is zero)
            vector<uint64_t> kernel_test_operand(size_t n, uint64_t bound, mt19937_64 &rng)
            {
                vector<uint64_t> values(n);
                for (size_t i = 0; i < n; i++)
                {
                    uint64_t x = (i % 4 == 0) ? ~uint64_t(0) : (i % 4 == 1 ? 0 : rng());
                    values[i] = bound ? (i % 4 == 0 ? bound - 1 : x % bound) : x;
                }
                return values;
            }

            // x * y mod modulus; barrett_reduce_128 is checked in UIntArithSmallMod.BarrettReduce128Random
            uint64_t reference_multiply_mod(uint64_t x, uint64_t y, const Modulus &modulus)
            {
                unsigned long long z[2];
                multiply_uint64(x, y, z);
                return barrett_reduce_128(z, modulus);
            }
        } // namespace

        TEST(PolyArithSmallMod, ModuloPolyCoeffsRandom)
        {
            mt19937_64 rng(31337);
            for (const Modulus &modulus : kernel_test_moduli())
            {
                for (size_t n : kernel_test_sizes)
                {
                    vector<uint64_t> a = kernel_test_operand(n, 0, rng), out(n);
                    modulo_poly_coeffs(a.data(), n, modulus, out.data());
                    for (size_t i = 0; i < n; i++)
                    {
                        ASSERT_EQ(a[i] % modulus.value(), out[i]);
                    }
                    modulo_poly_coeffs(a.data(), n, modulus, a.data());
                    ASSERT_EQ(out, a);
                }
            }
        }

        TEST(PolyArithSmallMod, AddSubPolyScalarCoeffModRandom)
        {
            mt19937_64 rng(31339);
            for (const Modulus &modulus : kernel_test_moduli())
            {
                uint64_t p = modulus.value();
                for (size_t n : kernel_test_sizes)
                {
                    vector<uint64_t> a = kernel_test_operand(n, p, rng), sum(n), diff(n);
                    for (uint64_t scalar : { uint64_t(0), uint64_t(1), p - 1, uint64_t(rng()) % p })
                    {
                        add_poly_scalar_coeffmod(a.data(), n, scalar, modulus, sum.data());
                        sub_poly_scalar_coeffmod(a.data(), n, scalar, modulus, diff.data());
                        for (size_t i = 0; i < n; i++)
                        {
                            ASSERT_EQ((a[i] + scalar) % p, sum[i]);
                            ASSERT_EQ((a[i] + p - scalar) % p, diff[i]);
                        }
                        vector<uint64_t> in_place = a;
                        add_poly_scalar_coeffmod(in_place.data(), n, scalar, modulus, in_place.data());
                        ASSERT_EQ(sum, in_place);
                        in_place = a;
                        sub_poly_scalar_coeffmod(in_place.data(), n, scalar, modulus, in_place.data());
                        ASSERT_EQ(diff, in_place);
                    }
                }
            }
        }

        TEST(PolyArithSmallMod, MultiplyPolyScalarCoeffModRandom)
        {
            mt19937_64 rng(31338);
            for (const Modulus &modulus : kernel_test_moduli())
            {
                uint64_t p = modulus.value();
                for (size_t n : kernel_test_sizes)
                {
                    vector<uint64_t> a = kernel_test_operand(n, lazy_operand_bound(modulus), rng), out(n);
                    for (uint64_t scalar : { uint64_t(0), uint64_t(1), p - 1, ~uint64_t(0), uint64_t(rng()) })
                    {
                        multiply_poly_scalar_coeffmod(a.data(), n, scalar, modulus, out.data());
                        for (size_t i = 0; i < n; i++)
                        {
                            ASSERT_EQ(reference_multiply_mod(a[i], scalar % p, modulus), out[i]);
                        }
                        vector<uint64_t> in_place = a;
                        multiply_poly_scalar_coeffmod(in_place.data(), n, scalar, modulus, in_place.data());
                        ASSERT_EQ(out, in_place);
                    }
                }
            }
        }

        TEST(PolyArithSmallMod, DyadicProductCoeffModRandom)
        {
            mt19937_64 rng(31339);
            for (const Modulus &modulus : kernel_test_moduli())
            {
                for (size_t n : kernel_test_sizes)
                {
                    vector<uint64_t> a = kernel_test_operand(n, lazy_operand_bound(modulus), rng);
                    vector<uint64_t> b = kernel_test_operand(n, lazy_operand_bound(modulus), rng);
                    vector<uint64_t> ref(n), out(n);
                    for (size_t i = 0; i < n; i++)
                    {
                        ref[i] = reference_multiply_mod(a[i], b[i], modulus);
                    }
                    dyadic_product_coeffmod(a.data(), b.data(), n, modulus, out.data());
                    ASSERT_EQ(ref, out);

                    // The result may alias either operand
                    out = a;
                    dyadic_product_coeffmod(out.data(), b.data(), n, modulus, out.data());
                    ASSERT_EQ(ref, out);
                    out = b;
                    dyadic_product_coeffmod(a.data(), out.data(), n, modulus, out.data());
                    ASSERT_EQ(ref, out);
                }
            }
        }

        TEST(PolyArithSmallMod, DyadicProductAddCoeffMod)
        {
            mt19937_64 rng(31340);
            for (const Modulus &modulus : kernel_test_moduli())
            {
                uint64_t p = modulus.value();
                for (size_t n : kernel_test_sizes)
                {
                    vector<uint64_t> a = kernel_test_operand(n, lazy_operand_bound(modulus), rng);
                    vector<uint64_t> b = kernel_test_operand(n, p, rng);
                    vector<uint64_t> c = kernel_test_operand(n, p, rng);
                    vector<uint64_t> ref(n), out(n);
                    for (size_t i = 0; i < n; i++)
                    {
                        ref[i] = (reference_multiply_mod(a[i], b[i], modulus) + c[i]) % p;
                    }
                    dyadic_product_add_coeffmod(a.data(), b.data(), c.data(), n, modulus, out.data());
                    ASSERT_EQ(ref, out);

                    // The result may alias operand1 or operand2
                    out = a;
                    dyadic_product_add_coeffmod(out.data(), b.data(), c.data(), n, modulus, out.data());
                    ASSERT_EQ(ref, out);
                    out = b;
                    dyadic_product_add_coeffmod(a.data(), out.data(), c.data(), n, modulus, out.data());
                    ASSERT_EQ(ref, out);
                }
            }
#ifdef SEAL_DEBUG
            // operand2 and addend must be reduced
            Modulus modulus(65537);
            vector<uint64_t> a{ 1, 2 }, b{ 3, 4 }, c{ 5, 6 }, out(2);
            ASSERT_NO_THROW(dyadic_product_add_coeffmod(a.data(), b.data(), c.data(), 2, modulus, out.data()));
            b[1] = modulus.value();
            ASSERT_THROW(
                dyadic_product_add_coeffmod(a.data(), b.data(), c.data(), 2, modulus, out.data()), invalid_argument);
            b[1] = 4;
            c[0] = modulus.value();
            ASSERT_THROW(
                dyadic_product_add_coeffmod(a.data(), b.data(), c.data(), 2, modulus, out.data()), invalid_argument);
#endif
        }

        TEST(PolyArithSmallMod, DyadicProductSharedCoeffMod)
        {
            mt19937_64 rng(31341);
            for (const Modulus &modulus : kernel_test_moduli())
            {
                uint64_t p = modulus.value();
                for (size_t n : kernel_test_sizes)
                {
                    vector<uint64_t> a1 = kernel_test_operand(n, lazy_operand_bound(modulus), rng);
                    vector<uint64_t> a2 = kernel_test_operand(n, lazy_operand_bound(modulus), rng);
                    vector<uint64_t> b = kernel_test_operand(n, p, rng);
                    vector<uint64_t> ref1(n), ref2(n), out1(n), out2(n);
                    for (size_t i = 0; i < n; i++)
                    {
                        ref1[i] = reference_multiply_mod(a1[i], b[i], modulus);
                        ref2[i] = reference_multiply_mod(a2[i], b[i], modulus);
                    }
                    dyadic_product_shared_coeffmod(
                        a1.data(), a2.data(), b.data(), n, modulus, out1.data(), out2.data());
                    ASSERT_EQ(ref1, out1);
                    ASSERT_EQ(ref2, out2);

                    // result1 may alias operand1, and result2 operand2
                    out1 = a1;
                    out2 = a2;
                    dyadic_product_shared_coeffmod(
                        out1.data(), out2.data(), b.data(), n, modulus, out1.data(), out2.data());
                    ASSERT_EQ(ref1, out1);
                    ASSERT_EQ(ref2, out2);
                }
            }
#ifdef SEAL_DEBUG
            // shared must be reduced
            Modulus modulus(65537);
            vector<uint64_t> a1{ 1, 2 }, a2{ 3, 4 }, b{ 5, modulus.value() }, out1(2), out2(2);
            ASSERT_THROW(
                dyadic_product_shared_coeffmod(a1.data(), a2.data(), b.data(), 2, modulus, out1.data(), out2.data()),
                invalid_argument);
#endif
        }
    } // namespace util
} // namespace sealtest
