// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/defines.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/uintcore.h"
#include <cstddef>
#include <cstdint>
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
    } // namespace util
} // namespace sealtest
