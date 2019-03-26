// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/uintcore.h"
#include "seal/util/polycore.h"
#include "seal/util/polyarithsmallmod.h"
#include <cstdint>
#include <cstddef>

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
   namespace util
   {
        TEST(PolyArithSmallMod, SmallModuloPolyCoeffs)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly(allocate_zero_poly(3, 1, pool));
            auto modulus(allocate_uint(2, pool));
            poly[0] = 2;
            poly[1] = 15;
            poly[2] = 77;
            SmallModulus mod(15);
            modulo_poly_coeffs(poly.get(), 3, mod, poly.get());
            ASSERT_EQ(2ULL, poly[0]);
            ASSERT_EQ(0ULL, poly[1]);
            ASSERT_EQ(2ULL, poly[2]);
        }

        TEST(PolyArithSmallMod, NegatePolyCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly(allocate_zero_poly(3, 1, pool));
            poly[0] = 2;
            poly[1] = 3;
            poly[2] = 4;
            SmallModulus mod(15);
            negate_poly_coeffmod(poly.get(), 3, mod, poly.get());
            ASSERT_EQ(static_cast<uint64_t>(13), poly[0]);
            ASSERT_EQ(static_cast<uint64_t>(12), poly[1]);
            ASSERT_EQ(static_cast<uint64_t>(11), poly[2]);

            poly[0] = 2;
            poly[1] = 3;
            poly[2] = 4;
            mod = 0xFFFFFFFFFFFFFFULL;
            negate_poly_coeffmod(poly.get(), 3, mod, poly.get());
            ASSERT_EQ(0xFFFFFFFFFFFFFDULL, poly[0]);
            ASSERT_EQ(0xFFFFFFFFFFFFFCULL, poly[1]);
            ASSERT_EQ(0xFFFFFFFFFFFFFBULL, poly[2]);
        }

        TEST(PolyArithSmallMod, AddPolyPolyCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly1(allocate_zero_poly(3, 1, pool));
            auto poly2(allocate_zero_poly(3, 1, pool));
            poly1[0] = 1;
            poly1[1] = 3;
            poly1[2] = 4;
            poly2[0] = 1;
            poly2[1] = 2;
            poly2[2] = 4;
            SmallModulus mod(5);
            add_poly_poly_coeffmod(poly1.get(), poly2.get(), 3, mod, poly1.get());
            ASSERT_EQ(2ULL, poly1[0]);
            ASSERT_EQ(0ULL, poly1[1]);
            ASSERT_EQ(3ULL, poly1[2]);
        }

        TEST(PolyArithSmallMod, SubPolyPolyCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly1(allocate_zero_poly(3, 1, pool));
            auto poly2(allocate_zero_poly(3, 1, pool));
            poly1[0] = 4;
            poly1[1] = 3;
            poly1[2] = 2;
            poly2[0] = 2;
            poly2[1] = 3;
            poly2[2] = 4;
            SmallModulus mod(5);
            sub_poly_poly_coeffmod(poly1.get(), poly2.get(), 3, mod, poly1.get());
            ASSERT_EQ(2ULL, poly1[0]);
            ASSERT_EQ(0ULL, poly1[1]);
            ASSERT_EQ(3ULL, poly1[2]);
        }

        TEST(PolyArithSmallMod, MultiplyPolyScalarCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly(allocate_zero_poly(3, 1, pool));
            poly[0] = 1;
            poly[1] = 3;
            poly[2] = 4;
            uint64_t scalar = 3;
            SmallModulus mod(5);
            multiply_poly_scalar_coeffmod(poly.get(), 3, scalar, mod, poly.get());
            ASSERT_EQ(3ULL, poly[0]);
            ASSERT_EQ(4ULL, poly[1]);
            ASSERT_EQ(2ULL, poly[2]);
        }

        TEST(PolyArithSmallMod, MultiplyPolyMonoCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly1(allocate_zero_poly(4, 1, pool));
            poly1[0] = 1;
            poly1[1] = 3;
            poly1[2] = 4;
            poly1[3] = 2;
            uint64_t mono_coeff = 3;
            auto result(allocate_zero_poly(4, 1, pool));
            SmallModulus mod(5);

            size_t mono_exponent = 0;
            negacyclic_multiply_poly_mono_coeffmod(poly1.get(), 1, mono_coeff, mono_exponent, mod, result.get(), pool);
            ASSERT_EQ(3ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            negacyclic_multiply_poly_mono_coeffmod(poly1.get(), 2, mono_coeff, mono_exponent, mod, result.get(), pool);
            ASSERT_EQ(3ULL, result[0]);
            ASSERT_EQ(4ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            mono_exponent = 1;
            negacyclic_multiply_poly_mono_coeffmod(poly1.get(), 2, mono_coeff, mono_exponent, mod, result.get(), pool);
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(3ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            negacyclic_multiply_poly_mono_coeffmod(poly1.get(), 4, mono_coeff, mono_exponent, mod, result.get(), pool);
            ASSERT_EQ(4ULL, result[0]);
            ASSERT_EQ(3ULL, result[1]);
            ASSERT_EQ(4ULL, result[2]);
            ASSERT_EQ(2ULL, result[3]);

            mono_coeff = 1;
            negacyclic_multiply_poly_mono_coeffmod(poly1.get(), 4, mono_coeff, mono_exponent, mod, result.get(), pool);
            ASSERT_EQ(3ULL, result[0]);
            ASSERT_EQ(1ULL, result[1]);
            ASSERT_EQ(3ULL, result[2]);
            ASSERT_EQ(4ULL, result[3]);

            mono_coeff = 4;
            mono_exponent = 3;
            negacyclic_multiply_poly_mono_coeffmod(poly1.get(), 4, mono_coeff, mono_exponent, mod, result.get(), pool);
            ASSERT_EQ(3ULL, result[0]);
            ASSERT_EQ(4ULL, result[1]);
            ASSERT_EQ(2ULL, result[2]);
            ASSERT_EQ(4ULL, result[3]);

            mono_coeff = 1;
            mono_exponent = 0;
            negacyclic_multiply_poly_mono_coeffmod(poly1.get(), 4, mono_coeff, mono_exponent, mod, result.get(), pool);
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(3ULL, result[1]);
            ASSERT_EQ(4ULL, result[2]);
            ASSERT_EQ(2ULL, result[3]);
        }

        TEST(PolyArithSmallMod, MultiplyPolyPolyCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly1(allocate_zero_poly(3, 1, pool));
            auto poly2(allocate_zero_poly(3, 1, pool));
            auto result(allocate_zero_poly(5, 1, pool));
            poly1[0] = 1;
            poly1[1] = 2;
            poly1[2] = 3;
            poly2[0] = 2;
            poly2[1] = 3;
            poly2[2] = 4;
            SmallModulus mod(5);
            multiply_poly_poly_coeffmod(poly1.get(), 3, poly2.get(), 3, mod, 5, result.get());
            ASSERT_EQ(2ULL, result[0]);
            ASSERT_EQ(2ULL, result[1]);
            ASSERT_EQ(1ULL, result[2]);
            ASSERT_EQ(2ULL, result[3]);
            ASSERT_EQ(2ULL, result[4]);

            poly2[0] = 2;
            poly2[1] = 3;
            multiply_poly_poly_coeffmod(poly1.get(), 3, poly2.get(), 2, mod, 5, result.get());
            ASSERT_EQ(2ULL, result[0]);
            ASSERT_EQ(2ULL, result[1]);
            ASSERT_EQ(2ULL, result[2]);
            ASSERT_EQ(4ULL, result[3]);
            ASSERT_EQ(0ULL, result[4]);
        }

        TEST(PolyArithSmallMod, DividePolyPolyCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly1(allocate_zero_poly(5, 1, pool));
            auto poly2(allocate_zero_poly(5, 1, pool));
            auto result(allocate_zero_poly(5, 1, pool));
            auto quotient(allocate_zero_poly(5, 1, pool));
            SmallModulus mod(5);

            poly1[0] = 2;
            poly1[1] = 2;
            poly2[0] = 2;
            poly2[1] = 3;
            poly2[2] = 4;

            divide_poly_poly_coeffmod_inplace(poly1.get(), poly2.get(), 5, mod, result.get());
            ASSERT_EQ(2ULL, poly1[0]);
            ASSERT_EQ(2ULL, poly1[1]);
            ASSERT_EQ(0ULL, poly1[2]);
            ASSERT_EQ(0ULL, poly1[3]);
            ASSERT_EQ(0ULL, poly1[4]);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);
            ASSERT_EQ(0ULL, result[4]);

            poly1[0] = 2;
            poly1[1] = 2;
            poly1[2] = 1;
            poly1[3] = 2;
            poly1[4] = 2;
            poly2[0] = 4;
            poly2[1] = 3;
            poly2[2] = 2;

            divide_poly_poly_coeffmod(poly1.get(), poly2.get(), 5, mod, quotient.get(), result.get());
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);
            ASSERT_EQ(0ULL, result[4]);
            ASSERT_EQ(3ULL, quotient[0]);
            ASSERT_EQ(2ULL, quotient[1]);
            ASSERT_EQ(1ULL, quotient[2]);
            ASSERT_EQ(0ULL, quotient[3]);
            ASSERT_EQ(0ULL, quotient[4]);
        }

        TEST(PolyArithSmallMod, DyadicProductCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly1(allocate_zero_poly(3, 1, pool));
            auto poly2(allocate_zero_poly(3, 1, pool));
            auto result(allocate_zero_poly(3, 1, pool));
            SmallModulus mod(13);

            poly1[0] = 1;
            poly1[1] = 1;
            poly1[2] = 1;
            poly2[0] = 2;
            poly2[1] = 3;
            poly2[2] = 4;

            dyadic_product_coeffmod(poly1.get(), poly2.get(), 3, mod, result.get());
            ASSERT_EQ(2ULL, result[0]);
            ASSERT_EQ(3ULL, result[1]);
            ASSERT_EQ(4ULL, result[2]);

            poly1[0] = 0;
            poly1[1] = 0;
            poly1[2] = 0;
            poly2[0] = 2;
            poly2[1] = 3;
            poly2[2] = 4;

            dyadic_product_coeffmod(poly1.get(), poly2.get(), 3, mod, result.get());
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);

            poly1[0] = 3;
            poly1[1] = 5;
            poly1[2] = 8;
            poly2[0] = 2;
            poly2[1] = 3;
            poly2[2] = 4;

            dyadic_product_coeffmod(poly1.get(), poly2.get(), 3, mod, result.get());
            ASSERT_EQ(6ULL, result[0]);
            ASSERT_EQ(2ULL, result[1]);
            ASSERT_EQ(6ULL, result[2]);
        }

        TEST(PolyArithSmallMod, TryInvertPolyCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly(allocate_zero_poly(4, 1, pool));
            auto polymod(allocate_zero_poly(4, 1, pool));
            auto result(allocate_zero_poly(4, 1, pool));
            SmallModulus mod(5);

            polymod[0] = 4;
            polymod[1] = 3;
            polymod[2] = 0;
            polymod[3] = 2;

            ASSERT_FALSE(try_invert_poly_coeffmod(poly.get(), polymod.get(), 4, mod, result.get(), pool));

            poly[0] = 1;
            ASSERT_TRUE(try_invert_poly_coeffmod(poly.get(), polymod.get(), 4, mod, result.get(), pool));
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            poly[0] = 1;
            poly[1] = 2;
            poly[2] = 3;
            ASSERT_TRUE(try_invert_poly_coeffmod(poly.get(), polymod.get(), 4, mod, result.get(), pool));
            ASSERT_EQ(4ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(2ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);
        }

        TEST(PolyArithSmallMod, PolyInftyNormCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly(allocate_zero_poly(4, 1, pool));
            SmallModulus mod(10);

            poly[0] = 0;
            poly[1] = 1;
            poly[2] = 2;
            poly[3] = 3;
            ASSERT_EQ(0x3ULL, poly_infty_norm_coeffmod(poly.get(), 4, mod));

            poly[0] = 0;
            poly[1] = 1;
            poly[2] = 2;
            poly[3] = 8;
            ASSERT_EQ(0x2ULL, poly_infty_norm_coeffmod(poly.get(), 4, mod));
        }

        TEST(PolyArithSmallMod, NegacyclicShiftPolyCoeffSmallMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly(allocate_zero_poly(4, 1, pool));
            auto result(allocate_zero_poly(4, 1, pool));

            SmallModulus mod(10);
            size_t coeff_count = 4;

            negacyclic_shift_poly_coeffmod(poly.get(), coeff_count, 0, mod, result.get());
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);
            negacyclic_shift_poly_coeffmod(poly.get(), coeff_count, 1, mod, result.get());
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);
            negacyclic_shift_poly_coeffmod(poly.get(), coeff_count, 2, mod, result.get());
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);
            negacyclic_shift_poly_coeffmod(poly.get(), coeff_count, 3, mod, result.get());
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            poly[0] = 1;
            poly[1] = 2;
            poly[2] = 3;
            poly[3] = 4;
            negacyclic_shift_poly_coeffmod(poly.get(), coeff_count, 0, mod, result.get());
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(2ULL, result[1]);
            ASSERT_EQ(3ULL, result[2]);
            ASSERT_EQ(4ULL, result[3]);
            negacyclic_shift_poly_coeffmod(poly.get(), coeff_count, 1, mod, result.get());
            ASSERT_EQ(6ULL, result[0]);
            ASSERT_EQ(1ULL, result[1]);
            ASSERT_EQ(2ULL, result[2]);
            ASSERT_EQ(3ULL, result[3]);
            negacyclic_shift_poly_coeffmod(poly.get(), coeff_count, 2, mod, result.get());
            ASSERT_EQ(7ULL, result[0]);
            ASSERT_EQ(6ULL, result[1]);
            ASSERT_EQ(1ULL, result[2]);
            ASSERT_EQ(2ULL, result[3]);
            negacyclic_shift_poly_coeffmod(poly.get(), coeff_count, 3, mod, result.get());
            ASSERT_EQ(8ULL, result[0]);
            ASSERT_EQ(7ULL, result[1]);
            ASSERT_EQ(6ULL, result[2]);
            ASSERT_EQ(1ULL, result[3]);

            poly[0] = 1;
            poly[1] = 2;
            poly[2] = 3;
            poly[3] = 4;
            coeff_count = 2;
            negacyclic_shift_poly_coeffmod(poly.get(), coeff_count, 1, mod, result.get());
            negacyclic_shift_poly_coeffmod(poly.get() + 2, coeff_count, 1, mod, result.get() + 2);
            ASSERT_EQ(8ULL, result[0]);
            ASSERT_EQ(1ULL, result[1]);
            ASSERT_EQ(6ULL, result[2]);
            ASSERT_EQ(3ULL, result[3]);
        }
   }
}
