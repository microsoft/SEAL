// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/modulus.h"
#include "seal/util/ntt.h"
#include "seal/util/numth.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
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
        TEST(NTTTablesTest, NTTBasics)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            Pointer<NTTTables> tables;
            int coeff_count_power = 1;
            Modulus modulus(get_prime(uint64_t(2) << coeff_count_power, 60));
            ASSERT_NO_THROW(tables = allocate<NTTTables>(pool, coeff_count_power, modulus, pool));
            ASSERT_EQ(2ULL, tables->coeff_count());
            ASSERT_EQ(1, tables->coeff_count_power());

            coeff_count_power = 2;
            modulus = get_prime(uint64_t(2) << coeff_count_power, 50);
            ASSERT_NO_THROW(tables = allocate<NTTTables>(pool, coeff_count_power, modulus, pool));
            ASSERT_EQ(4ULL, tables->coeff_count());
            ASSERT_EQ(2, tables->coeff_count_power());

            coeff_count_power = 10;
            modulus = get_prime(uint64_t(2) << coeff_count_power, 40);
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

        TEST(NTTTablesTest, InvalidCoeffCountPower)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            Pointer<NTTTables> tables;

            // The modulus supports NTT sizes up to 2 * SEAL_POLY_MOD_DEGREE_MAX
            int max_power = get_power_of_two(SEAL_POLY_MOD_DEGREE_MAX);
            Modulus modulus(get_prime(uint64_t(2) << (max_power + 1), 60));
            for (int coeff_count_power : { -1, 0, max_power + 1 })
            {
                ASSERT_THROW(tables = allocate<NTTTables>(pool, coeff_count_power, modulus, pool), invalid_argument);
                ASSERT_THROW(CreateNTTTables(coeff_count_power, { modulus }, tables, pool), invalid_argument);
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

        namespace
        {
            // The smallest NTT-friendly prime and the largest ones of several bit sizes
            vector<Modulus> ntt_test_moduli(int log_n)
            {
                const uint64_t factor = uint64_t(2) << log_n;
                vector<Modulus> moduli;
                for (uint64_t value = factor + 1;; value += factor)
                {
                    if (is_prime(Modulus(value)))
                    {
                        moduli.emplace_back(value);
                        break;
                    }
                }

                vector<int> bit_sizes;
                if (log_n <= 10)
                {
                    for (int bits = moduli[0].bit_count() + 1; bits <= SEAL_MOD_BIT_COUNT_MAX; bits++)
                    {
                        bit_sizes.push_back(bits);
                    }
                }
                else if (log_n <= 14)
                {
                    bit_sizes = { 30, 45, 50, 55, 59, 60, 61 };
                }
                else
                {
                    bit_sizes = { 49, 61 };
                }

                for (int bits : bit_sizes)
                {
                    try
                    {
                        moduli.push_back(get_prime(factor, bits));
                    }
                    catch (const logic_error &)
                    {
                        // No NTT-friendly prime of this size
                    }
                }
                return moduli;
            }

            void fill_ntt_input(vector<uint64_t> &values, int pattern, uint64_t bound, mt19937_64 &rng)
            {
                for (size_t i = 0; i < values.size(); i++)
                {
                    switch (pattern)
                    {
                    case 0:
                        values[i] = 0;
                        break;
                    case 1:
                        values[i] = bound - 1;
                        break;
                    case 2:
                        values[i] = (i & 1) ? bound - 1 : 0;
                        break;
                    default:
                        values[i] = rng() % bound;
                        break;
                    }
                }
            }

            vector<uint64_t> reference_ntt(vector<uint64_t> values, const NTTTables &tables, bool full_reduce)
            {
                tables.ntt_handler().transform_to_rev(
                    values.data(), tables.coeff_count_power(), tables.get_from_root_powers());
                if (full_reduce)
                {
                    for (auto &x : values)
                    {
                        x %= tables.modulus().value();
                    }
                }
                return values;
            }

            vector<uint64_t> reference_inverse_ntt(vector<uint64_t> values, const NTTTables &tables, bool full_reduce)
            {
                MultiplyUIntModOperand inv_n = tables.inv_degree_modulo();
                tables.ntt_handler().transform_from_rev(
                    values.data(), tables.coeff_count_power(), tables.get_from_inv_root_powers(), &inv_n);
                if (full_reduce)
                {
                    for (auto &x : values)
                    {
                        x %= tables.modulus().value();
                    }
                }
                return values;
            }
        } // namespace

        // Without Intel HEXL, the lazy outputs must be identical to the reference, not just congruent
        TEST(NTTTablesTest, NTTKernelsMatchReference)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            mt19937_64 rng(12345);
            for (int log_n = 1; log_n <= get_power_of_two(SEAL_POLY_MOD_DEGREE_MAX); log_n++)
            {
                size_t n = size_t(1) << log_n;
                vector<int> patterns = log_n <= 14 ? vector<int>{ 0, 1, 2, 3 } : vector<int>{ 1, 3 };
                for (const Modulus &modulus : ntt_test_moduli(log_n))
                {
                    uint64_t p = modulus.value();
                    NTTTables tables(log_n, modulus, pool);
                    vector<uint64_t> in(n), out(n);
                    for (int pattern : patterns)
                    {
                        // Forward, inputs in [0, 4p)
                        fill_ntt_input(in, pattern, 4 * p, rng);
                        out = in;
                        ntt_negacyclic_harvey_lazy(out.data(), tables);
#ifndef SEAL_USE_INTEL_HEXL
                        ASSERT_EQ(reference_ntt(in, tables, false), out) << "log_n " << log_n << ", p " << p;
#endif

                        out = in;
                        ntt_negacyclic_harvey(out.data(), tables);
                        ASSERT_EQ(reference_ntt(in, tables, true), out) << "log_n " << log_n << ", p " << p;

                        // Inverse, inputs in [0, 2p)
                        fill_ntt_input(in, pattern, 2 * p, rng);
                        out = in;
                        inverse_ntt_negacyclic_harvey_lazy(out.data(), tables);
#ifndef SEAL_USE_INTEL_HEXL
                        ASSERT_EQ(reference_inverse_ntt(in, tables, false), out) << "log_n " << log_n << ", p " << p;
#endif

                        out = in;
                        inverse_ntt_negacyclic_harvey(out.data(), tables);
                        ASSERT_EQ(reference_inverse_ntt(in, tables, true), out) << "log_n " << log_n << ", p " << p;
                    }
                }
            }
        }

        // Also with operand equal to result
        TEST(NTTTablesTest, OutOfPlaceNTTVariants)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            mt19937_64 rng(999);
            for (int log_n = 1; log_n <= get_power_of_two(SEAL_POLY_MOD_DEGREE_MAX); log_n++)
            {
                size_t n = size_t(1) << log_n;
                vector<Modulus> moduli = ntt_test_moduli(log_n);
                if (log_n <= 10)
                {
                    vector<Modulus> subset;
                    for (size_t i = 0; i < moduli.size(); i += 4)
                    {
                        subset.push_back(moduli[i]);
                    }
                    subset.push_back(moduli.back());
                    moduli = subset;
                }
                for (const Modulus &modulus : moduli)
                {
                    uint64_t p = modulus.value();
                    NTTTables tables(log_n, modulus, pool);
                    vector<uint64_t> in(n), in_copy(n), out(n), ref(n);

                    // Forward, input in [0, 4p)
                    fill_ntt_input(in, 3, 4 * p, rng);
                    in[0] = 4 * p - 1;
                    in_copy = in;

                    ref = reference_ntt(in, tables, false);
                    ntt_negacyclic_harvey_lazy(ConstCoeffIter(in.data()), tables, CoeffIter(out.data()));
                    ASSERT_EQ(in_copy, in);
#ifndef SEAL_USE_INTEL_HEXL
                    ASSERT_EQ(ref, out) << "log_n " << log_n << ", p " << p;
#endif

                    ref = reference_ntt(in, tables, true);
                    modulo_poly_coeffs(out.data(), n, modulus, out.data());
                    ASSERT_EQ(ref, out);

                    out = in;
                    ntt_negacyclic_harvey_lazy(ConstCoeffIter(out.data()), tables, false, CoeffIter(out.data()));
                    modulo_poly_coeffs(out.data(), n, modulus, out.data());
                    ASSERT_EQ(ref, out);

                    // Forward, any 64-bit input
                    for (auto &x : in)
                    {
                        x = rng();
                    }
                    in[0] = ~uint64_t(0);
                    in[n - 1] = p;
                    in_copy = in;

                    modulo_poly_coeffs(in.data(), n, modulus, ref.data());
                    ref = reference_ntt(ref, tables, false);
                    ntt_negacyclic_harvey_lazy(ConstCoeffIter(in.data()), tables, true, CoeffIter(out.data()));
                    ASSERT_EQ(in_copy, in);
#ifndef SEAL_USE_INTEL_HEXL
                    ASSERT_EQ(ref, out) << "log_n " << log_n << ", p " << p;
#endif

                    ntt_negacyclic_harvey_lazy(ConstCoeffIter(in.data()), tables, true, CoeffIter(in.data()));
                    ASSERT_EQ(out, in);

                    modulo_poly_coeffs(ref.data(), n, modulus, ref.data());
                    modulo_poly_coeffs(out.data(), n, modulus, out.data());
                    ASSERT_EQ(ref, out);

                    // Inverse, input in [0, 2p)
                    fill_ntt_input(in, 3, 2 * p, rng);
                    in[n - 1] = 2 * p - 1;
                    in_copy = in;

                    ref = reference_inverse_ntt(in, tables, true);
                    inverse_ntt_negacyclic_harvey(ConstCoeffIter(in.data()), tables, CoeffIter(out.data()));
                    ASSERT_EQ(in_copy, in);
                    ASSERT_EQ(ref, out) << "log_n " << log_n << ", p " << p;

                    out = in;
                    inverse_ntt_negacyclic_harvey(ConstCoeffIter(out.data()), tables, CoeffIter(out.data()));
                    ASSERT_EQ(ref, out);

                    // Scaled inverse
                    for (uint64_t scalar : { uint64_t(0), uint64_t(1), uint64_t(2), p - 1, p, p + 1, ~uint64_t(0),
                                             static_cast<uint64_t>(rng()) })
                    {
                        vector<uint64_t> scaled_ref = ref;
                        multiply_poly_scalar_coeffmod(scaled_ref.data(), n, scalar, modulus, scaled_ref.data());

                        inverse_ntt_negacyclic_harvey_scaled(
                            ConstCoeffIter(in.data()), scalar, tables, CoeffIter(out.data()));
                        ASSERT_EQ(in_copy, in);
                        ASSERT_EQ(scaled_ref, out) << "log_n " << log_n << ", p " << p << ", scalar " << scalar;

                        out = in;
                        inverse_ntt_negacyclic_harvey_scaled(
                            ConstCoeffIter(out.data()), scalar, tables, CoeffIter(out.data()));
                        ASSERT_EQ(scaled_ref, out);
                    }
                }
            }
        }

        TEST(NTTTablesTest, OutOfPlaceNTTRNS)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            mt19937_64 rng(1234);
            int log_n = 6;
            size_t n = size_t(1) << log_n;
            vector<Modulus> moduli = get_primes(uint64_t(2) << log_n, 40, 3);
            Pointer<NTTTables> tables;
            CreateNTTTables(log_n, moduli, tables, pool);
            vector<uint64_t> in(3 * n), ref(3 * n), out(3 * n);
            for (size_t i = 0; i < 3; i++)
            {
                for (size_t c = 0; c < n; c++)
                {
                    in[i * n + c] = rng() % (4 * moduli[i].value());
                }
            }
            vector<uint64_t> in_copy = in;

            ref = in;
            ntt_negacyclic_harvey_lazy(RNSIter(ref.data(), n), 3, tables.get());
            ntt_negacyclic_harvey_lazy(ConstRNSIter(in.data(), n), 3, tables.get(), RNSIter(out.data(), n));
            ASSERT_EQ(in_copy, in);
            ASSERT_EQ(ref, out);

            ntt_negacyclic_harvey_lazy(ConstRNSIter(in.data(), n), 3, tables.get(), RNSIter(in.data(), n));
            ASSERT_EQ(ref, in);
        }

        TEST(NTTTablesTest, OutOfPlaceInverseNTTRNS)
        {
            MemoryPoolHandle pool = MemoryPoolHandle::Global();
            mt19937_64 rng(4321);
            int log_n = 6;
            size_t n = size_t(1) << log_n;
            vector<Modulus> moduli = get_primes(uint64_t(2) << log_n, 40, 3);
            Pointer<NTTTables> tables;
            CreateNTTTables(log_n, moduli, tables, pool);
            vector<uint64_t> in(3 * n), ref(3 * n), out(3 * n);
            for (size_t i = 0; i < 3; i++)
            {
                for (size_t c = 0; c < n; c++)
                {
                    in[i * n + c] = rng() % (2 * moduli[i].value());
                }
            }

            ref = in;
            inverse_ntt_negacyclic_harvey(RNSIter(ref.data(), n), 3, tables.get());
            inverse_ntt_negacyclic_harvey(ConstRNSIter(in.data(), n), 3, tables.get(), RNSIter(out.data(), n));
            ASSERT_EQ(ref, out);
        }
    } // namespace util
} // namespace sealtest
