// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ciphertext.h"
#include "seal/memorymanager.h"
#include "seal/util/iterator.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <type_traits>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(IteratorTest, IterType)
        {
            ASSERT_TRUE((is_same<decltype(iter(int(0))), SeqIter<int>>::value));
            ASSERT_TRUE((is_same<decltype(iter(size_t(0))), SeqIter<size_t>>::value));
            ASSERT_TRUE((is_same<decltype(iter(bool(true))), SeqIter<bool>>::value));
            ASSERT_TRUE((is_same<decltype(iter(double(0.0))), SeqIter<double>>::value));
            ASSERT_TRUE((is_same<decltype(iter(char(0))), SeqIter<char>>::value));
            ASSERT_TRUE((is_same<decltype(iter(uint64_t(0))), SeqIter<uint64_t>>::value));

            ASSERT_TRUE((is_same<decltype(iter(declval<Ciphertext &>())), PolyIter>::value));
            ASSERT_TRUE((is_same<decltype(iter(declval<const Ciphertext &>())), ConstPolyIter>::value));

            ASSERT_TRUE((is_same<decltype(iter(declval<int *>())), PtrIter<int *>>::value));
            ASSERT_TRUE((is_same<decltype(iter(declval<const int *>())), PtrIter<const int *>>::value));
            ASSERT_TRUE((is_same<decltype(iter(declval<void *>())), PtrIter<void *>>::value));
            ASSERT_TRUE((is_same<decltype(iter(declval<const void *>())), PtrIter<const void *>>::value));

            ASSERT_TRUE((is_same<decltype(iter(declval<vector<Ciphertext> &>())), PtrIter<Ciphertext *>>::value));
            ASSERT_TRUE(
                (is_same<decltype(iter(declval<const vector<Ciphertext> &>())), PtrIter<const Ciphertext *>>::value));

            ASSERT_TRUE((is_same<
                         decltype(iter(declval<int>(), declval<size_t>(), declval<Ciphertext &>())),
                         IterTuple<SeqIter<int>, SeqIter<size_t>, PolyIter>>::value));

            ASSERT_TRUE((is_same<decltype(iter(declval<PolyIter>())), PolyIter>::value));
            ASSERT_TRUE((is_same<decltype(iter(declval<RNSIter>())), RNSIter>::value));
            ASSERT_TRUE((is_same<decltype(iter(declval<CoeffIter>())), CoeffIter>::value));
            ASSERT_TRUE((is_same<decltype(iter(declval<PtrIter<int *>>())), PtrIter<int *>>::value));
            ASSERT_TRUE((is_same<decltype(iter(declval<SeqIter<int>>())), SeqIter<int>>::value));
            ASSERT_TRUE((is_same<decltype(iter(declval<ReverseIter<RNSIter>>())), ReverseIter<RNSIter>>::value));
            ASSERT_TRUE((is_same<
                         decltype(iter(declval<ReverseIter<ReverseIter<RNSIter>>>())),
                         ReverseIter<ReverseIter<RNSIter>>>::value));
            ASSERT_TRUE((is_same<
                         decltype(iter(declval<IterTuple<RNSIter, ReverseIter<RNSIter>>>())),
                         IterTuple<RNSIter, ReverseIter<RNSIter>>>::value));
        }

        TEST(IteratorTest, Iterate)
        {
            int calls, sum;

            calls = 0;
            sum = 0;
            SEAL_ITERATE(iter(0), 0, [&](auto I) {
                sum += I;
                calls++;
            });
            ASSERT_EQ(0, calls);
            ASSERT_EQ(0, sum);

            calls = 0;
            sum = 0;
            SEAL_ITERATE(iter(0), 1, [&](auto I) {
                sum += I;
                calls++;
            });
            ASSERT_EQ(1, calls);
            ASSERT_EQ(0, sum);

            calls = 0;
            sum = 0;
            SEAL_ITERATE(iter(0), 10, [&](auto I) {
                sum += I;
                calls++;
            });
            ASSERT_EQ(10, calls);
            ASSERT_EQ(45, sum);

            sum = 0;
            SEAL_ITERATE(iter(0, reverse_iter(0)), 10, [&](auto I) { sum += get<0>(I) + get<1>(I); });
        }

        TEST(IteratorTest, SeqIter)
        {
            // Construction
            SeqIter<int> s{};
            ASSERT_EQ(0, *s);
            s = 1;
            ASSERT_EQ(1, *s);
            s = -1;
            ASSERT_EQ(-1, *s);
            SeqIter<size_t> t(5);
            ASSERT_EQ(5, *t);
            t = 0;
            ASSERT_EQ(0, *t);
            SeqIter<bool> b(true);
            ASSERT_EQ(true, b);
            b = false;
            ASSERT_EQ(false, b);

            // Dereference
            s = 10;
            SeqIter<int> u = *s;
            ASSERT_EQ(10, *u);

            // Array access
            ASSERT_EQ(10, s[0]);
            ASSERT_EQ(9, s[-1]);
            ASSERT_EQ(0, s[-10]);
            ASSERT_EQ(20, s[10]);
            ASSERT_EQ(true, b[1]);

            // Increment/Decrement
            u = s--;
            ASSERT_EQ(10, u);
            ASSERT_EQ(9, s);
            u = s++;
            ASSERT_EQ(9, u);
            ASSERT_EQ(10, s);
            u = --s;
            ASSERT_EQ(9, u);
            ASSERT_EQ(9, s);
            u = ++s;
            ASSERT_EQ(10, u);
            ASSERT_EQ(10, s);
            s += 1;
            ASSERT_EQ(11, s);
            s -= 1;
            ASSERT_EQ(10, s);
            u = s - 1;
            ASSERT_EQ(10, s);
            ASSERT_EQ(9, u);
            u = u + 1;
            ASSERT_EQ(10, u);
            s = 1 + u;
            ASSERT_EQ(11, s);
            s = -1 + s;
            ASSERT_EQ(10, s);

            // Difference
            ASSERT_EQ(0, u - s);
            ASSERT_EQ(1, (u + 1) - s);

            // Equality
            ASSERT_TRUE(u == s);
            ASSERT_TRUE(u != s + 1);
            ASSERT_FALSE(u == s + 1);

            // Comparison
            ASSERT_TRUE(u - 1 < s);
            ASSERT_FALSE(u < s - 1);
            ASSERT_TRUE(u > s - 1);
            ASSERT_FALSE(u - 1 > s);
            ASSERT_TRUE(u >= s - 1);
            ASSERT_TRUE(u >= s);
            ASSERT_FALSE(u - 1 >= s);
            ASSERT_TRUE(u - 1 <= s);
            ASSERT_TRUE(u <= s);
            ASSERT_FALSE(u <= s - 1);

            // Value
            ASSERT_EQ(10, *s);
            ASSERT_EQ(11, *(s + 1));
        }

        TEST(IteratorTest, PtrIter)
        {
            array<int, 3> arr{ -1, 0, 1 };
            auto arr_zero = arr.data() + 1;

            // Construction
            PtrIter<int *> s(arr_zero);
            ASSERT_EQ(arr_zero, s.ptr());
            s = arr_zero;
            ASSERT_EQ(arr_zero, s.ptr());

            // Dereference
            s = arr_zero;
            PtrIter<int *> u = s;
            ASSERT_EQ(arr_zero, u.ptr());

            // Array access
            ASSERT_EQ(-1, s[-1]);
            ASSERT_EQ(0, s[0]);
            ASSERT_EQ(1, s[1]);

            // Increment/Decrement
            u = s--;
            ASSERT_EQ(0, *u);
            ASSERT_EQ(-1, *s);
            u = s++;
            ASSERT_EQ(-1, *u);
            ASSERT_EQ(0, *s);
            u = --s;
            ASSERT_EQ(-1, *u);
            ASSERT_EQ(-1, *s);
            u = ++s;
            ASSERT_EQ(0, *u);
            ASSERT_EQ(0, *s);
            s += 1;
            ASSERT_EQ(1, *s);
            s -= 1;
            ASSERT_EQ(0, *s);
            u = s - 1;
            ASSERT_EQ(0, *s);
            ASSERT_EQ(-1, *u);
            u = u + 1;
            ASSERT_EQ(0, *u);
            s = 1 + u;
            ASSERT_EQ(1, *s);
            s = -1 + s;
            ASSERT_EQ(0, *s);

            // Difference
            ASSERT_EQ(0, u - s);
            ASSERT_EQ(1, (u + 1) - s);

            // Equality
            ASSERT_TRUE(u == s);
            ASSERT_TRUE(u != s + 1);
            ASSERT_FALSE(u == s + 1);

            // Comparison
            ASSERT_TRUE(u - 1 < s);
            ASSERT_FALSE(u < s - 1);
            ASSERT_TRUE(u > s - 1);
            ASSERT_FALSE(u - 1 > s);
            ASSERT_TRUE(u >= s - 1);
            ASSERT_TRUE(u >= s);
            ASSERT_FALSE(u - 1 >= s);
            ASSERT_TRUE(u - 1 <= s);
            ASSERT_TRUE(u <= s);
            ASSERT_FALSE(u <= s - 1);

            // Pointer
            ASSERT_EQ(arr_zero, s.ptr());
            ASSERT_EQ(arr_zero, static_cast<int *>(s));
            ASSERT_EQ(arr_zero, static_cast<const int *>(s));
        }

        TEST(IteratorTest, StrideIter)
        {
            array<uint64_t, 6> arr{ 0, 1, 2, 3, 4, 5 };
            auto arr_zero = arr.data();

            // Construction
            StrideIter<uint64_t *> s(arr_zero, 3);
            ASSERT_EQ(3, s.stride());
            s = StrideIter<uint64_t *>(arr_zero, 2);
            ASSERT_EQ(2, s.stride());

            // Dereference
            CoeffIter t = *s;
            ASSERT_EQ(arr_zero, t.ptr());

            // Array access
            ASSERT_EQ(0, *s[0]);
            ASSERT_EQ(2, *s[1]);
            ASSERT_EQ(4, *s[2]);

            // Increment/Decrement
            StrideIter<uint64_t *> u = s++;
            ASSERT_EQ(0, **u);
            ASSERT_EQ(2, **s);
            u = s--;
            ASSERT_EQ(2, **u);
            ASSERT_EQ(0, **s);
            u = ++s;
            ASSERT_EQ(2, **u);
            ASSERT_EQ(2, **s);
            u = --s;
            ASSERT_EQ(0, **u);
            ASSERT_EQ(0, **s);
            s += 1;
            ASSERT_EQ(2, **s);
            s -= 1;
            ASSERT_EQ(0, **s);
            u = s + 1;
            ASSERT_EQ(0, **s);
            ASSERT_EQ(2, **u);
            u = u - 1;
            ASSERT_EQ(0, **u);
            s = 2 + u;
            ASSERT_EQ(4, **s);
            s = -1 + s;
            ASSERT_EQ(2, **s);

            // Difference
            u = s;
            ASSERT_EQ(0, u - s);
            ASSERT_EQ(1, (u + 1) - s);

            // Equality
            ASSERT_TRUE(u == s);
            ASSERT_TRUE(u != s + 1);
            ASSERT_FALSE(u == s + 1);

            // Comparison
            ASSERT_TRUE(u - 1 < s);
            ASSERT_FALSE(u < s - 1);
            ASSERT_TRUE(u > s - 1);
            ASSERT_FALSE(u - 1 > s);
            ASSERT_TRUE(u >= s - 1);
            ASSERT_TRUE(u >= s);
            ASSERT_FALSE(u - 1 >= s);
            ASSERT_TRUE(u - 1 <= s);
            ASSERT_TRUE(u <= s);
            ASSERT_FALSE(u <= s - 1);
        }

        TEST(IteratorTest, RNSIter)
        {
            array<uint64_t, 6> arr{ 0, 1, 2, 3, 4, 5 };
            auto arr_zero = arr.data();

            // Construction
            RNSIter s(arr_zero, 3);
            ASSERT_EQ(3, s.poly_modulus_degree());
            s = RNSIter(arr_zero, 2);
            ASSERT_EQ(2, s.poly_modulus_degree());

            // Dereference
            CoeffIter t = *s;
            ASSERT_EQ(arr_zero, t.ptr());

            // Array access
            ASSERT_EQ(0, *s[0]);
            ASSERT_EQ(2, *s[1]);
            ASSERT_EQ(4, *s[2]);

            // Increment/Decrement
            RNSIter u = s++;
            ASSERT_EQ(0, **u);
            ASSERT_EQ(2, **s);
            u = s--;
            ASSERT_EQ(2, **u);
            ASSERT_EQ(0, **s);
            u = ++s;
            ASSERT_EQ(2, **u);
            ASSERT_EQ(2, **s);
            u = --s;
            ASSERT_EQ(0, **u);
            ASSERT_EQ(0, **s);
            s += 1;
            ASSERT_EQ(2, **s);
            s -= 1;
            ASSERT_EQ(0, **s);
            u = s + 1;
            ASSERT_EQ(0, **s);
            ASSERT_EQ(2, **u);
            u = u - 1;
            ASSERT_EQ(0, **u);
            s = 2 + u;
            ASSERT_EQ(4, **s);
            s = -1 + s;
            ASSERT_EQ(2, **s);

            // Difference
            u = s;
            ASSERT_EQ(0, u - s);
            ASSERT_EQ(1, (u + 1) - s);

            // Equality
            ASSERT_TRUE(u == s);
            ASSERT_TRUE(u != s + 1);
            ASSERT_FALSE(u == s + 1);

            // Comparison
            ASSERT_TRUE(u - 1 < s);
            ASSERT_FALSE(u < s - 1);
            ASSERT_TRUE(u > s - 1);
            ASSERT_FALSE(u - 1 > s);
            ASSERT_TRUE(u >= s - 1);
            ASSERT_TRUE(u >= s);
            ASSERT_FALSE(u - 1 >= s);
            ASSERT_TRUE(u - 1 <= s);
            ASSERT_TRUE(u <= s);
            ASSERT_FALSE(u <= s - 1);
        }

        TEST(IteratorTest, PolyIter)
        {
            array<uint64_t, 18> arr{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
            auto arr_zero = arr.data();

            // Construction
            PolyIter s(arr_zero, 3, 2);
            ASSERT_EQ(3, s.poly_modulus_degree());
            ASSERT_EQ(2, s.coeff_modulus_size());
            s = PolyIter(arr_zero, 2, 3);
            ASSERT_EQ(2, s.poly_modulus_degree());
            ASSERT_EQ(3, s.coeff_modulus_size());

            // Dereference
            RNSIter t = *s;
            ASSERT_EQ(arr_zero, t);
            ASSERT_EQ(2, t.poly_modulus_degree());

            // Array access
            ASSERT_EQ(0, **s[0]);
            ASSERT_EQ(6, **s[1]);
            ASSERT_EQ(12, **s[2]);

            // Increment/Decrement
            PolyIter u = s++;
            ASSERT_EQ(0, ***u);
            ASSERT_EQ(6, ***s);
            u = s--;
            ASSERT_EQ(6, ***u);
            ASSERT_EQ(0, ***s);
            u = ++s;
            ASSERT_EQ(6, ***u);
            ASSERT_EQ(6, ***s);
            u = --s;
            ASSERT_EQ(0, ***u);
            ASSERT_EQ(0, ***s);
            s += 1;
            ASSERT_EQ(6, ***s);
            s -= 1;
            ASSERT_EQ(0, ***s);
            u = s + 1;
            ASSERT_EQ(0, ***s);
            ASSERT_EQ(6, ***u);
            u = u - 1;
            ASSERT_EQ(0, ***u);
            s = 2 + u;
            ASSERT_EQ(12, ***s);
            s = -1 + s;
            ASSERT_EQ(6, ***s);

            // Difference
            u = s;
            ASSERT_EQ(0, u - s);
            ASSERT_EQ(1, (u + 1) - s);

            // Equality
            ASSERT_TRUE(u == s);
            ASSERT_TRUE(u != s + 1);
            ASSERT_FALSE(u == s + 1);

            // Comparison
            ASSERT_TRUE(u - 1 < s);
            ASSERT_FALSE(u < s - 1);
            ASSERT_TRUE(u > s - 1);
            ASSERT_FALSE(u - 1 > s);
            ASSERT_TRUE(u >= s - 1);
            ASSERT_TRUE(u >= s);
            ASSERT_FALSE(u - 1 >= s);
            ASSERT_TRUE(u - 1 <= s);
            ASSERT_TRUE(u <= s);
            ASSERT_FALSE(u <= s - 1);
        }

        TEST(IteratorTest, IterTuple)
        {
            // Construction/Get
            IterTuple<SeqIter<int>, SeqIter<int>> s(0, 1);
            ASSERT_EQ(0, get<0>(s));
            ASSERT_EQ(1, get<1>(s));
            s = IterTuple<SeqIter<int>, SeqIter<int>>(1, 0);
            ASSERT_EQ(1, *get<0>(s));
            ASSERT_EQ(0, *get<1>(s));

            // Get
            ASSERT_EQ(0, get<0>(IterTuple<SeqIter<int>, SeqIter<int>>{ 0, 1 }));
            ASSERT_EQ(1, get<1>(IterTuple<SeqIter<int>, SeqIter<int>>{ 0, 1 }));

            // Dereference
            auto t = *s;
            ASSERT_EQ(1, get<0>(t));
            ASSERT_EQ(0, get<1>(t));

            // Array access
            ASSERT_EQ(1, get<0>(s[0]));
            ASSERT_EQ(0, get<1>(s[0]));
            ASSERT_EQ(0, get<0>(s[-1]));
            ASSERT_EQ(-1, get<1>(s[-1]));
            ASSERT_EQ(2, get<0>(s[1]));
            ASSERT_EQ(1, get<1>(s[1]));

            // Increment/Decrement
            auto u = s++;
            ASSERT_EQ(1, *get<0>(u));
            ASSERT_EQ(0, *get<1>(u));
            ASSERT_EQ(2, *get<0>(s));
            ASSERT_EQ(1, *get<1>(s));
            u = s--;
            ASSERT_EQ(2, *get<0>(u));
            ASSERT_EQ(1, *get<1>(u));
            ASSERT_EQ(1, *get<0>(s));
            ASSERT_EQ(0, *get<1>(s));
            u = ++s;
            ASSERT_EQ(2, *get<0>(u));
            ASSERT_EQ(1, *get<1>(u));
            ASSERT_EQ(2, *get<0>(s));
            ASSERT_EQ(1, *get<1>(s));
            u = --s;
            ASSERT_EQ(1, *get<0>(u));
            ASSERT_EQ(0, *get<1>(u));
            ASSERT_EQ(1, *get<0>(s));
            ASSERT_EQ(0, *get<1>(s));
            s += 1;
            ASSERT_EQ(2, *get<0>(s));
            ASSERT_EQ(1, *get<1>(s));
            s -= 1;
            ASSERT_EQ(1, *get<0>(s));
            ASSERT_EQ(0, *get<1>(s));
            u = s + 1;
            ASSERT_EQ(2, *get<0>(u));
            ASSERT_EQ(1, *get<1>(u));
            ASSERT_EQ(1, *get<0>(s));
            ASSERT_EQ(0, *get<1>(s));
            u = u - 1;
            ASSERT_EQ(1, *get<0>(u));
            ASSERT_EQ(0, *get<1>(u));
            s = 2 + u;
            ASSERT_EQ(3, *get<0>(s));
            ASSERT_EQ(2, *get<1>(s));
            s = -1 + s;
            ASSERT_EQ(2, *get<0>(s));
            ASSERT_EQ(1, *get<1>(s));

            // Difference
            u = s;
            ASSERT_EQ(0, u - s);
            ASSERT_EQ(1, (u + 1) - s);

            // Equality
            ASSERT_TRUE(u == s);
            ASSERT_TRUE(u != s + 1);
            ASSERT_FALSE(u == s + 1);

            // Comparison
            ASSERT_TRUE(u - 1 < s);
            ASSERT_FALSE(u < s - 1);
            ASSERT_TRUE(u > s - 1);
            ASSERT_FALSE(u - 1 > s);
            ASSERT_TRUE(u >= s - 1);
            ASSERT_TRUE(u >= s);
            ASSERT_FALSE(u - 1 >= s);
            ASSERT_TRUE(u - 1 <= s);
            ASSERT_TRUE(u <= s);
            ASSERT_FALSE(u <= s - 1);
        }

        TEST(IteratorTest, ReverseIter)
        {
            // Construction
            ReverseIter<SeqIter<int>> s{};
            ASSERT_EQ(0, *s);
            s = reverse_iter(-1);
            ASSERT_EQ(-1, *s);
            s = reverse_iter(1);
            ASSERT_EQ(1, *s);
            ReverseIter<SeqIter<size_t>> t(5);
            ASSERT_EQ(5, *t);
            t = reverse_iter(size_t(0));
            ASSERT_EQ(0, *t);

            // Dereference
            s = reverse_iter(10);
            SeqIter<int> v = *s;
            ASSERT_EQ(10, *v);

            // Array access
            ASSERT_EQ(10, s[0]);
            ASSERT_EQ(11, s[-1]);
            ASSERT_EQ(20, s[-10]);
            ASSERT_EQ(0, s[10]);

            // Increment/Decrement
            auto u = s--;
            ASSERT_EQ(10, u);
            ASSERT_EQ(11, s);
            u = s++;
            ASSERT_EQ(11, u);
            ASSERT_EQ(10, s);
            u = --s;
            ASSERT_EQ(11, u);
            ASSERT_EQ(11, s);
            u = ++s;
            ASSERT_EQ(10, u);
            ASSERT_EQ(10, s);
            s += 1;
            ASSERT_EQ(9, s);
            s -= 1;
            ASSERT_EQ(10, s);
            u = s - 1;
            ASSERT_EQ(10, s);
            ASSERT_EQ(11, u);
            u = u + 1;
            ASSERT_EQ(10, u);
            s = 1 + u;
            ASSERT_EQ(9, s);
            s = -1 + s;
            ASSERT_EQ(10, s);

            // Difference
            ASSERT_EQ(0, u - s);
            ASSERT_EQ(1, (u + 1) - s);
            ASSERT_EQ(-1, (u - 1) - s);
            ASSERT_EQ(1, u - (s - 1));
            ASSERT_EQ(-1, u - (s + 1));

            // Equality
            ASSERT_TRUE(u == s);
            ASSERT_TRUE(u != s + 1);
            ASSERT_FALSE(u == s + 1);

            // Comparison
            ASSERT_TRUE(u - 1 < s);
            ASSERT_FALSE(u < s - 1);
            ASSERT_TRUE(u > s - 1);
            ASSERT_FALSE(u - 1 > s);
            ASSERT_TRUE(u >= s - 1);
            ASSERT_TRUE(u >= s);
            ASSERT_FALSE(u - 1 >= s);
            ASSERT_TRUE(u - 1 <= s);
            ASSERT_TRUE(u <= s);
            ASSERT_FALSE(u <= s - 1);
        }
    } // namespace util
} // namespace sealtest
