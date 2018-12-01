// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/numth.h"
#include "seal/util/uintcore.h"

using namespace std;

namespace seal
{
    namespace util
    {
        vector<uint64_t> conjugate_classes(uint64_t modulus, 
            uint64_t subgroup_generator)
        {
            if (!product_fits_in(modulus, subgroup_generator))
            {
                throw invalid_argument("inputs too large");
            }

            vector<uint64_t> classes{};
            for (uint64_t i = 0; i < modulus; i++)
            {
                if (gcd(i, modulus) > 1)
                {
                    classes.push_back(0);
                }
                else
                {
                    classes.push_back(i);
                }
            }
            for (uint64_t i = 0; i < modulus; i++)
            {
                if (classes[i] == 0)
                {
                    continue;
                }
                if (classes[i] < i)
                {
                    // i is not a pivot, updated its pivot
                    classes[i] = classes[classes[i]];
                    continue;
                }
                // If i is a pivot, update other pivots to point to it
                uint64_t j = (i * subgroup_generator) % modulus;
                while (classes[j] != i)
                {
                    // Merge the equivalence classes of j and i
                    // Note: if classes[j] != j then classes[j] will be updated later,
                    // when we get to i = j and use the code for "i not pivot".
                    classes[classes[j]] = i;
                    j = (j * subgroup_generator) % modulus;
                }
            }
            return classes;
        }

        vector<uint64_t> multiplicative_orders(
            vector<uint64_t> conjugate_classes, uint64_t modulus)
        {
            if (!product_fits_in(modulus, modulus))
            {
                throw invalid_argument("inputs too large");
            }

            vector<uint64_t> orders{};
            orders.push_back(0);
            orders.push_back(1);

            for (uint64_t i = 2; i < modulus; i++)
            {
                if (conjugate_classes[i] <= 1)
                {
                    orders.push_back(conjugate_classes[i]);
                    continue;
                }
                if (conjugate_classes[i] < i)
                {
                    orders.push_back(orders[conjugate_classes[i]]);
                    continue;
                }
                uint64_t j = (i * i) % modulus;
                uint64_t order = 2;
                while (conjugate_classes[j] != 1)
                {
                    j = (j * i) % modulus;
                    order++;
                }
                orders.push_back(order);
            }
            return orders;
        }

        void babystep_giantstep(uint64_t modulus, 
            vector<uint64_t> &baby_steps, vector<uint64_t> &giant_steps)
        {
            int exponent = get_power_of_two(modulus);
            if (exponent < 0)
            {
                throw invalid_argument("modulus must be a power of 2");
            }

            // Compute square root of modulus (k stores the baby steps)
            uint64_t k = uint64_t(1) << (exponent / 2);
            uint64_t l = modulus / k;

            baby_steps.clear();
            giant_steps.clear();

            uint64_t m = mul_safe(modulus, uint64_t(2));
            uint64_t g = 3; // the generator
            uint64_t kprime = k >> 1;
            uint64_t value = 1;
            for (uint64_t i = 0; i < kprime; i++)
            {
                baby_steps.push_back(value);
                baby_steps.push_back(m - value);
                value = mul_safe(value, g) % m;
            }

            // now value should equal to g**kprime 
            uint64_t value2 = value;
            for (uint64_t j = 0; j < l; j++)
            {
                giant_steps.push_back(value2);
                value2 = mul_safe(value2, value) % m;
            }
        }

        pair<size_t, size_t> decompose_babystep_giantstep(
            uint64_t modulus, uint64_t input, 
            const vector<uint64_t> &baby_steps, 
            const vector<uint64_t> &giant_steps)
        {
            for (size_t i = 0; i < giant_steps.size(); i++)
            {
                uint64_t gs = giant_steps[i];
                for (size_t j = 0; j < baby_steps.size(); j++)
                {
                    uint64_t bs = baby_steps[j];
                    if (mul_safe(gs, bs) % modulus == input)
                    {
                        return { i, j };
                    }
                }
            }
            throw logic_error("failed to decompose input");
        }
    }
}
