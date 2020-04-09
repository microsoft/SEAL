// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/randomgen.h"
#include "seal/randomtostd.h"
#include "seal/util/clipnormal.h"
#include <cmath>
#include <memory>
#include "gtest/gtest.h"

using namespace seal::util;
using namespace seal;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(ClipNormal, ClipNormalGenerate)
        {
            shared_ptr<UniformRandomGenerator> generator(UniformRandomGeneratorFactory::DefaultFactory()->create());
            RandomToStandardAdapter rand(generator);
            ClippedNormalDistribution dist(50.0, 10.0, 20.0);

            ASSERT_EQ(50.0, dist.mean());
            ASSERT_EQ(10.0, dist.standard_deviation());
            ASSERT_EQ(20.0, dist.max_deviation());
            ASSERT_EQ(30.0, dist.min());
            ASSERT_EQ(70.0, dist.max());
            double average = 0;
            double stddev = 0;
            for (int i = 0; i < 100; ++i)
            {
                double value = dist(rand);
                average += value;
                stddev += (value - 50.0) * (value - 50.0);
                ASSERT_TRUE(value >= 30.0 && value <= 70.0);
            }
            average /= 100;
            stddev /= 100;
            stddev = sqrt(stddev);
            ASSERT_TRUE(average >= 40.0 && average <= 60.0);
            ASSERT_TRUE(stddev >= 5.0 && stddev <= 15.0);
        }
    } // namespace util
} // namespace sealtest
